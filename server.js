/**
 * Captive Portal Server
 * OPNsense captive portal with Google OAuth, CardDAV verification, and Home Assistant integration
 * 
 * This is the main entry point that ties together all modules.
 */

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const Database = require('better-sqlite3');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bodyParser = require('body-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Import modules
const db = require('./lib/database');
const carddav = require('./lib/carddav');
const homeassistant = require('./lib/homeassistant');
const opnsense = require('./lib/opnsense');
const people = require('./lib/people');
const logger = require('./lib/logger');

// Initialize people module with database and HA notification
people.init(db, homeassistant.notifyHomeAssistant);

// Re-export commonly used functions for convenience
const { 
  normalizePhone, 
  normalizeBirthdate,
  searchCardDAV, 
  searchCardDAVByName, 
  searchCardDAVByPhone,
  updateCardDAVContactBirthdate,
  createCardDAVContact,
  createOrUpdateCardDAVContact,
  getContactWithPhoto,
  getContactByNameWithDetails,
  getContactByPhoneWithDetails,
  fuzzySearchCardDAVByName,
  findBestMatchingContact,
  CardDAVError,
  CardDAVErrorCodes
} = carddav;

const { notifyHomeAssistant, registerDeviceTracker } = homeassistant;
const { 
  allowMacInOPNsense, 
  revokeMacInOPNsense, 
  normalizeMacAddress, 
  getArpTable, 
  checkMacsOnline,
  getWhitelistedMacs,
  OPNsenseError,
  ErrorCodes: OPNsenseErrorCodes
} = opnsense;
const { findOrCreatePerson, associateDeviceWithPerson, getPersonDevices, getPersonPresence } = people;

// Session timeout redirect URL
const SESSION_TIMEOUT_REDIRECT = process.env.SESSION_TIMEOUT_REDIRECT || '/';

// Success page redirect URL (where to go after successful login)
const SUCCESS_REDIRECT_URL = process.env.SUCCESS_REDIRECT_URL || null; // null means stay on success page

// Success page auto-close configuration
const SUCCESS_AUTO_CLOSE_ENABLED = process.env.SUCCESS_AUTO_CLOSE_ENABLED !== 'false'; // default true
const SUCCESS_AUTO_CLOSE_TIMEOUT = parseInt(process.env.SUCCESS_AUTO_CLOSE_TIMEOUT) || 1500; // default 1500ms

// ARP polling interval (ms)
const ARP_POLL_INTERVAL = (parseInt(process.env.OPNSENSE_ARP_POLL_INTERVAL) || 60) * 1000;

// Session purge interval (ms) - default 24 hours
const SESSION_PURGE_INTERVAL = (parseInt(process.env.SESSION_PURGE_HOURS) || 24) * 60 * 60 * 1000;

// Session max age for purge (hours) - sessions older than this are deleted
const SESSION_MAX_AGE_HOURS = parseInt(process.env.SESSION_MAX_AGE_HOURS) || 72; // 3 days

// Device offline timeout in seconds - device is considered offline after this many seconds since last_seen
// Can be changed via /api/ha/config endpoint
let DEVICE_OFFLINE_TIMEOUT = parseInt(process.env.DEVICE_OFFLINE_TIMEOUT) || 30;

// Maximum failed authentication attempts before blocking a MAC
const MAX_FAILED_ATTEMPTS = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 3;

// OPNsense MAC sync interval (ms) - how often to check for removed MACs
const OPNSENSE_SYNC_INTERVAL = (parseInt(process.env.OPNSENSE_SYNC_INTERVAL) || 60) * 1000;

// In-memory store for invalidated session IDs
// When a person/device is deleted, their session IDs are added here
// Express sessions with these IDs will be destroyed on next request
const invalidatedSessionIds = new Set();

// Auto-approval mode state
let autoApprovalMode = {
  enabled: false,
  expiresAt: null,
  timeoutMinutes: 60,
  timer: null
};

// Clean up old invalidated session IDs periodically (they expire after 24 hours anyway)
setInterval(() => {
  // We'll keep track of when sessions were invalidated in a Map if we need expiry
  // For now, just keep them since sessions expire anyway
  logger.info(`[Session Invalidation] Tracking ${invalidatedSessionIds.size} invalidated session IDs`);
}, 60 * 60 * 1000); // Log every hour

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    },
  },
}));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Rate limiting for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { error: 'Too many authentication attempts, please try again later.' }
});

// Session store using SQLite (persistent, production-ready)
const sessionDbPath = process.env.SESSION_DB_PATH || path.join(__dirname, 'data', 'sessions.db');
const sessionDb = new Database(sessionDbPath);
logger.info(`[Session Store] Using SQLite session store at ${sessionDbPath}`);

// Session configuration
// NOTE: For OAuth to work, the session cookie must persist across redirects to Google
const isProduction = process.env.NODE_ENV === 'production';
app.use(session({
  store: new SqliteStore({
    client: sessionDb,
    expired: {
      clear: true,
      intervalMs: 15 * 60 * 1000 // Clear expired sessions every 15 minutes
    }
  }),
  secret: process.env.SESSION_SECRET || 'change-this-secret-in-production',
  resave: false, // Don't save session if unmodified (SQLite store handles this)
  saveUninitialized: false, // Don't create session until something stored
  rolling: true, // Reset expiration on each request
  cookie: {
    secure: isProduction, // Only require HTTPS in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Allow cookie to be sent on OAuth redirects
  }
}));

// Trust proxy if behind reverse proxy (needed for secure cookies)
if (isProduction) {
  app.set('trust proxy', 1);
} else {
  app.set('trust proxy', process.env.TRUST_PROXY ?? 1);
}

// ============================================================================
// INVALIDATED SESSION CHECK MIDDLEWARE
// ============================================================================

/**
 * Middleware to handle cookie sessions that have been invalidated
 * (e.g., when a person or device was deleted)
 * 
 * Instead of destroying the session (which breaks passport), we regenerate it
 * to get a fresh session while keeping the cookie infrastructure intact.
 */
app.use((req, res, next) => {
  if (req.session && req.session.sessionId) {
    if (invalidatedSessionIds.has(req.session.sessionId)) {
      const oldSessionId = req.session.sessionId;
      logger.info(`[Session] Invalidating cookie session: ${oldSessionId}`);
      // Remove from tracking
      invalidatedSessionIds.delete(oldSessionId);
      
      // Regenerate the session - this creates a new session ID and clears old data
      // but keeps the session infrastructure intact for passport
      req.session.regenerate((err) => {
        if (err) {
          logger.error('[Session] Error regenerating session:', err);
          // Fall back to just clearing session variables
          delete req.session.sessionId;
          delete req.session.userId;
          delete req.session.pendingMac;
          delete req.session.pendingIp;
          delete req.session.oauthUser;
          delete req.session.verifiedUser;
          delete req.session.contactVerified;
          delete req.session.authMethod;
          delete req.session.existingPersonId;
        }
        logger.info(`[Session] Session regenerated, old session ${oldSessionId} invalidated`);
        next();
      });
      return;
    }
  }
  next();
});

// ============================================================================
// MAC BLOCKING HELPERS
// ============================================================================

/**
 * Check if a MAC address is blocked
 */
function isMacBlocked(mac) {
  if (!mac) return false;
  const normalizedMac = mac.toUpperCase();
  const blocked = db.prepare('SELECT * FROM blocked_macs WHERE mac_address = ?').get(normalizedMac);
  return !!blocked;
}

/**
 * Record a failed authentication attempt
 * Returns true if MAC should be blocked (exceeded MAX_FAILED_ATTEMPTS)
 */
function recordFailedAttempt(mac, attemptType, details = '') {
  if (!mac) return false;
  const normalizedMac = mac.toUpperCase();
  
  // Record the attempt
  db.prepare(`
    INSERT INTO failed_attempts (mac_address, attempt_type, details)
    VALUES (?, ?, ?)
  `).run(normalizedMac, attemptType, details);
  
  // Count recent attempts (last 24 hours)
  const count = db.prepare(`
    SELECT COUNT(*) as count FROM failed_attempts 
    WHERE mac_address = ? 
    AND created_at > datetime('now', '-24 hours')
  `).get(normalizedMac);
  
  logger.info(`[Security] MAC ${normalizedMac} has ${count.count} failed attempts (max: ${MAX_FAILED_ATTEMPTS})`);
  
  if (count.count >= MAX_FAILED_ATTEMPTS) {
    // Block the MAC
    blockMac(normalizedMac, `Exceeded ${MAX_FAILED_ATTEMPTS} failed authentication attempts`);
    return true;
  }
  
  return false;
}

/**
 * Block a MAC address
 */
function blockMac(mac, reason) {
  if (!mac) return;
  const normalizedMac = mac.toUpperCase();
  
  db.prepare(`
    INSERT INTO blocked_macs (mac_address, reason)
    VALUES (?, ?)
    ON CONFLICT(mac_address) DO UPDATE SET reason = ?, blocked_at = CURRENT_TIMESTAMP
  `).run(normalizedMac, reason, reason);
  
  logger.warn(`[Security] BLOCKED MAC ${normalizedMac}: ${reason}`);
  
  // Also invalidate any existing sessions for this MAC
  const sessionIds = db.prepare('SELECT id FROM sessions WHERE mac_address = ?').all(normalizedMac).map(s => s.id);
  if (sessionIds.length > 0) {
    db.prepare(`UPDATE sessions SET disabled = 1 WHERE mac_address = ?`).run(normalizedMac);
    db.prepare(`
      UPDATE approval_requests SET disabled = 1, status = 'denied' 
      WHERE session_id IN (${sessionIds.map(() => '?').join(',')})
    `).run(...sessionIds);
    
    sessionIds.forEach(id => invalidatedSessionIds.add(id));
  }
}

/**
 * Get remaining attempts for a MAC
 */
function getRemainingAttempts(mac) {
  if (!mac) return MAX_FAILED_ATTEMPTS;
  const normalizedMac = mac.toUpperCase();
  
  const count = db.prepare(`
    SELECT COUNT(*) as count FROM failed_attempts 
    WHERE mac_address = ? 
    AND created_at > datetime('now', '-24 hours')
  `).get(normalizedMac);
  
  return Math.max(0, MAX_FAILED_ATTEMPTS - count.count);
}

// ============================================================================
// SESSION STATE MACHINE
// ============================================================================

/**
 * Session States:
 * - NO_SESSION: No MAC address, need to go through handoff
 * - NEED_AUTH: Has MAC but not authenticated
 * - NEED_VERIFICATION: Authenticated via OAuth but need to verify identity
 * - PENDING_APPROVAL: Verified, waiting for admin approval
 * - APPROVED: Admin approved, need to select device type
 * - COMPLETED: Flow complete, device whitelisted
 */
const SessionState = {
  NO_SESSION: 'no_session',
  NEED_AUTH: 'need_auth',
  NEED_VERIFICATION: 'need_verification',
  PENDING_APPROVAL: 'pending_approval',
  APPROVED: 'approved',
  COMPLETED: 'completed'
};

/**
 * Determine current session state
 */
function getSessionState(req) {
  // No MAC = no session started
  if (!req.session.pendingMac) {
    return SessionState.NO_SESSION;
  }
  
  // Not authenticated yet
  if (!req.session.sessionId) {
    return SessionState.NEED_AUTH;
  }
  
  // Check approval status from database
  const approval = db.prepare(`
    SELECT status, flow_completed, disabled FROM approval_requests WHERE session_id = ?
  `).get(req.session.sessionId);
  
  if (!approval) {
    logger.debug(`[State] No approval record for session ${req.session.sessionId}`);
    return SessionState.NEED_AUTH;
  }
  
  // If session is disabled (person/device was deleted), treat as need auth
  if (approval.disabled === 1) {
    logger.debug(`[State] Session ${req.session.sessionId} is disabled`);
    // Clear the session so user can start fresh
    delete req.session.sessionId;
    delete req.session.userId;
    return SessionState.NEED_AUTH;
  }
  
  // Flow completed
  if (approval.flow_completed === 1) {
    return SessionState.COMPLETED;
  }
  
  // Approved but not completed device selection
  if (approval.status === 'approved') {
    logger.debug(`[State] Session ${req.session.sessionId} is APPROVED (flow_completed=${approval.flow_completed})`);
    return SessionState.APPROVED;
  }
  
  // Pending approval
  if (approval.status === 'pending') {
    // Check if OAuth user needs verification
    if (req.session.authMethod === 'google' && !req.session.contactVerified) {
      logger.debug(`[State] Session ${req.session.sessionId} is PENDING but needs verification (authMethod=${req.session.authMethod}, contactVerified=${req.session.contactVerified})`);
      return SessionState.NEED_VERIFICATION;
    }
    logger.debug(`[State] Session ${req.session.sessionId} is PENDING_APPROVAL`);
    return SessionState.PENDING_APPROVAL;
  }
  
  logger.debug(`[State] Session ${req.session.sessionId} has unknown status: ${approval.status}`);
  return SessionState.NEED_AUTH;
}

/**
 * Get the correct page for a session state
 */
function getPageForState(state) {
  switch (state) {
    case SessionState.NO_SESSION:
    case SessionState.NEED_AUTH:
      return '/';
    case SessionState.NEED_VERIFICATION:
      return '/verify-identity.html';
    case SessionState.PENDING_APPROVAL:
      return '/waiting.html';
    case SessionState.APPROVED:
      return '/device-select.html';
    case SessionState.COMPLETED:
      return null; // No redirect needed, user has access
    default:
      return '/';
  }
}

/**
 * State machine middleware - redirects users to correct page based on state
 * Skip for API routes, static assets, auth routes
 */
function stateMiddleware(req, res, next) {
  // Skip for API routes
  if (req.path.startsWith('/api/')) {
    return next();
  }
  
  // Skip for auth routes (OAuth flow)
  if (req.path.startsWith('/auth/')) {
    return next();
  }
  
  // Skip for admin routes
  if (req.path.startsWith('/admin')) {
    return next();
  }

  // Skip special "end pages" so they aren't redirected out from under the user
  if (req.path === '/auto-approved' || req.path === '/success') return next();
  
  // Skip for static assets
  if (req.path.match(/\.(js|css|png|jpg|ico|svg|woff|woff2)$/)) {
    return next();
  }
  
  // Skip for handoff (entry point)
  if (req.path === '/handoff') {
    return next();
  }
  
  const state = getSessionState(req);
  logger.debug(`Current state ${state}`);
  const correctPage = getPageForState(state);
  
  // Debug logging
  logger.debug(`[STATE] ${req.method} ${req.path} - State: ${state}, Correct: ${correctPage || 'any'}`);
  
  // If completed, allow any page
  if (state === SessionState.COMPLETED) {
    return next();
  }
  
  // Check if user is on the correct page
  const currentPage = req.path === '/' ? '/' : req.path;
  
  // Allow index.html for need_auth state
  if (state === SessionState.NEED_AUTH && (currentPage === '/' || currentPage === '/index.html')) {
    return next();
  }
  
  // If on wrong page, redirect
  if (correctPage && currentPage !== correctPage) {
    logger.info(`[STATE] Redirecting from ${currentPage} to ${correctPage}`);
    return res.redirect(correctPage);
  }
  
  next();
}

// Apply state middleware BEFORE express.static (otherwise "/" gets served before redirects)
app.use(stateMiddleware);

app.use(passport.initialize());
app.use(passport.session());

// Serve static files, but DO NOT auto-serve index.html for "/"
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
    state: true,
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      oauth_id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value,
      auth_method: 'google'
    };
    return done(null, user);
  }));
}

// ============================================================================
// ARP POLLING FOR PRESENCE DETECTION
// ============================================================================

/**
 * Poll OPNsense ARP table to update device presence
 */
async function pollArpTable() {
  try {
    // Get all tracked phone MACs from whitelist
    const trackedDevices = db.prepare(`
      SELECT mac_address, person_id FROM whitelist WHERE device_type = 'phone'
    `).all();
    
    if (trackedDevices.length === 0) return;
    
    const macs = trackedDevices.map(d => d.mac_address);
    const onlineStatus = await checkMacsOnline(macs);
    
    const now = new Date().toISOString();
    
    for (const device of trackedDevices) {
      const isOnline = onlineStatus[device.mac_address];
      if (isOnline) {
        // Update last_seen if online
        db.prepare('UPDATE whitelist SET last_seen = ? WHERE mac_address = ?')
          .run(now, device.mac_address);
      }
    }
    
    logger.debug(`[ARP Poll] Checked ${macs.length} devices, ${Object.values(onlineStatus).filter(Boolean).length} online`);
  } catch (error) {
    logger.error('[ARP Poll] Error:', error.message);
  }
}

// Start ARP polling if OPNsense is configured
if (process.env.OPNSENSE_URL && process.env.OPNSENSE_API_KEY) {
  logger.info(`[ARP Poll] Starting ARP polling every ${ARP_POLL_INTERVAL / 1000} seconds`);
  setInterval(pollArpTable, ARP_POLL_INTERVAL);
  // Run immediately on startup
  setTimeout(pollArpTable, 5000);
}

// ============================================================================
// SESSION CHECK MIDDLEWARE
// ============================================================================

/**
 * Middleware to check if session is valid for protected routes
 * Redirects to SESSION_TIMEOUT_REDIRECT if session is lost
 */
function requireSession(req, res, next) {
  if (!req.session.pendingMac && !req.session.sessionId) {
    // Session lost - redirect to start over
    if (req.accepts('html')) {
      return res.redirect(SESSION_TIMEOUT_REDIRECT);
    } else {
      return res.status(401).json({ 
        error: 'Session expired', 
        redirect: SESSION_TIMEOUT_REDIRECT 
      });
    }
  }
  next();
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Allow MAC address through firewall (OPNsense + local whitelist)
 */
async function allowMacThroughFirewall(mac) {
  // First, add to OPNsense
  await allowMacInOPNsense(mac);
  
  // The local whitelist is handled separately in the approval flow
  return true;
}

// ============================================================================
// SECURE OPNSENSE HANDOFF
// ============================================================================

// In-memory store for handoff tokens (short-lived, one-time use)
const handoffTokens = new Map();

// Clean up expired tokens every minute
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of handoffTokens.entries()) {
    if (now > data.expires) {
      handoffTokens.delete(token);
    }
  }
}, 60 * 1000);

// Create a one-time handoff token (called from OPNsense template)
app.post('/api/create-handoff-token', (req, res) => {
  const { mac, ip } = req.body;
  
  if (!mac || !ip) {
    return res.status(400).json({ error: 'MAC and IP required' });
  }
  
  // Normalize MAC address
  const normalizedMac = mac.toUpperCase().replace(/[^A-F0-9]/g, '').match(/.{2}/g)?.join(':') || mac.toUpperCase();
  
  // Generate a secure random token
  const token = uuidv4() + '-' + uuidv4();
  
  // Store token with client info (expires in 60 seconds)
  handoffTokens.set(token, {
    mac: normalizedMac,
    ip: ip,
    expires: Date.now() + 60 * 1000, // 60 second expiry
    used: false
  });
  
  res.json({ token });
});

// Handoff endpoint - exchanges token for session
app.get('/handoff', (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.redirect('/?error=missing_token');
  }
  
  const tokenData = handoffTokens.get(token);
  
  if (!tokenData) {
    return res.redirect('/?error=invalid_token');
  }
  
  if (tokenData.used) {
    return res.redirect('/?error=token_used');
  }
  
  if (Date.now() > tokenData.expires) {
    handoffTokens.delete(token);
    return res.redirect('/?error=token_expired');
  }
  
  // Mark token as used (one-time use)
  tokenData.used = true;
  handoffTokens.delete(token);
  
  // Check if MAC is blocked
  if (isMacBlocked(tokenData.mac)) {
    logger.warn(`[Handoff] Blocked MAC attempted access: ${tokenData.mac}`);
    return res.redirect('/?error=blocked');
  }
  
  // Store MAC and IP in session securely
  req.session.pendingMac = tokenData.mac;
  req.session.pendingIp = tokenData.ip;
  
  // Check if already whitelisted in our database
  const whitelisted = db.prepare('SELECT * FROM whitelist WHERE mac_address = ?').get(tokenData.mac);
  
  if (whitelisted) {
    // Already whitelisted and completed the flow - just show success
    db.prepare('UPDATE whitelist SET last_seen = CURRENT_TIMESTAMP WHERE mac_address = ?').run(tokenData.mac);
    
    req.session.userName = whitelisted.user_name;
    req.session.autoApproved = true;
    
    return res.redirect('/auto-approved');
  }
  
  // Check if there's an existing session with this MAC that's approved but not completed
  // This means they were approved but haven't selected device type yet
  const existingSession = db.prepare(`
    SELECT ar.*, s.user_id FROM approval_requests ar
    JOIN sessions s ON ar.session_id = s.id
    WHERE s.mac_address = ? AND ar.status = 'approved' AND ar.flow_completed = 0 AND COALESCE(ar.disabled, 0) = 0
    ORDER BY ar.created_at DESC
    LIMIT 1
  `).get(tokenData.mac);
  
  if (existingSession) {
    // Resume the flow - user was approved but didn't finish device selection
    req.session.sessionId = existingSession.session_id;
    req.session.userId = existingSession.user_id;
    req.session.userName = existingSession.user_name;
    req.session.autoApproved = true;
    
    logger.debug(`[Handoff] Resuming approved session for MAC ${tokenData.mac} -> device-select`);
    return res.redirect('/device-select.html');
  }
  
  // Not whitelisted, show login page
  res.redirect('/');
});

// Auto-approved page (for whitelisted devices)
app.get('/auto-approved', (req, res) => {
  if (!req.session.autoApproved) {
    return res.redirect('/');
  }
  
  const redirectUrl = SUCCESS_REDIRECT_URL || 'http://detectportal.firefox.com/success.txt';
  const shouldRedirect = !!SUCCESS_REDIRECT_URL;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Connected!</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0;
        }
        .card {
          background: white;
          border-radius: 20px;
          padding: 40px;
          text-align: center;
          box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
        }
        .checkmark {
          width: 80px;
          height: 80px;
          background: #10b981;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 20px;
        }
        .checkmark svg { width: 40px; height: 40px; color: white; }
        h1 { color: #1f2937; margin-bottom: 10px; }
        p { color: #6b7280; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="checkmark">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <h1>You're Connected!</h1>
        <p>Welcome back, ${req.session.userName || 'friend'}!</p>
        ${shouldRedirect ? '<p style="margin-top: 10px; font-size: 0.875rem;">Redirecting...</p>' : ''}
      </div>
      ${shouldRedirect ? `
      <script>
        setTimeout(() => {
          window.location.href = '${redirectUrl}';
        }, 1500);
      </script>
      ` : ''}
    </body>
    </html>
  `);
});

// ============================================================================
// AUTHENTICATION ROUTES
// ============================================================================

// Google OAuth routes
app.get('/auth/google', (req, res, next) => {
  // MAC and IP should already be in session from handoff
  // But allow URL params as fallback for direct access
  if (req.query.mac) req.session.pendingMac = req.query.mac;
  if (req.query.ip) req.session.pendingIp = req.query.ip;
  
  // Check if we have MAC - if not, redirect to start
  if (!req.session.pendingMac) {
    logger.debug('No MAC in session for Google OAuth - redirecting to start');
    return res.redirect(SESSION_TIMEOUT_REDIRECT);
  }
  
  // Save session before redirecting to Google (important!)
  req.session.save((err) => {
    if (err) {
      logger.error('Session save error:', err);
    }
    passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
  });
});

app.get('/auth/google/callback',
  (req, res, next) => {
    // IMPORTANT: Save session data BEFORE passport.authenticate
    // Passport regenerates the session after successful auth (security feature)
    // which would wipe out our pendingMac and pendingIp
    res.locals.pendingMac = req.session.pendingMac;
    res.locals.pendingIp = req.session.pendingIp;
    logger.debug(`[OAuth] Saving MAC before passport: ${res.locals.pendingMac}`);
    next();
  },
  passport.authenticate('google', { failureRedirect: '/?error=oauth_failed' }),
  async (req, res) => {
    // Restore MAC and IP from res.locals (saved before passport regenerated session)
    const mac = res.locals.pendingMac || req.session.pendingMac;
    const ip = res.locals.pendingIp || req.session.pendingIp;
    
    // Also restore to session for later use
    req.session.pendingMac = mac;
    req.session.pendingIp = ip;
    
    const userName = req.user.name;
    const userEmail = req.user.email;
    const oauthId = req.user.oauth_id;
    
    // Check if MAC is in session - if not, session was lost
    if (!mac) {
      logger.error('Google OAuth callback: No MAC in session - session may have been lost');
      return res.redirect(SESSION_TIMEOUT_REDIRECT);
    }
    
    // Check if MAC is blocked
    if (isMacBlocked(mac)) {
      logger.warn(`[OAuth] Blocked MAC attempted OAuth: ${mac}`);
      return res.redirect('/?error=blocked');
    }
    
    logger.debug(`Google OAuth callback: user=${userName}, oauth_id=${oauthId}, mac=${mac}`);
    
    // ========================================================================
    // STEP 1: Check if this Google account is already associated with a person
    // ========================================================================
    const existingUserByOAuth = db.prepare(`
      SELECT u.*, p.id as person_id, p.name as person_name, p.phone as person_phone
      FROM users u
      LEFT JOIN people p ON u.person_id = p.id
      WHERE u.oauth_id = ?
    `).get(oauthId);
    
    let existingPersonId = existingUserByOAuth?.person_id || null;
    let personVerified = false;
    
    // If user has a linked person, they've completed verification before
    if (existingPersonId) {
      const person = db.prepare('SELECT * FROM people WHERE id = ?').get(existingPersonId);
      if (person) {
        personVerified = true;
        logger.debug(`OAuth user ${userName} already linked to person: ${person.name} (id: ${existingPersonId})`);
      }
    }
    
    // ========================================================================
    // STEP 2: Check if person has approved devices (auto-approve path)
    // ========================================================================
    let isAutoApproved = false;
    if (existingPersonId) {
      const approvedDevice = db.prepare('SELECT 1 FROM whitelist WHERE person_id = ? LIMIT 1')
        .get(existingPersonId);
      if (approvedDevice) {
        isAutoApproved = true;
        logger.info(`Auto-approving ${userName} - has existing approved devices`);
      }
    }
    
    // ========================================================================
    // STEP 3: If no existing person, try fuzzy search CardDAV
    // ========================================================================
    let cardDavContact = null;
    if (!existingPersonId) {
      cardDavContact = await findBestMatchingContact(userName, 0.5);
      if (cardDavContact) {
        logger.info(`Found CardDAV fuzzy match: "${cardDavContact.name}" (similarity: ${cardDavContact.similarity.toFixed(2)})`);
      } else {
        logger.info(`No CardDAV match found for "${userName}"`);
      }
    }
    
    // ========================================================================
    // STEP 4: Create or update user record
    // ========================================================================
    let userId;
    try {
      if (existingUserByOAuth) {
        db.prepare('UPDATE users SET mac_address = ?, approved = ? WHERE oauth_id = ?')
          .run(mac, isAutoApproved ? 1 : 0, oauthId);
        userId = existingUserByOAuth.id;
      } else {
        const result = db.prepare(`
          INSERT INTO users (name, auth_method, oauth_id, mac_address, approved, person_id)
          VALUES (?, 'google', ?, ?, ?, ?)
        `).run(userName, oauthId, mac, isAutoApproved ? 1 : 0, existingPersonId);
        userId = result.lastInsertRowid;
      }
    } catch (err) {
      logger.error('User creation error:', err);
      return res.redirect('/?error=user_creation_failed');
    }
    
    // ========================================================================
    // STEP 5: Check for existing pending approval or create new one
    // ========================================================================
    let sessionId;
    let existingApproval = null;
    
    // Check if this person already has a pending approval
    if (existingPersonId && !isAutoApproved) {
      existingApproval = db.prepare(`
        SELECT ar.* FROM approval_requests ar
        JOIN sessions s ON ar.session_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE u.person_id = ? AND ar.status = 'pending' AND ar.flow_completed = 0
        ORDER BY ar.created_at DESC
        LIMIT 1
      `).get(existingPersonId);
    }
    
    if (existingApproval) {
      // Reuse existing approval - this is another device for same person
      sessionId = existingApproval.session_id;
      logger.debug(`Reusing existing approval request ${sessionId} for person ${existingPersonId}`);
      
      // Create session record for this device pointing to same approval
      db.prepare(`
        INSERT INTO sessions (id, user_id, mac_address, ip_address, status)
        VALUES (?, ?, ?, ?, 'pending_approval')
      `).run(sessionId + '-' + mac.replace(/:/g, ''), userId, mac, ip);
      
    } else {
      // Create new session and approval request
      sessionId = uuidv4();
      db.prepare(`
        INSERT INTO sessions (id, user_id, mac_address, ip_address, status)
        VALUES (?, ?, ?, ?, ?)
      `).run(sessionId, userId, mac, ip, isAutoApproved ? 'approved' : 'pending_approval');
      
      db.prepare(`
        INSERT INTO approval_requests (session_id, user_name, device_type, mac_address, status, flow_completed)
        VALUES (?, ?, 'pending', ?, ?, 0)
      `).run(sessionId, userName, mac, isAutoApproved ? 'approved' : 'pending');
    }
    
    // ========================================================================
    // STEP 6: Set up session variables
    // ========================================================================
    req.session.oauthUser = {
      name: req.user.name,
      email: req.user.email,
      oauth_id: oauthId
    };
    req.session.authMethod = 'google';
    req.session.sessionId = sessionId;
    req.session.userId = userId;
    req.session.userName = userName;
    req.session.existingPersonId = existingPersonId;
    
    // Store CardDAV contact for verification page
    req.session.cardDavContact = cardDavContact;
    if (cardDavContact?.photo) {
      req.session.contactPhoto = cardDavContact.photo;
      req.session.contactPhotoMimeType = cardDavContact.photoMimeType;
    }
    
    // Mark verified if person already exists
    if (personVerified) {
      req.session.contactVerified = true;
    }
    
    // ========================================================================
    // STEP 7: Decide where to redirect based on state
    // ========================================================================
    req.session.save((err) => {
      if (err) logger.error('Session save error:', err);
      
      if (isAutoApproved) {
        // Has approved devices -> go to device selection
        logger.info(`[OAuth] Redirecting to device-select (auto-approved)`);
        res.redirect('/device-select.html');
      } else if (personVerified) {
        // Person exists but no devices yet -> wait for approval
        logger.info(`[OAuth] Redirecting to waiting (verified, pending approval)`);
        res.redirect('/waiting.html');
      } else {
        // Need to verify identity first
        logger.info(`[OAuth] Redirecting to verify-identity (need verification)`);
        res.redirect('/verify-identity.html');
      }
    });
  }
);

// ============================================================================
// SUPPORT CONFIG
// ============================================================================

const WIFI_ADMIN_NAME = process.env.WIFI_ADMIN_NAME || 'Admin';

function wifiSupportMessage() {
  // If you provide a custom full message, use it. Otherwise build a default.
  if (process.env.WIFI_SUPPORT_MESSAGE && process.env.WIFI_SUPPORT_MESSAGE.trim()) {
    return process.env.WIFI_SUPPORT_MESSAGE.replace(/\$\{WIFI_ADMIN_NAME\}/g, WIFI_ADMIN_NAME);
  }
  return `No matching contact found. Please talk to ${WIFI_ADMIN_NAME} about getting WiFi access.`;
}

app.get('/api/support-config', (req, res) => {
  res.json({
    adminName: WIFI_ADMIN_NAME,
    supportMessage: wifiSupportMessage()
  });
});

app.get('/api/portal-config', (req, res) => {
  res.json({
    portalBaseUrl: process.env.SESSION_TIMEOUT_REDIRECT || null
  });
});

// Manual phone + birthdate authentication
app.post('/api/auth/manual', authLimiter, async (req, res) => {
  const { phone, birthdate } = req.body;
  
  // Get MAC and IP from session (set during handoff)
  const mac = req.session.pendingMac;
  const ip = req.session.pendingIp;

  if (!phone || !birthdate) {
    return res.status(400).json({ error: 'Phone and birthdate are required' });
  }
  
  if (!mac) {
    return res.status(400).json({ 
      error: 'Session expired. Please reconnect to WiFi.',
      redirect: SESSION_TIMEOUT_REDIRECT
    });
  }

  // Check if MAC is blocked
  if (isMacBlocked(mac)) {
    return res.status(403).json({ 
      error: 'Your device has been blocked. Please contact an administrator.',
      blocked: true 
    });
  }

  try {
    // Search CardDAV for EXACT phone match (ignoring country code)
    const contact = await getContactWithPhoto(phone, birthdate);

    if (!contact) {
      // Record failed attempt
      const shouldBlock = recordFailedAttempt(mac, 'manual_auth', 
        `No CardDAV match for phone=${normalizePhone(phone)}`);
      
      if (shouldBlock) {
        return res.status(403).json({
          error: 'Too many failed attempts. Your device has been blocked.',
          blocked: true
        });
      }
      
      const remaining = getRemainingAttempts(mac);
      return res.status(401).json({ 
        error: `${wifiSupportMessage()} ${remaining} attempt(s) remaining.`,
        notFound: true,
        attemptsRemaining: remaining
      });
    }

    const normalizedPhone = normalizePhone(phone);
    
    // Find existing person by phone
    let existingPerson = db.prepare(`
      SELECT p.id, p.photo, p.photo_mime_type, p.name FROM people p
      WHERE p.phone = ?
    `).get(normalizedPhone);
    
    // Check if person has any approved devices (auto-approve path)
    let isAutoApproved = false;
    let existingPersonId = existingPerson?.id || null;
    
    if (existingPerson) {
      const approvedDevice = db.prepare('SELECT 1 FROM whitelist WHERE person_id = ? LIMIT 1')
        .get(existingPerson.id);
      
      if (approvedDevice) {
        isAutoApproved = true;
        logger.debug(`Auto-approving ${contact.name} - has existing approved devices`);
      }
    }

    // Check for existing pending approval for this person
    let sessionId;
    let existingApproval = null;
    
    if (existingPersonId && !isAutoApproved) {
      existingApproval = db.prepare(`
        SELECT ar.* FROM approval_requests ar
        JOIN sessions s ON ar.session_id = s.id
        JOIN users u ON s.user_id = u.id
        WHERE u.person_id = ? AND ar.status = 'pending' AND ar.flow_completed = 0
        ORDER BY ar.created_at DESC
        LIMIT 1
      `).get(existingPersonId);
    }

    // Create user in database
    const stmt = db.prepare(`
      INSERT INTO users (name, birthdate, phone, auth_method, mac_address, approved, person_id)
      VALUES (?, ?, ?, 'manual', ?, ?, ?)
    `);
    const result = stmt.run(
      contact.name, 
      birthdate, 
      normalizedPhone, 
      mac, 
      isAutoApproved ? 1 : 0,
      existingPersonId
    );
    const userId = result.lastInsertRowid;

    if (existingApproval) {
      // Reuse existing approval - another device for same person
      sessionId = existingApproval.session_id;
      logger.info(`Reusing existing approval request ${sessionId} for person ${existingPersonId}`);
      
      // Create session record for this device
      db.prepare(`
        INSERT INTO sessions (id, user_id, mac_address, ip_address, status)
        VALUES (?, ?, ?, ?, 'pending_approval')
      `).run(sessionId + '-' + mac.replace(/:/g, ''), userId, mac, ip);
      
    } else {
      // Create new session and approval request
      sessionId = uuidv4();
      db.prepare(`
        INSERT INTO sessions (id, user_id, mac_address, ip_address, status)
        VALUES (?, ?, ?, ?, ?)
      `).run(sessionId, userId, mac, ip, isAutoApproved ? 'approved' : 'pending_approval');

      db.prepare(`
        INSERT INTO approval_requests (session_id, user_name, device_type, mac_address, status, flow_completed)
        VALUES (?, ?, 'pending', ?, ?, 0)
      `).run(sessionId, contact.name, mac, isAutoApproved ? 'approved' : 'pending');
    }

    // Store contact photo in session
    if (existingPerson?.photo) {
      req.session.contactPhoto = existingPerson.photo;
      req.session.contactPhotoMimeType = existingPerson.photo_mime_type;
    } else {
      req.session.contactPhoto = contact.photo || null;
      req.session.contactPhotoMimeType = contact.photoMimeType || null;
    }
    
    req.session.userId = userId;
    req.session.sessionId = sessionId;
    req.session.userName = contact.name;
    req.session.authMethod = 'manual';
    req.session.contactVerified = true; // Already verified via CardDAV
    req.session.existingPersonId = existingPersonId;

    res.json({
      success: true,
      sessionId,
      userName: contact.name,
      autoApproved: isAutoApproved,
      message: isAutoApproved 
        ? 'Welcome back! Your device will be automatically approved.' 
        : 'Authentication successful'
    });
  } catch (error) {
    logger.error('Manual auth error:', error);
    
    // Check if it's a CardDAV connection error
    if (error instanceof CardDAVError) {
      return res.status(500).json({ 
        error: 'Unable to connect to contact server. Please try again later.',
        details: error.message
      });
    }
    
    res.status(500).json({ error: 'Authentication failed. Please try again.' });
  }
});

// Get current session info (for pre-filling forms securely)
app.get('/api/session-info', (req, res) => {
  const state = getSessionState(req);

  const sessionInfo = {
    // Only true if they completed an auth step (not just because userName exists)
    authenticated: !!req.session.oauthUser || (!!req.session.userId && !!req.session.sessionId),

    authMethod: req.session.authMethod || null,
    userName: req.session.userName || req.session.oauthUser?.name || null,
    email: req.session.oauthUser?.email || null,

    sessionId: req.session.sessionId || null,
    userId: req.session.userId || null,

    hasPendingDevice: !!req.session.pendingMac,
    contactVerified: !!req.session.contactVerified,

    approvalStatus: null,
    flowCompleted: false,
    deviceType: req.session.deviceType || null,
    autoApproved: !!req.session.autoApproved,

    // Server computed state
    state,

    cardDavContact: null
  };

  // Include CardDAV contact info for verification page
  if (req.session.oauthUser && req.session.cardDavContact) {
    const contact = req.session.cardDavContact;
    sessionInfo.cardDavContact = {
      name: contact.name,
      uid: contact.uid,
      phone: contact.phone,
      birthdate: contact.birthdate,
      hasPhoto: !!contact.photo,
      photo: contact.photo ? `data:${contact.photoMimeType || 'image/jpeg'};base64,${contact.photo}` : null,
      similarity: contact.similarity
    };
  }

  // Approval status from DB if session exists
  if (req.session.sessionId) {
    const approval = db
      .prepare(`SELECT status, device_type, flow_completed FROM approval_requests WHERE session_id = ?`)
      .get(req.session.sessionId);

    if (approval) {
      sessionInfo.approvalStatus = approval.status;
      sessionInfo.flowCompleted = approval.flow_completed === 1;
      sessionInfo.deviceType = approval.device_type;
      sessionInfo.autoApproved = approval.status === 'approved' && !!req.session.existingPersonId;
    }
  }

  res.json(sessionInfo);
});

// Get remaining authentication attempts for current session's MAC
app.get('/api/remaining-attempts', (req, res) => {
  const mac = req.session?.pendingMac;
  
  if (!mac) {
    return res.json({ remaining: MAX_FAILED_ATTEMPTS });
  }
  
  const remaining = getRemainingAttempts(mac);
  const isBlocked = isMacBlocked(mac);
  
  res.json({ 
    remaining,
    blocked: isBlocked,
    max: MAX_FAILED_ATTEMPTS
  });
});

// ============================================================================
// IDENTITY VERIFICATION (for Google OAuth users)
// ============================================================================

// Verify identity after Google OAuth - confirm CardDAV match or enter info
app.post('/api/verify-identity', requireSession, async (req, res) => {
  const { name, phone, birthdate, confirmMatch, cardDavUid } = req.body;
  
  if (!req.session.oauthUser) {
    return res.status(401).json({ error: 'Not authenticated via Google' });
  }
  
  const originalName = req.session.userName;
  const mac = req.session.pendingMac;
  const cardDavContact = req.session.cardDavContact;
  
  // Check if MAC is blocked
  if (isMacBlocked(mac)) {
    return res.status(403).json({ 
      error: 'Your device has been blocked. Please contact an administrator.',
      blocked: true 
    });
  }
  
  try {
    // Use provided name or original OAuth name
    const finalName = name?.trim() || originalName;
    
    // If user confirmed the CardDAV match, they MUST provide phone for verification
    if (confirmMatch && cardDavContact) {
      const contactPhone = cardDavContact.phone;
      
      // Phone verification is REQUIRED when confirming a match
      if (!phone) {
        return res.status(400).json({ 
          error: 'Phone number is required to verify your identity',
          phoneMismatch: true
        });
      }
      
      // Normalize phones for comparison
      const normalizedInputPhone = normalizePhone(phone);
      const normalizedContactPhone = normalizePhone(contactPhone);
      
      // Phone MUST match the contact's phone
      if (!normalizedContactPhone || normalizedInputPhone !== normalizedContactPhone) {
        logger.info(`[Verify] Phone mismatch for ${finalName}: input=${normalizedInputPhone}, contact=${normalizedContactPhone}`);
        
        // Record failed attempt
        const shouldBlock = recordFailedAttempt(mac, 'phone_verification', 
          `Phone mismatch: entered ${normalizedInputPhone}, expected ${normalizedContactPhone}`);
        
        if (shouldBlock) {
          return res.status(403).json({
            error: 'Too many failed attempts. Your device has been blocked.',
            blocked: true
          });
        }
        
        const remaining = getRemainingAttempts(mac);
        return res.status(400).json({
          error: `Phone number does not match. ${remaining} attempt(s) remaining.`,
          phoneMismatch: true,
          attemptsRemaining: remaining
        });
      }
      
      // Phone verified! Continue with the flow
      logger.info(`[Verify] Phone verified for ${finalName}`);
      
      // Update the user's name
      logger.debug(`[Verify] Setting display name to "${finalName}" (was "${originalName}")`);
      req.session.userName = finalName;
      db.prepare('UPDATE users SET name = ? WHERE id = ?').run(finalName, req.session.userId);
      db.prepare('UPDATE approval_requests SET user_name = ? WHERE session_id = ?')
        .run(finalName, req.session.sessionId);
      
      // Use provided birthdate if given, otherwise use contact's birthdate
      const contactBirthdate = birthdate || cardDavContact.birthdate;
      
      // Update birthdate in CardDAV if:
      // 1. User provided a birthdate AND
      // 2. Contact doesn't already have one (or user provided a different one)
      if (birthdate && cardDavContact.uid) {
        if (!cardDavContact.birthdate) {
          logger.debug(`[Verify] Adding birthdate ${birthdate} to CardDAV contact ${cardDavContact.name}`);
          try {
            await updateCardDAVContactBirthdate(cardDavContact.uid, birthdate, cardDavContact.href);
          } catch (cardDavError) {
            logger.error('[Verify] Failed to update CardDAV birthdate:', cardDavError);
            // Continue anyway - this is not critical
          }
        } else if (birthdate !== cardDavContact.birthdate) {
          logger.info(`[Verify] Updating birthdate in CardDAV from ${cardDavContact.birthdate} to ${birthdate}`);
          try {
            await updateCardDAVContactBirthdate(cardDavContact.uid, birthdate, cardDavContact.href);
          } catch (cardDavError) {
            logger.error('[Verify] Failed to update CardDAV birthdate:', cardDavError);
            // Continue anyway - this is not critical
          }
        }
      }
      
      // Check if phone matches an existing person in our database
      let personId = null;
      let isAutoApproved = false;
      
      if (contactPhone) {
        const personByPhone = db.prepare('SELECT * FROM people WHERE phone = ?').get(normalizedContactPhone);
        if (personByPhone) {
          personId = personByPhone.id;
          req.session.existingPersonId = personId;
          
          // Link user to person
          db.prepare('UPDATE users SET person_id = ? WHERE id = ?')
            .run(personId, req.session.userId);
          
          // Check if auto-approve (person has existing devices)
          const hasDevices = db.prepare('SELECT 1 FROM whitelist WHERE person_id = ?').get(personId);
          if (hasDevices) {
            isAutoApproved = true;
            db.prepare('UPDATE approval_requests SET status = ? WHERE session_id = ?')
              .run('approved', req.session.sessionId);
            db.prepare('UPDATE sessions SET status = ? WHERE id = ?')
              .run('approved', req.session.sessionId);
            db.prepare('UPDATE users SET approved = 1 WHERE id = ?')
              .run(req.session.userId);
            logger.info(`[Verify] Auto-approved ${finalName} - phone matches existing person with devices`);
          }
        }
      }
      
      // Update user with verified info
      db.prepare('UPDATE users SET name = ?, phone = ?, birthdate = ? WHERE id = ?')
        .run(finalName, contactPhone, contactBirthdate, req.session.userId);
      
      // Store contact photo
      if (cardDavContact.photo) {
        req.session.contactPhoto = cardDavContact.photo;
        req.session.contactPhotoMimeType = cardDavContact.photoMimeType;
      }
      
      req.session.contactVerified = true;
      req.session.verifiedPhone = contactPhone;
      req.session.verifiedBirthdate = contactBirthdate;
      
      logger.debug(`[Verify] Identity verified for ${finalName}, autoApproved: ${isAutoApproved}`);
      
      return res.json({ 
        success: true, 
        message: 'Identity verified',
        autoApproved: isAutoApproved
      });
    }
    
    // User said "not me" or no CardDAV match - they need to enter phone/birthdate manually
    // This will be handled by a separate endpoint or the manual auth flow
    return res.json({
      success: true,
      message: 'Please enter your phone number and birthdate to verify',
      needsManualVerification: true
    });
    
  } catch (error) {
    logger.error('Identity verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Manual verification with phone + birthdate (for OAuth users who didn't match CardDAV)
app.post('/api/verify-manual', requireSession, async (req, res) => {
  const { name, phone, birthdate } = req.body;
  
  if (!req.session.oauthUser) {
    return res.status(401).json({ error: 'Not authenticated via Google' });
  }
  
  if (!phone || !birthdate) {
    return res.status(400).json({ error: 'Phone and birthdate are required' });
  }
  
  const originalName = req.session.userName;
  const mac = req.session.pendingMac;
  
  // Check if MAC is blocked
  if (isMacBlocked(mac)) {
    return res.status(403).json({ 
      error: 'Your device has been blocked. Please contact an administrator.',
      blocked: true 
    });
  }
  
  try {
    const normalizedPhone = normalizePhone(phone);
    const finalName = name?.trim() || originalName;
    
    // Update name if changed
    if (finalName !== originalName) {
      req.session.userName = finalName;
      db.prepare('UPDATE users SET name = ? WHERE id = ?').run(finalName, req.session.userId);
      db.prepare('UPDATE approval_requests SET user_name = ? WHERE session_id = ?')
        .run(finalName, req.session.sessionId);
    }
    
    // Verify against CardDAV - EXACT phone match required
    const contact = await getContactWithPhoto(phone, birthdate);
    
    if (!contact) {
      // Record failed attempt
      const shouldBlock = recordFailedAttempt(mac, 'manual_verification', 
        `No CardDAV match for phone=${normalizedPhone}`);
      
      if (shouldBlock) {
        return res.status(403).json({
          error: 'Too many failed attempts. Your device has been blocked.',
          blocked: true
        });
      }
      
      const remaining = getRemainingAttempts(mac);
      return res.status(401).json({ 
        error: `${wifiSupportMessage()} ${remaining} attempt(s) remaining.`,
        notFound: true,
        attemptsRemaining: remaining
      });
    }
    
    // Found matching contact! Check if phone matches existing person in our DB
    const personByPhone = db.prepare('SELECT * FROM people WHERE phone = ?').get(normalizedPhone);
    let personId = personByPhone?.id || null;
    let isAutoApproved = false;
    
    if (personByPhone) {
      // Link OAuth user to existing person (same phone = same person)
      req.session.existingPersonId = personByPhone.id;
      db.prepare('UPDATE users SET person_id = ?, phone = ?, birthdate = ? WHERE id = ?')
        .run(personByPhone.id, normalizedPhone, birthdate, req.session.userId);
      
      // Check if auto-approve
      const hasDevices = db.prepare('SELECT 1 FROM whitelist WHERE person_id = ?').get(personByPhone.id);
      if (hasDevices) {
        isAutoApproved = true;
        db.prepare('UPDATE approval_requests SET status = ? WHERE session_id = ?')
          .run('approved', req.session.sessionId);
        db.prepare('UPDATE sessions SET status = ? WHERE id = ?')
          .run('approved', req.session.sessionId);
        db.prepare('UPDATE users SET approved = 1 WHERE id = ?')
          .run(req.session.userId);
        logger.debug(`Auto-approved ${finalName} - phone matches existing person ${personByPhone.name}`);
      }
    } else {
      // Update user with verified info
      db.prepare('UPDATE users SET phone = ?, birthdate = ? WHERE id = ?')
        .run(normalizedPhone, birthdate, req.session.userId);
    }
    
    // Store contact info
    req.session.contactPhoto = contact.photo;
    req.session.contactPhotoMimeType = contact.photoMimeType;
    req.session.contactVerified = true;
    req.session.verifiedPhone = normalizedPhone;
    req.session.verifiedBirthdate = birthdate;
    
    res.json({ 
      success: true, 
      message: 'Identity verified',
      contactName: contact.name,
      autoApproved: isAutoApproved
    });
  } catch (error) {
    logger.error('Manual verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ============================================================================
// DEVICE SELECTION & APPROVAL ROUTES
// ============================================================================

// Submit device type selection (called AFTER approval)
app.post('/api/device-select', async (req, res) => {
  const { deviceType } = req.body;
  
  // Get data from session (secure, server-side)
  const sessionId = req.session.sessionId;
  const mac = req.session.pendingMac;
  const userId = req.session.userId;

  if (!sessionId || !deviceType || !mac) {
    return res.status(400).json({ error: 'Missing required fields or session expired' });
  }

  try {
    // Update user with device type
    db.prepare('UPDATE users SET device_type = ? WHERE id = ?').run(deviceType, userId);
    
    // Update approval request with device type
    db.prepare('UPDATE approval_requests SET device_type = ? WHERE session_id = ?').run(deviceType, sessionId);
    
    // Update whitelist entry with device type
    db.prepare('UPDATE whitelist SET device_type = ? WHERE mac_address = ?').run(deviceType, mac);
    
    // Store device type in session
    req.session.deviceType = deviceType;

    res.json({
      success: true,
      message: 'Device type saved'
    });
  } catch (error) {
    logger.error('Device selection error:', error);
    res.status(500).json({ error: 'Failed to save device selection' });
  }
});

// Check if user's name exists in CardDAV contacts
app.get('/api/check-contact', async (req, res) => {
  const userName = req.session.userName || req.session.oauthUser?.name;
  
  if (!userName) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    // Search CardDAV for contact by name
    const contact = await searchCardDAVByName(userName);
    
    if (contact) {
      // Contact found - store in session
      req.session.contactFound = true;
      req.session.contactName = contact.name;
      return res.json({ 
        found: true, 
        name: contact.name,
        message: 'Contact found in address book'
      });
    }
    
    // Contact not found
    req.session.contactFound = false;
    res.json({ 
      found: false,
      name: userName,
      message: 'Contact not found - optional info can be provided'
    });
  } catch (error) {
    logger.error('Contact lookup error:', error);
    // On error, don't block the flow - just mark as not found
    req.session.contactFound = false;
    res.json({ found: false, name: userName });
  }
});

// Submit optional contact info (phone/birthdate)
app.post('/api/submit-contact-info', async (req, res) => {
  const { phone, birthdate, skip } = req.body;
  const userName = req.session.userName || req.session.oauthUser?.name;
  const mac = req.session.pendingMac;
  const deviceType = req.session.deviceType;
  
  if (!userName || !mac) {
    return res.status(401).json({ error: 'Session expired' });
  }
  
  try {
    if (skip) {
      // User skipped - just complete the flow
      await completeAccessFlow(req, res);
      return;
    }
    
    if (phone && birthdate) {
      const normalizedPhoneNum = normalizePhone(phone);
      
      // Check if phone matches an existing contact
      const existingContact = await searchCardDAVByPhone(normalizedPhoneNum);
      
      if (existingContact) {
        // Update existing contact's birthdate via CardDAV
        await updateCardDAVContactBirthdate(existingContact.uid, birthdate, existingContact.href);
        req.session.contactUpdated = true;
      } else {
        // Create new contact in CardDAV
        await createCardDAVContact(userName, normalizedPhoneNum, birthdate);
        req.session.contactCreated = true;
      }
      
      // Update user record with phone/birthdate
      db.prepare('UPDATE users SET phone = ?, birthdate = ? WHERE id = ?')
        .run(normalizedPhoneNum, birthdate, req.session.userId);
    }
    
    await completeAccessFlow(req, res);
  } catch (error) {
    logger.error('Contact info error:', error);
    // Don't block on error - complete the flow anyway
    await completeAccessFlow(req, res);
  }
});

// Helper to complete the access flow - THIS IS WHERE MAC GETS WHITELISTED
async function completeAccessFlow(req, res) {
  const mac = req.session.pendingMac;
  let deviceType = req.session.deviceType;
  const userName = req.session.userName || req.session.oauthUser?.name;
  const sessionId = req.session.sessionId;
  const userId = req.session.userId;
  
  logger.debug(`completeAccessFlow: mac=${mac}, deviceType=${deviceType}, userName=${userName}, sessionId=${sessionId}`);
  
  if (!mac || !sessionId) {
    logger.error('completeAccessFlow: Missing mac or sessionId');
    return res.status(400).json({ error: 'Session expired', redirect: SESSION_TIMEOUT_REDIRECT });
  }
  
  // Check that approval has been granted
  const approval = db.prepare('SELECT status FROM approval_requests WHERE session_id = ?').get(sessionId);
  if (!approval || approval.status !== 'approved') {
    logger.error(`completeAccessFlow: Not approved yet (status=${approval?.status})`);
    return res.status(403).json({ error: 'Not approved yet' });
  }
  
  // Mark flow as completed in database
  db.prepare('UPDATE approval_requests SET flow_completed = 1 WHERE session_id = ?').run(sessionId);
  
  // Use existing person if we found one during auth, otherwise find or create
  let personId = req.session.existingPersonId;
  
  if (!personId) {
    // Find or create person
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    logger.debug(`completeAccessFlow: Creating/finding person for ${userName}, phone=${user?.phone}`);
    personId = findOrCreatePerson(userName, {
      email: user?.oauth_id ? null : undefined,
      phone: user?.phone,
      birthdate: user?.birthdate
    });
    logger.debug(`completeAccessFlow: personId=${personId}`);
  }
  
  // ENFORCE ONE PHONE PER PERSON
  // If user selected 'phone' as device type, check if person already has a tracked phone
  // If so, demote the OLD phone to 'other' and let the NEW device be the phone
  if (deviceType === 'phone' && personId) {
    const existingPhone = db.prepare(`
      SELECT mac_address, user_name FROM whitelist 
      WHERE person_id = ? AND device_type = 'phone'
      LIMIT 1
    `).get(personId);
    
    if (existingPhone) {
      logger.info(`Person ${personId} already has phone ${existingPhone.mac_address} - demoting old phone to 'other'`);
      
      // Demote the OLD phone to 'other'
      db.prepare(`UPDATE whitelist SET device_type = 'other' WHERE mac_address = ?`)
        .run(existingPhone.mac_address);
      
      // Also update the user record if exists
      db.prepare(`UPDATE users SET device_type = 'other' WHERE mac_address = ?`)
        .run(existingPhone.mac_address);
      
      logger.info(`Demoted old phone ${existingPhone.mac_address} to 'other', new phone will be ${mac}`);
    }
  }
  
  // Save contact photo to person if available and person doesn't have one yet (manual auth only)
  if (personId && req.session.contactPhoto && req.session.authMethod === 'manual') {
    // Only update if person doesn't already have a photo
    const existingPhoto = db.prepare('SELECT photo FROM people WHERE id = ?').get(personId);
    if (!existingPhoto?.photo) {
      db.prepare('UPDATE people SET photo = ?, photo_mime_type = ? WHERE id = ?')
        .run(req.session.contactPhoto, req.session.contactPhotoMimeType, personId);
    }
  }
  
  // Add to local whitelist
  const normalizedMac = mac.toUpperCase();
  logger.info(`completeAccessFlow: Adding to whitelist - mac=${normalizedMac}, userName=${userName}, deviceType=${deviceType}, personId=${personId}`);
  
  db.prepare(`
    INSERT OR REPLACE INTO whitelist (mac_address, user_name, device_type, user_id, person_id, first_approved, last_seen, permanent)
    VALUES (?, ?, ?, ?, ?, COALESCE((SELECT first_approved FROM whitelist WHERE mac_address = ?), CURRENT_TIMESTAMP), CURRENT_TIMESTAMP, 1)
  `).run(normalizedMac, userName, deviceType, userId, personId, normalizedMac);
  
  // Update user with person_id
  if (personId) {
    db.prepare('UPDATE users SET person_id = ? WHERE id = ?').run(personId, userId);
  }
  
  // Register with Home Assistant if it's a phone (only if we kept it as phone)
  if (deviceType === 'phone') {
    await registerDeviceTracker(mac, userName, true);
  }
  
  // FINALLY - Grant access via OPNsense (last step!)
  logger.info(`completeAccessFlow: Whitelisting MAC ${normalizedMac} in OPNsense`);
  try {
    const opnResult = await allowMacInOPNsense(normalizedMac);
    
    if (opnResult.alreadyExists) {
      logger.debug(`MAC ${normalizedMac} was already in OPNsense whitelist`);
    }
  } catch (opnError) {
    // OPNsense error - return error to user
    logger.error(`OPNsense error: ${opnError.message}`);
    
    // Roll back local whitelist entry since OPNsense failed
    db.prepare('DELETE FROM whitelist WHERE mac_address = ?').run(normalizedMac);
    
    return res.status(500).json({
      success: false,
      error: 'Failed to grant network access',
      details: opnError instanceof OPNsenseError 
        ? `OPNsense error: ${opnError.message}` 
        : 'Could not connect to firewall'
    });
  }
  
  // Remove from opnsense_macs tracking table if it was there
  db.prepare('DELETE FROM opnsense_macs WHERE mac_address = ?').run(normalizedMac);
  
  logger.debug(`completeAccessFlow: SUCCESS - ${userName} (${normalizedMac}) granted access`);
  
  res.json({
    success: true,
    message: 'Access granted',
    redirectUrl: '/success'
  });
}

// Check approval status (session-based, secure)
app.get('/api/approval-status', (req, res) => {
  const sessionId = req.session.sessionId;

  if (!sessionId) {
    return res.status(401).json({ error: 'No active session' });
  }

  const approval = db.prepare(`
    SELECT status, disabled FROM approval_requests WHERE session_id = ?
  `).get(sessionId);

  if (!approval) {
    return res.status(404).json({ error: 'Request not found' });
  }
  
  // If session was disabled (person/device deleted), return session_invalidated
  if (approval.disabled === 1) {
    return res.json({ status: 'session_invalidated', message: 'Your session has been invalidated. Please reconnect to WiFi to login again.' });
  }

  res.json({ status: approval.status });
});

// Check approval status (legacy URL param version for admin/HA)
app.get('/api/approval-status/:sessionId', (req, res) => {
  const { sessionId } = req.params;

  const approval = db.prepare(`
    SELECT status FROM approval_requests WHERE session_id = ?
  `).get(sessionId);

  if (!approval) {
    return res.status(404).json({ error: 'Request not found' });
  }

  res.json({ status: approval.status });
});

// ============================================================================
// MAC ADDRESS & WHITELIST ROUTES
// ============================================================================

// Update last seen for a MAC address
app.post('/api/mac/heartbeat', (req, res) => {
  const { mac } = req.body;
  
  if (!mac) {
    return res.status(400).json({ error: 'MAC address required' });
  }
  
  const normalizedMac = mac.toUpperCase();
  
  const result = db.prepare('UPDATE whitelist SET last_seen = CURRENT_TIMESTAMP WHERE mac_address = ?').run(normalizedMac);
  
  if (result.changes > 0) {
    res.json({ success: true });
  } else {
    res.status(404).json({ error: 'MAC not found in whitelist' });
  }
});

// Check if MAC is whitelisted
app.get('/api/mac/check/:mac', (req, res) => {
  const mac = req.params.mac.toUpperCase();
  
  const whitelisted = db.prepare('SELECT * FROM whitelist WHERE mac_address = ?').get(mac);
  
  res.json({
    whitelisted: !!whitelisted,
    user: whitelisted?.user_name,
    device_type: whitelisted?.device_type
  });
});

// ============================================================================
// ADMIN ROUTES
// ============================================================================

// Create a getter for device offline timeout 
const getDeviceOfflineTimeout = () => DEVICE_OFFLINE_TIMEOUT;
const setDeviceOfflineTimeout = (value) => {
  const newValue = parseInt(value);
  if (!isNaN(newValue) && newValue > 0) {
    DEVICE_OFFLINE_TIMEOUT = newValue;
    logger.info(`[Config] Device offline timeout updated to ${newValue} seconds`);
    return true;
  }
  return false;
};

// Auto-approval mode API endpoints
app.get('/api/admin/auto-approval-status', (req, res) => {
  res.json({
    enabled: autoApprovalMode.enabled,
    expiresAt: autoApprovalMode.expiresAt,
    timeoutMinutes: autoApprovalMode.timeoutMinutes,
    remainingSeconds: autoApprovalMode.enabled && autoApprovalMode.expiresAt
      ? Math.max(0, Math.floor((new Date(autoApprovalMode.expiresAt) - Date.now()) / 1000))
      : 0
  });
});

app.post('/api/admin/auto-approval/enable', (req, res) => {
  const { timeoutMinutes } = req.body;

  if (!timeoutMinutes || timeoutMinutes < 1 || timeoutMinutes > 1440) {
    return res.status(400).json({ error: 'Timeout must be between 1 and 1440 minutes' });
  }

  // Clear existing timer if any
  if (autoApprovalMode.timer) {
    clearTimeout(autoApprovalMode.timer);
  }

  // Enable auto-approval mode
  autoApprovalMode.enabled = true;
  autoApprovalMode.timeoutMinutes = timeoutMinutes;
  autoApprovalMode.expiresAt = new Date(Date.now() + timeoutMinutes * 60 * 1000).toISOString();

  // Set timer to disable after timeout
  autoApprovalMode.timer = setTimeout(() => {
    autoApprovalMode.enabled = false;
    autoApprovalMode.expiresAt = null;
    autoApprovalMode.timer = null;
    logger.info('[Auto-Approval] Mode automatically disabled after timeout');
  }, timeoutMinutes * 60 * 1000);

  logger.info(`[Auto-Approval] Mode enabled for ${timeoutMinutes} minutes (expires at ${autoApprovalMode.expiresAt})`);

  res.json({
    success: true,
    enabled: true,
    expiresAt: autoApprovalMode.expiresAt,
    message: `Auto-approval enabled for ${timeoutMinutes} minute(s)`
  });
});

app.post('/api/admin/auto-approval/disable', (req, res) => {
  // Clear timer if any
  if (autoApprovalMode.timer) {
    clearTimeout(autoApprovalMode.timer);
  }

  autoApprovalMode.enabled = false;
  autoApprovalMode.expiresAt = null;
  autoApprovalMode.timer = null;

  logger.info('[Auto-Approval] Mode manually disabled');

  res.json({
    success: true,
    enabled: false,
    message: 'Auto-approval disabled'
  });
});

// Load admin routes from separate module
require('./routes/admin')(app, db, {
  revokeMacInOPNsense,
  getPersonDevices,
  getPersonPresence,
  invalidatedSessionIds,
  getDeviceOfflineTimeout,
  recordFailedAttempt,
  blockMac,
  isMacBlocked,
  autoApprovalMode
});

// ============================================================================
// HOME ASSISTANT API ENDPOINTS
// ============================================================================

// Load Home Assistant routes from separate module
require('./routes/homeassistant')(app, db, people, { 
  getDeviceOfflineTimeout, 
  setDeviceOfflineTimeout 
});

// ============================================================================
// SERVE HTML PAGES
// ============================================================================

// Static pages - middleware handles redirects based on session state
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/device-select.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'device-select.html'));
});

app.get('/waiting.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'waiting.html'));
});

app.get('/verify-identity.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'verify-identity.html'));
});

// Session timeout redirect URL endpoint (for client-side to know where to go)
app.get('/api/session-timeout-redirect', (req, res) => {
  res.json({ redirect: SESSION_TIMEOUT_REDIRECT });
});

// ============================================================================
// SYNC OPNSENSE WHITELISTED MACS
// ============================================================================

/**
 * Sync whitelisted MACs from OPNsense to local tracking
 * - MACs in OPNsense but not in our whitelist → tracked as unknown (opnsense_macs)
 * - MACs in our whitelist but NOT in OPNsense → removed from whitelist, sessions invalidated
 * - Excludes MACs currently being registered (pending approval, not yet in OPNsense)
 */
async function syncOPNsenseMacs() {
  logger.info('[OPNsense Sync] Starting sync...');
  
  try {
    const result = await getWhitelistedMacs();
    
    if (result.skipped) {
      logger.info('[OPNsense Sync] OPNsense not configured - skipping');
      return;
    }
    
    const opnsenseMacs = result.macs.map(m => m.toUpperCase());
    const opnsenseMacSet = new Set(opnsenseMacs);
    logger.info(`[OPNsense Sync] Found ${opnsenseMacs.length} MACs in OPNsense`);
    
    // Get all MACs in our local whitelist
    const localWhitelist = db.prepare('SELECT mac_address, person_id, user_name FROM whitelist').all();
    const localMacSet = new Set(localWhitelist.map(row => row.mac_address.toUpperCase()));
    
    // Get MACs that are currently being registered (pending/approved but flow not completed)
    // These should NOT be revoked just because they're not in OPNsense yet
    const pendingMacs = db.prepare(`
      SELECT DISTINCT mac_address FROM approval_requests 
      WHERE status IN ('pending', 'approved') 
      AND flow_completed = 0 
      AND COALESCE(disabled, 0) = 0
    `).all().map(r => r.mac_address?.toUpperCase()).filter(Boolean);
    const pendingMacSet = new Set(pendingMacs);
    
    // -------------------------------------------------------------------------
    // 1. Find MACs in OPNsense but NOT in our whitelist → track as unknown
    // -------------------------------------------------------------------------
    let addedCount = 0;
    for (const mac of opnsenseMacs) {
      if (!localMacSet.has(mac) && !pendingMacSet.has(mac)) {
        // Check if it's not a MAC currently being registered
        db.prepare(`
          INSERT INTO opnsense_macs (mac_address, description, first_seen, last_seen)
          VALUES (?, 'Unknown - synced from OPNsense', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          ON CONFLICT(mac_address) DO UPDATE SET last_seen = CURRENT_TIMESTAMP
        `).run(mac);
        addedCount++;
      } else if (localMacSet.has(mac)) {
        // MAC is in our whitelist - remove from opnsense_macs if it's there
        db.prepare('DELETE FROM opnsense_macs WHERE mac_address = ?').run(mac);
      }
    }
    
    // -------------------------------------------------------------------------
    // 2. Find MACs in our whitelist but NOT in OPNsense → revoke locally
    //    (Someone removed them from OPNsense directly)
    //    Skip MACs that are currently being registered
    // -------------------------------------------------------------------------
    let revokedCount = 0;
    for (const entry of localWhitelist) {
      const mac = entry.mac_address.toUpperCase();
      
      // Skip if in OPNsense or currently being registered
      if (opnsenseMacSet.has(mac) || pendingMacSet.has(mac)) {
        continue;
      }
      
      logger.info(`[OPNsense Sync] MAC ${mac} was removed from OPNsense - revoking locally`);
      
      // Remove from whitelist
      db.prepare('DELETE FROM whitelist WHERE mac_address = ?').run(mac);
      
      // Invalidate sessions for this MAC
      const sessionIds = db.prepare('SELECT id FROM sessions WHERE mac_address = ?').all(mac).map(s => s.id);
      if (sessionIds.length > 0) {
        db.prepare(`UPDATE sessions SET disabled = 1 WHERE mac_address = ?`).run(mac);
        db.prepare(`
          UPDATE approval_requests SET disabled = 1 
          WHERE session_id IN (${sessionIds.map(() => '?').join(',')})
        `).run(...sessionIds);
        
        sessionIds.forEach(id => {
          invalidatedSessionIds.add(id);
          logger.debug(`[OPNsense Sync] Invalidated session ${id} for removed MAC ${mac}`);
        });
      }
      
      // Update users
      db.prepare('UPDATE users SET approved = 0 WHERE mac_address = ?').run(mac);
      
      // Add to opnsense_macs for tracking (so it shows in "Unknown MACs" tab)
      db.prepare(`
        INSERT INTO opnsense_macs (mac_address, description, first_seen, last_seen)
        VALUES (?, 'Removed from OPNsense - session invalidated', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(mac_address) DO UPDATE SET 
          description = 'Removed from OPNsense - session invalidated',
          last_seen = CURRENT_TIMESTAMP
      `).run(mac);
      
      revokedCount++;
    }
    
    // -------------------------------------------------------------------------
    // 3. Clean up opnsense_macs entries that are no longer relevant
    // -------------------------------------------------------------------------
    const trackedMacs = db.prepare('SELECT mac_address FROM opnsense_macs').all();
    for (const tracked of trackedMacs) {
      // If it's now in OPNsense AND in our whitelist, remove from tracking
      if (opnsenseMacSet.has(tracked.mac_address) && localMacSet.has(tracked.mac_address)) {
        db.prepare('DELETE FROM opnsense_macs WHERE mac_address = ?').run(tracked.mac_address);
      }
    }
    
    if (addedCount > 0 || revokedCount > 0) {
      logger.info(`[OPNsense Sync] Added ${addedCount} unknown MACs, revoked ${revokedCount} removed MACs`);
    } else {
      logger.debug('[OPNsense Sync] No changes detected');
    }
  } catch (error) {
    if (error instanceof OPNsenseError) {
      logger.error(`[OPNsense Sync] Error [${error.code}]: ${error.message}`);
    } else {
      logger.error('[OPNsense Sync] Error:', error);
    }
  }
}

// API endpoint to manually trigger sync
app.post('/api/admin/sync-opnsense', async (req, res) => {
  try {
    await syncOPNsenseMacs();
    res.json({ success: true, message: 'Sync completed' });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error instanceof OPNsenseError ? error.message : 'Sync failed' 
    });
  }
});

// ============================================================================
// SUCCESS PAGE
// ============================================================================

// Success page after completing the flow
app.get('/success', (req, res) => {
  const userName = req.session.userName || 'friend';
  const redirectUrl = SUCCESS_REDIRECT_URL;
  const shouldRedirect = !!SUCCESS_REDIRECT_URL;
  const autoCloseEnabled = SUCCESS_AUTO_CLOSE_ENABLED && !shouldRedirect; // Don't auto-close if redirecting
  const autoCloseTimeout = SUCCESS_AUTO_CLOSE_TIMEOUT;
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Connected!</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0;
        }
        .card {
          background: white;
          border-radius: 20px;
          padding: 40px;
          text-align: center;
          box-shadow: 0 25px 50px -12px rgba(0,0,0,0.25);
          max-width: 400px;
        }
        .checkmark {
          width: 80px;
          height: 80px;
          background: #10b981;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 20px;
        }
        .checkmark svg { width: 40px; height: 40px; color: white; }
        h1 { color: #1f2937; margin-bottom: 10px; }
        p { color: #6b7280; margin: 5px 0; }
        .success-message { font-size: 1.1rem; color: #374151; margin-top: 15px; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="checkmark">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="3" d="M5 13l4 4L19 7"/>
          </svg>
        </div>
        <h1>You're Connected!</h1>
        <p>Welcome, ${userName}!</p>
        <p class="success-message">Your device has been successfully registered.</p>
        ${shouldRedirect
          ? '<p style="margin-top: 15px; font-size: 0.875rem; color: #9ca3af;">Redirecting...</p>'
          : autoCloseEnabled
            ? '<p style="margin-top: 15px; font-size: 0.875rem; color: #9ca3af;">This window will close automatically...</p>'
            : '<p style="margin-top: 15px; font-size: 0.875rem; color: #9ca3af;">You can close this window.</p>'}
      </div>
      ${(shouldRedirect || autoCloseEnabled) ? `
      <script>
        ${shouldRedirect ? `
        setTimeout(() => {
          window.location.href = '${redirectUrl}';
        }, 2000);
        ` : `
        // Auto-close after configured timeout so OS recognizes captive portal is complete
        setTimeout(() => {
          window.close();
        }, ${autoCloseTimeout});
        `}
      </script>
      ` : ''}
    </body>
    </html>
  `);
});

// API to get success page configuration (for frontend)
app.get('/api/success-config', (req, res) => {
  res.json({
    redirectUrl: SUCCESS_REDIRECT_URL,
    autoRedirect: !!SUCCESS_REDIRECT_URL,
    autoCloseEnabled: SUCCESS_AUTO_CLOSE_ENABLED,
    autoCloseTimeout: SUCCESS_AUTO_CLOSE_TIMEOUT
  });
});

// ============================================================================
// SESSION PURGE
// ============================================================================

/**
 * Purge old sessions from the database
 * Deletes sessions and approval requests older than SESSION_MAX_AGE_HOURS
 * Does NOT delete associated users (they may have other sessions)
 */
function purgeOldSessions() {
  const cutoffDate = new Date(Date.now() - SESSION_MAX_AGE_HOURS * 60 * 60 * 1000).toISOString();
  
  logger.debug(`[Session Purge] Purging sessions older than ${SESSION_MAX_AGE_HOURS} hours (before ${cutoffDate})`);
  
  try {
    // Delete old approval requests (completed or denied)
    const approvalResult = db.prepare(`
      DELETE FROM approval_requests 
      WHERE created_at < ? AND (flow_completed = 1 OR status = 'denied' OR disabled = 1)
    `).run(cutoffDate);
    
    // Delete old sessions that don't have pending approval requests
    const sessionResult = db.prepare(`
      DELETE FROM sessions 
      WHERE created_at < ? 
      AND id NOT IN (SELECT session_id FROM approval_requests WHERE status = 'pending' AND disabled = 0)
    `).run(cutoffDate);
    
    logger.debug(`[Session Purge] Deleted ${approvalResult.changes} approval requests, ${sessionResult.changes} sessions`);
  } catch (error) {
    logger.error('[Session Purge] Error:', error.message);
  }
}

// API endpoint to manually trigger session purge
app.post('/api/admin/purge-sessions', (req, res) => {
  try {
    purgeOldSessions();
    res.json({ success: true, message: 'Session purge completed' });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Session purge failed' });
  }
});

// ============================================================================
// START SERVER
// ============================================================================

app.listen(PORT, async () => {
  logger.info(`Captive Portal server running on port ${PORT}`);
  logger.info(`Admin panel: http://localhost:${PORT}/admin.html`);
  logger.info(`Success redirect: ${SUCCESS_REDIRECT_URL || 'disabled (stays on success page)'}`);
  logger.info(`Session purge: every ${SESSION_PURGE_INTERVAL / 1000 / 60 / 60} hours (max age: ${SESSION_MAX_AGE_HOURS} hours)`);
  logger.info(`OPNsense sync: every ${OPNSENSE_SYNC_INTERVAL / 1000} seconds`);
  logger.info(`Max failed auth attempts: ${MAX_FAILED_ATTEMPTS}`);
  
  // Sync OPNsense MACs on startup
  await syncOPNsenseMacs();
  
  // Run initial session purge
  purgeOldSessions();
  
  // Set up periodic session purge
  setInterval(purgeOldSessions, SESSION_PURGE_INTERVAL);
  
  // Set up periodic OPNsense MAC sync
  setInterval(syncOPNsenseMacs, OPNSENSE_SYNC_INTERVAL);
});

module.exports = app;
