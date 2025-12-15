/**
 * Database Module
 * Handles SQLite database initialization and common queries
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DB_PATH || './data/captive_portal.db';

// Ensure data directory exists
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);

// Initialize database tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    birthdate TEXT,
    phone TEXT,
    auth_method TEXT NOT NULL,
    oauth_id TEXT UNIQUE,
    mac_address TEXT,
    device_type TEXT,
    person_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved INTEGER DEFAULT 0,
    FOREIGN KEY (person_id) REFERENCES people(id)
  );

  CREATE TABLE IF NOT EXISTS people (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    normalized_name TEXT UNIQUE,
    oauth_email TEXT,
    phone TEXT,
    birthdate TEXT,
    photo TEXT,
    photo_mime_type TEXT,
    ha_entity_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER,
    mac_address TEXT,
    ip_address TEXT,
    status TEXT DEFAULT 'pending',
    approved_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS approval_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    user_name TEXT,
    device_type TEXT,
    mac_address TEXT,
    status TEXT DEFAULT 'pending',
    flow_completed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
  );

  CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    user_name TEXT,
    device_type TEXT,
    user_id INTEGER,
    person_id INTEGER,
    first_approved DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    permanent INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (person_id) REFERENCES people(id)
  );

  CREATE INDEX IF NOT EXISTS idx_whitelist_mac ON whitelist(mac_address);
  CREATE INDEX IF NOT EXISTS idx_whitelist_person ON whitelist(person_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_mac ON sessions(mac_address);
  CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
  CREATE INDEX IF NOT EXISTS idx_people_name ON people(normalized_name);

  -- Table to track OPNsense MACs that aren't in our whitelist DB
  -- These show up in admin panel so you can revoke them
  CREATE TABLE IF NOT EXISTS opnsense_macs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    description TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_opnsense_macs ON opnsense_macs(mac_address);
`);

// Add columns if they don't exist (for existing databases)
try {
  db.exec(`ALTER TABLE people ADD COLUMN photo TEXT`);
} catch (e) { /* column already exists */ }

try {
  db.exec(`ALTER TABLE people ADD COLUMN photo_mime_type TEXT`);
} catch (e) { /* column already exists */ }

try {
  db.exec(`ALTER TABLE approval_requests ADD COLUMN flow_completed INTEGER DEFAULT 0`);
} catch (e) { /* column already exists */ }

// Add disabled flag to sessions for when person is deleted
try {
  db.exec(`ALTER TABLE sessions ADD COLUMN disabled INTEGER DEFAULT 0`);
} catch (e) { /* column already exists */ }

// Add disabled flag to approval_requests
try {
  db.exec(`ALTER TABLE approval_requests ADD COLUMN disabled INTEGER DEFAULT 0`);
} catch (e) { /* column already exists */ }

// Table to track blocked MAC addresses (failed too many auth attempts)
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS blocked_macs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mac_address TEXT UNIQUE NOT NULL,
      reason TEXT,
      blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      unblock_at DATETIME
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_blocked_macs ON blocked_macs(mac_address)`);
} catch (e) { /* table already exists */ }

// Table to track failed authentication attempts per MAC
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS failed_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mac_address TEXT NOT NULL,
      attempt_type TEXT NOT NULL,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_failed_attempts_mac ON failed_attempts(mac_address)`);
} catch (e) { /* table already exists */ }

console.log('Database initialized');

module.exports = db;
