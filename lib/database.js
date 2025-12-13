/**
 * Database Module
 * Handles SQLite database initialization and common queries
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

function fatal(msg, err) {
  // Keep logs clean but useful
  console.error(`[DB] ${msg}`);
  if (err) console.error(err);
  process.exit(1);
}

// Resolve to an absolute path so relative DB_PATHs can't surprise us.
const dbPath = path.resolve(process.env.DB_PATH || './data/captive_portal.db');
const dataDir = path.dirname(dbPath);

// Helpful startup context (tiny + actionable)
console.log('[DB] init', {
  dbPath,
  dataDir,
  cwd: process.cwd(),
  uid: typeof process.getuid === 'function' ? process.getuid() : undefined,
  gid: typeof process.getgid === 'function' ? process.getgid() : undefined,
});

try {
  // Ensure directory exists (recursive is safe even if it already exists)
  fs.mkdirSync(dataDir, { recursive: true });
} catch (e) {
  fatal(`Failed to create data directory: ${dataDir}`, e);
}

try {
  // Ensure we can write to the directory
  fs.accessSync(dataDir, fs.constants.W_OK);
} catch (e) {
  fatal(`Data directory is not writable: ${dataDir}`, e);
}

try {
  // Ensure we can create/open the db file (does not truncate)
  fs.closeSync(fs.openSync(dbPath, 'a'));
} catch (e) {
  fatal(`Database file is not creatable/writable: ${dbPath}`, e);
}

let db;
try {
  // Optional: set a busy timeout so concurrent writes don't instantly fail
  db = new Database(dbPath, { timeout: 5000 });
} catch (e) {
  fatal(`Failed to open SQLite database at: ${dbPath}`, e);
}

// Initialize database tables
try {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

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

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER,
      mac_address TEXT,
      ip_address TEXT,
      status TEXT DEFAULT 'pending',
      approved_at DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      disabled INTEGER DEFAULT 0,
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
      disabled INTEGER DEFAULT 0,
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
} catch (e) {
  fatal('Failed creating base schema', e);
}

// Back-compat: Add columns if they don't exist (for existing databases)
const safeAlter = (sql) => {
  try {
    db.exec(sql);
  } catch (_) {
    // column already exists or table missing in older DBs; ignore
  }
};

safeAlter(`ALTER TABLE people ADD COLUMN photo TEXT`);
safeAlter(`ALTER TABLE people ADD COLUMN photo_mime_type TEXT`);
safeAlter(`ALTER TABLE approval_requests ADD COLUMN flow_completed INTEGER DEFAULT 0`);
safeAlter(`ALTER TABLE sessions ADD COLUMN disabled INTEGER DEFAULT 0`);
safeAlter(`ALTER TABLE approval_requests ADD COLUMN disabled INTEGER DEFAULT 0`);

console.log('[DB] Database initialized');

module.exports = db;
