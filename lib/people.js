const logger = require('./logger');
/**
 * People Management Module
 * Handles person-device associations for presence tracking
 */

// Note: db and notifyHomeAssistant are injected via init()
let db = null;
let notifyHomeAssistant = null;

/**
 * Initialize the module with dependencies
 */
function init(database, haNotify) {
  db = database;
  notifyHomeAssistant = haNotify || (() => {});
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Normalize a name for matching (lowercase, trim, collapse spaces)
 */
function normalizeName(name) {
  if (!name) return null;
  return name.toLowerCase().trim().replace(/\s+/g, ' ');
}

// ============================================================================
// PEOPLE FUNCTIONS
// ============================================================================

/**
 * Find or create a person by name (also checks phone match)
 * Returns the person_id
 */
function findOrCreatePerson(name, options = {}) {
  if (!db) throw new Error('People module not initialized');
  
  const { email, phone, birthdate } = options;
  const normalizedName = normalizeName(name);
  
  if (!normalizedName) return null;
  
  // Try to find existing person by phone first (most accurate match)
  let person = null;
  if (phone) {
    person = db.prepare('SELECT * FROM people WHERE phone = ?').get(phone);
  }
  
  // If not found by phone, try by name
  if (!person) {
    person = db.prepare('SELECT * FROM people WHERE normalized_name = ?').get(normalizedName);
  }
  
  if (person) {
    // Update with any new info
    const updates = [];
    const params = [];
    
    if (email && !person.oauth_email) {
      updates.push('oauth_email = ?');
      params.push(email);
    }
    if (phone && !person.phone) {
      updates.push('phone = ?');
      params.push(phone);
    }
    if (birthdate && !person.birthdate) {
      updates.push('birthdate = ?');
      params.push(birthdate);
    }
    
    if (updates.length > 0) {
      updates.push('updated_at = CURRENT_TIMESTAMP');
      params.push(person.id);
      db.prepare(`UPDATE people SET ${updates.join(', ')} WHERE id = ?`).run(...params);
    }
    
    return person.id;
  }
  
  // Create new person
  const haEntityId = `person.captive_portal_${normalizedName.replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '')}`;
  
  const result = db.prepare(`
    INSERT INTO people (name, normalized_name, oauth_email, phone, birthdate, ha_entity_id)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(name, normalizedName, email || null, phone || null, birthdate || null, haEntityId);
  
  logger.info(`Created new person: ${name} (id=${result.lastInsertRowid})`);
  
  // Notify Home Assistant about new person
  if (notifyHomeAssistant) {
    notifyHomeAssistant('person_created', {
      person_id: result.lastInsertRowid,
      name: name,
      entity_id: haEntityId
    });
  }
  
  return result.lastInsertRowid;
}

/**
 * Associate a device (MAC address) with a person
 */
function associateDeviceWithPerson(mac, personId) {
  if (!db) throw new Error('People module not initialized');
  if (!mac || !personId) return false;
  
  const normalizedMac = mac.toUpperCase();
  
  // Update whitelist
  db.prepare('UPDATE whitelist SET person_id = ? WHERE mac_address = ?').run(personId, normalizedMac);
  
  // Update users table
  db.prepare('UPDATE users SET person_id = ? WHERE mac_address = ?').run(personId, normalizedMac);
  
  return true;
}

/**
 * Get all devices for a person
 */
function getPersonDevices(personId) {
  if (!db) throw new Error('People module not initialized');
  
  return db.prepare(`
    SELECT w.*, 
           CASE WHEN w.last_seen > datetime('now', '-5 minutes') THEN 1 ELSE 0 END as online
    FROM whitelist w
    WHERE w.person_id = ?
    ORDER BY w.device_type = 'phone' DESC, w.last_seen DESC
  `).all(personId);
}

/**
 * Get person's presence status (online if any phone device is online)
 */
function getPersonPresence(personId) {
  if (!db) throw new Error('People module not initialized');
  
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  
  const onlinePhone = db.prepare(`
    SELECT 1 FROM whitelist 
    WHERE person_id = ? AND device_type = 'phone' AND last_seen > ?
    LIMIT 1
  `).get(personId, fiveMinutesAgo);
  
  return !!onlinePhone;
}

/**
 * Get a person by ID
 */
function getPersonById(personId) {
  if (!db) throw new Error('People module not initialized');
  return db.prepare('SELECT * FROM people WHERE id = ?').get(personId);
}

/**
 * Get all people
 */
function getAllPeople() {
  if (!db) throw new Error('People module not initialized');
  return db.prepare('SELECT * FROM people ORDER BY name').all();
}

/**
 * Update a person
 */
function updatePerson(personId, updates) {
  if (!db) throw new Error('People module not initialized');
  
  const { name, phone, birthdate, oauth_email } = updates;
  const fields = [];
  const params = [];
  
  if (name !== undefined) {
    fields.push('name = ?', 'normalized_name = ?');
    params.push(name, normalizeName(name));
  }
  if (phone !== undefined) {
    fields.push('phone = ?');
    params.push(phone);
  }
  if (birthdate !== undefined) {
    fields.push('birthdate = ?');
    params.push(birthdate);
  }
  if (oauth_email !== undefined) {
    fields.push('oauth_email = ?');
    params.push(oauth_email);
  }
  
  if (fields.length === 0) return false;
  
  fields.push('updated_at = CURRENT_TIMESTAMP');
  params.push(personId);
  
  db.prepare(`UPDATE people SET ${fields.join(', ')} WHERE id = ?`).run(...params);
  return true;
}

/**
 * Delete a person (disassociates devices but doesn't delete them)
 */
function deletePerson(personId) {
  if (!db) throw new Error('People module not initialized');
  
  // Disassociate devices
  db.prepare('UPDATE whitelist SET person_id = NULL WHERE person_id = ?').run(personId);
  db.prepare('UPDATE users SET person_id = NULL WHERE person_id = ?').run(personId);
  
  // Delete person
  db.prepare('DELETE FROM people WHERE id = ?').run(personId);
  
  return true;
}

/**
 * Merge two people (move all devices from source to target, delete source)
 */
function mergePeople(targetId, sourceId) {
  if (!db) throw new Error('People module not initialized');
  if (targetId === sourceId) return false;
  
  // Move devices from source to target
  db.prepare('UPDATE whitelist SET person_id = ? WHERE person_id = ?').run(targetId, sourceId);
  db.prepare('UPDATE users SET person_id = ? WHERE person_id = ?').run(targetId, sourceId);
  
  // Delete source person
  db.prepare('DELETE FROM people WHERE id = ?').run(sourceId);
  
  return true;
}

/**
 * Get people with their device counts and presence status
 */
function getPeopleWithStats() {
  if (!db) throw new Error('People module not initialized');
  
  const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
  
  return db.prepare(`
    SELECT p.*,
           (SELECT COUNT(*) FROM whitelist WHERE person_id = p.id) as device_count,
           (SELECT COUNT(*) FROM whitelist WHERE person_id = p.id AND device_type = 'phone') as phone_count,
           CASE WHEN EXISTS (
             SELECT 1 FROM whitelist 
             WHERE person_id = p.id AND device_type = 'phone' AND last_seen > ?
           ) THEN 1 ELSE 0 END as is_home
    FROM people p
    ORDER BY p.name
  `).all(fiveMinutesAgo);
}

module.exports = {
  init,
  normalizeName,
  findOrCreatePerson,
  associateDeviceWithPerson,
  getPersonDevices,
  getPersonPresence,
  getPersonById,
  getAllPeople,
  updatePerson,
  deletePerson,
  mergePeople,
  getPeopleWithStats
};
