/**
 * Home Assistant Routes Module
 * API endpoints for Home Assistant custom integration
 * 
 * Provides:
 * - approval_pending binary sensor (true when pending approvals exist)
 * - person phone entities with MAC address and photo
 * - tracked devices with online status
 * - configurable device offline timeout
 */

module.exports = function(app, db, people, config = {}) {
  const { getDeviceOfflineTimeout, setDeviceOfflineTimeout } = config;

  // ============================================================================
  // CONFIGURATION ENDPOINTS
  // ============================================================================

  // Get current configuration
  app.get('/api/ha/config', (req, res) => {
    res.json({
      device_offline_timeout: getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30
    });
  });

  // Update configuration (can be called from Home Assistant)
  app.post('/api/ha/config', (req, res) => {
    const { device_offline_timeout } = req.body;
    
    if (device_offline_timeout !== undefined) {
      if (setDeviceOfflineTimeout && setDeviceOfflineTimeout(device_offline_timeout)) {
        return res.json({ 
          success: true, 
          message: 'Configuration updated',
          device_offline_timeout: getDeviceOfflineTimeout()
        });
      } else {
        return res.status(400).json({ 
          error: 'Invalid device_offline_timeout value. Must be a positive integer.' 
        });
      }
    }
    
    res.status(400).json({ error: 'No valid configuration provided' });
  });

  // ============================================================================
  // HOME ASSISTANT API ENDPOINTS
  // ============================================================================

  // Get full status for Home Assistant integration
  // This is the main polling endpoint for the HA integration
  app.get('/api/ha/status', (req, res) => {
    const pending = db.prepare('SELECT COUNT(*) as count FROM approval_requests WHERE status = ? AND COALESCE(disabled, 0) = 0').get('pending');
    const approved = db.prepare('SELECT COUNT(*) as count FROM users WHERE approved = 1').get();
    const tracked = db.prepare('SELECT COUNT(*) as count FROM whitelist WHERE device_type = ?').get('phone');
    const peopleCount = db.prepare('SELECT COUNT(*) as count FROM people').get();

    // Binary sensor: approval_pending (true if any pending requests)
    const approvalPending = pending.count > 0;

    // Get device offline timeout (in seconds)
    const offlineTimeout = getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30;
    const cutoffTime = new Date(Date.now() - offlineTimeout * 1000).toISOString();
    
    const peopleList = db.prepare(`
      SELECT p.id, p.name, p.phone, p.birthdate, p.photo, p.photo_mime_type, p.ha_entity_id
      FROM people p
    `).all().map(person => {
      // Get phone devices for this person
      const phoneDevices = db.prepare(`
        SELECT mac_address, last_seen,
               CASE WHEN last_seen > ? THEN 1 ELSE 0 END as online
        FROM whitelist 
        WHERE person_id = ? AND device_type = 'phone'
      `).all(cutoffTime, person.id);
      
      // Get primary phone MAC (most recently seen)
      const primaryPhone = phoneDevices.length > 0 
        ? phoneDevices.sort((a, b) => b.last_seen?.localeCompare(a.last_seen || ''))[0]
        : null;
      
      return {
        id: person.id,
        name: person.name,
        entity_id: person.ha_entity_id || `person_${person.name.toLowerCase().replace(/\s+/g, '_')}`,
        // For person_phone entity
        phone_mac: primaryPhone?.mac_address || null,
        // Photo as data URI if available
        photo: person.photo ? `data:${person.photo_mime_type || 'image/jpeg'};base64,${person.photo}` : null,
        // Presence
        online: phoneDevices.some(d => d.online === 1),
        phone_count: phoneDevices.length
      };
    });

    res.json({
      // Binary sensor state
      approval_pending: approvalPending,
      pending_count: pending.count,
      
      // Stats
      approved_count: approved.count,
      tracked_count: tracked.count,
      people_count: peopleCount.count,
      
      // Config
      device_offline_timeout: offlineTimeout,
      
      // Person entities with phone MACs and photos
      people: peopleList
    });
  });

  // Get just the approval pending status (lightweight poll)
  app.get('/api/ha/approval-pending', (req, res) => {
    const pending = db.prepare('SELECT COUNT(*) as count FROM approval_requests WHERE status = ? AND COALESCE(disabled, 0) = 0').get('pending');
    res.json({
      approval_pending: pending.count > 0,
      pending_count: pending.count
    });
  });

  // Get all people with their phone entities
  // Each person with a phone device becomes a sensor showing their MAC
  app.get('/api/ha/people', (req, res) => {
    // Get device offline timeout (in seconds)
    const offlineTimeout = getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30;
    const cutoffTime = new Date(Date.now() - offlineTimeout * 1000).toISOString();
    
    const peopleList = db.prepare('SELECT * FROM people').all().map(person => {
      // Get phone devices for this person
      const phoneDevices = db.prepare(`
        SELECT mac_address, device_type, last_seen,
               CASE WHEN last_seen > ? THEN 1 ELSE 0 END as online
        FROM whitelist WHERE person_id = ? AND device_type = 'phone'
      `).all(cutoffTime, person.id);
      
      // Primary phone is most recently seen
      const primaryPhone = phoneDevices.length > 0 
        ? phoneDevices.sort((a, b) => (b.last_seen || '').localeCompare(a.last_seen || ''))[0]
        : null;
      
      return {
        id: person.id,
        name: person.name,
        // Entity ID for HA
        entity_id: person.ha_entity_id || `person_${person.name.toLowerCase().replace(/[^a-z0-9]/g, '_')}`,
        phone: person.phone,
        birthdate: person.birthdate,
        // Phone entity value = MAC address
        phone_mac: primaryPhone?.mac_address || null,
        // Photo as base64 data URI
        photo: person.photo ? `data:${person.photo_mime_type || 'image/jpeg'};base64,${person.photo}` : null,
        photo_raw: person.photo || null,
        photo_mime_type: person.photo_mime_type || null,
        // Presence based on phone
        online: primaryPhone?.online === 1,
        device_count: phoneDevices.length,
        devices: phoneDevices.map(d => ({
          mac_address: d.mac_address,
          online: d.online === 1,
          last_seen: d.last_seen
        }))
      };
    });
    
    res.json(peopleList);
  });

  // Get tracked phone devices for Home Assistant device trackers
  app.get('/api/ha/devices', (req, res) => {
    // Get device offline timeout (in seconds)
    const offlineTimeout = getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30;
    const cutoffTime = new Date(Date.now() - offlineTimeout * 1000).toISOString();
    
    const devices = db.prepare(`
      SELECT w.mac_address, w.user_name, w.device_type, w.last_seen, w.person_id,
             p.name as person_name, p.ha_entity_id as person_entity_id,
             CASE WHEN w.last_seen > ? THEN 1 ELSE 0 END as online
      FROM whitelist w
      LEFT JOIN people p ON w.person_id = p.id
      WHERE w.device_type = 'phone'
      ORDER BY w.last_seen DESC
    `).all(cutoffTime);
    
    res.json(devices.map(d => ({
      mac_address: d.mac_address,
      user_name: d.user_name,
      person_name: d.person_name,
      person_entity_id: d.person_entity_id,
      online: d.online === 1,
      last_seen: d.last_seen
    })));
  });

  // Get pending requests (for admin dashboard or HA notification)
  app.get('/api/ha/pending', (req, res) => {
    const pending = db.prepare(`
      SELECT ar.session_id, ar.user_name, ar.device_type, ar.mac_address, ar.created_at,
             s.ip_address
      FROM approval_requests ar
      LEFT JOIN sessions s ON ar.session_id = s.id
      WHERE ar.status = 'pending' AND COALESCE(ar.disabled, 0) = 0
      ORDER BY ar.created_at DESC
    `).all();

    res.json(pending);
  });

  // Get person photo by ID (for use in HA entity_picture)
  app.get('/api/ha/person/:id/photo', (req, res) => {
    const { id } = req.params;
    
    const person = db.prepare('SELECT photo, photo_mime_type FROM people WHERE id = ?').get(id);
    
    if (!person || !person.photo) {
      return res.status(404).send('No photo available');
    }
    
    // Return as image
    const buffer = Buffer.from(person.photo, 'base64');
    res.set('Content-Type', person.photo_mime_type || 'image/jpeg');
    res.set('Cache-Control', 'public, max-age=3600');
    res.send(buffer);
  });

  // NOTE: We removed /api/ha/approve and /api/ha/deny endpoints
  // Approvals should be done through the admin web interface
  // HA integration just shows approval_pending binary sensor
};
