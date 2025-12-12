/**
 * Admin Routes Module
 * Handles admin dashboard API endpoints
 */

module.exports = function(app, db, helpers) {
  const { 
    revokeMacInOPNsense,
    getPersonDevices,
    getPersonPresence,
    invalidatedSessionIds,
    getDeviceOfflineTimeout
  } = helpers;

  /**
   * Normalize a name for matching (lowercase, trim, collapse spaces)
   */
  function normalizeName(name) {
    if (!name) return null;
    return name.toLowerCase().trim().replace(/\s+/g, ' ');
  }

  // ============================================================================
  // ADMIN ROUTES
  // ============================================================================

  // Get pending requests
  app.get('/api/admin/pending', (req, res) => {
    const pending = db.prepare(`
      SELECT ar.*, s.ip_address, s.created_at as session_created
      FROM approval_requests ar
      LEFT JOIN sessions s ON ar.session_id = s.id
      WHERE ar.status = 'pending'
      ORDER BY ar.created_at DESC
    `).all();

    res.json(pending);
  });

  // Get authenticated users
  app.get('/api/admin/authenticated', (req, res) => {
    const users = db.prepare(`
      SELECT u.*, w.last_seen, w.first_approved
      FROM users u
      LEFT JOIN whitelist w ON u.mac_address = w.mac_address
      WHERE u.approved = 1
      ORDER BY w.last_seen DESC
    `).all();

    res.json(users);
  });

  // Get rejected users
  app.get('/api/admin/rejected', (req, res) => {
    const rejected = db.prepare(`
      SELECT ar.*, s.ip_address
      FROM approval_requests ar
      LEFT JOIN sessions s ON ar.session_id = s.id
      WHERE ar.status = 'denied'
      ORDER BY ar.created_at DESC
    `).all();

    res.json(rejected);
  });

  // Get tracked devices (phones)
  app.get('/api/admin/tracked-devices', (req, res) => {
    const tracked = db.prepare(`
      SELECT w.*, u.name, u.phone
      FROM whitelist w
      LEFT JOIN users u ON w.user_id = u.id
      WHERE w.device_type = 'phone'
      ORDER BY w.last_seen DESC
    `).all();

    // Add online status based on last_seen using configurable timeout
    const offlineTimeout = getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30;
    const cutoffTime = new Date(Date.now() - offlineTimeout * 1000).toISOString();
    
    const trackedWithStatus = tracked.map(device => ({
      ...device,
      online: device.last_seen > cutoffTime
    }));

    res.json(trackedWithStatus);
  });

  // Approve request - marks as approved but does NOT whitelist yet
  // MAC whitelisting happens when user completes device selection flow
  app.post('/api/admin/approve/:sessionId', async (req, res) => {
    const { sessionId } = req.params;

    try {
      // Get request details
      const request = db.prepare(`
        SELECT ar.*, s.user_id, s.ip_address
        FROM approval_requests ar
        LEFT JOIN sessions s ON ar.session_id = s.id
        WHERE ar.session_id = ?
      `).get(sessionId);

      if (!request) {
        return res.status(404).json({ error: 'Request not found' });
      }

      // Update approval request status (but NOT flow_completed - that happens after device selection)
      db.prepare('UPDATE approval_requests SET status = ? WHERE session_id = ?').run('approved', sessionId);

      // Update session status
      db.prepare('UPDATE sessions SET status = ?, approved_at = CURRENT_TIMESTAMP WHERE id = ?').run('approved', sessionId);

      // Update user approved status
      db.prepare('UPDATE users SET approved = 1 WHERE id = ?').run(request.user_id);

      // NOTE: We do NOT whitelist MAC here anymore!
      // MAC whitelisting happens in completeAccessFlow after device selection

      res.json({ success: true, message: 'Request approved - waiting for user to complete device selection' });
    } catch (error) {
      console.error('Approval error:', error);
      res.status(500).json({ error: 'Failed to approve request' });
    }
  });

  // Deny request
  app.post('/api/admin/deny/:sessionId', async (req, res) => {
    const { sessionId } = req.params;

    try {
      // Update approval request status
      db.prepare('UPDATE approval_requests SET status = ? WHERE session_id = ?').run('denied', sessionId);

      // Update session status
      db.prepare('UPDATE sessions SET status = ? WHERE id = ?').run('denied', sessionId);

      // NOTE: We no longer notify HA about approve/deny actions
      // HA just monitors the pending count via the approval_pending sensor

      res.json({ success: true, message: 'Request denied' });
    } catch (error) {
      console.error('Denial error:', error);
      res.status(500).json({ error: 'Failed to deny request' });
    }
  });

  // Remove from whitelist (revoke access)
  app.delete('/api/admin/whitelist/:mac', async (req, res) => {
    const { mac } = req.params;
    const normalizedMac = mac.toUpperCase();

    try {
      // Revoke in OPNsense if configured
      await revokeMacInOPNsense(normalizedMac);
      
      // Delete from whitelist
      db.prepare('DELETE FROM whitelist WHERE mac_address = ?').run(normalizedMac);
      
      // DISABLE all sessions with this MAC address so user can login again
      const sessionIds = db.prepare('SELECT id FROM sessions WHERE mac_address = ?').all(normalizedMac).map(s => s.id);
      
      if (sessionIds.length > 0) {
        db.prepare(`
          UPDATE approval_requests SET disabled = 1 WHERE session_id IN (${sessionIds.map(() => '?').join(',')})
        `).run(...sessionIds);
        
        db.prepare(`
          UPDATE sessions SET disabled = 1 WHERE id IN (${sessionIds.map(() => '?').join(',')})
        `).run(...sessionIds);
        
        // Add to invalidated set to destroy cookie sessions
        sessionIds.forEach(id => {
          invalidatedSessionIds.add(id);
          console.log(`[Session] Added ${id} to invalidated sessions (whitelist removal)`);
        });
      }
      
      // Update user approved status
      db.prepare('UPDATE users SET approved = 0 WHERE mac_address = ?').run(normalizedMac);
      
      res.json({ success: true, message: 'Access revoked', invalidatedSessions: sessionIds.length });
    } catch (error) {
      console.error('Whitelist removal error:', error);
      res.status(500).json({ error: 'Failed to remove from whitelist' });
    }
  });

  // Remove from tracking (but keep in whitelist)
  app.post('/api/admin/untrack/:mac', (req, res) => {
    const { mac } = req.params;
    const normalizedMac = mac.toUpperCase();

    try {
      db.prepare('UPDATE whitelist SET device_type = ? WHERE mac_address = ?').run('other', normalizedMac);
      res.json({ success: true, message: 'Device removed from tracking' });
    } catch (error) {
      console.error('Untrack error:', error);
      res.status(500).json({ error: 'Failed to untrack device' });
    }
  });

  // ============================================================================
  // PEOPLE ADMIN ENDPOINTS
  // ============================================================================

  // Get all people
  app.get('/api/admin/people', (req, res) => {
    const people = db.prepare(`
      SELECT p.*,
             (SELECT COUNT(*) FROM whitelist WHERE person_id = p.id) as device_count,
             (SELECT COUNT(*) FROM whitelist WHERE person_id = p.id AND device_type = 'phone') as phone_count
      FROM people p
      ORDER BY p.name ASC
    `).all();
    
    // Add presence status for each person using configurable timeout
    const offlineTimeout = getDeviceOfflineTimeout ? getDeviceOfflineTimeout() : 30;
    const cutoffTime = new Date(Date.now() - offlineTimeout * 1000).toISOString();
    
    const peopleWithStatus = people.map(person => {
      const onlinePhone = db.prepare(`
        SELECT 1 FROM whitelist 
        WHERE person_id = ? AND device_type = 'phone' AND last_seen > ?
        LIMIT 1
      `).get(person.id, cutoffTime);
      
      return {
        ...person,
        online: !!onlinePhone
      };
    });
    
    res.json(peopleWithStatus);
  });

  // Get single person with devices
  app.get('/api/admin/people/:id', (req, res) => {
    const { id } = req.params;
    
    const person = db.prepare('SELECT * FROM people WHERE id = ?').get(id);
    if (!person) {
      return res.status(404).json({ error: 'Person not found' });
    }
    
    const devices = getPersonDevices(id);
    const online = getPersonPresence(id);
    
    res.json({
      ...person,
      online,
      devices
    });
  });

  // Update person
  app.put('/api/admin/people/:id', (req, res) => {
    const { id } = req.params;
    const { name, phone, birthdate } = req.body;
    
    try {
      const updates = ['updated_at = CURRENT_TIMESTAMP'];
      const params = [];
      
      if (name) {
        updates.push('name = ?', 'normalized_name = ?');
        params.push(name, normalizeName(name));
      }
      if (phone !== undefined) {
        updates.push('phone = ?');
        params.push(phone || null);
      }
      if (birthdate !== undefined) {
        updates.push('birthdate = ?');
        params.push(birthdate || null);
      }
      
      params.push(id);
      db.prepare(`UPDATE people SET ${updates.join(', ')} WHERE id = ?`).run(...params);
      
      res.json({ success: true, message: 'Person updated' });
    } catch (error) {
      console.error('Person update error:', error);
      res.status(500).json({ error: 'Failed to update person' });
    }
  });

  // Delete person (and revoke ALL their devices from network)
  app.delete('/api/admin/people/:id', async (req, res) => {
    const { id } = req.params;
    
    try {
      // Get all devices for this person BEFORE deleting
      const devices = db.prepare(`
        SELECT mac_address FROM whitelist WHERE person_id = ?
      `).all(id);
      
      // Revoke each device from OPNsense
      for (const device of devices) {
        console.log(`Revoking MAC ${device.mac_address} for deleted person ${id}`);
        await revokeMacInOPNsense(device.mac_address);
      }
      
      // Delete from whitelist (revoke access)
      db.prepare('DELETE FROM whitelist WHERE person_id = ?').run(id);
      
      // DISABLE all sessions for this person's users so they can login again
      // First get all user IDs for this person
      const userIds = db.prepare('SELECT id FROM users WHERE person_id = ?').all(id).map(u => u.id);
      
      let invalidatedCount = 0;
      if (userIds.length > 0) {
        // Disable all approval requests for these users' sessions
        const sessionIds = db.prepare(`
          SELECT id FROM sessions WHERE user_id IN (${userIds.map(() => '?').join(',')})
        `).all(...userIds).map(s => s.id);
        
        if (sessionIds.length > 0) {
          db.prepare(`
            UPDATE approval_requests SET disabled = 1 WHERE session_id IN (${sessionIds.map(() => '?').join(',')})
          `).run(...sessionIds);
          
          db.prepare(`
            UPDATE sessions SET disabled = 1 WHERE id IN (${sessionIds.map(() => '?').join(',')})
          `).run(...sessionIds);
          
          // Add to invalidated set to destroy cookie sessions
          sessionIds.forEach(sid => {
            invalidatedSessionIds.add(sid);
            console.log(`[Session] Added ${sid} to invalidated sessions (person deletion)`);
          });
          invalidatedCount = sessionIds.length;
        }
      }
      
      // Update users - mark as not approved and disassociate
      db.prepare('UPDATE users SET person_id = NULL, approved = 0 WHERE person_id = ?').run(id);
      
      // Delete person
      db.prepare('DELETE FROM people WHERE id = ?').run(id);
      
      res.json({ 
        success: true, 
        message: `Person deleted and ${devices.length} device(s) revoked`,
        invalidatedSessions: invalidatedCount
      });
    } catch (error) {
      console.error('Person deletion error:', error);
      res.status(500).json({ error: 'Failed to delete person' });
    }
  });

  // Merge two people (move all devices from source to target)
  app.post('/api/admin/people/:targetId/merge/:sourceId', (req, res) => {
    const { targetId, sourceId } = req.params;
    
    try {
      // Move all devices to target person
      db.prepare('UPDATE whitelist SET person_id = ? WHERE person_id = ?').run(targetId, sourceId);
      db.prepare('UPDATE users SET person_id = ? WHERE person_id = ?').run(targetId, sourceId);
      
      // Delete source person
      db.prepare('DELETE FROM people WHERE id = ?').run(sourceId);
      
      res.json({ success: true, message: 'People merged' });
    } catch (error) {
      console.error('People merge error:', error);
      res.status(500).json({ error: 'Failed to merge people' });
    }
  });

  // Reassign device to different person
  app.post('/api/admin/devices/:mac/assign/:personId', (req, res) => {
    const { mac, personId } = req.params;
    const normalizedMac = mac.toUpperCase();
    
    try {
      db.prepare('UPDATE whitelist SET person_id = ? WHERE mac_address = ?').run(personId, normalizedMac);
      db.prepare('UPDATE users SET person_id = ? WHERE mac_address = ?').run(personId, normalizedMac);
      
      res.json({ success: true, message: 'Device reassigned' });
    } catch (error) {
      console.error('Device reassignment error:', error);
      res.status(500).json({ error: 'Failed to reassign device' });
    }
  });

  // Get stats for admin dashboard
  app.get('/api/admin/stats', (req, res) => {
    const pending = db.prepare('SELECT COUNT(*) as count FROM approval_requests WHERE status = ? AND COALESCE(disabled, 0) = 0').get('pending');
    const approved = db.prepare('SELECT COUNT(*) as count FROM users WHERE approved = 1').get();
    const denied = db.prepare('SELECT COUNT(*) as count FROM approval_requests WHERE status = ?').get('denied');
    const tracked = db.prepare('SELECT COUNT(*) as count FROM whitelist WHERE device_type = ?').get('phone');
    const peopleCount = db.prepare('SELECT COUNT(*) as count FROM people').get();
    const devices = db.prepare('SELECT COUNT(*) as count FROM whitelist').get();
    const unknownMacs = db.prepare('SELECT COUNT(*) as count FROM opnsense_macs').get();

    res.json({
      pending: pending.count,
      approved: approved.count,
      denied: denied.count,
      tracked: tracked.count,
      people: peopleCount.count,
      devices: devices.count,
      unknownMacs: unknownMacs.count
    });
  });

  // ============================================================================
  // OPNSENSE TRACKED MACS (Unknown devices in OPNsense not in our whitelist)
  // ============================================================================

  // Get all unknown/unlinked MACs from OPNsense
  app.get('/api/admin/opnsense-macs', (req, res) => {
    const macs = db.prepare(`
      SELECT * FROM opnsense_macs
      ORDER BY last_seen DESC
    `).all();

    res.json(macs);
  });

  // Revoke an OPNsense MAC (remove from OPNsense and tracking)
  app.delete('/api/admin/opnsense-macs/:mac', async (req, res) => {
    const { mac } = req.params;
    const normalizedMac = mac.toUpperCase();

    try {
      // Revoke in OPNsense
      await revokeMacInOPNsense(normalizedMac);
      
      // Remove from tracking
      db.prepare('DELETE FROM opnsense_macs WHERE mac_address = ?').run(normalizedMac);
      
      res.json({ success: true, message: 'MAC revoked from OPNsense' });
    } catch (error) {
      console.error('OPNsense MAC revocation error:', error);
      res.status(500).json({ error: 'Failed to revoke MAC' });
    }
  });

  // Update description for an OPNsense tracked MAC
  app.put('/api/admin/opnsense-macs/:mac', (req, res) => {
    const { mac } = req.params;
    const { description } = req.body;
    const normalizedMac = mac.toUpperCase();

    try {
      db.prepare('UPDATE opnsense_macs SET description = ? WHERE mac_address = ?')
        .run(description, normalizedMac);
      
      res.json({ success: true, message: 'Description updated' });
    } catch (error) {
      console.error('OPNsense MAC update error:', error);
      res.status(500).json({ error: 'Failed to update MAC' });
    }
  });
};
