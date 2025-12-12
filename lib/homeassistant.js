/**
 * Home Assistant Integration Module
 * Handles notifications and device tracking with Home Assistant
 */

// ============================================================================
// CONFIGURATION
// ============================================================================

function getHomeAssistantConfig() {
  return {
    url: process.env.HOME_ASSISTANT_URL,
    token: process.env.HOME_ASSISTANT_TOKEN,
    enabled: !!(process.env.HOME_ASSISTANT_URL && process.env.HOME_ASSISTANT_TOKEN)
  };
}

// ============================================================================
// HOME ASSISTANT FUNCTIONS
// ============================================================================

/**
 * Send notification to Home Assistant
 */
async function notifyHomeAssistant(event, data) {
  const config = getHomeAssistantConfig();

  if (!config.enabled) {
    console.log('Home Assistant not configured');
    return false;
  }

  try {
    const response = await fetch(`${config.url}/api/events/captive_portal_${event}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    return response.ok;
  } catch (error) {
    console.error('Home Assistant notification error:', error);
    return false;
  }
}

/**
 * Register device with Home Assistant device tracker
 */
async function registerDeviceTracker(mac, name, isPhone) {
  if (!isPhone) return false;
  
  const config = getHomeAssistantConfig();

  if (!config.enabled) {
    return false;
  }

  try {
    // Fire an event that can be used to create a device_tracker entity
    const response = await fetch(`${config.url}/api/events/captive_portal_device_registered`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        mac_address: mac,
        name: name,
        device_type: 'phone',
        is_tracked: true
      })
    });

    return response.ok;
  } catch (error) {
    console.error('Device tracker registration error:', error);
    return false;
  }
}

/**
 * Call a Home Assistant service
 */
async function callService(domain, service, data = {}) {
  const config = getHomeAssistantConfig();

  if (!config.enabled) {
    return false;
  }

  try {
    const response = await fetch(`${config.url}/api/services/${domain}/${service}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });

    return response.ok;
  } catch (error) {
    console.error('Home Assistant service call error:', error);
    return false;
  }
}

/**
 * Get entity state from Home Assistant
 */
async function getState(entityId) {
  const config = getHomeAssistantConfig();

  if (!config.enabled) {
    return null;
  }

  try {
    const response = await fetch(`${config.url}/api/states/${entityId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${config.token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.ok) {
      return await response.json();
    }
    return null;
  } catch (error) {
    console.error('Home Assistant get state error:', error);
    return null;
  }
}

/**
 * Send a persistent notification
 */
async function sendNotification(title, message, notificationId = null) {
  const config = getHomeAssistantConfig();

  if (!config.enabled) {
    return false;
  }

  const data = {
    title,
    message
  };

  if (notificationId) {
    data.notification_id = notificationId;
  }

  return callService('persistent_notification', 'create', data);
}

module.exports = {
  getHomeAssistantConfig,
  notifyHomeAssistant,
  registerDeviceTracker,
  callService,
  getState,
  sendNotification
};
