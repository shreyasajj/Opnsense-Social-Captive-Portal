/**
 * OPNsense Integration Module
 * Handles MAC whitelist management via OPNsense Captive Portal API
 */

const https = require('https');

// ============================================================================
// CUSTOM ERROR CLASS
// ============================================================================

class OPNsenseError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'OPNsenseError';
    this.code = code;
    this.details = details;
  }
}

// Error codes
const ErrorCodes = {
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  INVALID_MAC: 'INVALID_MAC',
  CONNECTION_FAILED: 'CONNECTION_FAILED',
  ZONE_NOT_FOUND: 'ZONE_NOT_FOUND',
  ZONE_CONFIG_FAILED: 'ZONE_CONFIG_FAILED',
  UPDATE_FAILED: 'UPDATE_FAILED',
  RECONFIGURE_FAILED: 'RECONFIGURE_FAILED',
  MAC_ALREADY_EXISTS: 'MAC_ALREADY_EXISTS',
  MAC_NOT_FOUND: 'MAC_NOT_FOUND'
};

// ============================================================================
// ASYNC LOCK
// ============================================================================

/**
 * Simple async lock to prevent race conditions when modifying OPNsense config
 */
class AsyncLock {
  constructor() {
    this.locked = false;
    this.queue = [];
  }

  async acquire() {
    return new Promise((resolve) => {
      if (!this.locked) {
        this.locked = true;
        resolve();
      } else {
        this.queue.push(resolve);
      }
    });
  }

  release() {
    if (this.queue.length > 0) {
      const next = this.queue.shift();
      next();
    } else {
      this.locked = false;
    }
  }

  async withLock(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

// Global lock for OPNsense zone modifications
const opnsenseLock = new AsyncLock();

// ============================================================================
// CONFIGURATION
// ============================================================================

/**
 * Get OPNsense API configuration
 */
function getOPNsenseConfig(contentType = false) {
  const config = {
    url: process.env.OPNSENSE_URL,
    apiKey: process.env.OPNSENSE_API_KEY,
    apiSecret: process.env.OPNSENSE_API_SECRET,
    zoneId: process.env.OPNSENSE_ZONE_ID || '0',
    // Allow self-signed certs (common for OPNsense)
    // Set OPNSENSE_VERIFY_SSL=true to enforce certificate validation
    verifySsl: process.env.OPNSENSE_VERIFY_SSL === 'true',
    contentType: contentType,
    enabled: false
  };

  if (config.url && config.apiKey && config.apiSecret) {
    config.enabled = true;
    config.auth = 'Basic ' + Buffer.from(`${config.apiKey}:${config.apiSecret}`).toString('base64');
  }

  return config;
}

// ============================================================================
// HTTP CLIENT
// ============================================================================

/**
 * Make a fetch request to OPNsense API with proper SSL handling
 * Throws OPNsenseError on connection failure
 */
async function opnsenseFetch(url, options, config) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    
    const baseHeaders = {
      'Authorization': config.auth,
      ...options.headers
    };

    if (config.contentType) {
      baseHeaders['Content-Type'] = 'application/json';
    }

    const reqOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: baseHeaders,
      rejectUnauthorized: config.verifySsl ?? true,
      timeout: 30000 // 30 second timeout
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          ok: res.statusCode >= 200 && res.statusCode < 300,
          status: res.statusCode,
          json: () => {
            try {
              return Promise.resolve(JSON.parse(data));
            } catch (e) {
              return Promise.reject(new OPNsenseError(
                `Invalid JSON response: ${data.substring(0, 100)}`,
                ErrorCodes.CONNECTION_FAILED
              ));
            }
          },
          text: () => Promise.resolve(data)
        });
      });
    });

    req.on('error', (error) => {
      reject(new OPNsenseError(
        `Connection to OPNsense failed: ${error.message}`,
        ErrorCodes.CONNECTION_FAILED,
        { originalError: error.message }
      ));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new OPNsenseError(
        'Connection to OPNsense timed out',
        ErrorCodes.CONNECTION_FAILED
      ));
    });

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Normalize MAC address to uppercase with colons
 * Handles formats: aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabbccddeeff
 */
function normalizeMacAddress(mac) {
  if (!mac) return null;
  // Remove all non-hex characters and convert to uppercase
  const clean = mac.toUpperCase().replace(/[^A-F0-9]/g, '');
  if (clean.length !== 12) return null;
  // Format with colons
  return clean.match(/.{2}/g).join(':');
}

/**
 * Extract current MAC addresses from zone config
 * Returns array of normalized MAC addresses
 */
function extractMacAddresses(zoneConfig) {
  const allowedMACs = zoneConfig?.zone?.allowedMACAddresses || {};
  const macs = [];
  
  for (const [key, value] of Object.entries(allowedMACs)) {
    if (key && key !== '' && value?.selected === 1) {
      const normalized = normalizeMacAddress(key);
      if (normalized) {
        macs.push(normalized);
      }
    }
  }
  
  return macs;
}

/**
 * Build the zone update payload
 * Preserves existing settings while updating allowedMACAddresses
 */
function buildZoneUpdatePayload(zoneConfig, newMacList) {
  const zone = zoneConfig.zone;
  
  // Helper to get selected value from object or return the value directly
  const getSelectedValue = (obj) => {
    if (typeof obj === 'string') return obj;
    if (typeof obj !== 'object' || obj === null) return '';
    
    for (const [key, value] of Object.entries(obj)) {
      if (value?.selected === 1) return key;
    }
    return '';
  };

  // Helper to get selected values (for multi-select fields like interfaces)
  const getSelectedValues = (obj) => {
    if (typeof obj === 'string') return obj;
    if (typeof obj !== 'object' || obj === null) return '';
    
    const selected = [];
    for (const [key, value] of Object.entries(obj)) {
      if (value?.selected === 1 && key !== '') {
        selected.push(key);
      }
    }
    return selected.join(',');
  };

  return {
    zone: {
      enabled: zone.enabled || '1',
      interfaces: getSelectedValues(zone.interfaces),
      disableRules: zone.disableRules || '0',
      authservers: getSelectedValues(zone.authservers),
      alwaysSendAccountingReqs: zone.alwaysSendAccountingReqs || '0',
      authEnforceGroup: getSelectedValue(zone.authEnforceGroup),
      idletimeout: zone.idletimeout || '0',
      hardtimeout: zone.hardtimeout || '0',
      concurrentlogins: zone.concurrentlogins || '1',
      certificate: getSelectedValue(zone.certificate),
      servername: zone.servername || '',
      allowedAddresses: getSelectedValues(zone.allowedAddresses),
      allowedMACAddresses: newMacList.join(','),
      extendedPreAuthData: zone.extendedPreAuthData || '0',
      template: getSelectedValue(zone.template),
      description: zone.description || ''
    }
  };
}

// ============================================================================
// ZONE API FUNCTIONS (with proper error handling)
// ============================================================================

/**
 * Search zones to find the UUID for a given zone ID
 * Throws OPNsenseError if zone not found
 */
async function getZoneUUID(config) {
  const response = await opnsenseFetch(
    `${config.url}/api/captiveportal/settings/search_zones`,
    { method: 'POST' },
    config
  );

  if (!response.ok) {
    throw new OPNsenseError(
      `Failed to search zones: HTTP ${response.status}`,
      ErrorCodes.ZONE_NOT_FOUND,
      { status: response.status }
    );
  }

  const data = await response.json();
  
  // Find zone with matching zoneid
  const zone = data.rows?.find(z => z.zoneid === config.zoneId);
  if (!zone) {
    throw new OPNsenseError(
      `Zone with ID "${config.zoneId}" not found. Available zones: ${data.rows?.map(z => z.zoneid).join(', ') || 'none'}`,
      ErrorCodes.ZONE_NOT_FOUND,
      { zoneId: config.zoneId, availableZones: data.rows?.map(z => z.zoneid) || [] }
    );
  }

  return zone.uuid;
}

/**
 * Get zone configuration by UUID
 * Throws OPNsenseError if config cannot be retrieved
 */
async function getZoneConfig(config, zoneUUID) {
  const response = await opnsenseFetch(
    `${config.url}/api/captiveportal/settings/get_zone/${zoneUUID}`,
    { method: 'GET' },
    config
  );

  if (!response.ok) {
    throw new OPNsenseError(
      `Failed to get zone config: HTTP ${response.status}`,
      ErrorCodes.ZONE_CONFIG_FAILED,
      { status: response.status, zoneUUID }
    );
  }

  const zoneConfig = await response.json();
  
  if (!zoneConfig || !zoneConfig.zone) {
    throw new OPNsenseError(
      'Invalid zone config response from OPNsense',
      ErrorCodes.ZONE_CONFIG_FAILED,
      { zoneUUID }
    );
  }

  return zoneConfig;
}

/**
 * Update zone configuration
 * Throws OPNsenseError if update fails
 */
async function updateZoneConfig(config, zoneUUID, payload) {
  const response = await opnsenseFetch(
    `${config.url}/api/captiveportal/settings/set_zone/${zoneUUID}`,
    { 
      method: 'POST',
      body: JSON.stringify(payload)
    },
    config
  );

  if (!response.ok) {
    const text = await response.text();
    throw new OPNsenseError(
      `Failed to update zone config: HTTP ${response.status}`,
      ErrorCodes.UPDATE_FAILED,
      { status: response.status, response: text, zoneUUID }
    );
  }

  const result = await response.json();
  
  // Check for validation errors
  if (result.validations && Object.keys(result.validations).length > 0) {
    throw new OPNsenseError(
      `Zone config validation failed: ${JSON.stringify(result.validations)}`,
      ErrorCodes.UPDATE_FAILED,
      { validations: result.validations }
    );
  }

  return true;
}

/**
 * Reconfigure captive portal to apply changes
 * Throws OPNsenseError if reconfigure fails
 */
async function reconfigureCaptivePortal(config) {
  const response = await opnsenseFetch(
    `${config.url}/api/captiveportal/service/reconfigure`,
    { method: 'POST' },
    config
  );

  if (!response.ok) {
    throw new OPNsenseError(
      `Failed to reconfigure captive portal: HTTP ${response.status}`,
      ErrorCodes.RECONFIGURE_FAILED,
      { status: response.status }
    );
  }

  const result = await response.json();
  
  if (result.status !== 'ok') {
    throw new OPNsenseError(
      `Captive portal reconfigure returned error: ${JSON.stringify(result)}`,
      ErrorCodes.RECONFIGURE_FAILED,
      { result }
    );
  }

  console.log('Captive portal reconfigured successfully');
  return true;
}

// ============================================================================
// MAC WHITELIST FUNCTIONS
// ============================================================================

/**
 * Add MAC address to OPNsense captive portal whitelist
 * Uses locking to prevent race conditions
 * 
 * Returns: { success: true } or throws OPNsenseError
 * Special case: returns { success: true, alreadyExists: true } if MAC already whitelisted
 */
async function allowMacInOPNsense(mac) {
  const config = getOPNsenseConfig();
  const content_config = getOPNsenseConfig(true);
  
  if (!config.enabled) {
    console.log('OPNsense API not configured - skipping MAC whitelist');
    return { success: true, skipped: true };
  }

  const normalizedMac = normalizeMacAddress(mac);
  if (!normalizedMac) {
    throw new OPNsenseError(
      `Invalid MAC address: ${mac}`,
      ErrorCodes.INVALID_MAC,
      { mac }
    );
  }

  console.log(`Adding MAC ${normalizedMac} to OPNsense whitelist...`);

  return opnsenseLock.withLock(async () => {
    // Step 1: Get zone UUID
    console.log('Step 1: Getting zone UUID...');
    const zoneUUID = await getZoneUUID(config);
    console.log(`Found zone UUID: ${zoneUUID}`);

    // Step 2: Get current zone config
    console.log('Step 2: Getting zone config...');
    const zoneConfig = await getZoneConfig(config, zoneUUID);

    // Step 3: Extract current MACs
    const currentMacs = extractMacAddresses(zoneConfig);
    console.log('Current whitelisted MACs:', currentMacs);

    // Step 4: Check if MAC already exists (not an error, just skip)
    if (currentMacs.includes(normalizedMac)) {
      console.log(`MAC ${normalizedMac} already whitelisted`);
      return { success: true, alreadyExists: true };
    }

    // Step 5: Add new MAC to list
    const newMacList = [...currentMacs, normalizedMac];
    console.log('New MAC list:', newMacList);

    // Step 6: Build and send update payload
    console.log('Step 6: Updating zone config...');
    const payload = buildZoneUpdatePayload(zoneConfig, newMacList);
    await updateZoneConfig(content_config, zoneUUID, payload);

    // Step 7: Reconfigure captive portal
    console.log('Step 7: Reconfiguring captive portal...');
    await reconfigureCaptivePortal(config);

    console.log(`Successfully added MAC ${normalizedMac} to whitelist`);
    return { success: true };
  });
}

/**
 * Remove MAC address from OPNsense captive portal whitelist
 * Uses locking to prevent race conditions
 * 
 * Returns: { success: true } or throws OPNsenseError
 * Special case: returns { success: true, notFound: true } if MAC not in whitelist
 */
async function revokeMacInOPNsense(mac) {
  const config = getOPNsenseConfig();
  const content_config = getOPNsenseConfig(true);
  
  if (!config.enabled) {
    console.log('OPNsense API not configured - skipping MAC removal');
    return { success: true, skipped: true };
  }

  const normalizedMac = normalizeMacAddress(mac);
  if (!normalizedMac) {
    throw new OPNsenseError(
      `Invalid MAC address: ${mac}`,
      ErrorCodes.INVALID_MAC,
      { mac }
    );
  }

  console.log(`Removing MAC ${normalizedMac} from OPNsense whitelist...`);

  return opnsenseLock.withLock(async () => {
    // Step 1: Get zone UUID
    console.log('Step 1: Getting zone UUID...');
    const zoneUUID = await getZoneUUID(config);
    console.log(`Found zone UUID: ${zoneUUID}`);

    // Step 2: Get current zone config
    console.log('Step 2: Getting zone config...');
    const zoneConfig = await getZoneConfig(config, zoneUUID);

    // Step 3: Extract current MACs
    const currentMacs = extractMacAddresses(zoneConfig);
    console.log('Current whitelisted MACs:', currentMacs);

    // Step 4: Check if MAC exists (not an error if missing, just skip)
    if (!currentMacs.includes(normalizedMac)) {
      console.log(`MAC ${normalizedMac} not in whitelist`);
      return { success: true, notFound: true };
    }

    // Step 5: Remove MAC from list
    const newMacList = currentMacs.filter(m => m !== normalizedMac);
    console.log('New MAC list:', newMacList);

    // Step 6: Build and send update payload
    console.log('Step 6: Updating zone config...');
    const payload = buildZoneUpdatePayload(zoneConfig, newMacList);
    await updateZoneConfig(content_config, zoneUUID, payload);

    // Step 7: Reconfigure captive portal
    console.log('Step 7: Reconfiguring captive portal...');
    await reconfigureCaptivePortal(config);

    console.log(`Successfully removed MAC ${normalizedMac} from whitelist`);
    return { success: true };
  });
}

/**
 * Get list of whitelisted MACs from OPNsense
 * Returns { success: true, macs: [...] } or throws OPNsenseError
 */
async function getWhitelistedMacs() {
  const config = getOPNsenseConfig();
  
  if (!config.enabled) {
    return { success: true, macs: [], skipped: true };
  }

  console.log('Fetching whitelisted MACs from OPNsense...');
  
  // Step 1: Get zone UUID
  const zoneUUID = await getZoneUUID(config);
  
  // Step 2: Get zone config
  const zoneConfig = await getZoneConfig(config, zoneUUID);
  
  // Step 3: Extract MACs
  const macs = extractMacAddresses(zoneConfig);
  
  console.log(`Found ${macs.length} whitelisted MACs in OPNsense`);
  return { success: true, macs };
}

// ============================================================================
// ARP TABLE POLLING FOR PRESENCE DETECTION
// ============================================================================

/**
 * Get ARP table from OPNsense to check which MACs are currently online
 * Uses the diagnostics API: /api/diagnostics/interface/getArp
 * Returns array of online MAC addresses (normalized to uppercase with colons)
 */
async function getArpTable() {
  const config = getOPNsenseConfig();
  
  if (!config.enabled) {
    return [];
  }

  try {
    const response = await opnsenseFetch(
      `${config.url}/api/diagnostics/interface/getArp`,
      { method: 'GET' },
      config
    );

    if (!response.ok) {
      console.error('Failed to get ARP table:', response.status);
      return [];
    }

    const data = await response.json();
    
    // OPNsense returns ARP entries in data.arp array
    // Each entry has: mac, ip, intf, expired, permanent, etc.
    const arpEntries = data.rows || data.arp || data;
    
    // Extract and normalize MAC addresses that are not expired
    const onlineMacs = [];
    for (const entry of arpEntries) {
      if (entry.mac && entry.expired !== '1' && entry.expired !== true) {
        const normalized = normalizeMacAddress(entry.mac);
        if (normalized) {
          onlineMacs.push(normalized);
        }
      }
    }
    
    return onlineMacs;
  } catch (error) {
    console.error('Error getting ARP table:', error);
    return [];
  }
}

/**
 * Check if a specific MAC address is online (in ARP table)
 */
async function isMacOnline(mac) {
  const normalizedMac = normalizeMacAddress(mac);
  if (!normalizedMac) return false;
  
  const onlineMacs = await getArpTable();
  return onlineMacs.includes(normalizedMac);
}

/**
 * Check which MACs from a list are currently online
 * Returns object: { [mac]: boolean }
 */
async function checkMacsOnline(macs) {
  const onlineMacs = await getArpTable();
  const onlineSet = new Set(onlineMacs);
  
  const result = {};
  for (const mac of macs) {
    const normalized = normalizeMacAddress(mac);
    if (normalized) {
      result[normalized] = onlineSet.has(normalized);
    }
  }
  
  return result;
}

module.exports = {
  OPNsenseError,
  ErrorCodes,
  getOPNsenseConfig,
  normalizeMacAddress,
  allowMacInOPNsense,
  revokeMacInOPNsense,
  getWhitelistedMacs,
  opnsenseFetch,
  getArpTable,
  isMacOnline,
  checkMacsOnline
};
