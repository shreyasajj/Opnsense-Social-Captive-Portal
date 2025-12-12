/**
 * CardDAV Integration Module
 * Handles Nextcloud/CardDAV contact verification and management
 */

const ICAL = require('ical.js');
const xml2js = require('xml2js');
const { v4: uuidv4 } = require('uuid');

// ============================================================================
// CUSTOM ERROR CLASS
// ============================================================================

class CardDAVError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'CardDAVError';
    this.code = code;
    this.details = details;
  }
}

// Error codes
const CardDAVErrorCodes = {
  NOT_CONFIGURED: 'NOT_CONFIGURED',
  CONNECTION_FAILED: 'CONNECTION_FAILED',
  AUTH_FAILED: 'AUTH_FAILED',
  NOT_FOUND: 'NOT_FOUND',
  UPDATE_FAILED: 'UPDATE_FAILED',
  CREATE_FAILED: 'CREATE_FAILED',
  PARSE_ERROR: 'PARSE_ERROR'
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Normalize phone number - remove all non-digits except +, return last 10 digits
 */
function normalizePhone(phone) {
  if (!phone) return null;
  const cleaned = phone.replace(/[^0-9+]/g, '');
  return cleaned.slice(-10);
}

/**
 * Normalize birthdate to YYYYMMDD format
 */
function normalizeBirthdate(birthdate) {
  if (!birthdate) return null;
  // Remove dashes, T, Z, colons and take first 8 characters
  return birthdate.replace(/[-T:Z]/g, '').substring(0, 8);
}

/**
 * Format birthdate for CardDAV (YYYY-MM-DD)
 */
function formatBirthdateForCardDAV(birthdate) {
  if (!birthdate) return null;
  const normalized = normalizeBirthdate(birthdate);
  if (normalized.length >= 8) {
    return `${normalized.substring(0, 4)}-${normalized.substring(4, 6)}-${normalized.substring(6, 8)}`;
  }
  return birthdate;
}

// ============================================================================
// CARDDAV CONFIGURATION
// ============================================================================

function getCardDAVConfig() {
  return {
    url: process.env.CARDDAV_URL,
    username: process.env.CARDDAV_USERNAME,
    password: process.env.CARDDAV_PASSWORD,
    enabled: !!(process.env.CARDDAV_URL && process.env.CARDDAV_USERNAME && process.env.CARDDAV_PASSWORD)
  };
}

// ============================================================================
// CARDDAV FUNCTIONS
// ============================================================================

/**
 * Search CardDAV for a contact with matching phone and birthdate
 */
async function searchCardDAV(phone, birthdate) {
  const config = getCardDAVConfig();

  console.log('CardDAV Config:', { 
    url: config.url, 
    username: config.username,
    hasPassword: !!config.password 
  });

  if (!config.enabled) {
    console.error('CardDAV not configured');
    return null;
  }

  const normalizedPhone = normalizePhone(phone);
  const normalizedBirthdate = normalizeBirthdate(birthdate);

  if (!normalizedPhone || !normalizedBirthdate) {
    return null;
  }

  // Ensure URL ends with /
  const url = config.url.endsWith('/') ? config.url : config.url + '/';
  
  console.log('CardDAV Request URL:', url);

  // CardDAV REPORT request to get all contacts
  const reportXml = `<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag/>
    <C:address-data/>
  </D:prop>
</C:addressbook-query>`;

  try {
    const response = await fetch(url, {
      method: 'REPORT',
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'Depth': '1',
        'Authorization': 'Basic ' + Buffer.from(`${config.username}:${config.password}`).toString('base64')
      },
      body: reportXml
    });

    console.log('CardDAV Response:', response.status, response.statusText);

    if (!response.ok) {
      const errorBody = await response.text();
      console.error('CardDAV request failed:', response.status, response.statusText);
      console.error('Error body:', errorBody.substring(0, 500));
      return null;
    }

    const xmlData = await response.text();
    const parser = new xml2js.Parser({ explicitArray: false, ignoreAttrs: false });
    const result = await parser.parseStringPromise(xmlData);

    // Navigate the response structure
    const responses = result?.['d:multistatus']?.['d:response'] || 
                     result?.['D:multistatus']?.['D:response'] ||
                     result?.multistatus?.response || [];
    
    const responseArray = Array.isArray(responses) ? responses : [responses];

    for (const resp of responseArray) {
      const addressData = resp?.['d:propstat']?.['d:prop']?.['card:address-data'] ||
                         resp?.['D:propstat']?.['D:prop']?.['card:address-data'] ||
                         resp?.propstat?.prop?.['address-data'] ||
                         resp?.['d:propstat']?.['d:prop']?.['C:address-data'] ||
                         resp?.['D:propstat']?.['D:prop']?.['C:address-data'];
      
      let vcardData = typeof addressData === 'string' ? addressData : addressData?._ || addressData;
      
      if (!vcardData || typeof vcardData !== 'string') continue;

      try {
        const jcard = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcard);
        
        // Get phone numbers
        const telProps = vcard.getAllProperties('tel');
        let phoneMatch = false;
        
        for (const tel of telProps) {
          const telValue = tel.getFirstValue();
          const normalizedTel = normalizePhone(telValue);
          if (normalizedTel === normalizedPhone) {
            phoneMatch = true;
            break;
          }
        }

        if (!phoneMatch) continue;

        // Check birthdate
        const bdayProp = vcard.getFirstProperty('bday');
        if (bdayProp) {
          const bdayValue = bdayProp.getFirstValue();
          let bdayStr = '';
          
          if (typeof bdayValue === 'object' && bdayValue.toICALString) {
            bdayStr = bdayValue.toICALString();
          } else {
            bdayStr = String(bdayValue);
          }
          
          const normalizedBday = normalizeBirthdate(bdayStr);
          
          if (normalizedBday === normalizedBirthdate) {
            // Found matching contact
            const fnProp = vcard.getFirstProperty('fn');
            const name = fnProp ? fnProp.getFirstValue() : 'Unknown';
            return { name, phone: normalizedPhone, birthdate: normalizedBirthdate };
          }
        }
      } catch (parseError) {
        console.error('Error parsing vCard:', parseError);
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV search error:', error);
    return null;
  }
}

/**
 * Search CardDAV for contact by name
 */
async function searchCardDAVByName(name) {
  const config = getCardDAVConfig();

  if (!config.enabled || !name) {
    return null;
  }

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    // Fetch all contacts
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
      <c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
        <d:prop>
          <d:getetag/>
          <c:address-data/>
        </d:prop>
      </c:addressbook-query>`;

    const response = await fetch(config.url, {
      method: 'REPORT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/xml',
        'Depth': '1'
      },
      body: reportBody
    });

    if (!response.ok) {
      return null;
    }

    const xmlText = await response.text();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlText);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                      result?.['multistatus']?.['response'] || [];

    const normalizedSearchName = name.toLowerCase().trim();

    for (const item of responses) {
      const propstat = item['d:propstat']?.[0] || item['propstat']?.[0];
      const addressData = propstat?.['d:prop']?.[0]?.['c:address-data']?.[0] || 
                          propstat?.['prop']?.[0]?.['address-data']?.[0]||
                          propstat?.['d:prop']?.[0]?.['card:address-data']?.[0];

      if (!addressData) continue;

      try {
        const vcardData = typeof addressData === 'string' ? addressData : addressData._;
        if (!vcardData) continue;

        const jcalData = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcalData);
        
        const fnProp = vcard.getFirstProperty('fn');
        if (!fnProp) continue;
        
        const contactName = fnProp.getFirstValue();
        if (!contactName) continue;
        
        // Check if name matches (case insensitive)
        if (contactName.toLowerCase().trim() === normalizedSearchName) {
          const uidProp = vcard.getFirstProperty('uid');
          return { 
            name: contactName, 
            uid: uidProp ? uidProp.getFirstValue() : null 
          };
        }
      } catch (parseError) {
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV name search error:', error);
    return null;
  }
}

/**
 * Search CardDAV for contact by phone number
 */
async function searchCardDAVByPhone(phone) {
  const config = getCardDAVConfig();

  if (!config.enabled || !phone) {
    return null;
  }

  const normalizedSearchPhone = normalizePhone(phone);
  if (!normalizedSearchPhone) return null;

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
      <c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
        <d:prop>
          <d:getetag/>
          <c:address-data/>
        </d:prop>
      </c:addressbook-query>`;

    const response = await fetch(config.url, {
      method: 'REPORT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/xml',
        'Depth': '1'
      },
      body: reportBody
    });

    if (!response.ok) return null;

    const xmlText = await response.text();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlText);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                      result?.['multistatus']?.['response'] || [];

    for (const item of responses) {
      const propstat = item['d:propstat']?.[0] || item['propstat']?.[0];
      const addressData = propstat?.['d:prop']?.[0]?.['c:address-data']?.[0] || 
                          propstat?.['prop']?.[0]?.['address-data']?.[0]||
                          propstat?.['d:prop']?.[0]?.['card:address-data']?.[0];

      if (!addressData) continue;

      try {
        const vcardData = typeof addressData === 'string' ? addressData : addressData._;
        if (!vcardData) continue;

        const jcalData = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcalData);
        
        // Get phone numbers
        const telProps = vcard.getAllProperties('tel');
        for (const telProp of telProps) {
          const telValue = telProp.getFirstValue();
          const contactPhone = normalizePhone(telValue);
          
          if (contactPhone === normalizedSearchPhone) {
            const fnProp = vcard.getFirstProperty('fn');
            const uidProp = vcard.getFirstProperty('uid');
            const href = item['d:href']?.[0] || item['href']?.[0];
            
            return { 
              name: fnProp ? fnProp.getFirstValue() : 'Unknown',
              uid: uidProp ? uidProp.getFirstValue() : null,
              href: href
            };
          }
        }
      } catch (parseError) {
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV phone search error:', error);
    return null;
  }
}

/**
 * Update a contact's birthdate in CardDAV
 */
async function updateCardDAVContactBirthdate(uid, birthdate) {
  const config = getCardDAVConfig();

  if (!config.enabled || !uid || !birthdate) {
    return false;
  }

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    const contactUrl = config.url.replace(/\/$/, '') + `/${uid}.vcf`;

    // First, fetch the existing contact
    const getResponse = await fetch(contactUrl, {
      method: 'GET',
      headers: {
        'Authorization': `Basic ${auth}`
      }
    });

    if (!getResponse.ok) {
      console.error('Failed to fetch contact for update');
      return false;
    }

    let vcardText = await getResponse.text();
    const formattedBirthdate = formatBirthdateForCardDAV(birthdate);

    // Update or add BDAY field
    if (vcardText.includes('BDAY:')) {
      vcardText = vcardText.replace(/BDAY:[^\r\n]+/, `BDAY:${formattedBirthdate}`);
    } else {
      // Add BDAY before END:VCARD
      vcardText = vcardText.replace('END:VCARD', `BDAY:${formattedBirthdate}\r\nEND:VCARD`);
    }

    // Update the contact
    const putResponse = await fetch(contactUrl, {
      method: 'PUT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'text/vcard; charset=utf-8'
      },
      body: vcardText
    });

    return putResponse.ok || putResponse.status === 204;
  } catch (error) {
    console.error('CardDAV update birthdate error:', error);
    return false;
  }
}

/**
 * Create a new contact in CardDAV
 */
async function createCardDAVContact(name, phone, birthdate) {
  const config = getCardDAVConfig();

  if (!config.enabled) {
    return false;
  }

  const uid = uuidv4();
  const formattedBirthdate = birthdate ? formatBirthdateForCardDAV(birthdate) : '';
  const formattedPhone = phone ? phone.replace(/[^0-9+]/g, '') : '';

  let vcard = `BEGIN:VCARD\r\nVERSION:3.0\r\nUID:${uid}\r\nFN:${name}\r\n`;
  if (formattedPhone) vcard += `TEL;TYPE=CELL:${formattedPhone}\r\n`;
  if (formattedBirthdate) vcard += `BDAY:${formattedBirthdate}\r\n`;
  vcard += `END:VCARD`;

  const contactUrl = config.url.replace(/\/$/, '') + `/${uid}.vcf`;

  try {
    const response = await fetch(contactUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': 'text/vcard; charset=utf-8',
        'Authorization': 'Basic ' + Buffer.from(`${config.username}:${config.password}`).toString('base64')
      },
      body: vcard
    });

    return response.ok || response.status === 201;
  } catch (error) {
    console.error('CardDAV create contact error:', error);
    return false;
  }
}

/**
 * Create or update a contact in CardDAV (legacy function)
 */
async function createOrUpdateCardDAVContact(name, phone, birthdate) {
  const config = getCardDAVConfig();

  if (!config.enabled) {
    console.error('CardDAV not configured');
    return false;
  }

  if (!phone || !birthdate) {
    return false;
  }

  const uid = uuidv4();
  const formattedBirthdate = formatBirthdateForCardDAV(birthdate);
  const formattedPhone = phone.replace(/[^0-9+]/g, '');

  const vcard = `BEGIN:VCARD
VERSION:3.0
UID:${uid}
FN:${name}
TEL;TYPE=CELL:${formattedPhone}
BDAY:${formattedBirthdate}
END:VCARD`;

  const contactUrl = config.url.replace(/\/$/, '') + `/${uid}.vcf`;

  try {
    const response = await fetch(contactUrl, {
      method: 'PUT',
      headers: {
        'Content-Type': 'text/vcard; charset=utf-8',
        'Authorization': 'Basic ' + Buffer.from(`${config.username}:${config.password}`).toString('base64')
      },
      body: vcard
    });

    if (response.ok || response.status === 201) {
      console.log('Contact created successfully');
      return true;
    } else {
      console.error('Failed to create contact:', response.status, response.statusText);
      return false;
    }
  } catch (error) {
    console.error('CardDAV create contact error:', error);
    return false;
  }
}

/**
 * Get full contact details including photo from CardDAV by phone/birthdate match
 * Returns { name, phone, birthdate, photo (base64), photoMimeType }
 */
async function getContactWithPhoto(phone, birthdate) {
  const config = getCardDAVConfig();

  if (!config.enabled) {
    return null;
  }

  const normalizedPhone = normalizePhone(phone);
  const normalizedBirthdate = normalizeBirthdate(birthdate);

  if (!normalizedPhone || !normalizedBirthdate) {
    return null;
  }

  const url = config.url.endsWith('/') ? config.url : config.url + '/';

  const reportXml = `<?xml version="1.0" encoding="utf-8" ?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop>
    <D:getetag/>
    <C:address-data/>
  </D:prop>
</C:addressbook-query>`;

  try {
    const response = await fetch(url, {
      method: 'REPORT',
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'Depth': '1',
        'Authorization': 'Basic ' + Buffer.from(`${config.username}:${config.password}`).toString('base64')
      },
      body: reportXml
    });

    if (!response.ok) {
      return null;
    }

    const xmlData = await response.text();
    const parser = new xml2js.Parser({ explicitArray: false, ignoreAttrs: false });
    const result = await parser.parseStringPromise(xmlData);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                     result?.['D:multistatus']?.['D:response'] ||
                     result?.multistatus?.response || [];
    
    const responseArray = Array.isArray(responses) ? responses : [responses];

    for (const resp of responseArray) {
      const addressData = resp?.['d:propstat']?.['d:prop']?.['card:address-data'] ||
                         resp?.['D:propstat']?.['D:prop']?.['card:address-data'] ||
                         resp?.propstat?.prop?.['address-data'] ||
                         resp?.['d:propstat']?.['d:prop']?.['C:address-data'] ||
                         resp?.['D:propstat']?.['D:prop']?.['C:address-data'];
      
      let vcardData = typeof addressData === 'string' ? addressData : addressData?._ || addressData;
      
      if (!vcardData || typeof vcardData !== 'string') continue;

      try {
        const jcard = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcard);
        
        // Get phone numbers
        const telProps = vcard.getAllProperties('tel');
        let phoneMatch = false;
        
        for (const tel of telProps) {
          const telValue = tel.getFirstValue();
          const normalizedTel = normalizePhone(telValue);
          if (normalizedTel === normalizedPhone) {
            phoneMatch = true;
            break;
          }
        }

        if (!phoneMatch) continue;

        // Check birthdate
        const bdayProp = vcard.getFirstProperty('bday');
        if (bdayProp) {
          const bdayValue = bdayProp.getFirstValue();
          let bdayStr = '';
          
          if (typeof bdayValue === 'object' && bdayValue.toICALString) {
            bdayStr = bdayValue.toICALString();
          } else {
            bdayStr = String(bdayValue);
          }
          
          const normalizedBday = normalizeBirthdate(bdayStr);
          
          if (normalizedBday === normalizedBirthdate) {
            // Found matching contact - get all details
            const fnProp = vcard.getFirstProperty('fn');
            const name = fnProp ? fnProp.getFirstValue() : 'Unknown';
            
            // Get photo
            let photo = null;
            let photoMimeType = null;
            const photoProp = vcard.getFirstProperty('photo');
            
            if (photoProp) {
              const photoValue = photoProp.getFirstValue();
              // Photo can be base64 encoded or a URL
              if (photoValue) {
                // Check if it's already base64 or needs to be extracted
                if (typeof photoValue === 'string') {
                  // Check for data URI or direct base64
                  if (photoValue.startsWith('data:')) {
                    const match = photoValue.match(/^data:(image\/[^;]+);base64,(.+)$/);
                    if (match) {
                      photoMimeType = match[1];
                      photo = match[2];
                    }
                  } else if (!photoValue.startsWith('http')) {
                    // Assume it's raw base64
                    photo = photoValue;
                    // Try to get type from parameter
                    const typeParam = photoProp.getParameter('type');
                    if (typeParam) {
                      const types = Array.isArray(typeParam) ? typeParam : [typeParam];
                      const imgType = types.find(t => t.toLowerCase().match(/jpeg|png|gif/));
                      photoMimeType = imgType ? `image/${imgType.toLowerCase()}` : 'image/jpeg';
                    } else {
                      photoMimeType = 'image/jpeg';
                    }
                  }
                }
              }
            }
            
            return { 
              name, 
              phone: normalizedPhone, 
              birthdate: normalizedBirthdate,
              photo,
              photoMimeType
            };
          }
        }
      } catch (parseError) {
        console.error('Error parsing vCard for photo:', parseError);
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV search with photo error:', error);
    return null;
  }
}

/**
 * Get full contact details by name including photo
 * Used for Google OAuth flow to check if person exists in CardDAV
 */
async function getContactByNameWithDetails(name) {
  const config = getCardDAVConfig();

  if (!config.enabled || !name) {
    return null;
  }

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
      <c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
        <d:prop>
          <d:getetag/>
          <c:address-data/>
        </d:prop>
      </c:addressbook-query>`;

    const response = await fetch(config.url, {
      method: 'REPORT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/xml',
        'Depth': '1'
      },
      body: reportBody
    });

    if (!response.ok) {
      return null;
    }

    const xmlText = await response.text();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlText);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                      result?.['multistatus']?.['response'] || [];

    const normalizedSearchName = name.toLowerCase().trim();

    for (const item of responses) {
      const propstat = item['d:propstat']?.[0] || item['propstat']?.[0];
      const addressData = propstat?.['d:prop']?.[0]?.['c:address-data']?.[0] || 
                          propstat?.['prop']?.[0]?.['address-data']?.[0]||
                          propstat?.['d:prop']?.[0]?.['card:address-data']?.[0];

      if (!addressData) continue;

      try {
        const vcardData = typeof addressData === 'string' ? addressData : addressData._;
        if (!vcardData) continue;

        const jcalData = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcalData);
        
        const fnProp = vcard.getFirstProperty('fn');
        if (!fnProp) continue;
        
        const contactName = fnProp.getFirstValue();
        if (!contactName) continue;
        
        // Check if name matches (case insensitive)
        if (contactName.toLowerCase().trim() === normalizedSearchName) {
          const uidProp = vcard.getFirstProperty('uid');
          
          // Get phone
          let phone = null;
          const telProps = vcard.getAllProperties('tel');
          if (telProps.length > 0) {
            phone = normalizePhone(telProps[0].getFirstValue());
          }
          
          // Get birthdate
          let birthdate = null;
          const bdayProp = vcard.getFirstProperty('bday');
          if (bdayProp) {
            const bdayValue = bdayProp.getFirstValue();
            if (typeof bdayValue === 'object' && bdayValue.toICALString) {
              birthdate = bdayValue.toICALString();
            } else {
              birthdate = String(bdayValue);
            }
          }
          
          // Get photo
          let photo = null;
          let photoMimeType = null;
          const photoProp = vcard.getFirstProperty('photo');
          if (photoProp) {
            const photoValue = photoProp.getFirstValue();
            if (photoValue && typeof photoValue === 'string') {
              if (photoValue.startsWith('data:')) {
                const match = photoValue.match(/^data:(image\/[^;]+);base64,(.+)$/);
                if (match) {
                  photoMimeType = match[1];
                  photo = match[2];
                }
              } else if (!photoValue.startsWith('http')) {
                photo = photoValue;
                const typeParam = photoProp.getParameter('type');
                if (typeParam) {
                  const types = Array.isArray(typeParam) ? typeParam : [typeParam];
                  const imgType = types.find(t => t.toLowerCase().match(/jpeg|png|gif/));
                  photoMimeType = imgType ? `image/${imgType.toLowerCase()}` : 'image/jpeg';
                } else {
                  photoMimeType = 'image/jpeg';
                }
              }
            }
          }
          
          return { 
            name: contactName, 
            uid: uidProp ? uidProp.getFirstValue() : null,
            phone,
            birthdate: birthdate ? normalizeBirthdate(birthdate) : null,
            birthdateFormatted: birthdate ? formatBirthdateForCardDAV(birthdate) : null,
            photo,
            photoMimeType
          };
        }
      } catch (parseError) {
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV name search with details error:', error);
    return null;
  }
}

/**
 * Get contact details by phone number (with photo)
 */
async function getContactByPhoneWithDetails(phone) {
  const config = getCardDAVConfig();

  if (!config.enabled || !phone) {
    return null;
  }

  const normalizedSearchPhone = normalizePhone(phone);
  if (!normalizedSearchPhone) return null;

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
      <c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
        <d:prop>
          <d:getetag/>
          <c:address-data/>
        </d:prop>
      </c:addressbook-query>`;

    const response = await fetch(config.url, {
      method: 'REPORT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/xml',
        'Depth': '1'
      },
      body: reportBody
    });

    if (!response.ok) return null;

    const xmlText = await response.text();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlText);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                      result?.['multistatus']?.['response'] || [];

    for (const item of responses) {
      const propstat = item['d:propstat']?.[0] || item['propstat']?.[0];
      const addressData = propstat?.['d:prop']?.[0]?.['c:address-data']?.[0] || 
                          propstat?.['prop']?.[0]?.['address-data']?.[0]||
                          propstat?.['d:prop']?.[0]?.['card:address-data']?.[0];

      if (!addressData) continue;

      try {
        const vcardData = typeof addressData === 'string' ? addressData : addressData._;
        if (!vcardData) continue;

        const jcalData = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcalData);
        
        // Check all phone numbers
        const telProps = vcard.getAllProperties('tel');
        let phoneMatch = false;
        for (const telProp of telProps) {
          const telValue = telProp.getFirstValue();
          const contactPhone = normalizePhone(telValue);
          if (contactPhone === normalizedSearchPhone) {
            phoneMatch = true;
            break;
          }
        }
        
        if (!phoneMatch) continue;
        
        // Found matching contact
        const fnProp = vcard.getFirstProperty('fn');
        const uidProp = vcard.getFirstProperty('uid');
        
        // Get birthdate
        let birthdate = null;
        const bdayProp = vcard.getFirstProperty('bday');
        if (bdayProp) {
          const bdayValue = bdayProp.getFirstValue();
          if (typeof bdayValue === 'object' && bdayValue.toICALString) {
            birthdate = bdayValue.toICALString();
          } else {
            birthdate = String(bdayValue);
          }
        }
        
        // Get photo
        let photo = null;
        let photoMimeType = null;
        const photoProp = vcard.getFirstProperty('photo');
        if (photoProp) {
          const photoValue = photoProp.getFirstValue();
          if (photoValue && typeof photoValue === 'string') {
            if (photoValue.startsWith('data:')) {
              const match = photoValue.match(/^data:(image\/[^;]+);base64,(.+)$/);
              if (match) {
                photoMimeType = match[1];
                photo = match[2];
              }
            } else if (!photoValue.startsWith('http')) {
              photo = photoValue;
              const typeParam = photoProp.getParameter('type');
              if (typeParam) {
                const types = Array.isArray(typeParam) ? typeParam : [typeParam];
                const imgType = types.find(t => t.toLowerCase().match(/jpeg|png|gif/));
                photoMimeType = imgType ? `image/${imgType.toLowerCase()}` : 'image/jpeg';
              } else {
                photoMimeType = 'image/jpeg';
              }
            }
          }
        }
        
        return { 
          name: fnProp ? fnProp.getFirstValue() : 'Unknown',
          uid: uidProp ? uidProp.getFirstValue() : null,
          phone: normalizedSearchPhone,
          birthdate: birthdate ? normalizeBirthdate(birthdate) : null,
          birthdateFormatted: birthdate ? formatBirthdateForCardDAV(birthdate) : null,
          photo,
          photoMimeType
        };
      } catch (parseError) {
        continue;
      }
    }

    return null;
  } catch (error) {
    console.error('CardDAV phone search with details error:', error);
    return null;
  }
}

// ============================================================================
// FUZZY NAME MATCHING
// ============================================================================

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Calculate similarity score between two names (0-1, higher is better)
 */
function nameSimilarity(name1, name2) {
  if (!name1 || !name2) return 0;
  
  const n1 = name1.toLowerCase().trim();
  const n2 = name2.toLowerCase().trim();
  
  // Exact match
  if (n1 === n2) return 1;
  
  // Check if one contains the other (e.g., "Jag" matches "Jag Scrammer")
  if (n1.includes(n2) || n2.includes(n1)) {
    return 0.9;
  }
  
  // Check if first name matches
  const parts1 = n1.split(/\s+/);
  const parts2 = n2.split(/\s+/);
  if (parts1[0] === parts2[0]) {
    return 0.85;
  }
  
  // Check if any word in one name matches any word in the other
  for (const p1 of parts1) {
    for (const p2 of parts2) {
      if (p1 === p2 && p1.length > 2) {
        return 0.8;
      }
    }
  }
  
  // Levenshtein distance based similarity
  const maxLen = Math.max(n1.length, n2.length);
  const distance = levenshteinDistance(n1, n2);
  const similarity = 1 - (distance / maxLen);
  
  return similarity;
}

/**
 * Fuzzy search CardDAV for contacts matching a name
 * Returns array of matches sorted by similarity score
 */
async function fuzzySearchCardDAVByName(searchName, minSimilarity = 0.5) {
  const config = getCardDAVConfig();

  if (!config.enabled || !searchName) {
    return [];
  }

  try {
    const auth = Buffer.from(`${config.username}:${config.password}`).toString('base64');
    
    // Get all contacts
    const reportBody = `<?xml version="1.0" encoding="UTF-8"?>
      <c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
        <d:prop>
          <d:getetag/>
          <c:address-data/>
        </d:prop>
      </c:addressbook-query>`;

    const response = await fetch(config.url, {
      method: 'REPORT',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/xml',
        'Depth': '1'
      },
      body: reportBody
    });

    if (!response.ok) {
      return [];
    }

    const xmlText = await response.text();
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlText);

    const responses = result?.['d:multistatus']?.['d:response'] || 
                      result?.['multistatus']?.['response'] || [];

    const matches = [];

    for (const item of responses) {
      const propstat = item['d:propstat']?.[0] || item['propstat']?.[0];
      const addressData = propstat?.['d:prop']?.[0]?.['c:address-data']?.[0] || 
                          propstat?.['prop']?.[0]?.['address-data']?.[0]||
                          propstat?.['d:prop']?.[0]?.['card:address-data']?.[0];

      if (!addressData) continue;

      try {
        const vcardData = typeof addressData === 'string' ? addressData : addressData._;
        if (!vcardData) continue;

        const jcalData = ICAL.parse(vcardData);
        const vcard = new ICAL.Component(jcalData);
        
        const fnProp = vcard.getFirstProperty('fn');
        if (!fnProp) continue;
        
        const contactName = fnProp.getFirstValue();
        if (!contactName) continue;
        
        const similarity = nameSimilarity(searchName, contactName);
        
        if (similarity >= minSimilarity) {
          const uidProp = vcard.getFirstProperty('uid');
          
          // Get phone
          let phone = null;
          const telProps = vcard.getAllProperties('tel');
          if (telProps.length > 0) {
            phone = normalizePhone(telProps[0].getFirstValue());
          }
          
          // Get birthdate
          let birthdate = null;
          let birthdateRaw = null;
          const bdayProp = vcard.getFirstProperty('bday');
          if (bdayProp) {
            const bdayValue = bdayProp.getFirstValue();
            if (typeof bdayValue === 'object' && bdayValue.toICALString) {
              birthdateRaw = bdayValue.toICALString();
            } else {
              birthdateRaw = String(bdayValue);
            }
            birthdate = formatBirthdateForCardDAV(birthdateRaw);
          }
          
          // Get photo
          let photo = null;
          let photoMimeType = null;
          const photoProp = vcard.getFirstProperty('photo');
          if (photoProp) {
            const photoValue = photoProp.getFirstValue();
            if (photoValue && typeof photoValue === 'string') {
              if (photoValue.startsWith('data:')) {
                const match = photoValue.match(/^data:(image\/[^;]+);base64,(.+)$/);
                if (match) {
                  photoMimeType = match[1];
                  photo = match[2];
                }
              } else if (!photoValue.startsWith('http')) {
                photo = photoValue;
                const typeParam = photoProp.getParameter('type');
                if (typeParam) {
                  const types = Array.isArray(typeParam) ? typeParam : [typeParam];
                  const imgType = types.find(t => t.toLowerCase().match(/jpeg|png|gif/));
                  photoMimeType = imgType ? `image/${imgType.toLowerCase()}` : 'image/jpeg';
                } else {
                  photoMimeType = 'image/jpeg';
                }
              }
            }
          }
          
          matches.push({
            name: contactName,
            uid: uidProp ? uidProp.getFirstValue() : null,
            phone,
            birthdate,
            photo,
            photoMimeType,
            similarity
          });
        }
      } catch (parseError) {
        continue;
      }
    }

    // Sort by similarity (highest first)
    matches.sort((a, b) => b.similarity - a.similarity);
    
    return matches;
  } catch (error) {
    console.error('CardDAV fuzzy search error:', error);
    return [];
  }
}

/**
 * Find best matching contact by name using fuzzy search
 * Returns the best match if similarity is above threshold
 */
async function findBestMatchingContact(searchName, minSimilarity = 0.5) {
  const matches = await fuzzySearchCardDAVByName(searchName, minSimilarity);
  return matches.length > 0 ? matches[0] : null;
}

module.exports = {
  CardDAVError,
  CardDAVErrorCodes,
  normalizePhone,
  normalizeBirthdate,
  formatBirthdateForCardDAV,
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
  nameSimilarity
};
