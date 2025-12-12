# Captive Portal for OPNsense

A complete captive portal system with Google OAuth, Nextcloud CardDAV verification, and Home Assistant integration for WiFi access control and presence detection.

## Features

- **Two Authentication Methods:**
  - Google OAuth login with identity verification
  - Phone + Birthdate verification against Nextcloud contacts
  
- **Smart Identity Verification:**
  - Fuzzy name matching against CardDAV contacts
  - "Is this you?" confirmation flow for OAuth users
  - Exact phone match required for manual auth
  - Auto-approval for returning users with existing devices
  
- **Device Management:**
  - Device type selection (Phone, Laptop, Tablet, Other)
  - Phone devices are tracked for presence detection
  - One phone per person for presence tracking
  - MAC address whitelisting for persistent access
  
- **People Management:**
  - Automatic person creation from verified contacts
  - Multiple devices per person
  - Single approval covers all person's devices
  - Person deletion revokes all associated devices
  
- **Admin Dashboard:**
  - Real-time pending requests view
  - Approve/deny with one click
  - People management with device assignment
  - Unknown MACs from OPNsense tracking
  - Tracked device monitoring with online status
  
- **Session Management:**
  - Automatic session cleanup (configurable)
  - Session invalidation on person/device deletion
  - Cookie session destruction on revocation
  
- **Home Assistant Integration:**
  - Custom HACS-compatible integration
  - Configurable device offline timeout
  - Person presence sensors
  - Dynamic approve/deny buttons
  - Automation support for notifications

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│    OPNsense     │────▶│  Captive Portal  │────▶│ Home Assistant  │
│ (Firewall/WiFi) │     │   (Node.js)      │     │  (Automation)   │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │ Nextcloud CardDAV│
                        │   (Contacts)     │
                        └──────────────────┘
```

## Quick Start

### 1. Clone and Configure

```bash
git clone https://github.com/your-repo/captive-portal.git
cd captive-portal
cp .env.example .env
```

Edit `.env` with your configuration (see [Configuration](#configuration) below).

### 2. Start with Docker

```bash
docker-compose up -d
```

The portal will be available at `http://your-server:3000`

### 3. Configure OPNsense

See [OPNsense Configuration](#opnsense-configuration) below.

### 4. Install Home Assistant Integration

Copy the `custom_components/captive_portal` folder to your Home Assistant `config/custom_components/` directory and restart Home Assistant.

## Configuration

### Environment Variables

Create a `.env` file with the following:

```env
# Server
PORT=3000
SESSION_SECRET=your-random-32-character-string
DB_PATH=/app/data/captive_portal.db
NODE_ENV=production

# Google OAuth
GOOGLE_CLIENT_ID=your-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-secret
CALLBACK_URL=http://your-domain:3000/auth/google/callback

# Nextcloud CardDAV
CARDDAV_URL=https://nextcloud.example.com/remote.php/dav/addressbooks/users/admin/contacts/
CARDDAV_USERNAME=admin
CARDDAV_PASSWORD=your-app-password

# Home Assistant
HOME_ASSISTANT_URL=http://192.168.1.100:8123
HOME_ASSISTANT_TOKEN=your-long-lived-access-token

# OPNsense (Optional)
OPNSENSE_URL=https://192.168.1.1
OPNSENSE_API_KEY=your-api-key
OPNSENSE_API_SECRET=your-api-secret
OPNSENSE_ARP_POLL_INTERVAL=60  # seconds between ARP table polls

# Device Presence Detection
DEVICE_OFFLINE_TIMEOUT=30  # seconds - device considered offline after this

# Session Management
SESSION_TIMEOUT_REDIRECT=/  # where to redirect on session timeout
SUCCESS_REDIRECT_URL=       # optional - where to redirect after successful login (empty = stay on success page)
SESSION_PURGE_HOURS=24      # how often to run session cleanup
SESSION_MAX_AGE_HOURS=72    # delete sessions older than this
```

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the Google+ API
4. Go to **Credentials** → **Create Credentials** → **OAuth client ID**
5. Select **Web application**
6. Add authorized redirect URI: `http://your-domain:3000/auth/google/callback`
7. Copy the Client ID and Client Secret to your `.env` file

### Nextcloud CardDAV Setup

1. In Nextcloud, go to **Settings** → **Security** → **Devices & sessions**
2. Create a new app password
3. Use this password in your `.env` file

The CardDAV URL format is:
```
https://your-nextcloud.com/remote.php/dav/addressbooks/users/USERNAME/contacts/
```

### Home Assistant Long-Lived Token

1. Go to your Home Assistant profile
2. Scroll down to **Long-Lived Access Tokens**
3. Create a new token
4. Copy the token to your `.env` file

## OPNsense Configuration

### Captive Portal Setup

1. Go to **Services** → **Captive Portal** → **Administration**
2. Create a new zone or edit existing
3. Configure:
   - **Authentication**: None (handled by our portal)
   - **Landing Page**: Use one of the templates from `opnsense-templates/`
   - **Idle timeout**: As desired
   - **Hard timeout**: As desired

### Custom Portal Template

Copy one of the templates from `opnsense-templates/` to OPNsense:
- `captiveportal-redirect-minimal.html` - Simple redirect
- `captiveportal-redirect.html` - Styled redirect with loading indicator
- `captiveportal-secure.html` - Secure handoff with token exchange

### Walled Garden Configuration

**CRITICAL:** Only allow specific domains, NOT wildcards!

Go to **Services** → **Captive Portal** → **Allowed hostnames** and add:

```
# Google OAuth (specific domains only!)
accounts.google.com
oauth2.googleapis.com
www.gstatic.com
ssl.gstatic.com

# Your captive portal server
your-captive-portal.local

# DNS servers
1.1.1.1
8.8.8.8
```

⚠️ **WARNING:** Do NOT use wildcards like `*.google.com` - this would allow access to Gmail, YouTube, and other Google services before authentication!

### Allowed IP Addresses

Add your captive portal server's IP address to the allowed list.

## Home Assistant Integration

### Installation

1. Copy `custom_components/captive_portal/` to your Home Assistant `config/custom_components/` directory
2. Restart Home Assistant
3. Go to **Settings** → **Devices & Services** → **Add Integration**
4. Search for "Captive Portal"
5. Enter your captive portal server's IP and port

### Available Entities

**Binary Sensors:**
- `binary_sensor.captive_portal_approval_pending` - True when approval requests are pending

**Sensors:**
- `sensor.captive_portal_pending_requests` - Number of pending approval requests
- `sensor.captive_portal_approved_users` - Number of approved users
- `sensor.captive_portal_tracked_devices` - Number of tracked phones
- `sensor.captive_portal_people` - Number of people

**Device Trackers:**
- `device_tracker.<person_name>_phone` - One per person with a tracked phone

### Configuring Device Offline Timeout

The device offline timeout determines how long after a device stops responding it's considered offline. Default is 30 seconds.

**Via Environment Variable:**
```env
DEVICE_OFFLINE_TIMEOUT=30  # seconds
```

**Via Home Assistant REST Command:**
```yaml
rest_command:
  set_captive_portal_timeout:
    url: "http://your-captive-portal:3000/api/ha/config"
    method: POST
    headers:
      Content-Type: "application/json"
    payload: '{"device_offline_timeout": {{ timeout }}}'
```

**Via Automation:**
```yaml
automation:
  - alias: "Set shorter timeout during day"
    trigger:
      - platform: time
        at: "08:00:00"
    action:
      - service: rest_command.set_captive_portal_timeout
        data:
          timeout: 30
          
  - alias: "Set longer timeout at night"
    trigger:
      - platform: time
        at: "22:00:00"
    action:
      - service: rest_command.set_captive_portal_timeout
        data:
          timeout: 300  # 5 minutes
```

### Example Automation

```yaml
automation:
  - alias: "WiFi Access Request Notification"
    trigger:
      - platform: state
        entity_id: binary_sensor.captive_portal_approval_pending
        to: "on"
    action:
      - service: notify.mobile_app_your_phone
        data:
          title: "WiFi Access Request"
          message: "Someone wants to connect to WiFi"
          data:
            actions:
              - action: "OPEN_PORTAL_ADMIN"
                title: "Open Admin"
                uri: "http://your-captive-portal:3000/admin"
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/manual` | Phone + birthdate login |
| GET | `/auth/google` | Start Google OAuth flow |
| GET | `/auth/google/callback` | OAuth callback |
| POST | `/api/verify-identity` | Confirm CardDAV match (OAuth users) |
| POST | `/api/verify-manual` | Manual phone/birthdate verification |

### Session & Handoff

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/create-handoff-token` | Create secure handoff token |
| GET | `/handoff?token=xxx` | Exchange token for session |
| GET | `/api/session-info` | Get current session state |
| GET | `/api/approval-status` | Check approval status |

### Device & Approval

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/device-select` | Submit device type |
| POST | `/api/submit-contact-info` | Complete flow and whitelist |
| POST | `/api/admin/approve/:sessionId` | Approve request |
| POST | `/api/admin/deny/:sessionId` | Deny request |

### Whitelist & MAC

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/mac/check/:mac` | Check if MAC is whitelisted |
| POST | `/api/mac/heartbeat` | Update last_seen for MAC |
| DELETE | `/api/admin/whitelist/:mac` | Revoke access (invalidates sessions) |

### People Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/people` | List all people |
| GET | `/api/admin/people/:id` | Get person details |
| PUT | `/api/admin/people/:id` | Update person |
| DELETE | `/api/admin/people/:id` | Delete person (revokes all devices) |
| POST | `/api/admin/people/:targetId/merge/:sourceId` | Merge two people |
| POST | `/api/admin/devices/:mac/assign/:personId` | Reassign device |

### Admin Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/pending` | Get pending requests |
| GET | `/api/admin/authenticated` | Get approved users |
| GET | `/api/admin/rejected` | Get denied users |
| GET | `/api/admin/tracked-devices` | Get tracked phones |
| GET | `/api/admin/opnsense-macs` | Get unknown MACs from OPNsense |
| DELETE | `/api/admin/opnsense-macs/:mac` | Revoke unknown MAC |
| GET | `/api/admin/stats` | Get all stats |
| POST | `/api/admin/sync-opnsense` | Sync MACs from OPNsense |
| POST | `/api/admin/purge-sessions` | Manually purge old sessions |

### Home Assistant

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ha/status` | Full status for HA integration |
| GET | `/api/ha/approval-pending` | Lightweight approval check |
| GET | `/api/ha/people` | People with phone MACs |
| GET | `/api/ha/devices` | Tracked phone devices |
| GET | `/api/ha/pending` | Pending approval requests |
| GET | `/api/ha/person/:id/photo` | Person photo image |
| GET | `/api/ha/config` | Get current configuration |
| POST | `/api/ha/config` | Update configuration (e.g., timeout) |

## User Flow

### OAuth Flow
```
1. Device connects to WiFi
   └── OPNsense redirects to captive portal with MAC

2. User clicks "Sign in with Google"
   └── Redirects through Google OAuth

3. Check if Google account already linked to person
   ├── YES + has devices → Auto-approve → Device Select
   ├── YES + no devices → Wait for approval
   └── NO → Fuzzy search CardDAV

4. CardDAV match found?
   ├── YES → Show "Is this you?" → Confirm → Wait for approval
   └── NO → Enter phone/birthdate → Exact match required

5. If no match → Show error: "Please talk to admin"

6. Wait for admin approval → Device Select → Connected!
```

### Manual Flow
```
1. Device connects to WiFi
   └── OPNsense redirects to captive portal with MAC

2. User enters Phone + Birthdate
   └── Exact CardDAV match required

3. Match found?
   ├── YES → Wait for approval → Device Select → Connected!
   └── NO → Show error: "Please talk to admin"
```

### Returning User Flow
```
1. Device connects to WiFi (already whitelisted)
   └── Auto-approved → "You're Connected!" → Done

2. New device, existing person
   └── Auto-approved → Device Select → Connected!
```

## Database Schema

```sql
-- Users table (login records)
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  birthdate TEXT,
  phone TEXT,
  auth_method TEXT NOT NULL,  -- 'google' or 'manual'
  oauth_id TEXT UNIQUE,
  mac_address TEXT,
  device_type TEXT,
  person_id INTEGER,          -- FK to people
  created_at DATETIME,
  approved INTEGER DEFAULT 0
);

-- People table (verified individuals)
CREATE TABLE people (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  normalized_name TEXT UNIQUE,
  oauth_email TEXT,
  phone TEXT,
  birthdate TEXT,
  photo TEXT,                 -- Base64 encoded
  photo_mime_type TEXT,
  ha_entity_id TEXT,
  created_at DATETIME,
  updated_at DATETIME
);

-- Sessions table
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,        -- UUID
  user_id INTEGER,
  mac_address TEXT,
  ip_address TEXT,
  status TEXT,                -- 'pending', 'approved', 'denied'
  disabled INTEGER DEFAULT 0, -- Set when person/device deleted
  approved_at DATETIME,
  created_at DATETIME
);

-- Approval requests
CREATE TABLE approval_requests (
  id INTEGER PRIMARY KEY,
  session_id TEXT,
  user_name TEXT,
  device_type TEXT,
  mac_address TEXT,
  status TEXT,                -- 'pending', 'approved', 'denied'
  flow_completed INTEGER DEFAULT 0,
  disabled INTEGER DEFAULT 0,
  created_at DATETIME
);

-- Whitelist (approved MACs)
CREATE TABLE whitelist (
  id INTEGER PRIMARY KEY,
  mac_address TEXT UNIQUE,
  user_name TEXT,
  device_type TEXT,           -- 'phone', 'laptop', 'tablet', 'other'
  user_id INTEGER,
  person_id INTEGER,
  first_approved DATETIME,
  last_seen DATETIME,
  expires_at DATETIME,
  permanent INTEGER DEFAULT 1
);

-- OPNsense tracked MACs (not in our whitelist)
CREATE TABLE opnsense_macs (
  id INTEGER PRIMARY KEY,
  mac_address TEXT UNIQUE,
  description TEXT,
  first_seen DATETIME,
  last_seen DATETIME
);
```

## Troubleshooting

### Google OAuth not working

1. Verify `CALLBACK_URL` matches exactly what's configured in Google Cloud Console
2. Check that `accounts.google.com` and `oauth2.googleapis.com` are in the walled garden
3. Ensure the captive portal is accessible from the network
4. Check browser console for CORS errors

### CardDAV verification failing

1. Test the CardDAV URL manually with curl:
   ```bash
   curl -u username:password https://nextcloud.example.com/remote.php/dav/addressbooks/users/admin/contacts/
   ```
2. Verify phone numbers in contacts match expected format (digits only)
3. Check birthdate format (YYYY-MM-DD)

### Sessions not being invalidated

1. Check that `invalidatedSessionIds` is being updated in admin routes
2. The user needs to make a new request for their session to be destroyed
3. Users can manually reconnect to WiFi to get a fresh session

### Device showing as offline when it should be online

1. Check `DEVICE_OFFLINE_TIMEOUT` setting (default 30 seconds)
2. Verify ARP polling is working (check logs for `[ARP Poll]`)
3. Increase timeout via `/api/ha/config` or `.env` file

### MAC addresses not persisting

1. Verify the database is mounted as a volume: `./data:/app/data`
2. Check database permissions
3. Verify OPNsense is passing MAC address correctly

### Home Assistant not receiving updates

1. Verify the `HOME_ASSISTANT_TOKEN` is valid
2. Check Home Assistant logs for connection errors
3. Ensure the captive portal can reach Home Assistant's network
4. Check that the HA integration is polling the correct URL

### Unknown MACs not appearing in admin

1. Run manual sync: `POST /api/admin/sync-opnsense`
2. Check OPNsense API credentials are correct
3. Verify the captive portal zone is correct in OPNsense

## Development

### Running locally

```bash
npm install
npm run dev
```

### Building Docker image

```bash
docker build -t captive-portal .
```

### Testing CardDAV

```bash
# Test CardDAV search
curl -X REPORT \
  -u admin:app-password \
  -H "Content-Type: application/xml" \
  -H "Depth: 1" \
  -d '<?xml version="1.0" encoding="utf-8"?><C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/><C:address-data/></D:prop></C:addressbook-query>' \
  https://nextcloud.example.com/remote.php/dav/addressbooks/users/admin/contacts/
```

### Testing Home Assistant Config API

```bash
# Get current config
curl http://localhost:3000/api/ha/config

# Update device offline timeout
curl -X POST http://localhost:3000/api/ha/config \
  -H "Content-Type: application/json" \
  -d '{"device_offline_timeout": 60}'
```

## Security Considerations

1. **Walled Garden:** Only allow specific OAuth domains, never wildcards
2. **Session Security:** Sessions are HTTP-only and secure in production
3. **Rate Limiting:** Authentication endpoints are rate-limited
4. **Input Validation:** All user inputs are sanitized
5. **No Browser Storage:** localStorage/sessionStorage not used (captive portal limitation)
6. **Session Invalidation:** Deleting a person/device immediately invalidates their sessions
7. **Secure Handoff:** Uses one-time tokens for MAC address exchange

## Error Messages

| Error | Meaning | Solution |
|-------|---------|----------|
| "Please talk to Name about getting WiFi access" | No CardDAV match found | Add contact to Nextcloud with phone number |
| "Session expired" | Cookie session lost | Reconnect to WiFi to start fresh |
| "Session invalidated" | Person/device was deleted | Reconnect to WiFi to re-authenticate |
| "Unable to connect to contact server" | CardDAV connection failed | Check Nextcloud credentials and URL |
| "Failed to grant network access" | OPNsense API error | Check OPNsense credentials and connectivity |

## License

MIT License - See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Support

For issues and feature requests, please use the GitHub issue tracker.
