/**
 * Admin Dashboard JavaScript
 * Handles data loading, tab switching, and admin actions
 */

// State
let currentTab = 'pending';
let refreshInterval;
let countdown = 5;

// Elements
const tabButtons = document.querySelectorAll('.tab-btn');
const loadingState = document.getElementById('loading-state');
const emptyState = document.getElementById('empty-state');
const emptyMessage = document.getElementById('empty-message');
const dataTable = document.getElementById('data-table');
const tableHead = document.getElementById('table-head');
const tableBody = document.getElementById('table-body');
const countdownEl = document.getElementById('refresh-countdown');

// Stats elements
const statPending = document.getElementById('stat-pending');
const statApproved = document.getElementById('stat-approved');
const statDenied = document.getElementById('stat-denied');
const statTracked = document.getElementById('stat-tracked');
const statPeople = document.getElementById('stat-people');
const statUnknown = document.getElementById('stat-unknown');
const tabPendingCount = document.getElementById('tab-pending-count');
const tabPeopleCount = document.getElementById('tab-people-count');
const tabUnknownCount = document.getElementById('tab-unknown-count');

// Modal elements
const confirmModal = document.getElementById('confirm-modal');
const modalTitle = document.getElementById('modal-title');
const modalMessage = document.getElementById('modal-message');
const modalCancel = document.getElementById('modal-cancel');
const modalConfirm = document.getElementById('modal-confirm');

let pendingAction = null;

// ============================================================================
// TAB SWITCHING
// ============================================================================

tabButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    switchTab(tab);
  });
});

function switchTab(tab) {
  currentTab = tab;
  
  // Update active tab UI
  tabButtons.forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
    btn.classList.toggle('text-gray-500', btn.dataset.tab !== tab);
  });
  
  // Load data for new tab
  loadTabData();
}

// ============================================================================
// DATA LOADING
// ============================================================================

async function loadStats() {
  try {
    const response = await fetch('/api/admin/stats');
    const stats = await response.json();
    
    statPending.textContent = stats.pending;
    statApproved.textContent = stats.approved;
    statDenied.textContent = stats.denied;
    statTracked.textContent = stats.tracked;
    statPeople.textContent = stats.people || 0;
    statUnknown.textContent = stats.unknownMacs || 0;
    tabPendingCount.textContent = stats.pending;
    tabPeopleCount.textContent = stats.people || 0;
    tabUnknownCount.textContent = stats.unknownMacs || 0;
  } catch (err) {
    console.error('Failed to load stats:', err);
  }
}

async function loadTabData() {
  showLoading();
  
  const endpoints = {
    pending: '/api/admin/pending',
    people: '/api/admin/people',
    authenticated: '/api/admin/authenticated',
    rejected: '/api/admin/rejected',
    tracked: '/api/admin/tracked-devices',
    unknown: '/api/admin/opnsense-macs'
  };
  
  try {
    const response = await fetch(endpoints[currentTab]);
    const data = await response.json();
    renderTable(data);
  } catch (err) {
    console.error('Failed to load data:', err);
    showEmpty('Failed to load data');
  }
}

function showLoading() {
  loadingState.classList.remove('hidden');
  emptyState.classList.add('hidden');
  dataTable.classList.add('hidden');
}

function showEmpty(message) {
  loadingState.classList.add('hidden');
  emptyState.classList.remove('hidden');
  dataTable.classList.add('hidden');
  emptyMessage.textContent = message || 'No items to display';
}

function showTable() {
  loadingState.classList.add('hidden');
  emptyState.classList.add('hidden');
  dataTable.classList.remove('hidden');
}

// ============================================================================
// TABLE RENDERING
// ============================================================================

function renderTable(data) {
  if (!data || data.length === 0) {
    const messages = {
      pending: 'No pending requests',
      people: 'No people registered',
      authenticated: 'No authenticated users',
      rejected: 'No rejected users',
      tracked: 'No tracked devices',
      unknown: 'No unknown MACs in OPNsense'
    };
    showEmpty(messages[currentTab]);
    return;
  }
  
  showTable();
  
  // Render based on current tab
  switch (currentTab) {
    case 'pending':
      renderPendingTable(data);
      break;
    case 'people':
      renderPeopleTable(data);
      break;
    case 'authenticated':
      renderAuthenticatedTable(data);
      break;
    case 'rejected':
      renderRejectedTable(data);
      break;
    case 'tracked':
      renderTrackedTable(data);
      break;
    case 'unknown':
      renderUnknownTable(data);
      break;
  }
}

function renderPendingTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">User</th>
      <th class="px-4 py-3">Device</th>
      <th class="px-4 py-3">MAC Address</th>
      <th class="px-4 py-3">Requested</th>
      <th class="px-4 py-3 text-right">Actions</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <div class="font-medium text-gray-800">${escapeHtml(item.user_name)}</div>
      </td>
      <td class="px-4 py-4">
        <span class="badge ${item.device_type === 'phone' ? 'badge-phone' : 'badge-other'}">
          ${item.device_type === 'phone' ? '📱 Phone' : item.device_type === 'pending' ? '⏳ Pending' : '💻 Other'}
        </span>
      </td>
      <td class="px-4 py-4">
        <code class="text-sm bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.mac_address || 'N/A')}</code>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${formatDate(item.created_at)}
      </td>
      <td class="px-4 py-4 text-right">
        <button data-action="approve" data-session-id="${escapeHtml(item.session_id)}" 
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-green-100 text-green-700 rounded-lg hover:bg-green-200 mr-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
          Approve
        </button>
        <button data-action="deny" data-session-id="${escapeHtml(item.session_id)}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
          Deny
        </button>
      </td>
    </tr>
  `).join('');
}

function renderAuthenticatedTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">User</th>
      <th class="px-4 py-3">Device</th>
      <th class="px-4 py-3">MAC Address</th>
      <th class="px-4 py-3">Auth Method</th>
      <th class="px-4 py-3">Last Seen</th>
      <th class="px-4 py-3 text-right">Actions</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <div class="font-medium text-gray-800">${escapeHtml(item.name)}</div>
        ${item.phone ? `<div class="text-sm text-gray-500">${escapeHtml(item.phone)}</div>` : ''}
      </td>
      <td class="px-4 py-4">
        <span class="badge ${item.device_type === 'phone' ? 'badge-phone' : 'badge-other'}">
          ${item.device_type === 'phone' ? '📱 Phone' : '💻 Other'}
        </span>
      </td>
      <td class="px-4 py-4">
        <code class="text-sm bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.mac_address || 'N/A')}</code>
      </td>
      <td class="px-4 py-4">
        <span class="text-sm ${item.auth_method === 'google' ? 'text-blue-600' : 'text-purple-600'}">
          ${item.auth_method === 'google' ? '🔵 Google' : '📞 Phone'}
        </span>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${item.last_seen ? formatDate(item.last_seen) : 'Never'}
      </td>
      <td class="px-4 py-4 text-right">
        <button data-action="revoke" data-mac="${escapeHtml(item.mac_address)}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          Revoke
        </button>
      </td>
    </tr>
  `).join('');
}

function renderRejectedTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">User</th>
      <th class="px-4 py-3">Device</th>
      <th class="px-4 py-3">MAC Address</th>
      <th class="px-4 py-3">Rejected At</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <div class="font-medium text-gray-800">${escapeHtml(item.user_name)}</div>
      </td>
      <td class="px-4 py-4">
        <span class="badge ${item.device_type === 'phone' ? 'badge-phone' : 'badge-other'}">
          ${item.device_type === 'phone' ? '📱 Phone' : '💻 Other'}
        </span>
      </td>
      <td class="px-4 py-4">
        <code class="text-sm bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.mac_address || 'N/A')}</code>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${formatDate(item.created_at)}
      </td>
    </tr>
  `).join('');
}

function renderTrackedTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">User</th>
      <th class="px-4 py-3">Status</th>
      <th class="px-4 py-3">MAC Address</th>
      <th class="px-4 py-3">Last Seen</th>
      <th class="px-4 py-3 text-right">Actions</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <div class="font-medium text-gray-800">${escapeHtml(item.user_name || item.name || 'Unknown')}</div>
        ${item.phone ? `<div class="text-sm text-gray-500">${escapeHtml(item.phone)}</div>` : ''}
      </td>
      <td class="px-4 py-4">
        <span class="badge ${item.online ? 'badge-online' : 'badge-offline'}">
          ${item.online ? '🟢 Online' : '⚫ Offline'}
        </span>
      </td>
      <td class="px-4 py-4">
        <code class="text-sm bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.mac_address)}</code>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${formatDate(item.last_seen)}
      </td>
      <td class="px-4 py-4 text-right">
        <button data-action="untrack" data-mac="${escapeHtml(item.mac_address)}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
          </svg>
          Stop Tracking
        </button>
      </td>
    </tr>
  `).join('');
}

function renderPeopleTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">Person</th>
      <th class="px-4 py-3">Status</th>
      <th class="px-4 py-3">Devices</th>
      <th class="px-4 py-3">Contact Info</th>
      <th class="px-4 py-3">HA Entity</th>
      <th class="px-4 py-3 text-right">Actions</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <div class="font-medium text-gray-800">${escapeHtml(item.name)}</div>
        <div class="text-xs text-gray-400">ID: ${item.id}</div>
      </td>
      <td class="px-4 py-4">
        <span class="badge ${item.online ? 'badge-online' : 'badge-offline'}">
          ${item.online ? '🟢 Home' : '⚫ Away'}
        </span>
      </td>
      <td class="px-4 py-4">
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-600">${item.device_count || 0} device${item.device_count !== 1 ? 's' : ''}</span>
          ${item.phone_count > 0 ? `<span class="text-xs bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">📱 ${item.phone_count}</span>` : ''}
        </div>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${item.phone ? `📞 ${escapeHtml(item.phone)}` : ''}
        ${item.birthdate ? `<br>🎂 ${escapeHtml(item.birthdate)}` : ''}
        ${!item.phone && !item.birthdate ? '<span class="text-gray-400">Not set</span>' : ''}
      </td>
      <td class="px-4 py-4">
        <code class="text-xs bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.ha_entity_id || 'N/A')}</code>
      </td>
      <td class="px-4 py-4 text-right">
        <button data-action="view-person" data-person-id="${item.id}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200 mr-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
          </svg>
          View
        </button>
        <button data-action="delete-person" data-person-id="${item.id}" data-person-name="${escapeHtml(item.name)}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
          Delete
        </button>
      </td>
    </tr>
  `).join('');
}

function renderUnknownTable(data) {
  tableHead.innerHTML = `
    <tr class="text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
      <th class="px-4 py-3">MAC Address</th>
      <th class="px-4 py-3">Description</th>
      <th class="px-4 py-3">First Seen</th>
      <th class="px-4 py-3">Last Seen</th>
      <th class="px-4 py-3 text-right">Actions</th>
    </tr>
  `;
  
  tableBody.innerHTML = data.map(item => `
    <tr class="table-row border-t">
      <td class="px-4 py-4">
        <code class="text-sm bg-gray-100 px-2 py-1 rounded">${escapeHtml(item.mac_address)}</code>
      </td>
      <td class="px-4 py-4">
        <div class="text-sm text-gray-600">${escapeHtml(item.description || 'Unknown device')}</div>
        <div class="text-xs text-gray-400 mt-1">
          <em>These devices are in OPNsense but were not added through this portal</em>
        </div>
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${formatDate(item.first_seen)}
      </td>
      <td class="px-4 py-4 text-sm text-gray-500">
        ${formatDate(item.last_seen)}
      </td>
      <td class="px-4 py-4 text-right">
        <button data-action="revoke-unknown" data-mac="${escapeHtml(item.mac_address)}"
                class="action-btn inline-flex items-center gap-1 px-3 py-1.5 bg-red-100 text-red-700 rounded-lg hover:bg-red-200">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
          </svg>
          Revoke Access
        </button>
      </td>
    </tr>
  `).join('');
}

// ============================================================================
// ACTIONS
// ============================================================================

function approveRequest(sessionId) {
  showModal(
    'Approve Request',
    'Are you sure you want to approve this access request?',
    async () => {
      try {
        const response = await fetch(`/api/admin/approve/${sessionId}`, { method: 'POST' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to approve request');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

function denyRequest(sessionId) {
  showModal(
    'Deny Request',
    'Are you sure you want to deny this access request?',
    async () => {
      try {
        const response = await fetch(`/api/admin/deny/${sessionId}`, { method: 'POST' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to deny request');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

function revokeAccess(mac) {
  if (!mac) return;
  
  showModal(
    'Revoke Access',
    'Are you sure you want to revoke access for this device? They will need to re-authenticate.',
    async () => {
      try {
        const response = await fetch(`/api/admin/whitelist/${encodeURIComponent(mac)}`, { method: 'DELETE' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to revoke access');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

function untrackDevice(mac) {
  if (!mac) return;
  
  showModal(
    'Stop Tracking',
    'This device will no longer be used for presence detection, but will remain authenticated.',
    async () => {
      try {
        const response = await fetch(`/api/admin/untrack/${encodeURIComponent(mac)}`, { method: 'POST' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to untrack device');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

async function viewPerson(personId) {
  try {
    const response = await fetch(`/api/admin/people/${personId}`);
    const person = await response.json();
    
    // Build devices list
    let devicesHtml = '';
    if (person.devices && person.devices.length > 0) {
      devicesHtml = person.devices.map(d => 
        `• ${d.device_type === 'phone' ? '📱' : '💻'} ${d.mac_address} ${d.online ? '(online)' : '(offline)'}`
      ).join('\n');
    } else {
      devicesHtml = 'No devices';
    }
    
    const message = `Name: ${person.name}
Status: ${person.online ? '🟢 Home' : '⚫ Away'}
Phone: ${person.phone || 'Not set'}
Birthdate: ${person.birthdate || 'Not set'}
HA Entity: ${person.ha_entity_id || 'N/A'}

Devices:
${devicesHtml}`;
    
    alert(message);
  } catch (err) {
    alert('Error loading person: ' + err.message);
  }
}

function deletePerson(personId, personName) {
  showModal(
    'Delete Person',
    `Are you sure you want to delete "${personName}"? All their devices will be revoked from the network and they will need to re-authenticate.`,
    async () => {
      try {
        const response = await fetch(`/api/admin/people/${personId}`, { method: 'DELETE' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to delete person');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

function revokeUnknownMac(mac) {
  if (!mac) return;
  
  showModal(
    'Revoke Unknown MAC',
    'Are you sure you want to revoke access for this device? It will be removed from the OPNsense whitelist.',
    async () => {
      try {
        const response = await fetch(`/api/admin/opnsense-macs/${encodeURIComponent(mac)}`, { method: 'DELETE' });
        if (response.ok) {
          refreshData();
        } else {
          alert('Failed to revoke MAC');
        }
      } catch (err) {
        alert('Error: ' + err.message);
      }
    }
  );
}

// ============================================================================
// MODAL
// ============================================================================

function showModal(title, message, onConfirm) {
  modalTitle.textContent = title;
  modalMessage.textContent = message;
  pendingAction = onConfirm;
  confirmModal.classList.remove('hidden');
}

function hideModal() {
  confirmModal.classList.add('hidden');
  pendingAction = null;
}

modalCancel.addEventListener('click', hideModal);
modalConfirm.addEventListener('click', async () => {
  if (pendingAction) {
    await pendingAction();
  }
  hideModal();
});

// Close modal on overlay click
confirmModal.querySelector('.modal-overlay').addEventListener('click', hideModal);

// ============================================================================
// UTILITIES
// ============================================================================

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now - date;
  
  // If less than a minute ago
  if (diff < 60000) {
    return 'Just now';
  }
  
  // If less than an hour ago
  if (diff < 3600000) {
    const mins = Math.floor(diff / 60000);
    return `${mins} min${mins > 1 ? 's' : ''} ago`;
  }
  
  // If today
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  
  // Otherwise show date and time
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ============================================================================
// AUTO REFRESH
// ============================================================================

function refreshData() {
  loadStats();
  loadTabData();
}

function startAutoRefresh() {
  countdown = 5;
  
  // Update countdown every second
  setInterval(() => {
    countdown--;
    countdownEl.textContent = countdown;
    
    if (countdown <= 0) {
      countdown = 5;
      refreshData();
    }
  }, 1000);
}

// ============================================================================
// INITIALIZE
// ============================================================================

// Event delegation for action buttons (avoids inline onclick handlers)
tableBody.addEventListener('click', (e) => {
  const button = e.target.closest('button[data-action]');
  if (!button) return;
  
  const action = button.dataset.action;
  const sessionId = button.dataset.sessionId;
  const mac = button.dataset.mac;
  const personId = button.dataset.personId;
  const personName = button.dataset.personName;
  
  switch (action) {
    case 'approve':
      approveRequest(sessionId);
      break;
    case 'deny':
      denyRequest(sessionId);
      break;
    case 'revoke':
      revokeAccess(mac);
      break;
    case 'untrack':
      untrackDevice(mac);
      break;
    case 'view-person':
      viewPerson(personId);
      break;
    case 'delete-person':
      deletePerson(personId, personName);
      break;
    case 'revoke-unknown':
      revokeUnknownMac(mac);
      break;
  }
});

// Initial load
loadStats();
loadTabData();
startAutoRefresh();
