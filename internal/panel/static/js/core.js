/* =========================================================================
   TLS Relay Admin Panel — core.js
   Core variables, UI selectors, dialog modals, segmented controls,
   and theme manager.
   ========================================================================= */

"use strict";

// ---------------------------------------------------------------------------
// Global State
// ---------------------------------------------------------------------------
let allDomains = [];
let allUsers = [];
let allBlacklistEntries = [];
let allPresenceUsers = [];
let presencePollInterval = null;
let currentUserIPsUserId = null;
let currentUserIPsUsername = null;

// Settings
let currentTimezone = 'UTC';
let currentServerDomain = '';
let isEgressProxyEnabled = false;

async function fetchAppSettings() {
  try {
    const res = await apiFetch('/api/settings');
    if (res.ok) {
      const data = await res.json();
      if (data.timezone) currentTimezone = data.timezone;
      if (data.server_domain !== undefined) currentServerDomain = data.server_domain;
      isEgressProxyEnabled = !!data.egress_proxy_enabled;
      updateEgressVisibility();
    }
  } catch (e) {
    console.error('fetchAppSettings error:', e);
  }
}

function updateEgressVisibility() {
  const egressContainers = [
    'add-domain-egress-group',
    'edit-domain-egress-group',
    'quick-add-domain-egress-group',
    'bulk-assign-egress-btn'
  ];
  egressContainers.forEach(id => {
    const el = $(id);
    if (!el) return;
    if (!isEgressProxyEnabled) {
      hideEl(id);
    } else {
      if (id === 'add-domain-egress-group') {
        const mode = $('domain-mode') ? $('domain-mode').value : 'proxy';
        if (mode === 'proxy') showEl(id); else hideEl(id);
      } else if (id === 'edit-domain-egress-group') {
        const mode = $('edit-domain-mode') ? $('edit-domain-mode').value : 'proxy';
        if (mode === 'proxy') showEl(id); else hideEl(id);
      } else if (id === 'quick-add-domain-egress-group') {
        const mode = $('quick-add-domain-mode') ? $('quick-add-domain-mode').value : 'proxy';
        if (mode === 'proxy') showEl(id); else hideEl(id);
      } else {
        showEl(id);
      }
    }
  });
}

// Centralized Source of Truth for Base URL, Magic Link, and Setup URLs
function getBaseUrl() {
  const domain = (currentServerDomain || window.serverDomain || '').trim();
  if (domain) {
    let clean = domain.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    return `http://${clean}`;
  }
  return `${location.protocol}//${location.host}`;
}

function getMagicLinkUrl(token) {
  if (!token) return getBaseUrl();
  return `${getBaseUrl()}/connect/${token}`;
}

function getSetupUrl(token) {
  if (!token) return `${getBaseUrl()}/setup`;
  return `${getBaseUrl()}/setup/${token}`;
}

// UI Selection & Sort State
let selectedDomains = new Set();
let selectedBlacklistIds = new Set();
let domainSortCol = 'domain';
let domainSortDir = 'asc';
let expandedGroups = new Set(); // groups default to COLLAPSED; add to this Set to expand

// Group Selectors
let addDomainGroupController = null;
let bulkGroupController = null;
let editDomainGroupController = null;
let quickAddDomainGroupController = null;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function $(id) { return document.getElementById(id); }

function formatBytes(bytes) {
  if (bytes === 0 || !bytes || isNaN(bytes)) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showEl(id) {
  const el = $(id);
  if (el) el.classList.remove('hidden');
}

async function loadAllTabPages() {
  const panels = document.querySelectorAll('.tab-panel[data-page-src]');
  const promises = Array.from(panels).map(async (panel) => {
    try {
      const src = panel.dataset.pageSrc;
      if (!src) return;
      const res = await fetch(getApiUrl(src));
      if (res.ok) {
        const html = await res.text();
        panel.innerHTML = html;
        panel.dataset.loaded = 'true';
      } else {
        console.error(`Failed to load page "${src}": ${res.status}`);
      }
    } catch (err) {
      console.error('Failed to load page for panel:', panel.id, err);
    }
  });
  await Promise.all(promises);
}

// Global scope helpers for backward compatibility
window.$ = $;
window.showEl = showEl;
window.hideEl = hideEl;
window.formatBytes = formatBytes;
window.loadAllTabPages = loadAllTabPages;

function getActiveTab() {
  const activeBtn = document.querySelector('.tab-btn.active');
  return activeBtn ? activeBtn.dataset.tab : 'domains';
}

function updateBulkBar() {
  const tab = getActiveTab();
  const countText = $('bulk-count-text');

  let count = 0;
  if (tab === 'domains') {
    count = selectedDomains.size;
    showEl('bulk-assign-group-btn');
  } else if (tab === 'blacklist') {
    count = selectedBlacklistIds.size;
    hideEl('bulk-assign-group-btn');
  } else {
    hideEl('bulk-bar');
    return;
  }

  if (count > 0) {
    if (countText) countText.textContent = `${count} item${count > 1 ? 's' : ''} selected`;
    showEl('bulk-bar');
  } else {
    hideEl('bulk-bar');
  }
}

function updateSelectAllCheckboxes() {
  const tab = getActiveTab();
  if (tab === 'domains') {
    const allChks = document.querySelectorAll('#domain-tbody .domain-chk');
    const selectAll = $('domain-select-all');
    if (selectAll) {
      if (allChks.length > 0 && selectedDomains.size === allDomains.length) {
        selectAll.checked = true;
      } else {
        selectAll.checked = false;
      }
    }
  } else if (tab === 'blacklist') {
    const allChks = document.querySelectorAll('#blacklist-tbody .blacklist-chk');
    const selectAll = $('blacklist-select-all');
    if (selectAll) {
      if (allChks.length > 0 && selectedBlacklistIds.size === allBlacklistEntries.length) {
        selectAll.checked = true;
      } else {
        selectAll.checked = false;
      }
    }
  }
}

function updateMetrics() {
  if ($('stat-domain-count')) $('stat-domain-count').textContent = allDomains.length;
  if ($('stat-user-count')) $('stat-user-count').textContent = allUsers.length;
  if ($('stat-blacklist-count')) $('stat-blacklist-count').textContent = allBlacklistEntries.length;
}

function clearSelection() {
  selectedDomains.clear();
  selectedBlacklistIds.clear();
  if ($('domain-select-all')) $('domain-select-all').checked = false;
  if ($('blacklist-select-all')) $('blacklist-select-all').checked = false;
  hideEl('bulk-bar');
  if (typeof renderDomains === 'function') renderDomains();
  if (typeof renderBlacklist === 'function') renderBlacklist();
}

function switchTab(tabName) {
  let targetSubtab = null;
  if (tabName === 'online-users') {
    tabName = 'users';
    targetSubtab = 'online';
  }

  document.querySelectorAll('.tab-btn').forEach(b => {
    if (b.dataset.tab === tabName || (tabName === 'users' && b.dataset.tab === 'online-users')) {
      b.classList.add('active');
    } else {
      b.classList.remove('active');
    }
  });

  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.remove('active');
    p.classList.add('hidden');
  });

  const panel = $('tab-' + tabName);
  if (panel) {
    panel.classList.remove('hidden');
    panel.classList.add('active');
  }

  if (targetSubtab && $('user-subtab-toggle')) {
    const btn = $('user-subtab-toggle').querySelector(`.segmented-btn[data-subtab="${targetSubtab}"]`);
    if (btn) btn.click();
  }

  clearSelection();

  if (tabName === 'dashboard') {
    if (typeof stopReqLogPolling === 'function') stopReqLogPolling();
    if (typeof stopPresencePolling === 'function') stopPresencePolling();
    if (typeof stopUsagePolling === 'function') stopUsagePolling();
    if (typeof startStatsPolling === 'function') startStatsPolling();
  } else if (tabName === 'settings') {
    if (typeof stopStatsPolling === 'function') stopStatsPolling();
    if (typeof stopReqLogPolling === 'function') stopReqLogPolling();
    if (typeof stopPresencePolling === 'function') stopPresencePolling();
    if (typeof stopUsagePolling === 'function') stopUsagePolling();
    if (typeof loadSettings === 'function') loadSettings();
  } else if (tabName === 'users') {
    if (typeof stopStatsPolling === 'function') stopStatsPolling();
    if (typeof stopReqLogPolling === 'function') stopReqLogPolling();
    if (typeof stopUsagePolling === 'function') stopUsagePolling();
    if (typeof startPresencePolling === 'function') startPresencePolling();
    if (typeof loadUsers === 'function') loadUsers();
  } else if (tabName === 'usage') {
    if (typeof stopStatsPolling === 'function') stopStatsPolling();
    if (typeof stopReqLogPolling === 'function') stopReqLogPolling();
    if (typeof stopPresencePolling === 'function') stopPresencePolling();
    if (typeof startUsagePolling === 'function') startUsagePolling();
  } else if (tabName === 'request-logs') {
    if (typeof stopStatsPolling === 'function') stopStatsPolling();
    if (typeof stopPresencePolling === 'function') stopPresencePolling();
    if (typeof stopUsagePolling === 'function') stopUsagePolling();
    if (typeof startReqLogPolling === 'function') startReqLogPolling();
  } else {
    if (typeof stopStatsPolling === 'function') stopStatsPolling();
    if (typeof stopReqLogPolling === 'function') stopReqLogPolling();
    if (typeof stopPresencePolling === 'function') stopPresencePolling();
    if (typeof stopUsagePolling === 'function') stopUsagePolling();
  }
}

window.getActiveTab = getActiveTab;
window.switchTab = switchTab;
window.updateBulkBar = updateBulkBar;
window.updateSelectAllCheckboxes = updateSelectAllCheckboxes;
window.updateMetrics = updateMetrics;
window.clearSelection = clearSelection;


function hideEl(id) {
  const el = $(id);
  if (el) el.classList.add('hidden');
}

function showError(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function showSuccess(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
  setTimeout(() => el.classList.add('hidden'), 4000);
}

function clearMessages(...ids) {
  for (const id of ids) {
    if (id && $(id)) $(id).classList.add('hidden');
  }
}

// ---------------------------------------------------------------------------
// Apple-Style Toast & Custom Modal Dialog Systems
// ---------------------------------------------------------------------------
function showToast(message, type = 'info', duration = 3500) {
  let container = $('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;

  let iconSvg = '';
  if (type === 'success') {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
  } else if (type === 'error') {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
  } else {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
  }

  toast.innerHTML = `
    <div class="toast-icon">${iconSvg}</div>
    <div class="toast-content">${escapeHtml(message)}</div>
    <button type="button" class="toast-close">&times;</button>
  `;

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.add('show');
  });

  const removeToast = () => {
    toast.classList.remove('show');
    toast.classList.add('hide');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 300);
  };

  toast.querySelector('.toast-close').addEventListener('click', removeToast);

  if (duration > 0) {
    setTimeout(removeToast, duration);
  }
}

function showConfirmDialog({ title = 'Confirm Action', message = 'Are you sure?', confirmText = 'Confirm', cancelText = 'Cancel', isDanger = false }) {
  return new Promise((resolve) => {
    const overlay = $('custom-modal-overlay');
    const titleEl = $('custom-modal-title');
    const msgEl = $('custom-modal-message');
    const inputContainer = $('custom-modal-input-container');
    const iconEl = $('custom-modal-icon');
    const confirmBtn = $('custom-modal-confirm-btn');
    const cancelBtn = $('custom-modal-cancel-btn');

    titleEl.textContent = title;
    msgEl.textContent = message;
    inputContainer.classList.add('hidden');

    confirmBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;

    if (isDanger) {
      confirmBtn.className = 'btn btn-danger';
      iconEl.className = 'custom-modal-icon danger';
    } else {
      confirmBtn.className = 'btn btn-primary';
      iconEl.className = 'custom-modal-icon';
    }

    overlay.classList.remove('hidden');

    const cleanup = () => {
      overlay.classList.add('hidden');
      confirmBtn.removeEventListener('click', onConfirm);
      cancelBtn.removeEventListener('click', onCancel);
    };

    const onConfirm = () => {
      cleanup();
      resolve(true);
    };

    const onCancel = () => {
      cleanup();
      resolve(false);
    };

    confirmBtn.addEventListener('click', onConfirm);
    cancelBtn.addEventListener('click', onCancel);
  });
}

function showPromptDialog({ title = 'Enter Value', message = '', defaultValue = '', placeholder = '', confirmText = 'Submit', cancelText = 'Cancel' }) {
  return new Promise((resolve) => {
    const overlay = $('custom-modal-overlay');
    const titleEl = $('custom-modal-title');
    const msgEl = $('custom-modal-message');
    const inputContainer = $('custom-modal-input-container');
    const input = $('custom-modal-input');
    const iconEl = $('custom-modal-icon');
    const confirmBtn = $('custom-modal-confirm-btn');
    const cancelBtn = $('custom-modal-cancel-btn');

    titleEl.textContent = title;
    msgEl.textContent = message;
    inputContainer.classList.remove('hidden');

    input.value = defaultValue;
    input.placeholder = placeholder;
    confirmBtn.textContent = confirmText;
    cancelBtn.textContent = cancelText;
    confirmBtn.className = 'btn btn-primary';
    iconEl.className = 'custom-modal-icon';

    overlay.classList.remove('hidden');
    setTimeout(() => input.focus(), 100);

    const cleanup = () => {
      overlay.classList.add('hidden');
      confirmBtn.removeEventListener('click', onConfirm);
      cancelBtn.removeEventListener('click', onCancel);
      input.removeEventListener('keydown', onKeyDown);
    };

    const onConfirm = () => {
      const val = input.value;
      cleanup();
      resolve(val);
    };

    const onCancel = () => {
      cleanup();
      resolve(null);
    };

    const onKeyDown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        onConfirm();
      } else if (e.key === 'Escape') {
        onCancel();
      }
    };

    confirmBtn.addEventListener('click', onConfirm);
    cancelBtn.addEventListener('click', onCancel);
    input.addEventListener('keydown', onKeyDown);
  });
}

function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  } else {
    return new Promise((resolve, reject) => {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.left = '-9999px';
      textarea.style.top = '-9999px';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      try {
        const successful = document.execCommand('copy');
        document.body.removeChild(textarea);
        if (successful) resolve();
        else reject(new Error('execCommand copy failed'));
      } catch (err) {
        document.body.removeChild(textarea);
        reject(err);
      }
    });
  }
}

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

function getApiUrl(path) {
  let base = window.location.pathname;
  if (!base.endsWith('/')) {
    base += '/';
  }
  const cleanPath = path.startsWith('/') ? path.slice(1) : path;
  return base + cleanPath;
}

async function apiFetch(path, opts = {}) {
  const url = getApiUrl(path);
  const method = (opts.method || 'GET').toUpperCase();
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (['POST', 'PUT', 'DELETE'].includes(method)) {
    const csrfToken = getCookie('relay_csrf');
    if (csrfToken) {
      headers['X-CSRF-Token'] = csrfToken;
    }
  }
  const res = await fetch(url, {
    credentials: 'include',
    headers: headers,
    ...opts,
  });
  if (res.status === 401) {
    showLoginPage();
    throw new Error('Not authenticated');
  }
  return res;
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTimestamp(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString('en-GB', {
      timeZone: currentTimezone,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function populateTimezoneSelect() {
  const sel = $('settings-timezone-select');
  if (!sel) return;

  let zones = [];
  if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
    try { zones = Intl.supportedValuesOf('timeZone'); } catch { /* ignore */ }
  }
  if (zones.length === 0) {
    zones = [
      'UTC', 'Africa/Abidjan', 'Africa/Cairo', 'Africa/Nairobi', 'America/Anchorage',
      'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/New_York',
      'America/Sao_Paulo', 'America/Toronto', 'Asia/Bangkok', 'Asia/Dhaka',
      'Asia/Dubai', 'Asia/Hong_Kong', 'Asia/Jakarta', 'Asia/Karachi', 'Asia/Kolkata',
      'Asia/Seoul', 'Asia/Shanghai', 'Asia/Singapore', 'Asia/Tehran', 'Asia/Tokyo',
      'Australia/Melbourne', 'Australia/Sydney', 'Europe/Amsterdam', 'Europe/Berlin',
      'Europe/Istanbul', 'Europe/London', 'Europe/Moscow', 'Europe/Paris',
      'Pacific/Auckland', 'Pacific/Honolulu',
    ];
  }

  sel.innerHTML = '';
  for (const tz of zones) {
    const opt = document.createElement('option');
    opt.value = tz;
    opt.textContent = tz;
    if (tz === currentTimezone) opt.selected = true;
    sel.appendChild(opt);
  }
}

// ---------------------------------------------------------------------------
// Segmented Control Component Helper
// ---------------------------------------------------------------------------
function initSegmentedControls() {
  document.querySelectorAll('.segmented-control').forEach(ctrl => {
    const hiddenInput = ctrl.parentNode.querySelector('input[type="hidden"]');
    ctrl.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        ctrl.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        if (hiddenInput) {
          hiddenInput.value = btn.dataset.val;
        }
      });
    });
  });
}

function setSegmentedValue(ctrlId, value) {
  const ctrl = $(ctrlId);
  if (!ctrl) return;
  const hiddenInput = ctrl.parentNode.querySelector('input[type="hidden"]');
  if (hiddenInput) hiddenInput.value = value;
  ctrl.querySelectorAll('.segmented-btn').forEach(btn => {
    if (btn.dataset.val === value) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
}

// ---------------------------------------------------------------------------
// Group selector dropdown helpers
// ---------------------------------------------------------------------------
function updateCustomGroupDropdown(optionsId, onSelectCallback) {
  const container = $(optionsId);
  if (!container) return;

  const existingGroups = Array.from(new Set(allDomains.map(d => d.group_name).filter(g => g && g.trim() !== ''))).sort((a, b) => a.localeCompare(b));

  let html = `<div class="custom-select-option" data-val="">Default (No Group)</div>`;
  for (const g of existingGroups) {
    html += `<div class="custom-select-option" data-val="${escapeHtml(g)}">📁 ${escapeHtml(g)}</div>`;
  }

  container.innerHTML = html;
  container.querySelectorAll('.custom-select-option').forEach(opt => {
    opt.addEventListener('click', () => {
      onSelectCallback(opt.dataset.val);
    });
  });
}

function initGroupSelectorComponent({ modeSelectBtnId, modeCreateBtnId, selectWrapId, createWrapId, triggerId, dropdownId, searchId, optionsId, inputId, hiddenValId, labelId }) {
  const selectBtn = $(modeSelectBtnId);
  const createBtn = $(modeCreateBtnId);
  const selectWrap = $(selectWrapId);
  const createWrap = $(createWrapId);
  const trigger = $(triggerId);
  const dropdown = $(dropdownId);
  const searchInput = $(searchId);
  const optionsEl = $(optionsId);
  const textInput = $(inputId);
  const hiddenVal = $(hiddenValId);
  const labelEl = $(labelId);

  if (!selectBtn || !createBtn || !hiddenVal) return null;

  let currentMode = 'select'; // 'select' | 'create'

  const filterOptions = (q) => {
    if (!optionsEl) return;
    const query = (q || '').trim().toLowerCase();
    optionsEl.querySelectorAll('.custom-select-option').forEach(opt => {
      const txt = opt.textContent.toLowerCase();
      if (!query || txt.includes(query)) {
        opt.style.display = 'block';
      } else {
        opt.style.display = 'none';
      }
    });
  };

  const updateSelectedGroup = (val) => {
    hiddenVal.value = val;
    if (labelEl) {
      labelEl.textContent = val ? `📁 ${val}` : 'Default (No Group)';
    }
    if (dropdown) dropdown.classList.add('hidden');
  };

  const setMode = (mode) => {
    currentMode = mode;
    if (mode === 'select') {
      selectBtn.classList.add('active');
      createBtn.classList.remove('active');
      selectWrap.classList.remove('hidden');
      createWrap.classList.add('hidden');
      if (dropdown) dropdown.classList.add('hidden');
      updateSelectedGroup('');
    } else {
      createBtn.classList.add('active');
      selectBtn.classList.remove('active');
      createWrap.classList.remove('hidden');
      selectWrap.classList.add('hidden');
      if (dropdown) dropdown.classList.add('hidden');
      hiddenVal.value = textInput ? textInput.value.trim() : '';
    }
  };

  selectBtn.addEventListener('click', () => setMode('select'));
  createBtn.addEventListener('click', () => setMode('create'));

  if (trigger && dropdown) {
    trigger.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('hidden');
      if (!dropdown.classList.contains('hidden') && searchInput) {
        searchInput.value = '';
        searchInput.focus();
        filterOptions('');
      }
    });

    document.addEventListener('click', (e) => {
      if (!trigger.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.add('hidden');
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', (e) => filterOptions(e.target.value));
  }

  if (textInput) {
    textInput.addEventListener('input', () => {
      if (currentMode === 'create') {
        hiddenVal.value = textInput.value.trim();
      }
    });
  }

  return {
    refreshOptions: () => updateCustomGroupDropdown(optionsId, updateSelectedGroup),
    setValue: (val) => {
      updateSelectedGroup(val);
      const existingGroups = Array.from(new Set(allDomains.map(d => d.group_name).filter(g => g && g.trim() !== '')));
      if (val && !existingGroups.includes(val)) {
        setMode('create');
        if (textInput) textInput.value = val;
      } else {
        setMode('select');
      }
    }
  };
}

function initGroupSelectors() {
  if ($('group-mode-select-btn')) {
    addDomainGroupController = initGroupSelectorComponent({
      modeSelectBtnId: 'group-mode-select-btn',
      modeCreateBtnId: 'group-mode-create-btn',
      selectWrapId: 'group-select-mode-wrap',
      createWrapId: 'group-create-mode-wrap',
      triggerId: 'group-select-trigger',
      dropdownId: 'group-select-dropdown',
      searchId: 'group-select-search',
      optionsId: 'group-select-options',
      inputId: 'domain-group-name-input',
      hiddenValId: 'domain-group-name',
      labelId: 'group-select-label',
    });
  }

  if ($('bulk-group-mode-select-btn')) {
    bulkGroupController = initGroupSelectorComponent({
      modeSelectBtnId: 'bulk-group-mode-select-btn',
      modeCreateBtnId: 'bulk-group-mode-create-btn',
      selectWrapId: 'bulk-group-select-wrap',
      createWrapId: 'bulk-group-create-wrap',
      triggerId: 'bulk-group-select-trigger',
      dropdownId: 'bulk-group-select-dropdown',
      searchId: 'bulk-group-select-search',
      optionsId: 'bulk-group-select-options',
      inputId: 'bulk-group-input',
      hiddenValId: 'bulk-group-val',
      labelId: 'bulk-group-select-label',
    });
  }

  if ($('edit-group-mode-select-btn')) {
    editDomainGroupController = initGroupSelectorComponent({
      modeSelectBtnId: 'edit-group-mode-select-btn',
      modeCreateBtnId: 'edit-group-mode-create-btn',
      selectWrapId: 'edit-group-select-mode-wrap',
      createWrapId: 'edit-group-create-mode-wrap',
      triggerId: 'edit-group-select-trigger',
      dropdownId: 'edit-group-select-dropdown',
      searchId: 'edit-group-select-search',
      optionsId: 'edit-group-select-options',
      inputId: 'edit-domain-group-name-input',
      hiddenValId: 'edit-domain-group-name',
      labelId: 'edit-group-select-label',
    });
  }

  if ($('quick-group-mode-select-btn')) {
    quickAddDomainGroupController = initGroupSelectorComponent({
      modeSelectBtnId: 'quick-group-mode-select-btn',
      modeCreateBtnId: 'quick-group-mode-create-btn',
      selectWrapId: 'quick-group-select-mode-wrap',
      createWrapId: 'quick-group-create-mode-wrap',
      triggerId: 'quick-group-select-trigger',
      dropdownId: 'quick-group-select-dropdown',
      searchId: 'quick-group-select-search',
      optionsId: 'quick-group-select-options',
      inputId: 'quick-domain-group-name-input',
      hiddenValId: 'quick-add-domain-group',
      labelId: 'quick-group-select-label',
    });
  }
}

function updateGroupDatalist() {
  if (addDomainGroupController) addDomainGroupController.refreshOptions();
  if (bulkGroupController) bulkGroupController.refreshOptions();
  if (editDomainGroupController) editDomainGroupController.refreshOptions();
  if (quickAddDomainGroupController) quickAddDomainGroupController.refreshOptions();

  const datalist = $('existing-groups-list');
  if (!datalist) return;
  datalist.innerHTML = '';
  const groups = new Set();
  for (const d of allDomains) {
    if (d.group_name && d.group_name.trim()) {
      groups.add(d.group_name.trim());
    }
  }
  const sorted = Array.from(groups).sort((a, b) => a.localeCompare(b));
  for (const g of sorted) {
    const opt = document.createElement('option');
    opt.value = g;
    datalist.appendChild(opt);
  }
}

// ---------------------------------------------------------------------------
// Egress Proxy Radio Group Component
// ---------------------------------------------------------------------------
function initEgressProxyRadioGroup() {
  ['domain-egress', 'edit-domain-egress', 'quick-add-domain-egress'].forEach(prefix => {
    const container = $(prefix + '-radio-group');
    const hiddenInput = $(prefix);
    if (!container || !hiddenInput) return;

    container.querySelectorAll('input[type="radio"]').forEach(radio => {
      radio.addEventListener('change', () => {
        if (radio.checked) {
          hiddenInput.value = radio.value;
        }
      });
    });
  });

  // Wire Mode radio groups and toggle ports/egress field visibility
  [
    { hiddenId: 'domain-mode', groupPrefix: 'domain-mode', portsGroupId: 'add-domain-ports-group', egressGroupId: 'add-domain-egress-group' },
    { hiddenId: 'edit-domain-mode', groupPrefix: 'edit-domain-mode', portsGroupId: 'edit-domain-ports-group', egressGroupId: 'edit-domain-egress-group' },
    { hiddenId: 'quick-add-domain-mode', groupPrefix: 'quick-add-domain-mode', portsGroupId: 'quick-add-domain-ports-group', egressGroupId: 'quick-add-domain-egress-group' },
  ].forEach(cfg => {
    const container = $(cfg.groupPrefix + '-radio-group');
    const hiddenInput = $(cfg.hiddenId);
    const portsGroup = $(cfg.portsGroupId);
    const egressGroup = $(cfg.egressGroupId);
    if (!container || !hiddenInput) return;

    container.querySelectorAll('input[type="radio"]').forEach(radio => {
      radio.addEventListener('change', () => {
        if (radio.checked) {
          hiddenInput.value = radio.value;
          if (portsGroup && egressGroup) {
            if (radio.value === 'direct' || radio.value === 'block') {
              hideEl(cfg.portsGroupId);
              hideEl(cfg.egressGroupId);
            } else {
              showEl(cfg.portsGroupId);
              if (isEgressProxyEnabled) {
                showEl(cfg.egressGroupId);
              } else {
                hideEl(cfg.egressGroupId);
              }
            }
          }
        }
      });
    });
  });

  updateEgressVisibility();
}

// ---------------------------------------------------------------------------
// Custom Bulk Action Modals
// ---------------------------------------------------------------------------
function initBulkActionModals() {
  if ($('bulk-assign-group-btn')) {
    $('bulk-assign-group-btn').addEventListener('click', () => {
      if (selectedDomains.size === 0) return;
      const overlay = $('bulk-group-modal-overlay');
      const desc = $('bulk-group-modal-desc');
      if (desc) desc.textContent = `Assign group for ${selectedDomains.size} selected domain(s).`;
      if (bulkGroupController) {
        bulkGroupController.refreshOptions();
        bulkGroupController.setValue('');
      }
      overlay.classList.remove('hidden');
    });
  }

  if ($('bulk-group-cancel-btn')) {
    $('bulk-group-cancel-btn').addEventListener('click', () => {
      $('bulk-group-modal-overlay').classList.add('hidden');
    });
  }

  if ($('bulk-group-confirm-btn')) {
    $('bulk-group-confirm-btn').addEventListener('click', async () => {
      const groupVal = ($('bulk-group-val').value || '').trim();
      $('bulk-group-modal-overlay').classList.add('hidden');

      try {
        const res = await apiFetch('/api/domains/bulk-assign-group', {
          method: 'POST',
          body: JSON.stringify({
            domains: Array.from(selectedDomains),
            group_name: groupVal,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showToast(data.error || 'Bulk group assignment failed.', 'error');
          return;
        }
        showToast(`Updated group for ${data.updated} domain rule(s).`, 'success');
        selectedDomains.clear();
        loadDomains();
      } catch {
        showToast('An error occurred during group assignment.', 'error');
      }
    });
  }

  if ($('bulk-assign-egress-btn')) {
    $('bulk-assign-egress-btn').addEventListener('click', () => {
      if (selectedDomains.size === 0) return;
      const overlay = $('bulk-egress-modal-overlay');
      const desc = $('bulk-egress-modal-desc');
      if (desc) desc.textContent = `Set egress proxy mode for ${selectedDomains.size} selected domain(s).`;
      overlay.classList.remove('hidden');
    });
  }

  if ($('bulk-assign-mode-btn')) {
    $('bulk-assign-mode-btn').addEventListener('click', () => {
      if (selectedDomains.size === 0) return;
      const overlay = $('bulk-mode-modal-overlay');
      const desc = $('bulk-mode-modal-desc');
      if (desc) desc.textContent = `Set domain mode for ${selectedDomains.size} selected domain(s).`;
      overlay.classList.remove('hidden');
    });
  }

  if ($('bulk-mode-cancel-btn')) {
    $('bulk-mode-cancel-btn').addEventListener('click', () => {
      $('bulk-mode-modal-overlay').classList.add('hidden');
    });
  }

  if ($('bulk-mode-confirm-btn')) {
    $('bulk-mode-confirm-btn').addEventListener('click', async () => {
      const selectedRadio = document.querySelector('input[name="bulk-mode-radio"]:checked');
      const modeVal = selectedRadio ? selectedRadio.value : 'proxy';
      $('bulk-mode-modal-overlay').classList.add('hidden');

      try {
        const res = await apiFetch('/api/domains/bulk-assign-mode', {
          method: 'POST',
          body: JSON.stringify({
            domains: Array.from(selectedDomains),
            mode: modeVal,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showToast(data.error || 'Bulk domain mode update failed.', 'error');
          return;
        }
        showToast(`Updated mode for ${data.updated || selectedDomains.size} domain(s).`, 'success');
        selectedDomains.clear();
        loadDomains();
      } catch {
        showToast('Failed to update domain mode.', 'error');
      }
    });
  }

  if ($('bulk-egress-cancel-btn')) {
    $('bulk-egress-cancel-btn').addEventListener('click', () => {
      $('bulk-egress-modal-overlay').classList.add('hidden');
    });
  }

  if ($('bulk-egress-confirm-btn')) {
    $('bulk-egress-confirm-btn').addEventListener('click', async () => {
      const selectedRadio = document.querySelector('input[name="bulk-egress-radio"]:checked');
      const mode = selectedRadio ? selectedRadio.value : 'false';
      $('bulk-egress-modal-overlay').classList.add('hidden');

      try {
        const res = await apiFetch('/api/domains/bulk-assign-egress', {
          method: 'POST',
          body: JSON.stringify({
            domains: Array.from(selectedDomains),
            use_egress_proxy: mode,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showToast(data.error || 'Bulk egress proxy update failed.', 'error');
          return;
        }
        showToast(`Updated egress proxy for ${data.updated || selectedDomains.size} domain(s).`, 'success');
        selectedDomains.clear();
        loadDomains();
      } catch {
        showToast('Failed to update egress proxy.', 'error');
      }
    });
  }

  if ($('bulk-clear-btn')) {
    $('bulk-clear-btn').addEventListener('click', clearSelection);
  }

  if ($('domain-select-all')) {
    $('domain-select-all').addEventListener('change', (e) => {
      const checked = e.target.checked;
      allDomains.forEach(d => {
        if (checked) selectedDomains.add(d.domain);
        else selectedDomains.delete(d.domain);
      });
      renderDomains();
    });
  }

  if ($('blacklist-select-all')) {
    $('blacklist-select-all').addEventListener('change', (e) => {
      const checked = e.target.checked;
      allBlacklistEntries.forEach(b => {
        if (checked) selectedBlacklistIds.add(b.id);
        else selectedBlacklistIds.delete(b.id);
      });
      renderBlacklist();
    });
  }

  if ($('bulk-delete-btn')) {
    $('bulk-delete-btn').addEventListener('click', async () => {
      const tab = getActiveTab();
      if (tab === 'domains') {
        if (selectedDomains.size === 0) return;
        const confirmed = await showConfirmDialog({
          title: 'Bulk Delete Domain Rules',
          message: `Are you sure you want to delete ${selectedDomains.size} selected domain rule(s)?`,
          confirmText: `Delete ${selectedDomains.size} Rules`,
          isDanger: true,
        });
        if (!confirmed) return;

        try {
          const res = await apiFetch('/api/domains/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({ domains: Array.from(selectedDomains) }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            showToast(data.error || 'Bulk delete failed.', 'error');
            return;
          }
          showToast(`Deleted ${data.deleted} domain rule(s).`, 'success');
          selectedDomains.clear();
          loadDomains();
        } catch {
          showToast('An error occurred during bulk deletion.', 'error');
        }
      } else if (tab === 'blacklist') {
        if (selectedBlacklistIds.size === 0) return;
        const confirmed = await showConfirmDialog({
          title: 'Bulk Delete Blacklist Rules',
          message: `Are you sure you want to delete ${selectedBlacklistIds.size} selected blacklist entry(ies)?`,
          confirmText: `Delete ${selectedBlacklistIds.size} Rules`,
          isDanger: true,
        });
        if (!confirmed) return;

        try {
          const res = await apiFetch('/api/blacklist/bulk-delete', {
            method: 'POST',
            body: JSON.stringify({ ids: Array.from(selectedBlacklistIds) }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            showToast(data.error || 'Bulk delete failed.', 'error');
            return;
          }
          showToast(`Deleted ${data.deleted} blacklist rule(s).`, 'success');
          selectedBlacklistIds.clear();
          loadBlacklist();
        } catch {
          showToast('An error occurred during bulk deletion.', 'error');
        }
      }
    });
  }
}


// ---------------------------------------------------------------------------
// Flat vs Grouped View Mode Toggle
// ---------------------------------------------------------------------------
let domainViewMode = localStorage.getItem('domain-view-mode') || 'grouped';
let domainFlatPage = 1; // current page for flat-mode pagination (50 rows/page)

function initDomainViewToggle() {
  const modeContainer = $('domain-mode-tab-toggle');
  if (modeContainer) {
    setSegmentedValue('domain-mode-tab-toggle', currentDomainModeTab);
    modeContainer.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        modeContainer.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentDomainModeTab = btn.dataset.mode;
        domainFlatPage = 1;
        // Hide Egress bulk action if not in Proxy mode
        const bulkEgressBtn = $('bulk-assign-egress-btn');
        if (bulkEgressBtn) {
          if (currentDomainModeTab !== 'proxy') {
            hideEl('bulk-assign-egress-btn');
          } else {
            showEl('bulk-assign-egress-btn');
          }
        }
        renderDomains();
      });
    });
  }

  const container = $('domain-view-toggle');
  if (!container) return;
  setSegmentedValue('domain-view-toggle', domainViewMode);

  container.querySelectorAll('.segmented-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      domainViewMode = btn.dataset.view;
      domainFlatPage = 1;
      localStorage.setItem('domain-view-mode', domainViewMode);
      renderDomains();
    });
  });

  const flatPrev = $('domain-flat-prev-page');
  const flatNext = $('domain-flat-next-page');
  if (flatPrev) {
    flatPrev.addEventListener('click', () => {
      if (domainFlatPage > 1) {
        domainFlatPage--;
        renderDomains();
      }
    });
  }
  if (flatNext) {
    flatNext.addEventListener('click', () => {
      domainFlatPage++;
      renderDomains();
    });
  }
}

// ---------------------------------------------------------------------------
// Theme Toggle (Light / Dark Mode)
// ---------------------------------------------------------------------------
function initTheme() {
  const saved = localStorage.getItem('panel-theme') || 'dark';
  applyTheme(saved);

  const btn = $('theme-toggle-btn');
  if (btn) {
    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      const next = current === 'light' ? 'dark' : 'light';
      applyTheme(next);
      localStorage.setItem('panel-theme', next);
      showToast(`Switched to ${next === 'light' ? 'Light' : 'Dark'} theme.`, 'success');
    });
  }
}

function applyTheme(theme) {
  if (theme === 'light') {
    document.documentElement.setAttribute('data-theme', 'light');
    const sun = $('theme-icon-sun');
    const moon = $('theme-icon-moon');
    const text = $('theme-text');
    if (sun) sun.classList.remove('hidden');
    if (moon) moon.classList.add('hidden');
    if (text) text.textContent = 'Light';
  } else {
    document.documentElement.removeAttribute('data-theme');
    const sun = $('theme-icon-sun');
    const moon = $('theme-icon-moon');
    const text = $('theme-text');
    if (sun) sun.classList.add('hidden');
    if (moon) moon.classList.remove('hidden');
    if (text) text.textContent = 'Dark';
  }
}

window.fetchAppSettings = fetchAppSettings;
window.updateEgressVisibility = updateEgressVisibility;
