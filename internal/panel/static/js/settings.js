/* =========================================================================
   TLS Relay Admin Panel — settings.js
   Application Settings: access mode, unknown domain policy, timezone select,
   connection limits, request retention, custom path prefix redirects.
   ========================================================================= */

"use strict";

async function loadSettings() {
  try {
    const res = await apiFetch('/api/settings');
    if (!res.ok) return;
    const s = await res.json();

    // Access Mode radio group
    const accessRadio = document.querySelector(`input[name="settings-access-radio"][value="${s.access_mode}"]`);
    if (accessRadio) accessRadio.checked = true;

    // Unknown Domain Policy radio group
    const policyRadio = document.querySelector(`input[name="settings-policy-radio"][value="${s.unknown_domain_policy}"]`);
    if (policyRadio) policyRadio.checked = true;

    // Timezone
    currentTimezone = s.timezone || 'UTC';
    populateTimezoneSelect();
    const tzSel = $('settings-timezone-select');
    if (tzSel) tzSel.value = currentTimezone;

    // Server domain
    currentServerDomain = s.server_domain || '';
    window.serverDomain = currentServerDomain;
    const domainInput = $('settings-server-domain-input');
    if (domainInput) domainInput.value = currentServerDomain;

    // Panel path
    const pathInput = $('settings-panel-path-input');
    if (pathInput) pathInput.value = s.panel_path || '/';

    // Panel address (read-only)
    const addrEl = $('settings-panel-addr');
    if (addrEl) addrEl.textContent = s.panel_addr || '—';

    // Connection Limits
    if (s.max_connections_per_ip !== undefined) {
      const maxConnInput = $('settings-max-connections');
      if (maxConnInput) maxConnInput.value = s.max_connections_per_ip;
    }

    // Request Logging Settings
    if (s.request_logs_enabled !== undefined) {
      const valStr = s.request_logs_enabled ? 'true' : 'false';
      const enabledRadio1 = document.querySelector(`input[name="settings-reqlog-radio"][value="${valStr}"]`);
      if (enabledRadio1) enabledRadio1.checked = true;
      const enabledRadio2 = document.querySelector(`input[name="tab-reqlog-status-radio"][value="${valStr}"]`);
      if (enabledRadio2) enabledRadio2.checked = true;
    }
    if (s.request_logs_retention) {
      const retentionInput1 = $('settings-reqlog-retention');
      if (retentionInput1) retentionInput1.value = s.request_logs_retention;
      const retentionInput2 = $('tab-reqlog-retention-input');
      if (retentionInput2) retentionInput2.value = s.request_logs_retention;
    }

    // DNS Passthrough for Unregistered IPs
    if (s.dns_unauthorized_passthrough !== undefined) {
      const passthroughValStr = s.dns_unauthorized_passthrough ? 'true' : 'false';
      const passthroughRadio = document.querySelector(`input[name="settings-dns-passthrough-radio"][value="${passthroughValStr}"]`);
      if (passthroughRadio) passthroughRadio.checked = true;
    }

    if (s.egress_proxy_enabled !== undefined) {
      isEgressProxyEnabled = !!s.egress_proxy_enabled;
      if (typeof updateEgressVisibility === 'function') {
        updateEgressVisibility();
      }
    }

  } catch { /* ignore on settings tab not yet open */ }
}

function initSettingsTab() {
  // Access Mode — immediate save on radio change
  document.querySelectorAll('input[name="settings-access-radio"]').forEach(radio => {
    radio.addEventListener('change', async () => {
      if (!radio.checked) return;
      const mode = radio.value;
      clearMessages('settings-access-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ access_mode: mode }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-access-msg', 'error', data.error || 'Failed to save access mode.');
          return;
        }
        showAlert('settings-access-msg', 'success', 'Access mode updated to "' + mode + '".');
      } catch {
        showAlert('settings-access-msg', 'error', 'Network error.');
      }
    });
  });

  // Unknown Domain Policy — immediate save on radio change
  document.querySelectorAll('input[name="settings-policy-radio"]').forEach(radio => {
    radio.addEventListener('change', async () => {
      if (!radio.checked) return;
      const policy = radio.value;
      clearMessages('settings-policy-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ unknown_domain_policy: policy }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-policy-msg', 'error', data.error || 'Failed to save policy.');
          return;
        }
        showAlert('settings-policy-msg', 'success', 'Policy updated to "' + policy + '".');
      } catch {
        showAlert('settings-policy-msg', 'error', 'Network error.');
      }
    });
  });

  // Connection Limits Save & Presets
  const maxConnPresets = $('max-conn-presets');
  if (maxConnPresets) {
    maxConnPresets.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = $('settings-max-connections');
        if (input) input.value = btn.dataset.val;
      });
    });
  }

  const limitsBtn = $('settings-limits-save-btn');
  if (limitsBtn) {
    limitsBtn.addEventListener('click', async () => {
      const maxConnInput = $('settings-max-connections');
      const maxConn = maxConnInput ? parseInt(maxConnInput.value, 10) : 200;
      if (isNaN(maxConn) || maxConn <= 0) {
        showAlert('settings-limits-msg', 'error', 'Max connections must be a positive number.');
        return;
      }

      clearMessages('settings-limits-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({
            max_connections_per_ip: maxConn,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-limits-msg', 'error', data.error || 'Failed to save connection limits.');
          return;
        }
        showAlert('settings-limits-msg', 'success', 'Connection limits updated to ' + maxConn + ' per IP.');
      } catch {
        showAlert('settings-limits-msg', 'error', 'Network error.');
      }
    });
  }

  // Timezone Save
  const tzBtn = $('settings-tz-save-btn');
  if (tzBtn) {
    tzBtn.addEventListener('click', async () => {
      const sel = $('settings-timezone-select');
      if (!sel) return;
      const tz = sel.value;
      clearMessages('settings-tz-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ timezone: tz }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-tz-msg', 'error', data.error || 'Failed to save timezone.');
          return;
        }
        currentTimezone = tz;
        showAlert('settings-tz-msg', 'success', 'Timezone saved. Timestamps will now display in ' + tz + '.');
        renderDomains();
        renderUsers();
        renderBlacklist();
        loadRequestLogs();
      } catch {
        showAlert('settings-tz-msg', 'error', 'Network error.');
      }
    });
  }

  // Server Domain Save
  const domainBtn = $('settings-domain-save-btn');
  if (domainBtn) {
    domainBtn.addEventListener('click', async () => {
      const input = $('settings-server-domain-input');
      const domainVal = input ? input.value.trim() : '';
      clearMessages('settings-domain-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ server_domain: domainVal }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-domain-msg', 'error', data.error || 'Failed to save server domain.');
          return;
        }
        currentServerDomain = data.server_domain || '';
        window.serverDomain = currentServerDomain;
        if (input) input.value = currentServerDomain;
        const msg = currentServerDomain
          ? `Server domain updated to "${currentServerDomain}". All generated links now use this domain.`
          : 'Server domain cleared. Links will now fallback to server IP address.';
        showAlert('settings-domain-msg', 'success', msg);
        if (typeof renderUsers === 'function') renderUsers();
      } catch {
        showAlert('settings-domain-msg', 'error', 'Network error.');
      }
    });
  }

  // Request Logging Settings Save & Presets
  const retentionPresets = $('retention-presets');
  if (retentionPresets) {
    retentionPresets.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = $('settings-reqlog-retention');
        if (input) input.value = btn.dataset.val;
      });
    });
  }

  const reqlogBtn = $('settings-reqlog-save-btn');
  if (reqlogBtn) {
    reqlogBtn.addEventListener('click', async () => {
      const enabledRadio = document.querySelector('input[name="settings-reqlog-radio"]:checked');
      const enabled = enabledRadio ? enabledRadio.value === 'true' : true;
      const retentionInput = $('settings-reqlog-retention');
      const retention = retentionInput ? retentionInput.value.trim() : '24h';

      clearMessages('settings-reqlog-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({
            request_logs_enabled: enabled,
            request_logs_retention: retention,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-reqlog-msg', 'error', data.error || 'Failed to save logging settings.');
          return;
        }
        showAlert('settings-reqlog-msg', 'success', 'Request logging settings saved.');
      } catch {
        showAlert('settings-reqlog-msg', 'error', 'Network error.');
      }
    });
  }

  // Panel Path Save — shows confirmation modal
  const pathSaveBtn = $('settings-path-save-btn');
  if (pathSaveBtn) {
    pathSaveBtn.addEventListener('click', () => {
      const pathInput = $('settings-panel-path-input');
      if (!pathInput) return;
      const newPath = pathInput.value.trim();
      if (!newPath.startsWith('/')) {
        showAlert('settings-path-msg', 'error', 'Path must start with /.');
        return;
      }
      clearMessages('settings-path-msg');
      const modalPathEl = $('path-modal-new-path');
      if (modalPathEl) modalPathEl.textContent = newPath;
      const modal = $('path-change-modal');
      if (modal) modal.classList.remove('hidden');
    });
  }

  const pathModalCancel = $('path-modal-cancel');
  if (pathModalCancel) {
    pathModalCancel.addEventListener('click', () => {
      const modal = $('path-change-modal');
      if (modal) modal.classList.add('hidden');
    });
  }

  const pathModalConfirm = $('path-modal-confirm');
  if (pathModalConfirm) {
    pathModalConfirm.addEventListener('click', async () => {
      const pathInput = $('settings-panel-path-input');
      if (!pathInput) return;
      const newPath = pathInput.value.trim();
      const modal = $('path-change-modal');
      if (modal) modal.classList.add('hidden');

      clearMessages('settings-path-msg');
      const btn = pathModalConfirm;
      btn.disabled = true;
      btn.textContent = 'Applying…';

      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ panel_path: newPath }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-path-msg', 'error', data.error || 'Failed to apply panel path.');
          return;
        }
        window.location.href = data.panel_path || '/';
      } catch {
        showAlert('settings-path-msg', 'error', 'Network error.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Apply & Redirect';
      }
    });
  }

  // DNS Passthrough for Unregistered IPs — immediate save on radio change
  document.querySelectorAll('input[name="settings-dns-passthrough-radio"]').forEach(radio => {
    radio.addEventListener('change', async () => {
      if (!radio.checked) return;
      const enabled = radio.value === 'true';
      clearMessages('settings-dns-passthrough-msg');
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ dns_unauthorized_passthrough_enabled: enabled }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-dns-passthrough-msg', 'error', data.error || 'Failed to save DNS passthrough setting.');
          return;
        }
        showAlert('settings-dns-passthrough-msg', 'success', 'DNS Passthrough updated to ' + (enabled ? 'Enabled' : 'Disabled') + '.');
      } catch {
        showAlert('settings-dns-passthrough-msg', 'error', 'Network error.');
      }
    });
  });

  // Backup database listener
  if ($('download-backup-btn')) {
    $('download-backup-btn').addEventListener('click', () => {
      window.location.href = getApiUrl('api/backup');
    });
  }

  // Export / Import UI Handlers
  if ($('download-export-btn')) {
    $('download-export-btn').addEventListener('click', () => {
      window.location.href = getApiUrl('/api/export');
    });
  }

  if ($('import-form')) {
    $('import-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('import-error', 'import-success');

      const fileInput = $('import-file');
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        showError('import-error', 'Please select a JSON export file to import.');
        return;
      }

      const file = fileInput.files[0];
      const reader = new FileReader();

      reader.onload = async (evt) => {
        try {
          const payload = JSON.parse(evt.target.result);
          const btn = $('import-btn');
          if (btn) {
            btn.disabled = true;
            btn.textContent = 'Importing...';
          }

          const res = await apiFetch('/api/import', {
            method: 'POST',
            body: JSON.stringify(payload),
          });

          const data = await res.json().catch(() => ({}));
          if (!res.ok) {
            showError('import-error', data.error || 'Import failed validation or database write error.');
            return;
          }

          const addedDomains = (data.domains_added || 0) + (data.domains_updated || 0);
          const addedUsers = (data.users_added || 0) + (data.users_updated || 0);
          const addedBlacklist = (data.blacklist_added || 0) + (data.blacklist_updated || 0);
          showSuccess('import-success', `Successfully imported! Processed: ${addedDomains} domains, ${addedUsers} users, ${addedBlacklist} blacklist rules.`);
          if (typeof loadDomains === 'function') loadDomains();
          if (typeof loadUsers === 'function') loadUsers();
          if (typeof loadBlacklist === 'function') loadBlacklist();
          if (typeof loadSettings === 'function') loadSettings();
        } catch (err) {
          showError('import-error', err.message || 'Invalid JSON export file format or import error.');
        } finally {
          const btn = $('import-btn');
          if (btn) {
            btn.disabled = false;
            btn.textContent = 'Import Configuration';
          }
        }
      };

      reader.readAsText(file);
    });
  }
}

window.initSettingsTab = initSettingsTab;

function showAlert(id, type, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'alert ' + (type === 'success' ? 'alert-success' : 'alert-error');
  el.classList.remove('hidden');
  if (type === 'success') {
    setTimeout(() => el.classList.add('hidden'), 4500);
  }
}

