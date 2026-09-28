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

    // Admin Username
    if (s.admin_username) {
      const adminUserInput = $('admin-new-user');
      if (adminUserInput) adminUserInput.placeholder = s.admin_username;
    }

    // Allowed Destination Ports
    if (s.allowed_dest_ports && Array.isArray(s.allowed_dest_ports)) {
      const allowedPortsInput = $('settings-allowed-ports');
      if (allowedPortsInput) allowedPortsInput.value = s.allowed_dest_ports.join(', ');
    }

    // Server Listen Ports
    if (s.listen_ports && Array.isArray(s.listen_ports)) {
      const listenPortsInput = $('settings-listen-ports');
      if (listenPortsInput) listenPortsInput.value = s.listen_ports.join(', ');
    }
    if (s.listen_http_ports && Array.isArray(s.listen_http_ports)) {
      const listenHTTPPortsInput = $('settings-listen-http-ports');
      if (listenHTTPPortsInput) listenHTTPPortsInput.value = s.listen_http_ports.join(', ');
    }

    // Egress Proxy Settings
    if (s.egress_proxy_enabled !== undefined) {
      isEgressProxyEnabled = !!s.egress_proxy_enabled;
      const proxyRadioVal = s.egress_proxy_enabled ? 'true' : 'false';
      const proxyRadio = document.querySelector(`input[name="settings-proxy-radio"][value="${proxyRadioVal}"]`);
      if (proxyRadio) proxyRadio.checked = true;
      if (typeof updateEgressVisibility === 'function') {
        updateEgressVisibility();
      }
    }
    if (s.egress_proxy_addr !== undefined) {
      const proxyAddrInput = $('settings-proxy-addr');
      if (proxyAddrInput) proxyAddrInput.value = s.egress_proxy_addr || '';
    }
    if (s.egress_proxy_user !== undefined) {
      const proxyUserInput = $('settings-proxy-user');
      if (proxyUserInput) proxyUserInput.value = s.egress_proxy_user || '';
    }
    const proxyPassHint = $('settings-proxy-password-hint');
    if (proxyPassHint) {
      if (s.egress_proxy_has_password) {
        proxyPassHint.textContent = 'A password is currently saved. Leave blank to keep existing password.';
      } else {
        proxyPassHint.textContent = 'Optional password for proxy authentication.';
      }
    }

    // Service Uptime
    if (s.uptime_seconds !== undefined) {
      const uptimeBadge = $('service-uptime-badge');
      if (uptimeBadge) uptimeBadge.textContent = formatUptimeDuration(s.uptime_seconds);
    }

  } catch { /* ignore on settings tab not yet open */ }
}

function formatUptimeDuration(sec) {
  if (!sec || sec <= 0) return 'Just started';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (parts.length === 0 || s > 0) parts.push(`${s}s`);
  return parts.join(' ');
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

  // Admin Credentials form submit
  const adminForm = $('admin-credentials-form');
  if (adminForm) {
    adminForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('admin-credentials-msg');
      const currentPass = $('admin-current-pass') ? $('admin-current-pass').value : '';
      const newUser = $('admin-new-user') ? $('admin-new-user').value.trim() : '';
      const newPass = $('admin-new-pass') ? $('admin-new-pass').value : '';
      const confirmPass = $('admin-confirm-pass') ? $('admin-confirm-pass').value : '';

      if (newPass !== confirmPass) {
        showAlert('admin-credentials-msg', 'error', 'New password and confirmation do not match.');
        return;
      }
      if (newPass.length < 6) {
        showAlert('admin-credentials-msg', 'error', 'New password must be at least 6 characters.');
        return;
      }

      const saveBtn = $('admin-credentials-save-btn');
      if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Updating...';
      }

      try {
        const res = await apiFetch('/api/admin/credentials', {
          method: 'PUT',
          body: JSON.stringify({
            current_password: currentPass,
            new_username: newUser,
            new_password: newPass,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('admin-credentials-msg', 'error', data.error || 'Failed to update credentials.');
          return;
        }
        showAlert('admin-credentials-msg', 'success', 'Admin credentials updated successfully!');
        if ($('admin-current-pass')) $('admin-current-pass').value = '';
        if ($('admin-new-pass')) $('admin-new-pass').value = '';
        if ($('admin-confirm-pass')) $('admin-confirm-pass').value = '';
        if (data.username && $('admin-new-user')) {
          $('admin-new-user').value = '';
          $('admin-new-user').placeholder = data.username;
        }
      } catch {
        showAlert('admin-credentials-msg', 'error', 'Network error while updating credentials.');
      } finally {
        if (saveBtn) {
          saveBtn.disabled = false;
          saveBtn.textContent = 'Update Admin Credentials';
        }
      }
    });
  }

  // Allowed Destination Ports presets & save
  const portPresets = $('port-presets');
  if (portPresets) {
    portPresets.querySelectorAll('.port-preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const port = btn.dataset.port;
        const input = $('settings-allowed-ports');
        if (!input) return;
        const currentList = input.value.split(',').map(s => s.trim()).filter(Boolean);
        if (!currentList.includes(port)) {
          currentList.push(port);
          input.value = currentList.join(', ');
        }
      });
    });
  }

  const allowedPortsBtn = $('settings-allowed-ports-save-btn');
  if (allowedPortsBtn) {
    allowedPortsBtn.addEventListener('click', async () => {
      clearMessages('settings-allowed-ports-msg');
      const input = $('settings-allowed-ports');
      if (!input) return;
      const rawPorts = input.value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0 && n <= 65535);
      if (rawPorts.length === 0) {
        showAlert('settings-allowed-ports-msg', 'error', 'Please enter at least one valid port number.');
        return;
      }

      allowedPortsBtn.disabled = true;
      allowedPortsBtn.textContent = 'Saving...';
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({ allowed_dest_ports: rawPorts }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-allowed-ports-msg', 'error', data.error || 'Failed to save allowed ports.');
          return;
        }
        showAlert('settings-allowed-ports-msg', 'success', 'Allowed destination ports updated immediately.');
      } catch {
        showAlert('settings-allowed-ports-msg', 'error', 'Network error.');
      } finally {
        allowedPortsBtn.disabled = false;
        allowedPortsBtn.textContent = 'Save Allowed Ports';
      }
    });
  }

  // Listen Ports save
  const listenPortsBtn = $('settings-listen-ports-save-btn');
  if (listenPortsBtn) {
    listenPortsBtn.addEventListener('click', async () => {
      clearMessages('settings-listen-ports-msg');
      const tlsInput = $('settings-listen-ports');
      const httpInput = $('settings-listen-http-ports');
      if (!tlsInput || !httpInput) return;

      const rawTLSPorts = tlsInput.value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0 && n <= 65535);
      const rawHTTPPorts = httpInput.value.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0 && n <= 65535);

      if (rawTLSPorts.length === 0 || rawHTTPPorts.length === 0) {
        showAlert('settings-listen-ports-msg', 'error', 'TLS and HTTP ports cannot be empty.');
        return;
      }

      listenPortsBtn.disabled = true;
      listenPortsBtn.textContent = 'Saving...';
      try {
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify({
            listen_ports: rawTLSPorts,
            listen_http_ports: rawHTTPPorts,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-listen-ports-msg', 'error', data.error || 'Failed to save listen ports.');
          return;
        }
        showAlert('settings-listen-ports-msg', 'success', 'Listen ports saved! To bind the new ports, restart the service below.');
      } catch {
        showAlert('settings-listen-ports-msg', 'error', 'Network error.');
      } finally {
        listenPortsBtn.disabled = false;
        listenPortsBtn.textContent = 'Save Listen Ports';
      }
    });
  }

  // Egress Proxy settings save & test
  const proxySaveBtn = $('settings-proxy-save-btn');
  if (proxySaveBtn) {
    proxySaveBtn.addEventListener('click', async () => {
      clearMessages('settings-proxy-msg');
      const selectedRadio = document.querySelector('input[name="settings-proxy-radio"]:checked');
      const enabled = selectedRadio ? selectedRadio.value === 'true' : false;
      const addr = $('settings-proxy-addr') ? $('settings-proxy-addr').value.trim() : '';
      const user = $('settings-proxy-user') ? $('settings-proxy-user').value.trim() : '';
      const pass = $('settings-proxy-password') ? $('settings-proxy-password').value : '';

      if (enabled && !addr) {
        showAlert('settings-proxy-msg', 'error', 'Proxy server address is required when proxy is enabled.');
        return;
      }

      proxySaveBtn.disabled = true;
      proxySaveBtn.textContent = 'Saving...';
      try {
        const payload = {
          egress_proxy_enabled: enabled,
          egress_proxy_addr: addr,
          egress_proxy_user: user,
        };
        if (pass) {
          payload.egress_proxy_password = pass;
        }
        const res = await apiFetch('/api/settings', {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showAlert('settings-proxy-msg', 'error', data.error || 'Failed to save proxy settings.');
          return;
        }
        isEgressProxyEnabled = enabled;
        if (typeof updateEgressVisibility === 'function') updateEgressVisibility();
        showAlert('settings-proxy-msg', 'success', 'Egress proxy settings saved and updated live!');
        if (pass && $('settings-proxy-password')) {
          $('settings-proxy-password').value = '';
        }
        if (typeof loadSettings === 'function') loadSettings();
      } catch {
        showAlert('settings-proxy-msg', 'error', 'Network error.');
      } finally {
        proxySaveBtn.disabled = false;
        proxySaveBtn.textContent = 'Save Proxy Settings';
      }
    });
  }

  const proxyTestBtn = $('settings-proxy-test-btn');
  if (proxyTestBtn) {
    proxyTestBtn.addEventListener('click', async () => {
      clearMessages('settings-proxy-msg');
      proxyTestBtn.disabled = true;
      proxyTestBtn.innerHTML = '<span class="spinner spinner-xs"></span> Testing...';
      try {
        const res = await apiFetch('/api/settings/test-proxy', {
          method: 'POST',
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.ok) {
          showAlert('settings-proxy-msg', 'error', 'Connection test failed: ' + (data.error || 'Unable to connect to proxy.'));
          return;
        }
        showAlert('settings-proxy-msg', 'success', `Proxy connection successful! Latency: ${data.latency_ms}ms.`);
      } catch {
        showAlert('settings-proxy-msg', 'error', 'Test connection failed due to network error.');
      } finally {
        proxyTestBtn.disabled = false;
        proxyTestBtn.innerHTML = `
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
          </svg>
          Test Connection
        `;
      }
    });
  }

  // Service Restart modal & execution
  const restartBtn = $('settings-restart-service-btn');
  const restartModal = $('service-restart-modal');
  const restartCancelBtn = $('service-restart-cancel-btn');
  const restartConfirmBtn = $('service-restart-confirm-btn');
  const restartModalContent = $('restart-modal-content');
  const restartModalProgress = $('restart-modal-progress');

  if (restartBtn && restartModal) {
    restartBtn.addEventListener('click', () => {
      if (restartModalContent) restartModalContent.classList.remove('hidden');
      if (restartModalProgress) restartModalProgress.classList.add('hidden');
      restartModal.classList.remove('hidden');
    });

    if (restartCancelBtn) {
      restartCancelBtn.addEventListener('click', () => {
        restartModal.classList.add('hidden');
      });
    }

    if (restartConfirmBtn) {
      restartConfirmBtn.addEventListener('click', async () => {
        restartConfirmBtn.disabled = true;
        try {
          const res = await apiFetch('/api/service/restart', { method: 'POST' });
          if (!res.ok) {
            showAlert('settings-restart-msg', 'error', 'Failed to initiate service restart.');
            restartModal.classList.add('hidden');
            restartConfirmBtn.disabled = false;
            return;
          }
        } catch {
          // If server drops connection immediately during shutdown, proceed
        }

        if (restartModalContent) restartModalContent.classList.add('hidden');
        if (restartModalProgress) restartModalProgress.classList.remove('hidden');

        let remaining = 3;
        const timerEl = $('restart-countdown-timer');
        const descEl = $('restart-countdown-desc');
        const interval = setInterval(async () => {
          remaining--;
          if (timerEl) timerEl.textContent = Math.max(0, remaining);
          if (remaining <= 0) {
            clearInterval(interval);
            if (descEl) descEl.textContent = 'Pinging service...';
            let attempts = 0;
            const pollInterval = setInterval(async () => {
              attempts++;
              try {
                const check = await fetch(getApiUrl('/api/settings'), { method: 'GET', credentials: 'same-origin' });
                if (check.ok) {
                  clearInterval(pollInterval);
                  if (descEl) descEl.textContent = 'Service is back online! Reloading...';
                  setTimeout(() => {
                    window.location.reload();
                  }, 800);
                }
              } catch {
                if (attempts > 15) {
                  clearInterval(pollInterval);
                  if (descEl) descEl.textContent = 'Service restart may take longer. Please refresh manually.';
                }
              }
            }, 1000);
          }
        }, 1000);
      });
    }
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

