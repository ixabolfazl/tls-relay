/* =========================================================================
   TLS Relay Admin Panel — requestlogs.js
   Request logs viewing: filters, pagination, quick add domain modal, and
   rejection status badge colors.
   ========================================================================= */

"use strict";

let reqLogCurrentPage = 0;
let reqLogLimit = 50;
let reqLogTotal = 0;
let reqLogDebounceTimer = null;
let reqLogPollInterval = null;

function startReqLogPolling() {
  stopReqLogPolling();
  loadRequestLogs();
  reqLogPollInterval = setInterval(loadRequestLogs, 10000);
}

function stopReqLogPolling() {
  if (reqLogPollInterval) {
    clearInterval(reqLogPollInterval);
    reqLogPollInterval = null;
  }
}

async function loadRequestLogs() {
  const tbody = $('reqlog-tbody');
  if (!tbody) return;

  const domain = ($('reqlog-filter-domain') ? $('reqlog-filter-domain').value : '').trim();
  const clientIP = ($('reqlog-filter-ip') ? $('reqlog-filter-ip').value : '').trim();
  const username = ($('reqlog-filter-user') ? $('reqlog-filter-user').value : '').trim();
  const reqType = ($('reqlog-filter-type') ? $('reqlog-filter-type').value : '').trim();

  const params = new URLSearchParams();
  if (domain) params.set('domain', domain);
  if (clientIP) params.set('client_ip', clientIP);
  if (username) params.set('username', username);
  if (reqType) params.set('request_type', reqType);

  const offset = reqLogCurrentPage * reqLogLimit;
  params.set('limit', reqLogLimit);
  params.set('offset', offset);

  try {
    const res = await apiFetch(`/api/request-logs?${params.toString()}`);
    if (!res.ok) return;
    const data = await res.json();
    const logs = data.logs || [];
    reqLogTotal = data.total || 0;

    renderRequestLogs(logs);
    updateRequestLogsPagination();
  } catch {
    tbody.innerHTML = `<tr><td colspan="7" class="text-danger" style="text-align:center;">Failed to load request logs.</td></tr>`;
  }
}

function findDomainRuleForHostname(hostname) {
  if (!hostname) return null;
  const clean = hostname.trim().toLowerCase().replace(/^\*\./, '');
  if (!clean) return null;

  // 1. Exact match (e.g. "example.com" or "*.example.com")
  const exact = allDomains.find(d => d.domain.toLowerCase() === clean || d.domain.toLowerCase() === hostname.toLowerCase());
  if (exact) return exact;

  // 2. Wildcard match (e.g. "sub.example.com" matching "*.example.com")
  const parts = clean.split('.');
  for (let i = 1; i < parts.length; i++) {
    const wildcard = '*.' + parts.slice(i).join('.');
    const match = allDomains.find(d => d.domain.toLowerCase() === wildcard);
    if (match) return match;
  }

  // 3. Subdomain match against parent domain rule
  for (let i = 1; i < parts.length; i++) {
    const parent = parts.slice(i).join('.');
    const parentRule = allDomains.find(d => d.domain.toLowerCase() === parent);
    if (parentRule) return parentRule;
  }

  return null;
}

function formatRouteBadge(l, matchedRule) {
  const pillStyle = 'border-radius:9999px; font-size:0.75rem; padding:0.25rem 0.65rem; font-weight:600;';

  if (matchedRule) {
    const mode = (matchedRule.mode || 'proxy').toLowerCase();
    if (mode === 'direct') {
      return `<span class="badge" style="background:rgba(161, 161, 166, 0.15); color:#a1a1a6; border:1px solid rgba(161, 161, 166, 0.3); ${pillStyle}">Direct</span>`;
    }
    if (mode === 'block') {
      return `<span class="badge" style="background:rgba(255, 69, 58, 0.15); color:#ff453a; border:1px solid rgba(255, 69, 58, 0.3); ${pillStyle}">Block</span>`;
    }

    const pVal = (matchedRule.use_egress_proxy || 'default').toLowerCase();
    if (pVal === 'true') {
      return `<span class="badge" style="background:rgba(48, 209, 88, 0.15); color:#30d158; border:1px solid rgba(48, 209, 88, 0.3); ${pillStyle}">Proxy+</span>`;
    }
    return `<span class="badge" style="background:rgba(10, 132, 255, 0.15); color:#0a84ff; border:1px solid rgba(10, 132, 255, 0.3); ${pillStyle}">Proxy</span>`;
  }

  return `<span class="badge" style="background:rgba(161, 161, 166, 0.15); color:#a1a1a6; border:1px solid rgba(161, 161, 166, 0.3); ${pillStyle}">Direct</span>`;
}

function formatLogStatusCell(l) {
  const rawStatus = l.status || '';
  const pillStyle = 'border-radius:9999px; font-size:0.75rem; padding:0.25rem 0.65rem; font-weight:600;';

  if (rawStatus === 'resolved') {
    return `<span class="badge" style="background:rgba(48, 209, 88, 0.15); color:#30d158; border:1px solid rgba(48, 209, 88, 0.3); ${pillStyle}">Resolved</span>`;
  } else if (rawStatus === 'forwarded') {
    return `<span class="badge" style="background:rgba(10, 132, 255, 0.15); color:#0a84ff; border:1px solid rgba(10, 132, 255, 0.3); ${pillStyle}">Forwarded</span>`;
  } else if (rawStatus === 'connected') {
    return `<span class="badge" style="background:rgba(48, 209, 88, 0.15); color:#30d158; border:1px solid rgba(48, 209, 88, 0.3); ${pillStyle}">Connected</span>`;
  } else if (rawStatus === 'closed') {
    return `<span class="badge" style="background:rgba(161, 161, 166, 0.15); color:#a1a1a6; border:1px solid rgba(161, 161, 166, 0.3); ${pillStyle}">Closed</span>`;
  } else if (rawStatus === 'rejected_domain') {
    return `<span class="badge" style="background:rgba(255, 69, 58, 0.15); color:#ff453a; border:1px solid rgba(255, 69, 58, 0.3); ${pillStyle}">Rejected</span>`;
  } else if (rawStatus === 'rejected_client_ip') {
    return `<span class="badge" style="background:rgba(255, 69, 58, 0.15); color:#ff453a; border:1px solid rgba(255, 69, 58, 0.3); ${pillStyle}">Rejected (IP)</span>`;
  } else if (rawStatus === 'rejected_limit') {
    return `<span class="badge" style="background:rgba(255, 159, 10, 0.15); color:#ff9f0a; border:1px solid rgba(255, 159, 10, 0.3); ${pillStyle}">Rejected (Limit)</span>`;
  } else if (rawStatus === 'rejected_port') {
    return `<span class="badge" style="background:rgba(255, 69, 58, 0.15); color:#ff453a; border:1px solid rgba(255, 69, 58, 0.3); ${pillStyle}">Rejected (Port)</span>`;
  } else if (rawStatus.startsWith('rejected_') || rawStatus.startsWith('error')) {
    return `<span class="badge" style="background:rgba(255, 69, 58, 0.15); color:#ff453a; border:1px solid rgba(255, 69, 58, 0.3); ${pillStyle}">${escapeHtml(rawStatus)}</span>`;
  }
  return `<span class="badge" style="background:rgba(161, 161, 166, 0.15); color:#a1a1a6; border:1px solid rgba(161, 161, 166, 0.3); ${pillStyle}">${escapeHtml(rawStatus || '—')}</span>`;
}

function renderRequestLogs(logs) {
  const tbody = $('reqlog-tbody');
  if (!tbody) return;

  if (logs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="text-muted" style="text-align:center;">No request logs found.</td></tr>`;
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const userDisplay = l.username && l.username !== 'Unknown'
      ? `<strong>${escapeHtml(l.username)}</strong>`
      : `<span class="text-muted">Unknown</span>`;

    let typeBadge = '';
    if (l.request_type === 'DNS') {
      typeBadge = `<span class="badge" style="background:rgba(66, 153, 225, 0.15); color:#4299e1; border:1px solid rgba(66,153,225,0.3); border-radius:9999px; font-size:0.75rem; padding:0.25rem 0.65rem; font-weight:600;">DNS</span>`;
    } else if (l.request_type === 'HTTP') {
      typeBadge = `<span class="badge" style="background:rgba(237, 137, 54, 0.15); color:#ed8936; border:1px solid rgba(237,137,54,0.3); border-radius:9999px; font-size:0.75rem; padding:0.25rem 0.65rem; font-weight:600;">HTTP</span>`;
    } else {
      typeBadge = `<span class="badge" style="background:rgba(159, 122, 234, 0.15); color:#9f7aea; border:1px solid rgba(159,122,234,0.3); border-radius:9999px; font-size:0.75rem; padding:0.25rem 0.65rem; font-weight:600;">TLS</span>`;
    }

    const ts = formatTimestamp(l.timestamp);
    const domainStr = l.domain || '';
    const matchedRule = findDomainRuleForHostname(domainStr);

    const quickAddBtn = (domainStr && !matchedRule)
      ? `<button class="btn-quick-add-domain" data-domain="${escapeHtml(domainStr)}" title="Quick add '${escapeHtml(domainStr)}' to domain rules">+</button>`
      : ``;

    const routeBadge = formatRouteBadge(l, matchedRule);
    const statusContent = formatLogStatusCell(l);
    const domainVal = l.domain ? l.domain.trim() : '';
    const domainDisplay = domainVal ? `<code>${escapeHtml(domainVal)}</code>` : `<span class="text-muted">—</span>`;

    return `
      <tr>
        <td>${userDisplay}</td>
        <td><code>${escapeHtml(l.client_ip)}</code></td>
        <td>${typeBadge}</td>
        <td>${routeBadge}</td>
        <td>${domainDisplay}</td>
        <td>${l.port || '—'}</td>
        <td>${statusContent}</td>
        <td>${ts}</td>
        <td style="text-align:center;">${quickAddBtn}</td>
      </tr>
    `;
  }).join('');

  // Wire up quick-add buttons
  tbody.querySelectorAll('.btn-quick-add-domain[data-domain]').forEach(btn => {
    btn.addEventListener('click', () => openQuickAddDomainModal(btn.dataset.domain));
  });
}

function updateRequestLogsPagination() {
  const start = reqLogTotal > 0 ? (reqLogCurrentPage * reqLogLimit) + 1 : 0;
  const end = Math.min((reqLogCurrentPage + 1) * reqLogLimit, reqLogTotal);

  if ($('reqlog-pagination-info')) {
    $('reqlog-pagination-info').textContent = `Showing ${start}-${end} of ${reqLogTotal}`;
  }

  const prevBtn = $('reqlog-prev-page');
  const nextBtn = $('reqlog-next-page');

  if (prevBtn) prevBtn.disabled = reqLogCurrentPage === 0;
  if (nextBtn) nextBtn.disabled = end >= reqLogTotal;
}

function initRequestLogsTab() {
  const tabRetentionPresets = $('tab-retention-presets');
  if (tabRetentionPresets) {
    tabRetentionPresets.querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const input = $('tab-reqlog-retention-input');
        if (input) input.value = btn.dataset.val;
      });
    });
  }

  const tabReqlogSaveBtn = $('tab-reqlog-save-settings-btn');
  if (tabReqlogSaveBtn) {
    tabReqlogSaveBtn.addEventListener('click', async () => {
      const enabledRadio = document.querySelector('input[name="tab-reqlog-status-radio"]:checked');
      const enabled = enabledRadio ? enabledRadio.value === 'true' : true;
      const retentionInput = $('tab-reqlog-retention-input');
      const retention = retentionInput ? retentionInput.value.trim() : '24h';

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
          showToast(data.error || 'Failed to save logging settings.', 'error');
          return;
        }
        showToast('Request logging configuration saved.', 'success');
        const settingsRetention = $('settings-reqlog-retention');
        if (settingsRetention) settingsRetention.value = retention;
        const settingsRadio = document.querySelector(`input[name="settings-reqlog-radio"][value="${enabled ? 'true' : 'false'}"]`);
        if (settingsRadio) settingsRadio.checked = true;
        loadRequestLogs();
      } catch {
        showToast('Network error while saving settings.', 'error');
      }
    });
  }

  ['reqlog-filter-domain', 'reqlog-filter-ip', 'reqlog-filter-user'].forEach(id => {
    const el = $(id);
    if (el) {
      el.addEventListener('input', () => {
        clearTimeout(reqLogDebounceTimer);
        reqLogDebounceTimer = setTimeout(() => {
          reqLogCurrentPage = 0;
          loadRequestLogs();
        }, 300);
      });
    }
  });

  if ($('reqlog-filter-type')) {
    $('reqlog-filter-type').addEventListener('change', () => {
      reqLogCurrentPage = 0;
      loadRequestLogs();
    });
  }

  if ($('reqlog-prev-page')) {
    $('reqlog-prev-page').addEventListener('click', () => {
      if (reqLogCurrentPage > 0) {
        reqLogCurrentPage--;
        loadRequestLogs();
      }
    });
  }

  if ($('reqlog-next-page')) {
    $('reqlog-next-page').addEventListener('click', () => {
      if ((reqLogCurrentPage + 1) * reqLogLimit < reqLogTotal) {
        reqLogCurrentPage++;
        loadRequestLogs();
      }
    });
  }

  if ($('refresh-request-logs-btn')) {
    $('refresh-request-logs-btn').addEventListener('click', () => {
      loadRequestLogs();
      showToast('Request logs refreshed.', 'info');
    });
  }

  if ($('clear-request-logs-btn')) {
    $('clear-request-logs-btn').addEventListener('click', async () => {
      const ok = await showConfirmDialog({
        title: 'Clear Request Logs',
        message: 'Are you sure you want to permanently delete all stored request logs? This action cannot be undone.',
        confirmText: 'Clear Logs',
        confirmClass: 'btn btn-danger'
      });

      if (!ok) return;

      try {
        const res = await apiFetch('/api/request-logs/clear', { method: 'POST' });
        if (!res.ok) {
          showToast('Failed to clear request logs.', 'error');
          return;
        }
        showToast('All request logs cleared.', 'success');
        reqLogCurrentPage = 0;
        loadRequestLogs();
      } catch {
        showToast('Network error while clearing request logs.', 'error');
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Quick Add Domain from Request Logs
// ---------------------------------------------------------------------------
function openQuickAddDomainModal(domain) {
  const modal = $('quick-add-domain-modal');
  if (!modal) return;

  const nameInput = $('quick-add-domain-name');
  if (nameInput) nameInput.value = domain || '';

  const inclCheck = $('quick-add-domain-include-subdomains');
  if (inclCheck) inclCheck.checked = false;

  if (quickAddDomainGroupController) {
    quickAddDomainGroupController.refreshOptions();
    quickAddDomainGroupController.setValue('');
  } else {
    const groupInput = $('quick-add-domain-group');
    if (groupInput) groupInput.value = '';
  }

  const portsInput = $('quick-add-domain-ports');
  if (portsInput) portsInput.value = '443';

  const modeProxyRadio = document.querySelector('input[name="quick-add-domain-mode-radio"][value="proxy"]');
  if (modeProxyRadio) { modeProxyRadio.checked = true; modeProxyRadio.dispatchEvent(new Event('change')); }
  const modeHidden = $('quick-add-domain-mode');
  if (modeHidden) modeHidden.value = 'proxy';

  const defaultRadio = document.querySelector('input[name="quick-add-domain-egress-radio"][value="default"]');
  if (defaultRadio) defaultRadio.checked = true;
  const egressHidden = $('quick-add-domain-egress');
  if (egressHidden) egressHidden.value = 'default';

  clearMessages('quick-add-domain-error', 'quick-add-domain-success');

  modal.classList.remove('hidden');
  if (nameInput) nameInput.focus();
}

function closeQuickAddDomainModal() {
  const modal = $('quick-add-domain-modal');
  if (modal) modal.classList.add('hidden');
}

function initQuickAddDomainModal() {
  const radioGroup = $('quick-add-domain-egress-radio-group');
  if (radioGroup) {
    radioGroup.querySelectorAll('input[type="radio"]').forEach(radio => {
      radio.addEventListener('change', () => {
        const egressHidden = $('quick-add-domain-egress');
        if (egressHidden) egressHidden.value = radio.value;
      });
    });
  }

  if ($('close-quick-add-domain')) {
    $('close-quick-add-domain').addEventListener('click', closeQuickAddDomainModal);
  }
  if ($('cancel-quick-add-domain')) {
    $('cancel-quick-add-domain').addEventListener('click', closeQuickAddDomainModal);
  }

  const modal = $('quick-add-domain-modal');
  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeQuickAddDomainModal();
    });
  }

  const form = $('quick-add-domain-form');
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages('quick-add-domain-error', 'quick-add-domain-success');

    const btn = $('quick-add-domain-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Adding...'; }

    const domain = ($('quick-add-domain-name')?.value || '').trim();
    const groupName = ($('quick-add-domain-group')?.value || '').trim();
    const mode = $('quick-add-domain-mode')?.value || 'proxy';
    const ports = ($('quick-add-domain-ports')?.value || '443').trim();
    const egress = $('quick-add-domain-egress')?.value || 'default';
    const includeSubdomains = !!$('quick-add-domain-include-subdomains')?.checked;

    if (!domain) {
      showError('quick-add-domain-error', 'Domain name is required.');
      if (btn) { btn.disabled = false; btn.textContent = 'Add Domain Rule'; }
      return;
    }

    try {
      const res = await apiFetch('/api/domains', {
        method: 'POST',
        body: JSON.stringify({
          domain: domain,
          group_name: groupName,
          mode: mode,
          ports: ports,
          use_egress_proxy: egress,
          include_subdomains: includeSubdomains,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showError('quick-add-domain-error', data.error || 'Failed to add domain rule.');
        return;
      }
      showSuccess('quick-add-domain-success', `Domain "${domain}" added successfully!`);
      loadDomains();
      setTimeout(() => closeQuickAddDomainModal(), 1200);
    } catch {
      showError('quick-add-domain-error', 'Network error while adding domain.');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Add Domain Rule'; }
    }
  });
}
