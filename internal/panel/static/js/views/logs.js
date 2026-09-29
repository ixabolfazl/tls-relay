/**
 * Request logs view: live traffic inspection, filters, quick-rule creation, and logging configuration.
 * Fixes B6 (rule matching / quick-add "+"), B7 (destructive confirm styling), F13 (conditional polling).
 */

import { html, raw, setHtml, $, $$, escapeHtml } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatDateTime, formatDate, formatCount } from '../core/format.js';
import { Poller } from '../core/poller.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { getStatusMeta } from '../domain/status.js';
import { matchRule } from '../domain/rules.js';
import { createDomainRuleForm } from './domain-rule-form.js';
import { store } from '../core/store.js';

export function mount(container) {
  let logs = [];
  let totalLogs = null;
  let domainRules = [];
  let currentPage = 1;
  let pageSize = 50;
  let autoRefresh = true;
  let cursorStack = [null];
  let hasMore = false;

  const filters = {
    domain: '',
    client_ip: '',
    username: '',
    request_type: '',
  };

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Header & Config Bar -->
        <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Request Logs</h1>
            <p class="text-xs text-txt-muted mt-0.5">Live audit trail of DNS queries, TLS handshakes, and HTTP traffic</p>
          </div>

          <!-- Logging Config Quick Bar -->
          <div class="card p-2 px-4 flex flex-wrap items-center gap-4 text-xs">
            <div class="flex items-center gap-2">
              <label for="logs-enable-switch" class="font-medium text-txt select-none cursor-pointer">Logging:</label>
              <input id="logs-enable-switch" type="checkbox" class="checkbox" />
            </div>

            <div class="flex items-center gap-2">
              <label for="logs-retention-select" class="text-txt-muted">Retention:</label>
              <select id="logs-retention-select" class="select select-sm py-0.5 text-xs w-32">
                <option value="24h">1 Day (24h)</option>
                <option value="3d">3 Days</option>
                <option value="7d">7 Days</option>
                <option value="14d">14 Days</option>
                <option value="30d">30 Days</option>
                <option value="90d">90 Days</option>
                <option value="180d">180 Days</option>
                <option value="365d">365 Days</option>
              </select>
            </div>

            <button id="logs-save-config-btn" type="button" class="btn btn-secondary btn-sm">Save Config</button>
            <button id="logs-clear-btn" type="button" class="btn btn-danger-ghost btn-sm text-xs">Clear All Logs</button>
          </div>
        </div>

        <!-- Filters & Table Card -->
        <div class="card">
          <!-- Filter Controls -->
          <div class="p-4 border-b border-border grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 items-center">
            <div class="relative">
              <input
                id="filter-domain"
                type="text"
                class="input input-sm pl-7 text-xs font-mono"
                placeholder="Filter domain..."
              />
              <svg class="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-txt-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
            </div>

            <div>
              <input
                id="filter-ip"
                type="text"
                class="input input-sm text-xs font-mono"
                placeholder="Client IP..."
              />
            </div>

            <div>
              <input
                id="filter-username"
                type="text"
                class="input input-sm text-xs"
                placeholder="Username..."
              />
            </div>

            <div>
              <select id="filter-type" class="select select-sm text-xs">
                <option value="">All Types (DNS/TLS/HTTP)</option>
                <option value="DNS">DNS Only</option>
                <option value="TLS">TLS SNI Only</option>
                <option value="HTTP">HTTP Host Only</option>
              </select>
            </div>

            <div class="flex items-center justify-between sm:justify-end gap-3">
              <div class="flex items-center gap-1.5 text-xs text-txt-muted">
                <input id="logs-auto-refresh-switch" type="checkbox" class="checkbox" checked />
                <label for="logs-auto-refresh-switch" class="cursor-pointer select-none">Auto (10s)</label>
              </div>
              <button id="logs-refresh-btn" type="button" class="btn btn-secondary btn-sm" title="Refresh logs">
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
              </button>
            </div>
          </div>

          <!-- Logs Table -->
          <div class="overflow-x-auto">
            <table class="table text-xs">
              <thead>
                <tr>
                  <th class="table-th">Client IP</th>
                  <th class="table-th">Timestamp</th>
                  <th class="table-th">Type</th>
                  <th class="table-th">Client</th>
                  <th class="table-th">Domain / Hostname</th>
                  <th class="table-th">Port</th>
                  <th class="table-th">Status</th>
                  <th class="table-th w-10"></th>
                </tr>
              </thead>
              <tbody id="logs-table-body">
                <tr>
                  <td colspan="8" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading request logs...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Pagination Footer -->
          <div class="card-footer flex flex-col sm:flex-row items-center justify-between gap-3">
            <div class="flex items-center gap-3 text-xs text-txt-muted">
              <span id="logs-page-info">Showing 0 of 0</span>
              <div class="flex items-center gap-1.5">
                <span>Per page:</span>
                <select id="logs-page-size-select" class="select select-sm py-0.5 text-xs w-16">
                  <option value="25">25</option>
                  <option value="50" selected>50</option>
                  <option value="100">100</option>
                </select>
              </div>
            </div>

            <div class="flex items-center gap-2">
              <button id="logs-prev-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Previous</button>
              <span id="logs-page-num" class="text-xs font-medium text-txt px-2">Page 1</span>
              <button id="logs-next-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>
    `
  );

  function normalizeRetention(val) {
    if (!val) return '7d';
    const s = String(val).trim().toLowerCase();
    if (s === '24h' || s === '1d' || s === '1') return '24h';
    if (s === '72h' || s === '3d' || s === '3') return '3d';
    if (s === '168h' || s === '168h0m0s' || s === '7d' || s === '7') return '7d';
    if (s === '336h' || s === '336h0m0s' || s === '14d' || s === '14') return '14d';
    if (s === '720h' || s === '30d' || s === '30') return '30d';
    if (s === '90d' || s === '90') return '90d';
    if (s === '180d' || s === '180') return '180d';
    if (s === '365d' || s === '365') return '365d';
    return s;
  }

  // Load Settings for Config Bar
  async function loadSettings() {
    try {
      const s = await api.getSettings();
      $('#logs-enable-switch', container).checked = Boolean(s.request_logs_enabled);
      const retentionSelect = $('#logs-retention-select', container);
      const normVal = normalizeRetention(s.request_logs_retention);
      if (!Array.from(retentionSelect.options).some((opt) => opt.value === normVal)) {
        const opt = document.createElement('option');
        opt.value = normVal;
        opt.textContent = `${normVal}`;
        retentionSelect.appendChild(opt);
      }
      retentionSelect.value = normVal;
    } catch (err) {
      console.warn('Logs settings load error:', err);
    }
  }

  // Save Logging Config
  $('#logs-save-config-btn', container).addEventListener('click', async () => {
    const enabled = $('#logs-enable-switch', container).checked;
    const retention = $('#logs-retention-select', container).value || '7d';

    try {
      await api.updateSettings({
        request_logs_enabled: enabled,
        request_logs_retention: retention,
      });
      toast.success('Logging configuration saved');
    } catch (err) {
      toast.error(err.message || 'Failed to update logging settings');
    }
  });

  // Clear Logs (Fixes B7 destructive confirm styling)
  $('#logs-clear-btn', container).addEventListener('click', async () => {
    const confirmed = await dialog.confirm({
      title: 'Clear All Request Logs',
      message: 'Are you sure you want to delete all historical request logs? This action cannot be undone.',
      confirmText: 'Clear Logs',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await api.clearRequestLogs();
      toast.success('Request logs cleared');
      await fetchLogs();
    } catch (err) {
      toast.error(err.message || 'Failed to clear logs');
    }
  });

  // Auto-refresh switch
  $('#logs-auto-refresh-switch', container).addEventListener('change', (e) => {
    autoRefresh = e.target.checked;
    if (autoRefresh) logsPoller.start();
    else logsPoller.stop();
  });

  $('#logs-refresh-btn', container).addEventListener('click', () => {
    fetchLogs();
    toast.info('Logs refreshed');
  });

  function resetPagination() {
    currentPage = 1;
    cursorStack = [null];
    hasMore = false;
  }

  // Filters debounce
  let filterDebounceTimer = null;
  function onFilterChange() {
    clearTimeout(filterDebounceTimer);
    filterDebounceTimer = setTimeout(() => {
      filters.domain = $('#filter-domain', container).value.trim();
      filters.client_ip = $('#filter-ip', container).value.trim();
      filters.username = $('#filter-username', container).value.trim();
      filters.request_type = $('#filter-type', container).value;
      resetPagination();
      fetchLogs();
    }, 300);
  }

  $('#filter-domain', container).addEventListener('input', onFilterChange);
  $('#filter-ip', container).addEventListener('input', onFilterChange);
  $('#filter-username', container).addEventListener('input', onFilterChange);
  $('#filter-type', container).addEventListener('change', () => {
    filters.request_type = $('#filter-type', container).value;
    resetPagination();
    fetchLogs();
  });

  $('#logs-page-size-select', container).addEventListener('change', (e) => {
    pageSize = parseInt(e.target.value, 10) || 50;
    resetPagination();
    fetchLogs();
  });

  // Fetch Domain Rules (for rule matching & quick-add "+")
  async function fetchRules() {
    try {
      const res = await api.getDomains();
      domainRules = res.domains || [];
    } catch (err) {
      console.warn('Failed to load rules for matching:', err);
    }
  }

  // Fetch Logs
  async function fetchLogs() {
    const params = {
      limit: pageSize,
      ...filters,
    };
    const beforeId = cursorStack[currentPage - 1];
    if (beforeId) {
      params.before_id = beforeId;
    }

    try {
      const res = await api.getRequestLogs(params);
      logs = res.logs || [];
      totalLogs = res.total !== undefined ? res.total : null;
      hasMore = Boolean(res.has_more);
      if (hasMore && res.next_before_id) {
        cursorStack[currentPage] = res.next_before_id;
      }
      renderTable();
    } catch (err) {
      $('#logs-table-body', container).innerHTML = `
        <tr>
          <td colspan="8" class="table-td text-center py-8 text-danger">
            Failed to load request logs: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  // Render Logs Table
  function renderTable() {
    const tbody = $('#logs-table-body', container);

    if (logs.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="table-td text-center py-12 text-txt-subtle italic">
            No request logs matching current filters
          </td>
        </tr>
      `;
      updatePagination();
      return;
    }

    tbody.innerHTML = '';
    for (const log of logs) {
      const row = document.createElement('tr');
      row.className = 'table-row';

      const statusMeta = getStatusMeta(log.status);

      // Type Badge styling
      let typeBadge = `<span class="badge badge-neutral">${escapeHtml(log.request_type || '—')}</span>`;
      if (log.request_type === 'DNS') {
        typeBadge = `<span class="badge badge-info font-semibold">DNS</span>`;
      } else if (log.request_type === 'TLS') {
        typeBadge = `<span class="badge badge-success font-semibold">TLS</span>`;
      } else if (log.request_type === 'HTTP') {
        typeBadge = `<span class="badge badge-warning font-semibold">HTTP</span>`;
      }

      // Check matching domain rule (B6 fix: strict matching)
      const matchedRule = matchRule(log.domain, domainRules);

      row.innerHTML = `
        <td class="table-td font-mono text-txt-muted">
          ${escapeHtml(log.client_ip || '—')}
        </td>
        <td class="table-td text-txt-muted tabular-nums whitespace-nowrap">
          ${formatDateTime(log.timestamp)}
        </td>
        <td class="table-td">
          ${typeBadge}
        </td>
        <td class="table-td font-medium text-txt">
          ${log.username ? escapeHtml(log.username) : '<span class="text-txt-subtle italic">Anonymous</span>'}
        </td>
        <td class="table-td font-mono font-medium text-txt">
          <div class="flex items-center gap-1.5">
            <span>${escapeHtml(log.domain || '—')}</span>
            ${
              matchedRule
                ? `<span class="badge badge-neutral text-[10px] ml-1">${escapeHtml(matchedRule.group_name || matchedRule.mode || 'Rule')}</span>`
                : ''
            }
          </div>
        </td>
        <td class="table-td font-mono tabular-nums text-txt-muted">
          ${log.port || '—'}
        </td>
        <td class="table-td">
          <span class="badge ${statusMeta.className}">
            ${escapeHtml(statusMeta.label)}
          </span>
        </td>
        <td class="table-td text-right">
          ${
            !matchedRule && log.domain
              ? `<button type="button" class="quick-add-btn btn-icon-sm text-primary-600 hover:bg-primary-soft" title="Quick-add domain rule">
                   <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                 </button>`
              : ''
          }
        </td>
      `;

      // Quick add button handler
      const quickAddBtn = row.querySelector('.quick-add-btn');
      if (quickAddBtn) {
        quickAddBtn.addEventListener('click', () => {
          openQuickAddDialog(log.domain);
        });
      }

      tbody.appendChild(row);
    }

    updatePagination();
  }

  function openQuickAddDialog(domainName) {
    const groups = Array.from(new Set(domainRules.map((r) => r.group_name).filter(Boolean)));
    const formObj = createDomainRuleForm({
      initialData: { domain: domainName, mode: 'proxy' },
      groups,
      isEdit: false,
      layout: 'stacked',
    });

    dialog.open({
      title: `Quick Add Rule: ${domainName}`,
      content: formObj.el,
      size: 'md',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Add Rule',
          primary: true,
          onClick: async (_, { close }) => {
            const data = formObj.getData();
            try {
              await api.addDomain({
                domain: data.domain,
                group_name: data.group_name,
                mode: data.mode,
                ports: Array.isArray(data.ports) ? data.ports.join(',') : data.ports,
                use_egress_proxy: String(data.use_egress_proxy),
                include_subdomains: Boolean(data.include_subdomains),
              });
              toast.success(`Domain rule for ${domainName} added`);
              close();
              await fetchRules();
              resetPagination();
              await fetchLogs();
            } catch (err) {
              toast.error(err.message || 'Failed to add rule');
            }
          },
        },
      ],
    });
  }

  function updatePagination() {
    const pageInfo = $('#logs-page-info', container);
    if (totalLogs !== null && totalLogs !== undefined) {
      pageInfo.textContent = `Showing ${logs.length} of ${formatCount(totalLogs)}`;
    } else {
      pageInfo.textContent = `Showing ${logs.length}`;
    }
    $('#logs-page-num', container).textContent = `Page ${currentPage}`;

    $('#logs-prev-page-btn', container).disabled = currentPage <= 1;
    $('#logs-next-page-btn', container).disabled = !hasMore;
  }

  $('#logs-prev-page-btn', container).addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      fetchLogs();
    }
  });

  $('#logs-next-page-btn', container).addEventListener('click', () => {
    if (hasMore) {
      currentPage++;
      fetchLogs();
    }
  });

  // Poller: runs every 10s only if on page 1, tab is visible, and no filter input is focused (fixes F13)
  async function pollLogs() {
    if (!autoRefresh || currentPage !== 1) return;
    const activeEl = document.activeElement;
    if (activeEl && container.contains(activeEl) && activeEl.tagName === 'INPUT') {
      return; // Skip poll while user is typing in filter
    }
    await fetchLogs();
  }

  const logsPoller = new Poller(pollLogs, 10000, { immediate: false });
  logsPoller.start();

  // Boot
  loadSettings();
  fetchRules().then(() => fetchLogs());

  return {
    unmount: () => {
      logsPoller.stop();
      container.innerHTML = '';
    },
  };
}
