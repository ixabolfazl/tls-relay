/**
 * Usage view: aggregated bandwidth and DNS query reporting by user and domain.
 * Fixes B5 (reads domains for range), B7 (destructive confirm), B11 (removes dead usage/daily call).
 */

import { html, raw, setHtml, $, $$, escapeHtml } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatCount, formatDate } from '../core/format.js';
import { TableState } from '../ui/table.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { renderGroupedBarChart } from '../ui/chart.js';

export function mount(container) {
  let activeRange = 'today';
  let activeSubTab = 'users'; // users | domains

  let usersUsage = [];
  let domainsUsage = [];
  let searchQuery = '';

  const tableState = new TableState({
    pageSize: 50,
    sortKey: 'usage',
    sortDir: 'desc',
    getId: (item) => item.username || item.domain || item.id,
  });

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Header & Range Control -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Usage Analytics</h1>
            <p class="text-xs text-txt-muted mt-0.5">Historical bandwidth consumption and DNS queries breakdown</p>
          </div>
          <div id="usage-range-segmented"></div>
        </div>

        <!-- 2 Summary Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="card p-5">
            <div class="text-xs font-medium text-txt-muted">Total Bandwidth Consumed</div>
            <div id="usage-total-bandwidth" class="text-3xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-5">
            <div class="text-xs font-medium text-txt-muted">Total DNS Queries</div>
            <div id="usage-total-dns" class="text-3xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
        </div>

        <!-- Breakdown Card -->
        <div class="card">
          <div class="p-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div id="usage-subtab-segmented"></div>
            <div class="relative w-full sm:w-64">
              <input
                id="usage-search-input"
                type="text"
                class="input pl-8 text-sm"
                placeholder="Search breakdown..."
              />
              <svg class="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-txt-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="table text-xs">
              <thead id="usage-table-head"></thead>
              <tbody id="usage-table-body">
                <tr>
                  <td colspan="7" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading usage analytics...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div id="usage-pagination" class="card-footer">
            <div id="usage-page-info" class="text-xs text-txt-muted">Showing 0 of 0</div>
            <div class="flex items-center gap-2">
              <button id="usage-prev-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Previous</button>
              <span id="usage-page-num" class="text-xs font-medium text-txt px-2">Page 1</span>
              <button id="usage-next-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>
    `
  );

  // Range segmented control
  const rangeContainer = $('#usage-range-segmented', container);
  const rangeSegmented = createSegmentedControl({
    options: [
      { value: 'today', label: 'Today' },
      { value: '7d', label: '7 Days' },
      { value: '30d', label: '30 Days' },
      { value: 'monthly', label: 'Monthly' },
      { value: 'all', label: 'All Time' },
    ],
    value: activeRange,
    size: 'sm',
    onChange: (val) => {
      activeRange = val;
      fetchUsageData();
    },
  });
  rangeContainer.appendChild(rangeSegmented.el);

  // Subtab segmented control (By User vs By Domain)
  const subtabContainer = $('#usage-subtab-segmented', container);
  const subtabSegmented = createSegmentedControl({
    options: [
      { value: 'users', label: 'By User' },
      { value: 'domains', label: 'By Domain' },
    ],
    value: activeSubTab,
    size: 'sm',
    onChange: (val) => {
      activeSubTab = val;
      tableState.currentPage = 1;
      tableState.sortKey = 'usage';
      tableState.sortDir = 'desc';
      renderTable();
    },
  });
  subtabContainer.appendChild(subtabSegmented.el);

  // Search input
  $('#usage-search-input', container).addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    tableState.currentPage = 1;
    renderTable();
  });

  // Fetch Usage Data
  async function fetchUsageData() {
    try {
      const [statsRes, usersRes, domainsRes] = await Promise.all([
        api.getStats(activeRange),
        api.getUsers(activeRange),
        api.getDomains(activeRange),
      ]);

      // Summary KPIs
      const tlsBytes = statsRes.tls_bytes_total || (statsRes.tls_bytes_sent || 0) + (statsRes.tls_bytes_received || 0);
      const httpBytes = statsRes.http_bytes_total || (statsRes.http_bytes_sent || 0) + (statsRes.http_bytes_received || 0);
      const globalTotalBytes = statsRes.global_bytes_total || tlsBytes + httpBytes;

      $('#usage-total-bandwidth', container).textContent = formatBytes(globalTotalBytes);
      $('#usage-total-dns', container).textContent = formatCount(statsRes.dns_requests_total || statsRes.user_dns_queries_total || 0);

      usersUsage = usersRes.users || [];
      domainsUsage = domainsRes.domains || [];

      renderTable();
    } catch (err) {
      $('#usage-table-body', container).innerHTML = `
        <tr>
          <td colspan="7" class="table-td text-center py-8 text-danger">
            Failed to load usage data: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  function renderTable() {
    const thead = $('#usage-table-head', container);
    const tbody = $('#usage-table-body', container);

    const customComparators = {
      usage: (a, b) => {
        const uA = (a.total_bytes_sent || 0) + (a.total_bytes_received || 0);
        const uB = (b.total_bytes_sent || 0) + (b.total_bytes_received || 0);
        return uA - uB;
      },
    };

    if (activeSubTab === 'users') {
      thead.innerHTML = `
        <tr>
          <th class="table-th cursor-pointer select-none" data-sort="username">User</th>
          <th class="table-th text-right cursor-pointer select-none" data-sort="total_dns_queries">DNS Queries</th>
          <th class="table-th text-right font-mono">Bytes Sent</th>
          <th class="table-th text-right font-mono">Bytes Received</th>
          <th class="table-th text-right font-mono cursor-pointer select-none" data-sort="usage">Total Bandwidth</th>
          <th class="table-th w-28 text-right">Actions</th>
        </tr>
      `;

      let filtered = usersUsage;
      if (searchQuery) {
        filtered = filtered.filter((u) => u.username.toLowerCase().includes(searchQuery));
      }

      const sorted = tableState.getSortedItems(filtered, customComparators);

      if (sorted.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="table-td text-center py-12 text-txt-subtle italic">No user usage data found</td>
          </tr>
        `;
        updatePagination(0, 0, 0, 1, 1);
        return;
      }

      const sliceInfo = tableState.getPageSlice(sorted);
      tbody.innerHTML = '';

      for (const u of sliceInfo.slice) {
        const row = document.createElement('tr');
        row.className = 'table-row';
        const total = (u.total_bytes_sent || 0) + (u.total_bytes_received || 0);

        row.innerHTML = `
          <td class="table-td font-medium text-txt">${escapeHtml(u.username)}</td>
          <td class="table-td text-right tabular-nums text-txt-muted">${formatCount(u.total_dns_queries || 0)}</td>
          <td class="table-td text-right font-mono tabular-nums text-txt-muted">${formatBytes(u.total_bytes_sent || 0)}</td>
          <td class="table-td text-right font-mono tabular-nums text-txt-muted">${formatBytes(u.total_bytes_received || 0)}</td>
          <td class="table-td text-right font-mono tabular-nums font-semibold text-txt">${formatBytes(total)}</td>
          <td class="table-td text-right">
            <div class="flex items-center justify-end gap-1">
              <button type="button" class="view-chart-btn btn btn-secondary btn-sm py-0.5 px-2 text-xs">Analytics</button>
              <button type="button" class="reset-btn btn btn-danger-ghost btn-sm py-0.5 px-1.5" title="Reset user usage">Reset</button>
            </div>
          </td>
        `;

        row.querySelector('.view-chart-btn').addEventListener('click', () => openUserAnalyticsDialog(u));
        row.querySelector('.reset-btn').addEventListener('click', () => resetUserUsage(u));

        tbody.appendChild(row);
      }

      updatePagination(
        sliceInfo.startIdx,
        sliceInfo.endIdx,
        sliceInfo.total,
        sliceInfo.currentPage,
        sliceInfo.totalPages
      );
    } else {
      // Domains Subtab
      thead.innerHTML = `
        <tr>
          <th class="table-th cursor-pointer select-none" data-sort="domain">Domain</th>
          <th class="table-th cursor-pointer select-none" data-sort="group_name">Group</th>
          <th class="table-th text-right font-mono">Bytes Sent</th>
          <th class="table-th text-right font-mono">Bytes Received</th>
          <th class="table-th text-right font-mono cursor-pointer select-none" data-sort="usage">Total Bandwidth</th>
          <th class="table-th cursor-pointer select-none" data-sort="created_at">Created</th>
        </tr>
      `;

      let filtered = domainsUsage;
      if (searchQuery) {
        filtered = filtered.filter(
          (d) =>
            d.domain.toLowerCase().includes(searchQuery) ||
            (d.group_name && d.group_name.toLowerCase().includes(searchQuery))
        );
      }

      const sorted = tableState.getSortedItems(filtered, customComparators);

      if (sorted.length === 0) {
        tbody.innerHTML = `
          <tr>
            <td colspan="6" class="table-td text-center py-12 text-txt-subtle italic">No domain usage data found</td>
          </tr>
        `;
        updatePagination(0, 0, 0, 1, 1);
        return;
      }

      const sliceInfo = tableState.getPageSlice(sorted);
      tbody.innerHTML = '';

      for (const d of sliceInfo.slice) {
        const row = document.createElement('tr');
        row.className = 'table-row';
        const total = (d.total_bytes_sent || 0) + (d.total_bytes_received || 0);

        row.innerHTML = `
          <td class="table-td font-mono font-medium text-txt">${escapeHtml(d.domain)}</td>
          <td class="table-td text-txt-muted">${d.group_name ? `<span class="badge badge-neutral">${escapeHtml(d.group_name)}</span>` : '—'}</td>
          <td class="table-td text-right font-mono tabular-nums text-txt-muted">${formatBytes(d.total_bytes_sent || 0)}</td>
          <td class="table-td text-right font-mono tabular-nums text-txt-muted">${formatBytes(d.total_bytes_received || 0)}</td>
          <td class="table-td text-right font-mono tabular-nums font-semibold text-txt">${formatBytes(total)}</td>
          <td class="table-td text-txt-muted">${formatDate(d.created_at)}</td>
        `;

        tbody.appendChild(row);
      }

      updatePagination(
        sliceInfo.startIdx,
        sliceInfo.endIdx,
        sliceInfo.total,
        sliceInfo.currentPage,
        sliceInfo.totalPages
      );
    }

    // Bind sorting headers
    $$('#usage-table-head th[data-sort]', container).forEach((th) => {
      th.addEventListener('click', () => {
        tableState.setSort(th.dataset.sort);
        renderTable();
      });
    });
  }

  // User Analytics Dialog (bandwidth & domain breakdown, fixes B5)
  async function openUserAnalyticsDialog(u) {
    const content = document.createElement('div');
    content.className = 'space-y-4';
    content.innerHTML = `
      <div class="flex items-center justify-between">
        <h4 class="text-sm font-bold text-txt">${escapeHtml(u.username)}</h4>
        <span class="badge badge-neutral font-mono">${activeRange}</span>
      </div>
      <div id="user-usage-chart" class="min-h-[180px]"></div>
      <div class="pt-2 border-t border-border">
        <h4 class="text-xs font-semibold uppercase text-txt-muted mb-2">Domains Accessed by User</h4>
        <div id="user-domains-table-box" class="max-h-48 overflow-y-auto">
          <div class="text-xs text-txt-subtle italic py-2">Loading user domains...</div>
        </div>
      </div>
    `;

    let chartObj = null;

    async function loadUserDetail() {
      try {
        const [usageRes, domRes] = await Promise.all([
          api.getUserUsage(u.id, activeRange),
          api.getUserUsageDomains(u.id, activeRange), // B5 fix: reads domains for range
        ]);

        // Daily traffic chart
        const days = usageRes.days || [];
        const chartData = days.map((d) => ({
          label: formatDate(d.date),
          sent: d.bytes_sent || 0,
          recv: d.bytes_received || 0,
        }));

        if (chartObj) chartObj.destroy();
        chartObj = renderGroupedBarChart(content.querySelector('#user-usage-chart'), {
          data: chartData,
          series: [
            { key: 'sent', label: 'Bytes Sent', color: '#3b82f6' },
            { key: 'recv', label: 'Bytes Received', color: '#10b981' },
          ],
          formatValue: (v) => formatBytes(v),
        });

        // Domains accessed table (B5 fix)
        const domains = domRes.domains || [];
        const box = content.querySelector('#user-domains-table-box');

        if (domains.length === 0) {
          box.innerHTML = `<div class="text-xs text-txt-subtle italic py-2">No domain traffic recorded for this user</div>`;
        } else {
          box.innerHTML = `
            <table class="table text-xs">
              <thead>
                <tr>
                  <th class="table-th py-1.5">Domain</th>
                  <th class="table-th py-1.5 text-right">Sent</th>
                  <th class="table-th py-1.5 text-right">Received</th>
                  <th class="table-th py-1.5 text-right">Total</th>
                </tr>
              </thead>
              <tbody>
                ${domains
                  .map(
                    (d) => `
                  <tr>
                    <td class="table-td py-1.5 font-mono font-medium">${escapeHtml(d.domain)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums">${formatBytes(d.bytes_sent)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums">${formatBytes(d.bytes_received)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums font-semibold">${formatBytes(
                      (d.bytes_sent || 0) + (d.bytes_received || 0)
                    )}</td>
                  </tr>
                `
                  )
                  .join('')}
              </tbody>
            </table>
          `;
        }
      } catch (err) {
        console.warn('User analytics error:', err);
      }
    }

    dialog.open({
      title: `User Usage Analytics: ${u.username}`,
      content,
      size: 'lg',
      actions: [{ text: 'Close', className: 'btn btn-secondary', value: true }],
      onClose: () => {
        if (chartObj) chartObj.destroy();
      },
    });

    loadUserDetail();
  }

  // Reset User Usage (Fixes B7 destructive confirm)
  async function resetUserUsage(u) {
    const confirmed = await dialog.confirm({
      title: `Reset Usage: ${u.username}`,
      message: `Are you sure you want to reset all recorded bandwidth and query counters for "${u.username}"?`,
      confirmText: 'Reset Usage',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await api.resetUserUsage(u.id);
      toast.success(`Usage counters reset for ${u.username}`);
      await fetchUsageData();
    } catch (err) {
      toast.error(err.message || 'Failed to reset usage');
    }
  }

  // Pagination
  function updatePagination(start, end, total, page, totalPages) {
    $('#usage-page-info', container).textContent =
      total > 0 ? `Showing ${start}–${end} of ${total}` : 'Showing 0 of 0';
    $('#usage-page-num', container).textContent = `Page ${page} of ${totalPages}`;

    $('#usage-prev-page-btn', container).disabled = page <= 1;
    $('#usage-next-page-btn', container).disabled = page >= totalPages;
  }

  $('#usage-prev-page-btn', container).addEventListener('click', () => {
    if (tableState.currentPage > 1) {
      tableState.currentPage--;
      renderTable();
    }
  });

  $('#usage-next-page-btn', container).addEventListener('click', () => {
    tableState.currentPage++;
    renderTable();
  });

  // Initial load
  fetchUsageData();

  return {
    unmount: () => {
      container.innerHTML = '';
    },
  };
}
