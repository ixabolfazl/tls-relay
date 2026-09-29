/**
 * Shared tabular usage report modal for users and domains.
 * Replaces old chart modals with clean tabular reports.
 */

import { html, escapeHtml, $ } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatCount, formatDate } from '../core/format.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { createSegmentedControl } from '../ui/segmented.js';

export function openUsageReportDialog({ kind, id, name, onReset }) {
  const isUser = kind === 'user';
  const entityName = name || (isUser ? `User #${id}` : 'Domain');
  let currentRange = '30d';

  const content = document.createElement('div');
  content.className = 'space-y-5';

  content.innerHTML = `
    <!-- Header Controls -->
    <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
      <div class="flex items-center gap-2">
        <span class="text-xs font-semibold text-txt-muted uppercase tracking-wider">Time Range:</span>
        <div id="report-range-segmented"></div>
      </div>
      ${
        isUser
          ? `
        <button id="report-reset-usage-btn" type="button" class="btn btn-danger btn-xs self-start sm:self-auto">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
          </svg>
          <span>Reset Usage</span>
        </button>
      `
          : ''
      }
    </div>

    <!-- Summary Block -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div class="card p-3">
        <div class="text-[11px] font-medium text-txt-muted">Sent</div>
        <div id="report-sum-sent" class="text-base font-bold text-txt mt-0.5 tabular-nums">—</div>
      </div>
      <div class="card p-3">
        <div class="text-[11px] font-medium text-txt-muted">Received</div>
        <div id="report-sum-recv" class="text-base font-bold text-txt mt-0.5 tabular-nums">—</div>
      </div>
      <div class="card p-3">
        <div class="text-[11px] font-medium text-txt-muted">Total Traffic</div>
        <div id="report-sum-total" class="text-base font-bold text-txt mt-0.5 tabular-nums">—</div>
      </div>
      <div class="card p-3">
        <div class="text-[11px] font-medium text-txt-muted">DNS Queries</div>
        <div id="report-sum-dns" class="text-base font-bold text-txt mt-0.5 tabular-nums">—</div>
      </div>
    </div>

    <!-- Per-Day Table -->
    <div class="space-y-2">
      <h3 class="text-xs font-semibold text-txt uppercase tracking-wider">Daily Breakdown</h3>
      <div class="border border-border rounded-lg overflow-hidden">
        <div class="max-h-60 overflow-y-auto">
          <table class="table text-xs">
            <thead class="sticky top-0 bg-surface z-10">
              <tr>
                <th class="table-th py-2">Date</th>
                <th class="table-th py-2 text-right">Sent</th>
                <th class="table-th py-2 text-right">Received</th>
                <th class="table-th py-2 text-right">Total</th>
                <th class="table-th py-2 text-right">DNS Queries</th>
              </tr>
            </thead>
            <tbody id="report-daily-tbody">
              <tr>
                <td colspan="5" class="table-td text-center py-8 text-txt-subtle">
                  <div class="flex items-center justify-center gap-2">
                    <div class="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                    <span>Loading daily statistics...</span>
                  </div>
                </td>
              </tr>
            </tbody>
            <tfoot id="report-daily-tfoot" class="border-t-2 border-border font-semibold bg-surface-2 hidden">
              <tr>
                <td class="table-td py-2 text-txt">Total</td>
                <td id="report-foot-sent" class="table-td py-2 text-right font-mono tabular-nums text-txt">—</td>
                <td id="report-foot-recv" class="table-td py-2 text-right font-mono tabular-nums text-txt">—</td>
                <td id="report-foot-total" class="table-td py-2 text-right font-mono tabular-nums text-txt">—</td>
                <td id="report-foot-dns" class="table-td py-2 text-right font-mono tabular-nums text-txt">—</td>
              </tr>
            </tfoot>
          </table>
        </div>
      </div>
    </div>

    <!-- Top Talkers Sub-Table -->
    <div class="space-y-2">
      <h3 class="text-xs font-semibold text-txt uppercase tracking-wider">
        ${isUser ? 'Top Domains Accessed' : 'Top Users by Bandwidth'}
      </h3>
      <div class="border border-border rounded-lg overflow-hidden">
        <div class="max-h-48 overflow-y-auto">
          <table class="table text-xs">
            <thead class="sticky top-0 bg-surface z-10">
              <tr>
                <th class="table-th py-2">${isUser ? 'Domain' : 'User'}</th>
                <th class="table-th py-2 text-right">Sent</th>
                <th class="table-th py-2 text-right">Received</th>
                <th class="table-th py-2 text-right">Total</th>
              </tr>
            </thead>
            <tbody id="report-top-tbody">
              <tr>
                <td colspan="4" class="table-td text-center py-6 text-txt-subtle">
                  <div class="flex items-center justify-center gap-2">
                    <div class="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                    <span>Loading breakdown...</span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  async function loadData(range) {
    const dailyTbody = content.querySelector('#report-daily-tbody');
    const dailyTfoot = content.querySelector('#report-daily-tfoot');
    const topTbody = content.querySelector('#report-top-tbody');

    try {
      let usagePromise;
      let topPromise;

      if (isUser) {
        usagePromise = api.getUserUsage(id, range);
        topPromise = api.getUserUsageDomains(id, range);
      } else {
        usagePromise = api.getDomainUsage(name, range);
        topPromise = api.getDomainUsageUsers(name, range);
      }

      const [usageRes, topRes] = await Promise.all([usagePromise, topPromise]);

      // Process Daily Rows
      const dayMap = new Map();
      (usageRes.days || []).forEach((d) => {
        dayMap.set(d.date, {
          date: d.date,
          sent: d.bytes_sent || 0,
          recv: d.bytes_received || 0,
          queries: d.dns_queries || 0,
        });
      });
      (usageRes.dns_days || []).forEach((d) => {
        const existing = dayMap.get(d.date);
        if (existing) {
          if (!existing.queries) existing.queries = d.query_count || 0;
        } else {
          dayMap.set(d.date, {
            date: d.date,
            sent: 0,
            recv: 0,
            queries: d.query_count || 0,
          });
        }
      });

      const sortedDays = Array.from(dayMap.values()).sort((a, b) => b.date.localeCompare(a.date));

      let totalSent = 0;
      let totalRecv = 0;
      let totalQueries = usageRes.total_dns_queries || 0;

      sortedDays.forEach((d) => {
        totalSent += d.sent;
        totalRecv += d.recv;
      });
      if (!totalQueries) {
        sortedDays.forEach((d) => {
          totalQueries += d.queries;
        });
      }
      const totalCombined = totalSent + totalRecv;

      // Update Summary Cards
      content.querySelector('#report-sum-sent').textContent = formatBytes(totalSent);
      content.querySelector('#report-sum-recv').textContent = formatBytes(totalRecv);
      content.querySelector('#report-sum-total').textContent = formatBytes(totalCombined);
      content.querySelector('#report-sum-dns').textContent = formatCount(totalQueries);

      // Render Daily Table
      if (sortedDays.length === 0) {
        dailyTbody.innerHTML = `
          <tr>
            <td colspan="5" class="table-td text-center py-6 text-txt-subtle italic">
              No usage activity recorded for this period
            </td>
          </tr>
        `;
        dailyTfoot.classList.add('hidden');
      } else {
        dailyTbody.innerHTML = sortedDays
          .map((d) => {
            const dayTotal = d.sent + d.recv;
            return `
              <tr>
                <td class="table-td py-1.5 font-mono">${escapeHtml(d.date)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums text-txt-muted">${formatBytes(d.sent)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums text-txt-muted">${formatBytes(d.recv)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums font-semibold text-txt">${formatBytes(dayTotal)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums text-txt-muted">${formatCount(d.queries)}</td>
              </tr>
            `;
          })
          .join('');

        content.querySelector('#report-foot-sent').textContent = formatBytes(totalSent);
        content.querySelector('#report-foot-recv').textContent = formatBytes(totalRecv);
        content.querySelector('#report-foot-total').textContent = formatBytes(totalCombined);
        content.querySelector('#report-foot-dns').textContent = formatCount(totalQueries);
        dailyTfoot.classList.remove('hidden');
      }

      // Render Top Talkers Sub-Table
      const items = (isUser ? topRes.domains : topRes.users) || [];
      if (items.length === 0) {
        topTbody.innerHTML = `
          <tr>
            <td colspan="4" class="table-td text-center py-6 text-txt-subtle italic">
              ${isUser ? 'No domain traffic recorded for this user' : 'No user traffic recorded for this domain'}
            </td>
          </tr>
        `;
      } else {
        topTbody.innerHTML = items
          .map((item) => {
            const label = isUser ? item.domain : item.username || `User #${item.user_id}`;
            const sent = item.bytes_sent || 0;
            const recv = item.bytes_received || 0;
            const tot = sent + recv;
            return `
              <tr>
                <td class="table-td py-1.5 font-mono font-medium text-txt">${escapeHtml(label)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums text-txt-muted">${formatBytes(sent)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums text-txt-muted">${formatBytes(recv)}</td>
                <td class="table-td py-1.5 text-right font-mono tabular-nums font-semibold text-txt">${formatBytes(tot)}</td>
              </tr>
            `;
          })
          .join('');
      }
    } catch (err) {
      dailyTbody.innerHTML = `
        <tr>
          <td colspan="5" class="table-td text-center py-6 text-danger">
            Failed to load usage data: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
      dailyTfoot.classList.add('hidden');
      topTbody.innerHTML = `
        <tr>
          <td colspan="4" class="table-td text-center py-6 text-danger">
            Failed to load breakdown: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  // Setup Range Selector
  const rangeContainer = content.querySelector('#report-range-segmented');
  createSegmentedControl(rangeContainer, {
    options: [
      { value: '7d', label: '7d' },
      { value: '30d', label: '30d' },
      { value: '90d', label: '90d' },
      { value: '365d', label: '365d' },
    ],
    value: currentRange,
    onChange: (val) => {
      currentRange = val;
      loadData(currentRange);
    },
  });

  // Setup Reset Usage Button (User only)
  if (isUser) {
    const resetBtn = content.querySelector('#report-reset-usage-btn');
    if (resetBtn) {
      resetBtn.addEventListener('click', async () => {
        const confirmed = await dialog.confirm({
          title: `Reset Usage: ${entityName}`,
          message: `Are you sure you want to reset all recorded bandwidth and query counters for "${entityName}"? This action cannot be undone.`,
          confirmText: 'Reset Usage',
          danger: true,
        });
        if (!confirmed) return;

        try {
          await api.resetUserUsage(id);
          toast.success(`Usage counters reset for ${entityName}`);
          if (onReset) onReset();
          await loadData(currentRange);
        } catch (err) {
          toast.error(err.message || 'Failed to reset usage');
        }
      });
    }
  }

  dialog.open({
    title: `Usage Report: ${entityName}`,
    content,
    size: 'lg',
    actions: [{ text: 'Close', className: 'btn btn-secondary', value: true }],
  });

  loadData(currentRange);
}
