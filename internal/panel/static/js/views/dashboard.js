/**
 * Dashboard view: live KPIs, service counters, and activity charts.
 */

import { html, raw, setHtml, $ } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatCount, formatDuration, formatDate } from '../core/format.js';
import { Poller } from '../core/poller.js';
import { renderGroupedBarChart } from '../ui/chart.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { toast } from '../ui/toast.js';

export function mount(container) {
  let isMounted = true;
  let activeRange = 'today';
  let chartInstances = [];

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Header & Range Control -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Dashboard</h1>
            <p class="text-xs text-txt-muted mt-0.5">Real-time relay metrics and service traffic overview</p>
          </div>
          <div class="flex items-center gap-3">
            <div id="dash-range-segmented"></div>
            <button id="dash-refresh-btn" type="button" class="btn btn-secondary btn-sm" aria-label="Refresh metrics">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            </button>
          </div>
        </div>

        <!-- 6 KPI Top Cards -->
        <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Active Conns</span>
            <div id="kpi-conns" class="text-2xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Online Users</span>
            <div id="kpi-online" class="text-2xl font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Domain Rules</span>
            <div id="kpi-domains" class="text-2xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Total Users</span>
            <div id="kpi-users" class="text-2xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Blacklisted</span>
            <div id="kpi-blacklist" class="text-2xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-4 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Uptime</span>
            <div id="kpi-uptime" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
        </div>

        <!-- DNS Section -->
        <div class="card">
          <div class="card-header">
            <div class="flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-sky-500"></span>
              <h2 class="text-base font-semibold text-txt">DNS Resolver</h2>
            </div>
            <span id="dns-total-badge" class="badge badge-neutral tabular-nums">0 queries</span>
          </div>
          <div class="card-body space-y-6">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Total Queries</div>
                <div id="dns-total" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <div class="text-xs text-emerald-700 dark:text-emerald-400">Authorized</div>
                <div id="dns-authorized" class="text-lg font-bold text-emerald-700 dark:text-emerald-400 mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-sky-500/10 border border-sky-500/20">
                <div class="text-xs text-sky-700 dark:text-sky-400">Passthrough</div>
                <div id="dns-passthrough" class="text-lg font-bold text-sky-700 dark:text-sky-400 mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/20">
                <div class="text-xs text-rose-700 dark:text-rose-400">Blocked / Rejected</div>
                <div id="dns-blocked" class="text-lg font-bold text-rose-700 dark:text-rose-400 mt-0.5 tabular-nums">—</div>
              </div>
            </div>
            <div id="chart-dns-container" class="min-h-[220px]"></div>
          </div>
        </div>

        <!-- TLS Section -->
        <div class="card">
          <div class="card-header">
            <div class="flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
              <h2 class="text-base font-semibold text-txt">TLS SNI Relay (Port 443)</h2>
            </div>
            <span id="tls-bandwidth-badge" class="badge badge-neutral tabular-nums">0 B</span>
          </div>
          <div class="card-body space-y-6">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Total Bandwidth</div>
                <div id="tls-bandwidth" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Total Connections</div>
                <div id="tls-requests" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <div class="text-xs text-emerald-700 dark:text-emerald-400">Registered Users</div>
                <div id="tls-registered" class="text-lg font-bold text-emerald-700 dark:text-emerald-400 mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Unregistered / Direct</div>
                <div id="tls-unregistered" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
            </div>
            <div id="chart-tls-container" class="min-h-[220px]"></div>
          </div>
        </div>

        <!-- HTTP Section -->
        <div class="card">
          <div class="card-header">
            <div class="flex items-center gap-2">
              <span class="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <h2 class="text-base font-semibold text-txt">HTTP Host Relay (Port 80)</h2>
            </div>
            <span id="http-bandwidth-badge" class="badge badge-neutral tabular-nums">0 B</span>
          </div>
          <div class="card-body space-y-6">
            <div class="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Total Bandwidth</div>
                <div id="http-bandwidth" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Total Requests</div>
                <div id="http-requests" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <div class="text-xs text-emerald-700 dark:text-emerald-400">Registered Users</div>
                <div id="http-registered" class="text-lg font-bold text-emerald-700 dark:text-emerald-400 mt-0.5 tabular-nums">—</div>
              </div>
              <div class="p-3.5 rounded-lg bg-surface-2/60 border border-border">
                <div class="text-xs text-txt-muted">Unregistered / Direct</div>
                <div id="http-unregistered" class="text-lg font-bold text-txt mt-0.5 tabular-nums">—</div>
              </div>
            </div>
            <div id="chart-http-container" class="min-h-[220px]"></div>
          </div>
        </div>
      </div>
    `
  );

  // Range control
  const rangeContainer = $('#dash-range-segmented', container);
  const rangeSegmented = createSegmentedControl({
    options: [
      { value: 'today', label: 'Today' },
      { value: '7d', label: '7 Days' },
      { value: '30d', label: '30 Days' },
      { value: 'monthly', label: 'Monthly' },
    ],
    value: activeRange,
    size: 'sm',
    onChange: (newRange) => {
      activeRange = newRange;
      statsPoller.trigger();
      fetchCharts();
    },
  });
  rangeContainer.appendChild(rangeSegmented.el);

  // Stats updater
  async function updateStats() {
    if (!isMounted) return;
    try {
      const stats = await api.getStats(activeRange);
      if (!isMounted) return;

      $('#kpi-conns', container).textContent = formatCount(stats.active_connections);
      $('#kpi-online', container).textContent = formatCount(stats.online_users);
      $('#kpi-domains', container).textContent = formatCount(stats.total_domain_rules);
      $('#kpi-users', container).textContent = formatCount(stats.total_users);
      $('#kpi-blacklist', container).textContent = formatCount(stats.total_blacklist);
      $('#kpi-uptime', container).textContent = formatDuration(stats.uptime_seconds);

      // DNS
      const dnsTotal = stats.dns_requests_total || 0;
      const dnsAuth = stats.dns_requests_authorized || 0;
      const dnsPass = stats.dns_requests_unauthorized_passthrough || 0;
      const dnsBlock = (stats.dns_requests_blocked || 0) + (stats.dns_requests_unauthorized_rejected || 0);

      $('#dns-total-badge', container).textContent = `${formatCount(dnsTotal)} queries`;
      $('#dns-total', container).textContent = formatCount(dnsTotal);
      $('#dns-authorized', container).textContent = formatCount(dnsAuth);
      $('#dns-passthrough', container).textContent = formatCount(dnsPass);
      $('#dns-blocked', container).textContent = formatCount(dnsBlock);

      // TLS
      const tlsSent = stats.tls_bytes_sent || 0;
      const tlsRecv = stats.tls_bytes_received || 0;
      const tlsTotalBytes = stats.tls_bytes_total || (tlsSent + tlsRecv);
      const tlsReqs = stats.tls_requests_total || 0;
      const tlsReg = stats.tls_requests_registered || 0;
      const tlsUnreg = stats.tls_requests_unregistered || 0;

      $('#tls-bandwidth-badge', container).textContent = formatBytes(tlsTotalBytes);
      $('#tls-bandwidth', container).textContent = formatBytes(tlsTotalBytes);
      $('#tls-requests', container).textContent = formatCount(tlsReqs);
      $('#tls-registered', container).textContent = formatCount(tlsReg);
      $('#tls-unregistered', container).textContent = formatCount(tlsUnreg);

      // HTTP
      const httpSent = stats.http_bytes_sent || 0;
      const httpRecv = stats.http_bytes_received || 0;
      const httpTotalBytes = stats.http_bytes_total || (httpSent + httpRecv);
      const httpReqs = stats.http_requests_total || 0;
      const httpReg = stats.http_requests_registered || 0;
      const httpUnreg = stats.http_requests_unregistered || 0;

      $('#http-bandwidth-badge', container).textContent = formatBytes(httpTotalBytes);
      $('#http-bandwidth', container).textContent = formatBytes(httpTotalBytes);
      $('#http-requests', container).textContent = formatCount(httpReqs);
      $('#http-registered', container).textContent = formatCount(httpReg);
      $('#http-unregistered', container).textContent = formatCount(httpUnreg);
    } catch (err) {
      console.warn('Dashboard stats error:', err);
    }
  }

  // Charts updater
  async function fetchCharts() {
    if (!isMounted) return;
    chartInstances.forEach((c) => c.destroy && c.destroy());
    chartInstances = [];

    try {
      const [dnsData, tlsData, httpData] = await Promise.all([
        api.getRequestStatsDaily('DNS', activeRange),
        api.getRequestStatsDaily('TLS', activeRange),
        api.getRequestStatsDaily('HTTP', activeRange),
      ]);
      if (!isMounted) return;

      // Process DNS series
      const dnsGroupMap = new Map();
      for (const d of dnsData.days || []) {
        if (!dnsGroupMap.has(d.date)) {
          dnsGroupMap.set(d.date, { label: formatDate(d.date), authorized: 0, other: 0 });
        }
        const item = dnsGroupMap.get(d.date);
        if (d.category === 'authorized') {
          item.authorized += d.count;
        } else {
          item.other += d.count;
        }
      }

      const dnsChart = renderGroupedBarChart($('#chart-dns-container', container), {
        data: Array.from(dnsGroupMap.values()),
        series: [
          { key: 'authorized', label: 'Authorized Queries', color: '#10b981' },
          { key: 'other', label: 'Passthrough / Rejected', color: '#94a3b8' },
        ],
        formatValue: (v) => formatCount(v),
      });
      chartInstances.push(dnsChart);

      // Process TLS series
      const tlsGroupMap = new Map();
      for (const d of tlsData.days || []) {
        if (!tlsGroupMap.has(d.date)) {
          tlsGroupMap.set(d.date, { label: formatDate(d.date), registered: 0, unregistered: 0 });
        }
        const item = tlsGroupMap.get(d.date);
        if (d.category === 'registered') {
          item.registered += d.count;
        } else {
          item.unregistered += d.count;
        }
      }

      const tlsChart = renderGroupedBarChart($('#chart-tls-container', container), {
        data: Array.from(tlsGroupMap.values()),
        series: [
          { key: 'registered', label: 'Registered User Conns', color: '#3b82f6' },
          { key: 'unregistered', label: 'Unregistered / Direct', color: '#cbd5e1' },
        ],
        formatValue: (v) => formatCount(v),
      });
      chartInstances.push(tlsChart);

      // Process HTTP series
      const httpGroupMap = new Map();
      for (const d of httpData.days || []) {
        if (!httpGroupMap.has(d.date)) {
          httpGroupMap.set(d.date, { label: formatDate(d.date), registered: 0, unregistered: 0 });
        }
        const item = httpGroupMap.get(d.date);
        if (d.category === 'registered') {
          item.registered += d.count;
        } else {
          item.unregistered += d.count;
        }
      }

      const httpChart = renderGroupedBarChart($('#chart-http-container', container), {
        data: Array.from(httpGroupMap.values()),
        series: [
          { key: 'registered', label: 'Registered Requests', color: '#f59e0b' },
          { key: 'unregistered', label: 'Unregistered / Direct', color: '#cbd5e1' },
        ],
        formatValue: (v) => formatCount(v),
      });
      chartInstances.push(httpChart);
    } catch (err) {
      console.warn('Dashboard charts error:', err);
    }
  }

  // Refresh button
  $('#dash-refresh-btn', container).addEventListener('click', () => {
    statsPoller.trigger();
    fetchCharts();
    toast.info('Metrics refreshed');
  });

  // Pollers
  const statsPoller = new Poller(updateStats, 5000, { immediate: true });
  const chartPoller = new Poller(fetchCharts, 30000, { immediate: true });

  statsPoller.start();
  chartPoller.start();

  return {
    unmount: () => {
      isMounted = false;
      statsPoller.stop();
      chartPoller.stop();
      chartInstances.forEach((c) => c.destroy && c.destroy());
      container.innerHTML = '';
    },
  };
}
