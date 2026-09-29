/**
 * Dashboard view: live KPIs, service counters, and top talkers.
 */

import { html, raw, setHtml, $, escapeHtml } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatCount, formatDuration } from '../core/format.js';
import { Poller } from '../core/poller.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { toast } from '../ui/toast.js';

export function mount(container) {
  let isMounted = true;
  let activeRange = 'today';

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

        <!-- KPI Cards: Active Conns | Online Users | Domain Rules | Uptime | Total BW | Download | Upload | DNS Queries -->
        <div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Active Conns</span>
            <div id="kpi-conns" class="text-xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Online Users</span>
            <div id="kpi-online" class="text-xl font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Domain Rules</span>
            <div id="kpi-domains" class="text-xl font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Uptime</span>
            <div id="kpi-uptime" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">Total Bandwidth</span>
            <div id="kpi-bandwidth" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-sky-600 dark:text-sky-400 flex items-center gap-1">
              <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 14l-7 7m0 0l-7-7m7 7V3"/></svg>
              Download
            </span>
            <div id="kpi-download" class="text-lg font-bold text-sky-600 dark:text-sky-400 mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-violet-600 dark:text-violet-400 flex items-center gap-1">
              <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 10l7-7m0 0l7 7m-7-7v18"/></svg>
              Upload
            </span>
            <div id="kpi-upload" class="text-lg font-bold text-violet-600 dark:text-violet-400 mt-1 tabular-nums">—</div>
          </div>
          <div class="card p-3.5 flex flex-col justify-between">
            <span class="text-xs font-medium text-txt-muted">DNS Queries</span>
            <div id="kpi-dns-queries" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
          </div>
        </div>

        <!-- Top Talkers -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <!-- Top Domains -->
          <div class="card p-5">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-sm font-semibold text-txt flex items-center gap-2">
                <svg class="w-4 h-4 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/>
                </svg>
                <span>Top Domains by Traffic</span>
              </h3>
              <span class="text-xs text-txt-subtle">Top 5</span>
            </div>
            <div id="dash-top-domains" class="space-y-3">
              <div class="text-xs text-txt-subtle py-4 text-center italic">Loading top domains...</div>
            </div>
          </div>

          <!-- Top Users -->
          <div class="card p-5">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-sm font-semibold text-txt flex items-center gap-2">
                <svg class="w-4 h-4 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>
                </svg>
                <span>Top Users by Traffic</span>
              </h3>
              <span class="text-xs text-txt-subtle">Top 5</span>
            </div>
            <div id="dash-top-users" class="space-y-3">
              <div class="text-xs text-txt-subtle py-4 text-center italic">Loading top users...</div>
            </div>
          </div>
        </div>

        <!-- DNS Section -->
        <div class="card p-4">
          <div class="flex items-center gap-2 mb-4">
            <span class="w-2.5 h-2.5 rounded-full bg-sky-500 flex-shrink-0"></span>
            <h2 class="text-sm font-semibold text-txt">DNS Resolver</h2>
            <span id="dns-total-badge" class="badge badge-neutral tabular-nums ml-auto">0 queries</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Total Queries</span>
              <div id="dns-total" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-emerald-600 dark:text-emerald-400">Authorized</span>
              <div id="dns-authorized" class="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-sky-600 dark:text-sky-400">Passthrough</span>
              <div id="dns-passthrough" class="text-lg font-bold text-sky-600 dark:text-sky-400 mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-rose-600 dark:text-rose-400">Blocked / Rejected</span>
              <div id="dns-blocked" class="text-lg font-bold text-rose-600 dark:text-rose-400 mt-1 tabular-nums">—</div>
            </div>
          </div>
        </div>

        <!-- TLS Section -->
        <div class="card p-4">
          <div class="flex items-center gap-2 mb-4">
            <span class="w-2.5 h-2.5 rounded-full bg-emerald-500 flex-shrink-0"></span>
            <h2 class="text-sm font-semibold text-txt">TLS SNI Relay (Port 443)</h2>
            <span id="tls-bandwidth-badge" class="badge badge-neutral tabular-nums ml-auto">0 B</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Total Bandwidth</span>
              <div id="tls-bandwidth" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Total Connections</span>
              <div id="tls-requests" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-emerald-600 dark:text-emerald-400">Registered</span>
              <div id="tls-registered" class="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Unregistered</span>
              <div id="tls-unregistered" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
          </div>
        </div>

        <!-- HTTP Section -->
        <div class="card p-4">
          <div class="flex items-center gap-2 mb-4">
            <span class="w-2.5 h-2.5 rounded-full bg-amber-500 flex-shrink-0"></span>
            <h2 class="text-sm font-semibold text-txt">HTTP Host Relay (Port 80)</h2>
            <span id="http-bandwidth-badge" class="badge badge-neutral tabular-nums ml-auto">0 B</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Total Bandwidth</span>
              <div id="http-bandwidth" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Total Requests</span>
              <div id="http-requests" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-emerald-600 dark:text-emerald-400">Registered</span>
              <div id="http-registered" class="text-lg font-bold text-emerald-600 dark:text-emerald-400 mt-1 tabular-nums">—</div>
            </div>
            <div class="card p-3.5 flex flex-col justify-between">
              <span class="text-xs font-medium text-txt-muted">Unregistered</span>
              <div id="http-unregistered" class="text-lg font-bold text-txt mt-1 tabular-nums">—</div>
            </div>
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
      slowPoller.trigger();
    },
  });
  rangeContainer.appendChild(rangeSegmented.el);

  // Stats updater
  async function updateStats() {
    if (!isMounted) return;
    try {
      const stats = await api.getStats(activeRange);
      if (!isMounted) return;

      const tlsSent = stats.tls_bytes_sent || 0;
      const tlsRecv = stats.tls_bytes_received || 0;
      const httpSent = stats.http_bytes_sent || 0;
      const httpRecv = stats.http_bytes_received || 0;

      const totalDownload = tlsRecv + httpRecv;
      const totalUpload = tlsSent + httpSent;
      const totalBandwidth = stats.global_bytes_total || (totalDownload + totalUpload);
      const dnsTotal = stats.dns_requests_total || 0;
      const dnsAuth = stats.dns_requests_authorized || 0;
      const dnsPass = stats.dns_requests_unauthorized_passthrough || 0;
      const dnsBlock = (stats.dns_requests_blocked || 0) + (stats.dns_requests_unauthorized_rejected || 0);

      $('#kpi-conns', container).textContent = formatCount(stats.active_connections);
      $('#kpi-online', container).textContent = formatCount(stats.online_users);
      $('#kpi-domains', container).textContent = formatCount(stats.total_domain_rules);
      $('#kpi-uptime', container).textContent = formatDuration(stats.uptime_seconds);
      $('#kpi-bandwidth', container).textContent = formatBytes(totalBandwidth);
      $('#kpi-download', container).textContent = formatBytes(totalDownload);
      $('#kpi-upload', container).textContent = formatBytes(totalUpload);
      $('#kpi-dns-queries', container).textContent = formatCount(dnsTotal);

      // DNS
      $('#dns-total-badge', container).textContent = `${formatCount(dnsTotal)} queries`;
      $('#dns-total', container).textContent = formatCount(dnsTotal);
      $('#dns-authorized', container).textContent = formatCount(dnsAuth);
      $('#dns-passthrough', container).textContent = formatCount(dnsPass);
      $('#dns-blocked', container).textContent = formatCount(dnsBlock);

      // TLS
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

  // Top talkers updater
  async function fetchTopTalkers() {
    if (!isMounted) return;
    try {
      const [domainsRes, usersRes] = await Promise.all([
        api.getDomains(activeRange),
        api.getUsers(activeRange),
      ]);
      if (!isMounted) return;

      renderTopDomains(domainsRes.domains || []);
      renderTopUsers(usersRes.users || []);
    } catch (err) {
      console.warn('Dashboard top talkers error:', err);
    }
  }

  function renderTopDomains(domains) {
    const el = $('#dash-top-domains', container);
    if (!el) return;

    const list = (domains || [])
      .map((d) => ({
        domain: d.domain,
        usage: (d.total_bytes_sent || 0) + (d.total_bytes_received || 0),
      }))
      .filter((d) => d.usage > 0)
      .sort((a, b) => b.usage - a.usage)
      .slice(0, 5);

    if (list.length === 0) {
      el.innerHTML = `<div class="text-xs text-txt-subtle py-4 text-center italic">No domain traffic recorded for this period</div>`;
      return;
    }

    const maxVal = list[0].usage > 0 ? list[0].usage : 1;
    el.innerHTML = list
      .map((d) => {
        const pct = Math.max(4, Math.round((d.usage / maxVal) * 100));
        return `
          <div class="space-y-1">
            <div class="flex items-center justify-between text-xs">
              <span class="font-medium text-txt truncate max-w-[220px]" title="${escapeHtml(d.domain)}">${escapeHtml(d.domain)}</span>
              <span class="font-mono text-txt-muted tabular-nums">${formatBytes(d.usage)}</span>
            </div>
            <div class="w-full h-2 rounded-full bg-surface-3 overflow-hidden">
              <div class="h-full bg-primary-500 rounded-full transition-all duration-300" style="width: ${pct}%"></div>
            </div>
          </div>
        `;
      })
      .join('');
  }

  function renderTopUsers(users) {
    const el = $('#dash-top-users', container);
    if (!el) return;

    const list = (users || [])
      .map((u) => ({
        username: u.username,
        usage: (u.total_bytes_sent || 0) + (u.total_bytes_received || 0),
      }))
      .filter((u) => u.usage > 0)
      .sort((a, b) => b.usage - a.usage)
      .slice(0, 5);

    if (list.length === 0) {
      el.innerHTML = `<div class="text-xs text-txt-subtle py-4 text-center italic">No user traffic recorded for this period</div>`;
      return;
    }

    const maxVal = list[0].usage > 0 ? list[0].usage : 1;
    el.innerHTML = list
      .map((u) => {
        const pct = Math.max(4, Math.round((u.usage / maxVal) * 100));
        return `
          <div class="space-y-1">
            <div class="flex items-center justify-between text-xs">
              <span class="font-medium text-txt truncate max-w-[220px]" title="${escapeHtml(u.username)}">${escapeHtml(u.username)}</span>
              <span class="font-mono text-txt-muted tabular-nums">${formatBytes(u.usage)}</span>
            </div>
            <div class="w-full h-2 rounded-full bg-surface-3 overflow-hidden">
              <div class="h-full bg-emerald-500 rounded-full transition-all duration-300" style="width: ${pct}%"></div>
            </div>
          </div>
        `;
      })
      .join('');
  }

  // Refresh button
  $('#dash-refresh-btn', container).addEventListener('click', () => {
    statsPoller.trigger();
    slowPoller.trigger();
    toast.info('Metrics refreshed');
  });

  // Pollers: stats every 5s, top talkers every 30s
  const statsPoller = new Poller(updateStats, 5000, { immediate: true });
  const slowPoller = new Poller(fetchTopTalkers, 30000, { immediate: true });

  statsPoller.start();
  slowPoller.start();

  return {
    unmount: () => {
      isMounted = false;
      statsPoller.stop();
      slowPoller.stop();
      container.innerHTML = '';
    },
  };
}
