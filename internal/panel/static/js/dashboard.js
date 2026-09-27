/* =========================================================================
   TLS Relay Admin Panel — dashboard.js
   Dashboard metrics polling and live request statistics charting.
   ========================================================================= */

"use strict";

let currentDashboardRange = 'today';
let statsPollInterval = null;

function formatUptime(sec) {
  if (!sec || sec < 0) return '0s';
  const days = Math.floor(sec / 86400);
  const hours = Math.floor((sec % 86400) / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const secs = sec % 60;
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (mins > 0) parts.push(`${mins}m`);
  parts.push(`${secs}s`);
  return parts.join(' ');
}

async function loadDashboardStats(range = currentDashboardRange) {
  currentDashboardRange = range;
  try {
    const res = await apiFetch(`api/stats?range=${range}`);
    if (!res.ok) return;
    const stats = await res.json();

    if ($('stat-active-conns')) $('stat-active-conns').textContent = stats.active_connections ?? 0;
    if ($('stat-online-users')) $('stat-online-users').textContent = stats.online_users ?? 0;
    if ($('stat-domain-count')) $('stat-domain-count').textContent = stats.total_domain_rules ?? 0;
    if ($('stat-user-count')) $('stat-user-count').textContent = stats.total_users ?? 0;
    if ($('stat-blacklist-count')) $('stat-blacklist-count').textContent = stats.total_blacklist ?? 0;
    if ($('stat-uptime')) $('stat-uptime').textContent = formatUptime(stats.uptime_seconds);

    if ($('stat-dns-total')) $('stat-dns-total').textContent = (stats.dns_requests_total ?? 0).toLocaleString();
    if ($('stat-dns-authorized')) $('stat-dns-authorized').textContent = (stats.dns_requests_authorized ?? 0).toLocaleString();
    if ($('stat-dns-passthrough')) $('stat-dns-passthrough').textContent = (stats.dns_requests_unauthorized_passthrough ?? 0).toLocaleString();
    if ($('stat-dns-blocked')) $('stat-dns-blocked').textContent = ((stats.dns_requests_blocked ?? 0) + (stats.dns_requests_unauthorized_rejected ?? 0)).toLocaleString();

    if ($('stat-tls-bytes-total')) $('stat-tls-bytes-total').textContent = formatBytes(stats.tls_bytes_total || 0);
    if ($('stat-tls-total')) $('stat-tls-total').textContent = (stats.tls_requests_total ?? 0).toLocaleString();
    if ($('stat-tls-registered')) $('stat-tls-registered').textContent = (stats.tls_requests_registered ?? 0).toLocaleString();
    if ($('stat-tls-unregistered')) $('stat-tls-unregistered').textContent = (stats.tls_requests_unregistered ?? 0).toLocaleString();

    if ($('stat-http-bytes-total')) $('stat-http-bytes-total').textContent = formatBytes(stats.http_bytes_total || 0);
    if ($('stat-http-total')) $('stat-http-total').textContent = (stats.http_requests_total ?? 0).toLocaleString();
    if ($('stat-http-registered')) $('stat-http-registered').textContent = (stats.http_requests_registered ?? 0).toLocaleString();
    if ($('stat-http-unregistered')) $('stat-http-unregistered').textContent = (stats.http_requests_unregistered ?? 0).toLocaleString();

    await loadDNSRequestStatsChart(range);
    await loadTLSRequestStatsChart(range);
    await loadHTTPRequestStatsChart(range);
  } catch (err) {
    console.error('loadDashboardStats error:', err);
  }
}

function startStatsPolling() {
  stopStatsPolling();
  loadDashboardStats();
  statsPollInterval = setInterval(loadDashboardStats, 5000);
}

function stopStatsPolling() {
  if (statsPollInterval) {
    clearInterval(statsPollInterval);
    statsPollInterval = null;
  }
}

async function loadDNSRequestStatsChart(range) {
  const wrap = $('dns-stats-chart');
  const legend = $('dns-stats-legend');
  const empty = $('dns-stats-empty');
  if (!wrap) return;

  try {
    const res = await apiFetch(`/api/request-stats/daily?type=DNS&range=${range}`);
    if (!res.ok) return;
    const data = await res.json();
    const rawDays = data.days || [];

    if (rawDays.length === 0) {
      if (empty) empty.classList.remove('hidden');
      wrap.innerHTML = '';
      if (legend) legend.innerHTML = '';
      return;
    }
    if (empty) empty.classList.add('hidden');

    const dateMap = new Map();
    for (const r of rawDays) {
      if (!dateMap.has(r.date)) {
        dateMap.set(r.date, { date: r.date, bytes_sent: 0, bytes_received: 0 });
      }
      const item = dateMap.get(r.date);
      if (r.category === 'authorized') {
        item.bytes_sent += r.count;
      } else if (r.category !== 'total') {
        item.bytes_received += r.count;
      }
    }
    renderUsageChart(wrap, legend, empty, Array.from(dateMap.values()), {
      unit: 'count',
      series1Name: 'Authorized Queries',
      series2Name: 'Passthrough / Blocked',
      series1Color: 'var(--accent, #4f8ef7)',
      series2Color: 'var(--success, #22c55e)',
      countUnitLabel: 'queries'
    });
  } catch (err) {
    console.error('loadDNSRequestStatsChart error:', err);
  }
}

async function loadTLSRequestStatsChart(range) {
  const wrap = $('tls-stats-chart');
  const legend = $('tls-stats-legend');
  const empty = $('tls-stats-empty');
  if (!wrap) return;

  try {
    const res = await apiFetch(`/api/request-stats/daily?type=TLS&range=${range}`);
    if (!res.ok) return;
    const data = await res.json();
    const rawDays = data.days || [];

    if (rawDays.length === 0) {
      if (empty) empty.classList.remove('hidden');
      wrap.innerHTML = '';
      if (legend) legend.innerHTML = '';
      return;
    }
    if (empty) empty.classList.add('hidden');

    const dateMap = new Map();
    for (const r of rawDays) {
      if (!dateMap.has(r.date)) {
        dateMap.set(r.date, { date: r.date, bytes_sent: 0, bytes_received: 0 });
      }
      const item = dateMap.get(r.date);
      if (r.category === 'registered') {
        item.bytes_sent += r.count;
      } else if (r.category !== 'total') {
        item.bytes_received += r.count;
      }
    }
    renderUsageChart(wrap, legend, empty, Array.from(dateMap.values()), {
      unit: 'count',
      series1Name: 'Registered Users',
      series2Name: 'Unregistered Traffic',
      series1Color: 'var(--accent, #4f8ef7)',
      series2Color: 'var(--warning, #f59e0b)',
      countUnitLabel: 'connections'
    });
  } catch (err) {
    console.error('loadTLSRequestStatsChart error:', err);
  }
}

async function loadHTTPRequestStatsChart(range) {
  const wrap = $('http-stats-chart');
  const legend = $('http-stats-legend');
  const empty = $('http-stats-empty');
  if (!wrap) return;

  try {
    const res = await apiFetch(`/api/request-stats/daily?type=HTTP&range=${range}`);
    if (!res.ok) return;
    const data = await res.json();
    const rawDays = data.days || [];

    if (rawDays.length === 0) {
      if (empty) empty.classList.remove('hidden');
      wrap.innerHTML = '';
      if (legend) legend.innerHTML = '';
      return;
    }
    if (empty) empty.classList.add('hidden');

    const dateMap = new Map();
    for (const r of rawDays) {
      if (!dateMap.has(r.date)) {
        dateMap.set(r.date, { date: r.date, bytes_sent: 0, bytes_received: 0 });
      }
      const item = dateMap.get(r.date);
      if (r.category === 'registered') {
        item.bytes_sent += r.count;
      } else if (r.category !== 'total') {
        item.bytes_received += r.count;
      }
    }
    renderUsageChart(wrap, legend, empty, Array.from(dateMap.values()), {
      unit: 'count',
      series1Name: 'Registered Users',
      series2Name: 'Unregistered Traffic',
      series1Color: 'var(--accent, #4f8ef7)',
      series2Color: 'var(--warning, #f59e0b)',
      countUnitLabel: 'requests'
    });
  } catch (err) {
    console.error('loadHTTPRequestStatsChart error:', err);
  }
}

function initDashboardRequestStats() {
  const rangeBtns = $('dashboard-range-btns');
  if (rangeBtns) {
    rangeBtns.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        rangeBtns.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentDashboardRange = btn.dataset.range || 'today';
        loadDashboardStats(currentDashboardRange);
      });
    });
  }

  loadDashboardStats();

  // User domain table sort clicks
  document.querySelectorAll('#user-domains-table th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (userDomainSortCol === col) {
        userDomainSortDir = userDomainSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        userDomainSortCol = col;
        userDomainSortDir = 'desc';
      }
      renderUserDomainsTable();
    });
  });

  // User domain pagination buttons
  const udomPrev = $('user-dom-prev-btn');
  if (udomPrev) {
    udomPrev.addEventListener('click', () => {
      if (userDomainPage > 1) {
        userDomainPage--;
        renderUserDomainsTable();
      }
    });
  }
  const udomNext = $('user-dom-next-btn');
  if (udomNext) {
    udomNext.addEventListener('click', () => {
      userDomainPage++;
      renderUserDomainsTable();
    });
  }

  loadDashboardStats();
}

async function loadLiveStats() {
  await loadDashboardStats();
}

window.loadDashboardStats = loadDashboardStats;
window.loadLiveStats = loadLiveStats;

