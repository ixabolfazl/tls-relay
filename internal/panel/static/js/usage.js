/* =========================================================================
   TLS Relay Admin Panel — usage.js
   Usage tab components: total bandwidth graphs, per-user and per-domain
   breakdowns, domain usage details modal, and bandwidth unit formatting.
   ========================================================================= */

"use strict";

let currentGlobalUsageDays = 1;
let currentUserUsageDays = 1;
let selectedUsageUserId = null;
let selectedUsageUsername = '';
let currentUserUsageRange = 'today';

let usageUserPage = 1;
const usageUserPageSize = 10;
let usageUserSortCol = 'total';
let usageUserSortDir = 'desc';

let usageDomainPage = 1;
const usageDomainPageSize = 10;
let usageDomainSortCol = 'total';
let usageDomainSortDir = 'desc';

let currentDomainUsageName = '';
let currentDomainUsageRange = 'daily';

let userDomainPage = 1;
const userDomainPageSize = 10;
let userDomainSortCol = 'total';
let userDomainSortDir = 'desc';
let allUserDomainsList = [];

let usagePollInterval = null;

function _refreshActiveUsageSubtab() {
  const subtabToggle = $('usage-breakdown-subtab-toggle');
  if (subtabToggle) {
    const activeBtn = subtabToggle.querySelector('.segmented-btn.active');
    if (activeBtn && activeBtn.dataset.subtab === 'domain') {
      renderUsageDomainsTable();
    } else {
      renderUsageUsersTable();
    }
  } else {
    renderUsageUsersTable();
  }
}

function startUsagePolling() {
  stopUsagePolling();
  updateUsageTabRange(currentUsageTabRange);
  usagePollInterval = setInterval(() => {
    updateUsageTabRange(currentUsageTabRange);
  }, 10000);
}

function stopUsagePolling() {
  if (usagePollInterval) {
    clearInterval(usagePollInterval);
    usagePollInterval = null;
  }
}

function renderUsageChart(wrapEl, legendEl, emptyEl, dayRows, options = {}) {
  if (!wrapEl) return;
  if (!dayRows || dayRows.length === 0) {
    wrapEl.innerHTML = '';
    if (emptyEl) emptyEl.classList.remove('hidden');
    if (legendEl) legendEl.innerHTML = '';
    return;
  }
  if (emptyEl) emptyEl.classList.add('hidden');

  const opts = {
    unit: 'bytes', // 'bytes' or 'count'
    series1Name: 'Sent (Upload)',
    series2Name: 'Received (Download)',
    series1Color: 'var(--accent, #4f8ef7)',
    series2Color: 'var(--success, #22c55e)',
    countUnitLabel: 'queries',
    ...options
  };

  let maxVal = 0;
  for (const r of dayRows) {
    const s = r.bytes_sent || 0;
    const rec = r.bytes_received || 0;
    if (s > maxVal) maxVal = s;
    if (rec > maxVal) maxVal = rec;
  }
  if (maxVal === 0) maxVal = opts.unit === 'count' ? 10 : 1024; // fallback scale

  const width = Math.max(600, dayRows.length * 40);
  const height = 180;
  const paddingBottom = 30;
  const paddingTop = 20;
  const paddingLeft = 10;
  const paddingRight = 10;
  const chartH = height - paddingTop - paddingBottom;
  const barGroupW = (width - paddingLeft - paddingRight) / dayRows.length;
  const barW = Math.max(4, Math.min(14, (barGroupW - 6) / 2));

  let svg = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">`;

  // Draw grid lines
  for (let i = 0; i <= 3; i++) {
    const y = paddingTop + (chartH * i / 3);
    svg += `<line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" stroke="var(--border-subtle, rgba(255,255,255,0.08))" stroke-dasharray="3,3" stroke-width="1"/>`;
  }

  // Draw bars
  dayRows.forEach((r, idx) => {
    const s = r.bytes_sent || 0;
    const rec = r.bytes_received || 0;
    const sentH = (s / maxVal) * chartH;
    const recH = (rec / maxVal) * chartH;
    const groupX = paddingLeft + (idx * barGroupW) + (barGroupW / 2);

    const sentX = groupX - barW - 1;
    const sentY = paddingTop + (chartH - sentH);

    const recX = groupX + 1;
    const recY = paddingTop + (chartH - recH);

    const dateVal = r.date || r.month || '';
    const dateLabel = dateVal ? dateVal.slice(5) : '';

    const sValFormatted = opts.unit === 'count' ? `${s.toLocaleString()} ${opts.countUnitLabel}` : formatBytes(s);
    const recValFormatted = opts.unit === 'count' ? `${rec.toLocaleString()} ${opts.countUnitLabel}` : formatBytes(rec);

    // Series 1 bar
    if (s > 0) {
      svg += `<rect x="${sentX}" y="${sentY}" width="${barW}" height="${sentH}" rx="2" fill="${opts.series1Color}"><title>${escapeHtml(dateVal)} ${opts.series1Name}: ${sValFormatted}</title></rect>`;
    } else {
      svg += `<rect x="${sentX}" y="${paddingTop + chartH - 2}" width="${barW}" height="2" rx="1" fill="var(--border-subtle, #333)"/>`;
    }

    // Series 2 bar
    if (rec > 0) {
      svg += `<rect x="${recX}" y="${recY}" width="${barW}" height="${recH}" rx="2" fill="${opts.series2Color}"><title>${escapeHtml(dateVal)} ${opts.series2Name}: ${recValFormatted}</title></rect>`;
    } else {
      svg += `<rect x="${recX}" y="${paddingTop + chartH - 2}" width="${barW}" height="2" rx="1" fill="var(--border-subtle, #333)"/>`;
    }

    // Date Label below bar group (show every Nth label if dense)
    const step = Math.ceil(dayRows.length / 15);
    if (idx % step === 0 || idx === dayRows.length - 1) {
      svg += `<text x="${groupX}" y="${height - 8}" font-size="10" fill="var(--text-secondary, #94a3b8)" text-anchor="middle">${dateLabel}</text>`;
    }
  });

  svg += `</svg>`;
  wrapEl.innerHTML = svg;

  // Add interactive hover tooltip
  const svgEl = wrapEl.querySelector('svg');
  if (svgEl) {
    let tooltip = wrapEl.querySelector('.chart-tooltip');
    if (!tooltip) {
      tooltip = document.createElement('div');
      tooltip.className = 'chart-tooltip hidden';
      wrapEl.style.position = 'relative';
      wrapEl.appendChild(tooltip);
    }

    svgEl.addEventListener('mousemove', (evt) => {
      const rect = svgEl.getBoundingClientRect();
      const mouseX = evt.clientX - rect.left;
      const svgX = (mouseX / rect.width) * width;

      const idx = Math.floor((svgX - paddingLeft) / barGroupW);
      if (idx >= 0 && idx < dayRows.length) {
        const r = dayRows[idx];
        const dateVal = r.date || r.month || '';
        const s = r.bytes_sent || 0;
        const rec = r.bytes_received || 0;

        let content = `<div style="font-weight:600; margin-bottom:0.25rem; color:#fff;">${escapeHtml(dateVal)}</div>`;
        if (s > 0 || rec > 0) {
          const sValFormatted = opts.unit === 'count' ? `${s.toLocaleString()} ${opts.countUnitLabel}` : formatBytes(s);
          const recValFormatted = opts.unit === 'count' ? `${rec.toLocaleString()} ${opts.countUnitLabel}` : formatBytes(rec);
          if (s > 0 || opts.series1Name) {
            content += `<div style="color:${opts.series1Color}">${opts.series1Name}: ${sValFormatted}</div>`;
          }
          if (rec > 0 || opts.series2Name) {
            content += `<div style="color:${opts.series2Color}">${opts.series2Name}: ${recValFormatted}</div>`;
          }
          if (opts.unit === 'count') {
            content += `<div style="margin-top:0.25rem; padding-top:0.25rem; border-top:1px solid rgba(255,255,255,0.1); font-size:0.75rem; color:var(--text-secondary,#94a3b8);">Total: ${(s + rec).toLocaleString()} ${opts.countUnitLabel}</div>`;
          } else {
            content += `<div style="margin-top:0.25rem; padding-top:0.25rem; border-top:1px solid rgba(255,255,255,0.1); font-size:0.75rem; color:var(--text-secondary,#94a3b8);">Total: ${formatBytes(s + rec)}</div>`;
          }
        } else {
          content += `<div style="color:var(--text-muted,#64748b)">No activity</div>`;
        }

        tooltip.innerHTML = content;
        tooltip.classList.remove('hidden');

        const tooltipX = Math.min(rect.width - 150, Math.max(10, mouseX - 60));
        const tooltipY = Math.max(10, evt.clientY - rect.top - 65);
        tooltip.style.left = `${tooltipX}px`;
        tooltip.style.top = `${tooltipY}px`;
      } else {
        tooltip.classList.add('hidden');
      }
    });

    svgEl.addEventListener('mouseleave', () => {
      if (tooltip) tooltip.classList.add('hidden');
    });
  }

  if (legendEl) {
    let legendHTML = `
      <div class="usage-legend-item">
        <span class="usage-legend-swatch" style="background: ${opts.series1Color};"></span>
        <span>${escapeHtml(opts.series1Name)}</span>
      </div>
    `;
    if (opts.series2Name && opts.series2Color !== 'transparent') {
      legendHTML += `
        <div class="usage-legend-item">
          <span class="usage-legend-swatch" style="background: ${opts.series2Color};"></span>
          <span>${escapeHtml(opts.series2Name)}</span>
        </div>
      `;
    }
    legendEl.innerHTML = legendHTML;
  }
}

async function loadGlobalUsage(range = '30d') {
  currentGlobalUsageDays = range;
  const wrap = $('global-usage-chart');
  const legend = $('global-usage-legend');
  const empty = $('global-usage-empty');

  try {
    const res = await apiFetch(`/api/usage/daily?range=${range}`);
    if (!res.ok) return;
    const data = await res.json();
    renderUsageChart(wrap, legend, empty, data.days || []);
  } catch { /* handle */ }
}

let usageTabUsers = [];
let usageTabDomains = [];

async function loadUsageUsers(range = (currentUsageTabRange || 'today')) {
  try {
    const url = range ? `/api/users?range=${range}` : '/api/users';
    const res = await apiFetch(url);
    if (!res.ok) return;
    const data = await res.json();
    usageTabUsers = data.users || [];
    renderUsageUsersTable();
  } catch { /* handled */ }
}

async function loadUsageDomains(range = (currentUsageTabRange || 'today')) {
  try {
    const url = range ? `/api/domains?range=${range}` : '/api/domains';
    const res = await apiFetch(url);
    if (!res.ok) return;
    const data = await res.json();
    usageTabDomains = data.rules || [];
    renderUsageDomainsTable();
  } catch { /* handled */ }
}

async function loadUserUsageChart(userId, username, range = (currentUsageTabRange || 'today')) {
  selectedUsageUserId = userId;
  selectedUsageUsername = username;
  currentUserUsageRange = range;

  const panel = $('usage-user-chart-panel');
  const title = $('usage-user-chart-title');
  if (title) title.textContent = `User Traffic & DNS Activity: ${username}`;
  if (panel) panel.classList.remove('hidden');

  const wrap = $('user-usage-chart');
  const legend = $('user-usage-legend');
  const empty = $('user-usage-empty');

  const btns = $('user-usage-day-btns');
  if (btns) {
    btns.querySelectorAll('.segmented-btn').forEach(b => {
      b.classList.toggle('active', (b.dataset.range || 'today') === range);
    });
  }

  try {
    const res = await apiFetch(`/api/users/${userId}/usage?range=${range}`);
    if (res.ok) {
      const data = await res.json();
      const rawDays = data.days || [];
      const rawDNSDays = data.dns_days || [];

      let totalB = 0;
      rawDays.forEach(r => {
        totalB += (r.bytes_sent || 0) + (r.bytes_received || 0);
      });
      if ($('user-stat-bandwidth')) $('user-stat-bandwidth').textContent = formatBytes(totalB);
      if ($('user-stat-dns')) $('user-stat-dns').textContent = (data.total_dns_queries || 0).toLocaleString();

      if (rawDays.length > 0) {
        renderUsageChart(wrap, legend, empty, rawDays, {
          unit: 'bytes',
          series1Name: 'Upload (Sent)',
          series2Name: 'Download (Received)',
          series1Color: 'var(--accent, #4f8ef7)',
          series2Color: 'var(--success, #22c55e)'
        });
      } else if (rawDNSDays.length > 0) {
        const dnsRows = rawDNSDays.map(d => ({
          date: d.date,
          bytes_sent: d.query_count,
          bytes_received: 0
        }));
        renderUsageChart(wrap, legend, empty, dnsRows, {
          unit: 'count',
          series1Name: 'DNS Queries',
          series2Name: '',
          series1Color: 'var(--accent, #4f8ef7)',
          series2Color: 'transparent',
          countUnitLabel: 'queries'
        });
      } else {
        renderUsageChart(wrap, legend, empty, []);
      }
    }

    await loadUserUsageByDomain(userId, range);
    if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (err) {
    console.error('loadUserUsageChart error:', err);
  }
}

function renderUsageUsersTable() {
  const tbody = $('usage-user-tbody');
  const empty = $('usage-user-empty');
  const table = $('usage-user-table');
  if (!tbody) return;

  tbody.innerHTML = '';
  const sourceList = (usageTabUsers && usageTabUsers.length > 0) ? usageTabUsers : (allUsers || []);
  if (!sourceList || sourceList.length === 0) {
    if (empty) empty.classList.remove('hidden');
    if (table) table.classList.add('hidden');
    updateUsageUserPagination(0);
    return;
  }
  if (empty) empty.classList.add('hidden');
  if (table) table.classList.remove('hidden');

  // Sort users
  const users = [...sourceList].sort((a, b) => {
    let valA, valB;
    if (usageUserSortCol === 'username') {
      valA = a.username || '';
      valB = b.username || '';
      return usageUserSortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    } else if (usageUserSortCol === 'sent') {
      valA = a.total_bytes_sent || 0;
      valB = b.total_bytes_sent || 0;
    } else if (usageUserSortCol === 'received') {
      valA = a.total_bytes_received || 0;
      valB = b.total_bytes_received || 0;
    } else if (usageUserSortCol === 'dns') {
      valA = a.total_dns_queries || 0;
      valB = b.total_dns_queries || 0;
    } else { // total
      valA = (a.total_bytes_sent || 0) + (a.total_bytes_received || 0);
      valB = (b.total_bytes_sent || 0) + (b.total_bytes_received || 0);
    }
    return usageUserSortDir === 'asc' ? valA - valB : valB - valA;
  });

  // Paginate
  const totalItems = users.length;
  const totalPages = Math.ceil(totalItems / usageUserPageSize) || 1;
  if (usageUserPage > totalPages) usageUserPage = totalPages;
  if (usageUserPage < 1) usageUserPage = 1;

  const startIdx = (usageUserPage - 1) * usageUserPageSize;
  const endIdx = Math.min(startIdx + usageUserPageSize, totalItems);
  const pageItems = users.slice(startIdx, endIdx);

  for (const u of pageItems) {
    const sent = u.total_bytes_sent || 0;
    const recv = u.total_bytes_received || 0;
    const total = sent + recv;
    const dnsCnt = u.total_dns_queries || 0;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="code-cell">${escapeHtml(u.username)}</td>
      <td>${formatBytes(sent)}</td>
      <td>${formatBytes(recv)}</td>
      <td><span class="code-badge">${formatBytes(total)}</span></td>
      <td><span class="code-badge text-success">${dnsCnt.toLocaleString()}</span></td>
      <td class="text-right">
        <div class="action-btns-row" style="justify-content: flex-end;">
          <button type="button" class="btn btn-secondary btn-xs btn-view-user-chart" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">View Chart</button>
          <button type="button" class="btn btn-secondary btn-xs btn-reset-user-usage" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">Reset Usage</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }

  tbody.querySelectorAll('.btn-view-user-chart').forEach(btn => {
    btn.addEventListener('click', () => {
      loadUserUsageChart(parseInt(btn.dataset.userId), btn.dataset.username, currentUserUsageRange || 'today');
    });
  });

  tbody.querySelectorAll('.btn-reset-user-usage').forEach(btn => {
    btn.addEventListener('click', () => {
      resetUserUsage(parseInt(btn.dataset.userId), btn.dataset.username);
    });
  });

  updateUsageUserPagination(totalItems);
  updateUsageUserSortIcons();
}

function updateUsageUserPagination(totalItems) {
  const info = $('usage-user-page-info');
  const prevBtn = $('usage-user-prev-btn');
  const nextBtn = $('usage-user-next-btn');

  if (totalItems === 0) {
    if (info) info.textContent = 'Showing 0 of 0';
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    return;
  }

  const totalPages = Math.ceil(totalItems / usageUserPageSize) || 1;
  const startIdx = (usageUserPage - 1) * usageUserPageSize + 1;
  const endIdx = Math.min(usageUserPage * usageUserPageSize, totalItems);

  if (info) info.textContent = `Showing ${startIdx}-${endIdx} of ${totalItems} (Page ${usageUserPage}/${totalPages})`;
  if (prevBtn) prevBtn.disabled = (usageUserPage <= 1);
  if (nextBtn) nextBtn.disabled = (usageUserPage >= totalPages);
}

function updateUsageUserSortIcons() {
  ['username', 'sent', 'received', 'total'].forEach(col => {
    const el = $(`usage-sort-${col}`);
    if (el) {
      if (usageUserSortCol === col) {
        el.textContent = usageUserSortDir === 'asc' ? '▲' : '▼';
      } else {
        el.textContent = '';
      }
    }
  });
}

function renderUsageDomainsTable() {
  const tbody = $('usage-domain-tbody');
  const empty = $('usage-domain-empty');
  const table = $('usage-domain-table');
  if (!tbody) return;

  tbody.innerHTML = '';
  const sourceList = (usageTabDomains && usageTabDomains.length > 0) ? usageTabDomains : (allDomains || []);
  if (!sourceList || sourceList.length === 0) {
    if (empty) empty.classList.remove('hidden');
    if (table) table.classList.add('hidden');
    updateUsageDomainPagination(0);
    return;
  }
  if (empty) empty.classList.add('hidden');
  if (table) table.classList.remove('hidden');

  // Sort domains
  const domains = [...sourceList].sort((a, b) => {
    let valA, valB;
    if (usageDomainSortCol === 'domain') {
      valA = a.domain || '';
      valB = b.domain || '';
      return usageDomainSortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    } else if (usageDomainSortCol === 'sent') {
      valA = a.total_bytes_sent || 0;
      valB = b.total_bytes_sent || 0;
    } else if (usageDomainSortCol === 'received') {
      valA = a.total_bytes_received || 0;
      valB = b.total_bytes_received || 0;
    } else { // total
      valA = (a.total_bytes_sent || 0) + (a.total_bytes_received || 0);
      valB = (b.total_bytes_sent || 0) + (b.total_bytes_received || 0);
    }
    return usageDomainSortDir === 'asc' ? valA - valB : valB - valA;
  });

  const totalItems = domains.length;
  const totalPages = Math.ceil(totalItems / usageDomainPageSize) || 1;
  if (usageDomainPage > totalPages) usageDomainPage = totalPages;
  if (usageDomainPage < 1) usageDomainPage = 1;

  const startIdx = (usageDomainPage - 1) * usageDomainPageSize;
  const endIdx = Math.min(startIdx + usageDomainPageSize, totalItems);
  const pageItems = domains.slice(startIdx, endIdx);

  for (const d of pageItems) {
    const sent = d.total_bytes_sent || 0;
    const recv = d.total_bytes_received || 0;
    const total = sent + recv;

    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="code-cell">${escapeHtml(d.domain)}</td>
      <td>${formatBytes(sent)}</td>
      <td>${formatBytes(recv)}</td>
      <td><span class="code-badge">${formatBytes(total)}</span></td>
      <td class="text-right">
        <div class="action-btns-row" style="justify-content: flex-end;">
          <button type="button" class="btn btn-secondary btn-xs btn-view-domain-usage" data-domain="${escapeHtml(d.domain)}">View Usage</button>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }

  tbody.querySelectorAll('.btn-view-domain-usage').forEach(btn => {
    btn.addEventListener('click', () => {
      openDomainUsageModal(btn.dataset.domain);
    });
  });

  updateUsageDomainPagination(totalItems);
  updateUsageDomainSortIcons();
}

function updateUsageDomainPagination(totalItems) {
  const info = $('usage-domain-page-info');
  const prevBtn = $('usage-domain-prev-btn');
  const nextBtn = $('usage-domain-next-btn');

  if (totalItems === 0) {
    if (info) info.textContent = 'Showing 0 of 0';
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    return;
  }

  const totalPages = Math.ceil(totalItems / usageDomainPageSize) || 1;
  const startIdx = (usageDomainPage - 1) * usageDomainPageSize + 1;
  const endIdx = Math.min(usageDomainPage * usageDomainPageSize, totalItems);

  if (info) info.textContent = `Showing ${startIdx}-${endIdx} of ${totalItems} (Page ${usageDomainPage}/${totalPages})`;
  if (prevBtn) prevBtn.disabled = (usageDomainPage <= 1);
  if (nextBtn) nextBtn.disabled = (usageDomainPage >= totalPages);
}

function updateUsageDomainSortIcons() {
  ['domain', 'sent', 'received', 'total'].forEach(col => {
    const el = $(`usage-dom-sort-${col}`);
    if (el) {
      if (usageDomainSortCol === col) {
        el.textContent = usageDomainSortDir === 'asc' ? '▲' : '▼';
      } else {
        el.textContent = '';
      }
    }
  });
}

function resetUserUsage(userId, username) {
  showConfirmDialog({
    title: '⚠️ Reset User Usage History',
    message: `Are you sure you want to clear all traffic usage history for user "${username}"? Total sent/received bytes will be zeroed and daily history will be deleted.`,
    confirmText: 'Reset Usage',
    confirmBtnClass: 'btn-danger'
  }).then(async (confirmed) => {
    if (!confirmed) return;
    try {
      const res = await apiFetch(`/api/users/${userId}/usage/reset`, { method: 'POST' });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showToast(data.error || 'Failed to reset usage.', 'error');
        return;
      }
      showToast(`Usage history for "${username}" reset successfully.`, 'success');
      await loadUsageUsers(currentUsageTabRange || 'today');
      loadGlobalUsage(currentGlobalUsageDays);
      if (selectedUsageUserId === userId) {
        loadUserUsageChart(userId, username, currentUserUsageRange || currentUsageTabRange || 'today');
      }
    } catch {
      showToast('Network error while resetting usage.', 'error');
    }
  });
}

let currentUsageTabRange = 'today';

async function updateUsageTabRange(range = 'today') {
  currentUsageTabRange = range;
  currentGlobalUsageDays = range;
  try {
    const res = await apiFetch(`/api/stats?range=${range}`);
    if (res.ok) {
      const stats = await res.json();
      if ($('usage-summary-bandwidth')) $('usage-summary-bandwidth').textContent = formatBytes(stats.global_bytes_total || stats.tls_bytes_total || 0);
      const userDnsTotal = stats.user_dns_queries_total !== undefined ? stats.user_dns_queries_total : (stats.dns_requests_authorized || stats.dns_requests_total || 0);
      if ($('usage-summary-dns')) $('usage-summary-dns').textContent = userDnsTotal.toLocaleString();
    }
  } catch (err) {
    console.error('updateUsageTabRange error:', err);
  }

  loadGlobalUsage(range);
  await loadUsageUsers(range);
  await loadUsageDomains(range);
  _refreshActiveUsageSubtab();

  if (selectedUsageUserId) {
    await loadUserUsageChart(selectedUsageUserId, selectedUsageUsername, range);
  }
}

function initUsageTab() {
  const usageRangeBtns = $('usage-range-btns');
  if (usageRangeBtns) {
    usageRangeBtns.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        usageRangeBtns.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const range = btn.dataset.range || 'today';
        updateUsageTabRange(range);
      });
    });
  }

  // Day selector buttons for per-user usage chart
  const userDayBtns = $('user-usage-day-btns');
  if (userDayBtns) {
    userDayBtns.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        userDayBtns.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const range = btn.dataset.range || 'today';
        if (selectedUsageUserId) {
          loadUserUsageChart(selectedUsageUserId, selectedUsageUsername, range);
        }
      });
    });
  }

  // Close user usage chart panel
  const closeUserChartBtn = $('close-user-usage-chart');
  if (closeUserChartBtn) {
    closeUserChartBtn.addEventListener('click', () => {
      const panel = $('usage-user-chart-panel');
      if (panel) panel.classList.add('hidden');
      selectedUsageUserId = null;
    });
  }

  // Domain usage modal close and range toggle listeners
  const closeDomModalBtn = $('close-domain-usage-modal');
  if (closeDomModalBtn) {
    closeDomModalBtn.addEventListener('click', () => {
      const modal = $('domain-usage-modal');
      if (modal) modal.classList.add('hidden');
    });
  }

  const domModalOverlay = $('domain-usage-modal');
  if (domModalOverlay) {
    domModalOverlay.addEventListener('click', (e) => {
      if (e.target === domModalOverlay) {
        domModalOverlay.classList.add('hidden');
      }
    });
  }

  const rangeToggle = $('domain-usage-range-toggle');
  if (rangeToggle) {
    rangeToggle.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        rangeToggle.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentDomainUsageRange = btn.dataset.range || 'daily';
        refreshDomainUsageModalData();
      });
    });
  }
}

async function openDomainUsageModal(domain) {
  currentDomainUsageName = domain;
  currentDomainUsageRange = 'daily';

  const modal = $('domain-usage-modal');
  const title = $('domain-usage-modal-title');
  if (title) title.textContent = `Domain Usage: ${domain}`;

  const toggle = $('domain-usage-range-toggle');
  if (toggle) {
    toggle.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.range === 'daily');
    });
  }

  if (modal) modal.classList.remove('hidden');
  await refreshDomainUsageModalData();
}

async function refreshDomainUsageModalData() {
  if (!currentDomainUsageName) return;
  const domain = currentDomainUsageName;
  const range = currentDomainUsageRange;

  const wrap = $('domain-usage-chart-wrap');
  const legend = $('domain-usage-legend');
  const empty = $('domain-usage-empty');

  try {
    const url = range === 'monthly' ? `/api/domains/${encodeURIComponent(domain)}/usage/monthly?months=12` : `/api/domains/${encodeURIComponent(domain)}/usage?days=30`;
    const res = await apiFetch(url);
    if (res.ok) {
      const data = await res.json();
      const series = data.days || data.months || [];
      renderUsageChart(wrap, legend, empty, series);
    }
  } catch (err) {
    console.error('domain usage chart fetch error:', err);
  }

  const tbody = $('domain-usage-users-tbody');
  const usersEmpty = $('domain-usage-users-empty');
  if (tbody) {
    tbody.innerHTML = '';
    try {
      const res = await apiFetch(`/api/domains/${encodeURIComponent(domain)}/usage/users`);
      if (res.ok) {
        const data = await res.json();
        const users = data.users || [];
        if (users.length === 0) {
          if (usersEmpty) usersEmpty.classList.remove('hidden');
        } else {
          if (usersEmpty) usersEmpty.classList.add('hidden');
          for (const u of users) {
            const sent = u.bytes_sent || 0;
            const rec = u.bytes_received || 0;
            const tot = sent + rec;
            const tr = document.createElement('tr');
            tr.innerHTML = `
              <td>${escapeHtml(u.username || ('User #' + u.user_id))}</td>
              <td>${formatBytes(sent)}</td>
              <td>${formatBytes(rec)}</td>
              <td><strong>${formatBytes(tot)}</strong></td>
            `;
            tbody.appendChild(tr);
          }
        }
      }
    } catch (err) {
      console.error('domain top users fetch error:', err);
    }
  }
}

async function loadUserUsageByDomain(userId, range = '7d') {
  try {
    const res = await apiFetch(`/api/users/${userId}/usage/domains?range=${range}`);
    if (!res.ok) return;
    const data = await res.json();
    allUserDomainsList = data.domains || [];
    userDomainPage = 1;
    renderUserDomainsTable();
  } catch (err) {
    console.error('loadUserUsageByDomain error:', err);
  }
}

function renderUserDomainsTable() {
  const tbody = $('user-usage-domains-tbody');
  const empty = $('user-usage-domains-empty');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (!allUserDomainsList || allUserDomainsList.length === 0) {
    if (empty) empty.classList.remove('hidden');
    updateUserDomainPagination(0);
    return;
  }
  if (empty) empty.classList.add('hidden');

  const sorted = [...allUserDomainsList].sort((a, b) => {
    let valA, valB;
    if (userDomainSortCol === 'domain') {
      valA = a.domain || '';
      valB = b.domain || '';
      return userDomainSortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    } else if (userDomainSortCol === 'sent') {
      valA = a.bytes_sent || 0;
      valB = b.bytes_sent || 0;
    } else if (userDomainSortCol === 'received') {
      valA = a.bytes_received || 0;
      valB = b.bytes_received || 0;
    } else {
      valA = (a.bytes_sent || 0) + (a.bytes_received || 0);
      valB = (b.bytes_sent || 0) + (b.bytes_received || 0);
    }
    return userDomainSortDir === 'asc' ? valA - valB : valB - valA;
  });

  const totalItems = sorted.length;
  const totalPages = Math.ceil(totalItems / userDomainPageSize) || 1;
  if (userDomainPage > totalPages) userDomainPage = totalPages;
  if (userDomainPage < 1) userDomainPage = 1;

  const startIdx = (userDomainPage - 1) * userDomainPageSize;
  const endIdx = Math.min(startIdx + userDomainPageSize, totalItems);
  const pageItems = sorted.slice(startIdx, endIdx);

  for (const d of pageItems) {
    const sent = d.bytes_sent || 0;
    const rec = d.bytes_received || 0;
    const tot = sent + rec;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="code-cell">${escapeHtml(d.domain)}</span></td>
      <td>${formatBytes(sent)}</td>
      <td>${formatBytes(rec)}</td>
      <td><strong>${formatBytes(tot)}</strong></td>
    `;
    tbody.appendChild(tr);
  }

  updateUserDomainPagination(totalItems);
  updateUserDomainSortIcons();
}

function updateUserDomainPagination(totalItems) {
  const info = $('user-dom-page-info');
  const prevBtn = $('user-dom-prev-btn');
  const nextBtn = $('user-dom-next-btn');

  if (totalItems === 0) {
    if (info) info.textContent = 'Showing 0 of 0';
    if (prevBtn) prevBtn.disabled = true;
    if (nextBtn) nextBtn.disabled = true;
    return;
  }

  const totalPages = Math.ceil(totalItems / userDomainPageSize) || 1;
  const startIdx = (userDomainPage - 1) * userDomainPageSize + 1;
  const endIdx = Math.min(userDomainPage * userDomainPageSize, totalItems);

  if (info) info.textContent = `Showing ${startIdx}-${endIdx} of ${totalItems} (Page ${userDomainPage}/${totalPages})`;
  if (prevBtn) prevBtn.disabled = (userDomainPage <= 1);
  if (nextBtn) nextBtn.disabled = (userDomainPage >= totalPages);
}

function updateUserDomainSortIcons() {
  ['domain', 'sent', 'received', 'total'].forEach(col => {
    const el = $(`udom-sort-${col}`);
    if (el) {
      if (userDomainSortCol === col) {
        el.textContent = userDomainSortDir === 'asc' ? '▲' : '▼';
      } else {
        el.textContent = '';
      }
    }
  });
}

// Wire Usage Tab Subtabs, Sort Headers, and Pagination Controls
function initUsageTabSubtabsAndControls() {
  const subtabToggle = $('usage-breakdown-subtab-toggle');
  if (subtabToggle) {
    subtabToggle.querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        subtabToggle.querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const sub = btn.dataset.subtab;
        const userWrap = $('usage-subtab-user');
        const domWrap = $('usage-subtab-domain');
        if (sub === 'domain') {
          if (userWrap) userWrap.classList.add('hidden');
          if (domWrap) domWrap.classList.remove('hidden');
          renderUsageDomainsTable();
        } else {
          if (domWrap) domWrap.classList.add('hidden');
          if (userWrap) userWrap.classList.remove('hidden');
          renderUsageUsersTable();
        }
      });
    });
  }

  // User table sort header clicks
  document.querySelectorAll('#usage-user-table th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (usageUserSortCol === col) {
        usageUserSortDir = usageUserSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        usageUserSortCol = col;
        usageUserSortDir = 'desc';
      }
      renderUsageUsersTable();
    });
  });

  // User table pagination
  const userPrev = $('usage-user-prev-btn');
  if (userPrev) {
    userPrev.addEventListener('click', () => {
      if (usageUserPage > 1) {
        usageUserPage--;
        renderUsageUsersTable();
      }
    });
  }
  const userNext = $('usage-user-next-btn');
  if (userNext) {
    userNext.addEventListener('click', () => {
      usageUserPage++;
      renderUsageUsersTable();
    });
  }

  // Domain table sort header clicks
  document.querySelectorAll('#usage-domain-table th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (usageDomainSortCol === col) {
        usageDomainSortDir = usageDomainSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        usageDomainSortCol = col;
        usageDomainSortDir = 'desc';
      }
      renderUsageDomainsTable();
    });
  });

  // Domain table pagination
  const domPrev = $('usage-domain-prev-btn');
  if (domPrev) {
    domPrev.addEventListener('click', () => {
      if (usageDomainPage > 1) {
        usageDomainPage--;
        renderUsageDomainsTable();
      }
    });
  }
  const domNext = $('usage-domain-next-btn');
  if (domNext) {
    domNext.addEventListener('click', () => {
      usageDomainPage++;
      renderUsageDomainsTable();
    });
  }
}
