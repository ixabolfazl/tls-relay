/* =========================================================================
   TLS Relay Admin Panel — domains.js
   Domain Rules management: CRUD operations, group assignment,
   live preview parsing, list sorting, and merged rows logic.
   ========================================================================= */

"use strict";

let currentDomainModeTab = 'proxy';
let expandedMergedKeys = new Set();
let editModalOriginalHasWildcard = false;
let editModalOriginalSettingsMatched = false;
let previewDebounceTimer = null;

async function loadDomains(range) {
  try {
    const url = range ? `/api/domains?range=${encodeURIComponent(range)}` : '/api/domains';
    const res = await apiFetch(url);
    if (!res.ok) return;
    const data = await res.json();
    allDomains = data.domains || [];
    updateMetrics();
    updateGroupDatalist();
    renderDomains();
    if (typeof renderUsageDomainsTable === 'function') {
      renderUsageDomainsTable();
    }
  } catch { /* handled */ }
}

function getSortedDomains(domains) {
  const list = [...domains];
  list.sort((a, b) => {
    let valA = a[domainSortCol] || '';
    let valB = b[domainSortCol] || '';
    if (domainSortCol === 'ports') {
      valA = Array.isArray(a.ports) ? a.ports.join(',') : String(a.ports);
      valB = Array.isArray(b.ports) ? b.ports.join(',') : String(b.ports);
    }
    const comp = String(valA).localeCompare(String(valB), undefined, { numeric: true, sensitivity: 'base' });
    return domainSortDir === 'asc' ? comp : -comp;
  });
  return list;
}

function updateSortIcons() {
  ['domain', 'group_name', 'ports', 'created_at'].forEach(col => {
    const icon = $('sort-icon-' + col);
    if (icon) {
      if (domainSortCol === col) {
        icon.textContent = domainSortDir === 'asc' ? '▲' : '▼';
        icon.style.opacity = '1';
      } else {
        icon.textContent = '';
        icon.style.opacity = '0.4';
      }
    }
  });
}

function parseDomainToken(rawToken, existingDomains) {
  let s = (rawToken || '').trim();
  if (!s) return { raw: rawToken, valid: false, reason: 'empty token' };

  let hasWildcard = false;
  if (s.startsWith('*.')) {
    hasWildcard = true;
    s = s.slice(2);
  } else if (s[0] === '*') {
    return { raw: rawToken, valid: false, reason: "invalid wildcard syntax: '*' must be followed by '.' (e.g. *.example.com)" };
  }

  // Scheme strip
  if (s.startsWith('//')) {
    s = s.slice(2);
  } else {
    const schemeMatch = s.match(/^(https?|wss?|ftp):\/\//i);
    if (schemeMatch) {
      s = s.slice(schemeMatch[0].length);
    }
  }

  // Userinfo strip
  const atIdx = s.indexOf('@');
  const slashIdx = s.indexOf('/');
  if (atIdx >= 0 && (slashIdx < 0 || atIdx < slashIdx)) {
    s = s.slice(atIdx + 1);
  }

  // Bracketed IPv6 reject
  if (s.startsWith('[')) {
    return { raw: rawToken, valid: false, reason: 'IP addresses are not valid SNI domains' };
  }

  // Strip path/query/fragment
  let cutAt = s.length;
  for (const char of ['/', '?', '#']) {
    const idx = s.indexOf(char);
    if (idx >= 0 && idx < cutAt) cutAt = idx;
  }
  s = s.slice(0, cutAt);

  // Strip port / reject bare IPv6
  const colonCount = (s.match(/:/g) || []).length;
  if (colonCount > 1) {
    return { raw: rawToken, valid: false, reason: 'IP addresses are not valid SNI domains' };
  } else if (colonCount === 1) {
    const parts = s.split(':');
    s = parts[0];
  }

  // Lowercase & trim trailing dot
  s = s.toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);

  // IP address checks
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s)) {
    return { raw: rawToken, valid: false, reason: 'IP addresses are not valid SNI domains' };
  }

  if (s.includes('*')) {
    return { raw: rawToken, valid: false, reason: "invalid wildcard syntax: '*' may only appear as leading '*.'" };
  }

  if (!s) {
    return { raw: rawToken, valid: false, reason: 'empty domain after normalization' };
  }

  let isNonASCII = false;
  if (/[^\x00-\x7F]/.test(s)) {
    isNonASCII = true;
  }

  // Label validation
  const labels = s.split('.');
  for (const label of labels) {
    if (!label || label.length > 63 || !/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)) {
      if (!isNonASCII) {
        return { raw: rawToken, valid: false, reason: `invalid hostname syntax: label "${label}"` };
      }
    }
  }

  const normalized = hasWildcard ? '*.' + s : s;
  const isDuplicate = existingDomains.some(d => d.domain === normalized);

  return {
    raw: rawToken,
    normalized: normalized,
    valid: true,
    isNonASCII: isNonASCII,
    isDuplicate: isDuplicate,
  };
}

function extractCleanDomainsFromText(rawText) {
  if (!rawText) return [];

  const wildcardRegex = /\*\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/gi;
  const wildcardMatches = rawText.match(wildcardRegex) || [];

  const hostRegex = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/gi;
  const hostMatches = rawText.match(hostRegex) || [];

  const combined = [...wildcardMatches, ...hostMatches];
  const results = [];
  const seen = new Set();

  for (const token of combined) {
    const parsed = parseDomainToken(token, allDomains);
    if (parsed.valid && !seen.has(parsed.normalized)) {
      seen.add(parsed.normalized);
      results.push(parsed.normalized);
    }
  }

  return results;
}

function updateDomainPreview() {
  const textarea = $('domain-name');
  const container = $('domain-preview-container');
  if (!textarea || !container) return;

  const rawText = textarea.value;
  const rawTokens = (rawText || '').split(/[\n\r,\t ]+/).map(t => t.trim()).filter(Boolean);
  if (rawTokens.length === 0) {
    container.classList.add('hidden');
    container.innerHTML = '';
    return;
  }

  const parsed = rawTokens.map(t => parseDomainToken(t, allDomains));
  const validCount = parsed.filter(p => p.valid).length;

  let html = `<div class="preview-header">${parsed.length} item(s) detected (${validCount} valid)</div>`;
  html += '<div class="preview-list">';

  parsed.forEach(p => {
    if (!p.valid) {
      html += `<div class="preview-item invalid">❌ <code>${escapeHtml(p.raw)}</code> — ${escapeHtml(p.reason)}</div>`;
    } else if (p.isDuplicate) {
      html += `<div class="preview-item duplicate">⚠️ <code>${escapeHtml(p.normalized)}</code> — already exists (settings will be updated)</div>`;
    } else {
      const note = p.isNonASCII ? ' <span class="text-hint">(non-ASCII — converted server-side)</span>' : '';
      html += `<div class="preview-item valid">✓ <code>${escapeHtml(p.normalized)}</code>${note}</div>`;
    }
  });

  html += '</div>';
  container.innerHTML = html;
  container.classList.remove('hidden');
}

function initAutoExtractButton() {
  if ($('auto-extract-btn')) {
    $('auto-extract-btn').addEventListener('click', () => {
      const textarea = $('domain-name');
      if (!textarea) return;
      const raw = textarea.value;
      const extracted = extractCleanDomainsFromText(raw);
      if (extracted.length > 0) {
        textarea.value = extracted.join('\n');
        updateDomainPreview();
        showToast(`Successfully extracted ${extracted.length} clean domain(s).`, 'success');
      } else {
        showToast('No valid domain patterns found in the input text.', 'error');
      }
    });
  }
}


function arePortsEqual(p1, p2) {
  if (p1 === 'all' && p2 === 'all') return true;
  if (Array.isArray(p1) && Array.isArray(p2)) {
    if (p1.length !== p2.length) return false;
    const s1 = [...p1].sort((a, b) => a - b).join(',');
    const s2 = [...p2].sort((a, b) => a - b).join(',');
    return s1 === s2;
  }
  return String(p1) === String(p2);
}

function areRulesIdentical(r1, r2) {
  if (!r1 || !r2) return false;
  if ((r1.group_name || '') !== (r2.group_name || '')) return false;
  const eg1 = (r1.use_egress_proxy || 'false').toLowerCase();
  const eg2 = (r2.use_egress_proxy || 'false').toLowerCase();
  const eg1Norm = (eg1 === 'true' || eg1 === 'custom') ? 'true' : 'false';
  const eg2Norm = (eg2 === 'true' || eg2 === 'custom') ? 'true' : 'false';
  if (eg1Norm !== eg2Norm) return false;
  if ((r1.mode || 'proxy') !== (r2.mode || 'proxy')) return false;
  return arePortsEqual(r1.ports, r2.ports);
}

function buildDisplayRows(allDomainsList, sortedFilteredList) {
  const domainMap = new Map();
  for (const d of allDomainsList) {
    domainMap.set(d.domain, d);
  }

  const rows = [];
  const processedWildcards = new Set();

  for (const d of sortedFilteredList) {
    if (processedWildcards.has(d.domain)) {
      continue; // Skip wildcard that was merged with its apex
    }

    if (!d.domain.startsWith('*.')) {
      const wildcardKey = '*.' + d.domain;
      const wildcardRule = domainMap.get(wildcardKey);

      // Check if wildcardRule exists and has identical settings
      if (wildcardRule && areRulesIdentical(d, wildcardRule)) {
        if (!expandedMergedKeys.has(d.domain)) {
          // Display as merged row
          processedWildcards.add(wildcardKey);
          rows.push({
            type: 'merged',
            domain: d.domain,
            wildcardDomain: wildcardKey,
            apex: d,
            wildcard: wildcardRule,
            group_name: d.group_name,
            ports: d.ports,
            use_egress_proxy: d.use_egress_proxy,
            total_bytes_sent: (d.total_bytes_sent || 0) + (wildcardRule.total_bytes_sent || 0),
            total_bytes_received: (d.total_bytes_received || 0) + (wildcardRule.total_bytes_received || 0),
            created_at: (new Date(d.created_at || 0) < new Date(wildcardRule.created_at || 0)) ? d.created_at : wildcardRule.created_at,
          });
          continue;
        }
      }
    }

    // Single row
    rows.push({
      type: 'single',
      domain: d.domain,
      rule: d,
      group_name: d.group_name,
      ports: d.ports,
      use_egress_proxy: d.use_egress_proxy,
      mode: d.mode || 'proxy',
      total_bytes_sent: d.total_bytes_sent || 0,
      total_bytes_received: d.total_bytes_received || 0,
      created_at: d.created_at,
    });
  }

  return rows;
}

function renderDomains() {
  updateSortIcons();
  const query = ($('domain-search').value || '').trim().toLowerCase();
  const filtered = allDomains.filter(d => {
    const dMode = d.mode || 'proxy';
    if (dMode !== currentDomainModeTab) return false;
    return d.domain.toLowerCase().includes(query) ||
      (d.group_name && d.group_name.toLowerCase().includes(query));
  });

  const tbody = $('domain-tbody');
  const empty = $('domain-empty');
  const table = $('domain-table');
  tbody.innerHTML = '';

  if (filtered.length === 0) {
    empty.textContent = allDomains.length === 0 ? 'No domain rules configured yet.' : 'No domains match your search.';
    empty.classList.remove('hidden');
    table.classList.add('hidden');
    updateBulkBar();
    return;
  }
  empty.classList.add('hidden');
  table.classList.remove('hidden');

  const sorted = getSortedDomains(filtered);
  const displayRows = buildDisplayRows(allDomains, sorted);

  if (domainViewMode === 'flat') {
    const flatPag = $('domain-flat-pagination');
    const flatInfo = $('domain-flat-pagination-info');
    const flatPrev = $('domain-flat-prev-page');
    const flatNext = $('domain-flat-next-page');
    const pageSize = 50;
    const totalRows = displayRows.length;
    const totalPages = Math.max(1, Math.ceil(totalRows / pageSize));
    if (domainFlatPage > totalPages) domainFlatPage = totalPages;
    const startIdx = (domainFlatPage - 1) * pageSize;
    const endIdx = Math.min(startIdx + pageSize, totalRows);
    const pageRows = displayRows.slice(startIdx, endIdx);

    for (const row of pageRows) {
      const tr = createDomainRow(row);
      tbody.appendChild(tr);
    }

    if (flatPag) {
      if (totalRows > pageSize) {
        flatPag.classList.remove('hidden');
        flatPag.style.display = 'flex';
      } else {
        flatPag.classList.add('hidden');
        flatPag.style.display = 'none';
      }
    }
    if (flatInfo) {
      flatInfo.textContent = totalRows === 0
        ? 'Showing 0 of 0'
        : `Showing ${startIdx + 1}–${endIdx} of ${totalRows} (Page ${domainFlatPage}/${totalPages})`;
    }
    if (flatPrev) flatPrev.disabled = (domainFlatPage <= 1);
    if (flatNext) flatNext.disabled = (domainFlatPage >= totalPages);
  } else {
    // Hide flat pagination in grouped mode
    const flatPag = $('domain-flat-pagination');
    if (flatPag) {
      flatPag.classList.add('hidden');
      flatPag.style.display = 'none';
    }
    // Group rules by group_name
    const groupedMap = new Map();
    const ungroupedList = [];

    for (const row of displayRows) {
      const g = (row.group_name || '').trim();
      if (g === '') {
        ungroupedList.push(row);
      } else {
        if (!groupedMap.has(g)) {
          groupedMap.set(g, []);
        }
        groupedMap.get(g).push(row);
      }
    }

    // Helper to count selected domains in a row
    const isRowChecked = (row) => {
      if (row.type === 'merged') {
        return selectedDomains.has(row.domain) && selectedDomains.has(row.wildcardDomain);
      }
      return selectedDomains.has(row.domain);
    };

    // Render grouped rules
    for (const [groupName, rowsInGroup] of groupedMap.entries()) {
      const isCollapsed = !expandedGroups.has(groupName);

      // Group Header Row
      const headerTr = document.createElement('tr');
      headerTr.className = 'group-header-row';

      const checkedCountInGroup = rowsInGroup.filter(r => isRowChecked(r)).length;
      const allCheckedInGroup = rowsInGroup.length > 0 && checkedCountInGroup === rowsInGroup.length;

      headerTr.innerHTML = `
      <td class="checkbox-cell" onclick="event.stopPropagation();">
        <input type="checkbox" class="group-chk" data-group="${escapeHtml(groupName)}" ${allCheckedInGroup ? 'checked' : ''} />
      </td>
      <td colspan="7">
        <div class="group-title">
          <span class="group-chevron ${isCollapsed ? 'collapsed' : ''}">▼</span>
          📁 <span>${escapeHtml(groupName)}</span>
          <span class="group-badge">${rowsInGroup.length} item${rowsInGroup.length > 1 ? 's' : ''}</span>
        </div>
      </td>`;

      headerTr.addEventListener('click', (e) => {
        if (e.target.tagName === 'INPUT') return;
        if (expandedGroups.has(groupName)) {
          expandedGroups.delete(groupName);
        } else {
          expandedGroups.add(groupName);
        }
        renderDomains();
      });

      const groupChk = headerTr.querySelector('.group-chk');
      groupChk.addEventListener('change', (e) => {
        const checked = e.target.checked;
        rowsInGroup.forEach(row => {
          if (row.type === 'merged') {
            if (checked) { selectedDomains.add(row.domain); selectedDomains.add(row.wildcardDomain); }
            else { selectedDomains.delete(row.domain); selectedDomains.delete(row.wildcardDomain); }
          } else {
            if (checked) selectedDomains.add(row.domain);
            else selectedDomains.delete(row.domain);
          }
        });
        renderDomains();
      });

      tbody.appendChild(headerTr);

      if (!isCollapsed) {
        for (const row of rowsInGroup) {
          tbody.appendChild(createDomainRow(row));
        }
      }
    }

    // Render ungrouped rules if any
    if (ungroupedList.length > 0) {
      if (groupedMap.size > 0) {
        const ungroupedHeader = document.createElement('tr');
        ungroupedHeader.className = 'group-header-row';
        ungroupedHeader.innerHTML = `
        <td class="checkbox-cell"></td>
        <td colspan="7">
          <div class="group-title">
            📄 <span>Ungrouped Domains</span>
            <span class="group-badge">${ungroupedList.length}</span>
          </div>
        </td>`;
        tbody.appendChild(ungroupedHeader);
      }
      for (const row of ungroupedList) {
        tbody.appendChild(createDomainRow(row));
      }
    }
  }

  tbody.querySelectorAll('.btn-view-domain-usage').forEach(btn => {
    btn.addEventListener('click', () => openDomainUsageModal(btn.dataset.domain));
  });

  tbody.querySelectorAll('.btn-edit-domain').forEach(btn => {
    btn.addEventListener('click', () => openEditDomainModal(btn.dataset.domain));
  });

  tbody.querySelectorAll('.btn-delete-domain').forEach(btn => {
    btn.addEventListener('click', () => {
      const wildcard = btn.dataset.wildcard;
      if (wildcard) {
        deleteMergedPair(btn.dataset.domain, wildcard);
      } else {
        deleteDomain(btn.dataset.domain);
      }
    });
  });

  tbody.querySelectorAll('.btn-split').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      expandedMergedKeys.add(btn.dataset.apex);
      renderDomains();
    });
  });

  tbody.querySelectorAll('.domain-chk').forEach(chk => {
    chk.addEventListener('change', (e) => {
      const domain = e.target.dataset.domain;
      const wildcard = e.target.dataset.wildcard;
      if (wildcard) {
        if (e.target.checked) {
          selectedDomains.add(domain);
          selectedDomains.add(wildcard);
        } else {
          selectedDomains.delete(domain);
          selectedDomains.delete(wildcard);
        }
      } else {
        if (e.target.checked) selectedDomains.add(domain);
        else selectedDomains.delete(domain);
      }
      updateSelectAllCheckboxes();
      updateBulkBar();
    });
  });

  updateSelectAllCheckboxes();
  updateBulkBar();
}

function createDomainRow(item) {
  const tr = document.createElement('tr');

  let portsStr = '';
  if (item.ports === 'all') {
    portsStr = '<span class="port-badge">all ports</span>';
  } else if (Array.isArray(item.ports)) {
    portsStr = item.ports.map(p => `<span class="port-badge">${p}</span>`).join(' ');
  } else {
    portsStr = `<span class="port-badge">${escapeHtml(item.ports)}</span>`;
  }

  let egressStr = '';
  const itemMode = item.mode || 'proxy';
  if (itemMode === 'direct') {
    egressStr = '<span class="mode-badge-direct">Direct</span>';
  } else if (itemMode === 'block') {
    egressStr = '<span class="mode-badge-block">Blocked</span>';
  } else if (item.use_egress_proxy === 'true' || item.use_egress_proxy === 'custom') {
    egressStr = '<span class="status-badge status-allowed">Custom Proxy</span>';
  } else {
    egressStr = '<span class="status-badge status-neutral">Server Proxy</span>';
  }

  const groupStr = item.group_name ? `<span class="group-badge">${escapeHtml(item.group_name)}</span>` : '<span class="text-hint">—</span>';
  const createdStr = item.created_at ? `<span class="text-hint">${escapeHtml(formatTimestamp(item.created_at))}</span>` : '—';

  const totalBytes = (item.total_bytes_sent || 0) + (item.total_bytes_received || 0);
  const usageCellHtml = `<span class="usage-badge" title="Sent: ${formatBytes(item.total_bytes_sent || 0)}, Received: ${formatBytes(item.total_bytes_received || 0)}">${formatBytes(totalBytes)}</span>`;

  let isChecked = false;
  let domainColHtml = '';

  if (item.type === 'merged') {
    isChecked = selectedDomains.has(item.domain) && selectedDomains.has(item.wildcardDomain);
    domainColHtml = `
      <span class="code-cell">${escapeHtml(item.domain)}</span>
      <span class="subdomain-badge">+ subdomains</span>
      <button type="button" class="btn-split" data-apex="${escapeHtml(item.domain)}" title="Split into separate rows">Split</button>
    `;
  } else {
    isChecked = selectedDomains.has(item.domain);
    domainColHtml = `<span class="code-cell">${escapeHtml(item.domain)}</span>`;
  }

  tr.innerHTML = `
    <td class="checkbox-cell">
      <input type="checkbox" class="domain-chk" data-domain="${escapeHtml(item.domain)}" ${item.type === 'merged' ? `data-wildcard="${escapeHtml(item.wildcardDomain)}"` : ''} ${isChecked ? 'checked' : ''} />
    </td>
    <td>${domainColHtml}</td>
    <td>${groupStr}</td>
    <td>${portsStr}</td>
    <td>${egressStr}</td>
    <td>${usageCellHtml}</td>
    <td>${createdStr}</td>
    <td class="text-right">
      <div class="action-btns-row" style="justify-content: flex-end;">
        <button type="button" class="btn-icon btn-edit-domain" data-domain="${escapeHtml(item.domain)}" title="Edit domain rule">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
        </button>
        <button type="button" class="btn-icon btn-icon-danger btn-delete-domain" data-domain="${escapeHtml(item.domain)}" ${item.type === 'merged' ? `data-wildcard="${escapeHtml(item.wildcardDomain)}"` : ''} title="Delete domain rule">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
        </button>
      </div>
    </td>`;

  return tr;
}

async function deleteDomain(domain) {
  const confirmed = await showConfirmDialog({
    title: 'Delete Domain Rule',
    message: `Are you sure you want to delete the domain rule for "${domain}"?`,
    confirmText: 'Delete Domain',
    isDanger: true,
  });
  if (!confirmed) return;

  try {
    const encoded = encodeURIComponent(domain);
    const res = await apiFetch(`/api/domains/${encoded}`, { method: 'DELETE' });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Delete failed.', 'error');
      return;
    }
    selectedDomains.delete(domain);
    showToast(`Domain rule "${domain}" deleted.`, 'success');
    loadDomains();
  } catch {
    showToast('Failed to delete domain rule.', 'error');
  }
}

async function deleteMergedPair(apexDomain, wildcardDomain) {
  const confirmed = await showConfirmDialog({
    title: 'Delete Domain Rules',
    message: `This will delete both "${apexDomain}" and "${wildcardDomain}". Are you sure?`,
    confirmText: 'Delete Both',
    isDanger: true,
  });
  if (!confirmed) return;

  try {
    const res = await apiFetch('/api/domains/bulk-delete', {
      method: 'POST',
      body: JSON.stringify({ domains: [apexDomain, wildcardDomain] }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      showToast(data.error || 'Delete failed.', 'error');
      return;
    }
    selectedDomains.delete(apexDomain);
    selectedDomains.delete(wildcardDomain);
    showToast(`Deleted "${apexDomain}" and "${wildcardDomain}".`, 'success');
    loadDomains();
  } catch {
    showToast('Failed to delete domain rules.', 'error');
  }
}

function initDomainListeners() {
  initAutoExtractButton();

  // Input listener on domain-name textarea for live preview
  if ($('domain-name')) {
    $('domain-name').addEventListener('input', () => {
      clearTimeout(previewDebounceTimer);
      previewDebounceTimer = setTimeout(updateDomainPreview, 250);
    });
  }

  // Table Header Sorting Click Handlers
  document.querySelectorAll('#domain-table th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (domainSortCol === col) {
        domainSortDir = domainSortDir === 'asc' ? 'desc' : 'asc';
      } else {
        domainSortCol = col;
        domainSortDir = 'asc';
      }
      renderDomains();
    });
  });

  if ($('domain-search')) {
    $('domain-search').addEventListener('input', () => {
      domainFlatPage = 1;
      renderDomains();
    });
  }

  // Add / Bulk add domain form submit handler
  if ($('add-domain-form')) {
    $('add-domain-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('add-domain-error', 'add-domain-success');

      const btn = $('add-domain-btn');
      btn.disabled = true;
      btn.textContent = 'Adding Domain(s)...';

      const groupName = $('domain-group-name').value.trim();
      const domainRaw = $('domain-name').value.trim();
      const mode = $('domain-mode') ? $('domain-mode').value || 'proxy' : 'proxy';
      const ports = $('domain-ports').value.trim() || '443';
      const egress = $('domain-egress') ? $('domain-egress').value || 'false' : 'false';
      const includeSubdomains = $('domain-include-subdomains') ? $('domain-include-subdomains').checked : false;

      try {
        const res = await apiFetch('/api/domains', {
          method: 'POST',
          body: JSON.stringify({
            group_name: groupName,
            domain: domainRaw,
            mode: mode,
            ports: ports,
            use_egress_proxy: egress,
            include_subdomains: includeSubdomains,
          }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('add-domain-error', data.error || 'Failed to add domain rules.');
          return;
        }

        let msg = `Successfully processed: ${data.added || 0} added, ${data.updated || 0} updated.`;
        if (data.errors && data.errors.length > 0) {
          msg += ` (${data.errors.length} skipped with errors)`;
          let errDetails = data.errors.map(e => `"${e.input}": ${e.reason}`).join('; ');
          showError('add-domain-error', `Skipped invalid domain(s): ${errDetails}`);
        }
        showSuccess('add-domain-success', msg);

        if (addDomainGroupController) addDomainGroupController.setValue('');
        else $('domain-group-name').value = '';
        $('domain-name').value = '';
        const proxyModeRadio = document.querySelector('input[name="domain-mode-radio"][value="proxy"]');
        if (proxyModeRadio) { proxyModeRadio.checked = true; proxyModeRadio.dispatchEvent(new Event('change')); }
        if ($('domain-mode')) $('domain-mode').value = 'proxy';
        $('domain-ports').value = '443';
        if ($('domain-include-subdomains')) $('domain-include-subdomains').checked = false;
        if ($('domain-preview-container')) hideEl('domain-preview-container');
        const serverRadio = document.querySelector('input[name="domain-egress-radio"][value="false"]');
        if (serverRadio) serverRadio.checked = true;
        if ($('domain-egress')) $('domain-egress').value = 'false';
        loadDomains();
      } catch {
        showError('add-domain-error', 'An error occurred while adding domains.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Add Domain Rule(s)';
      }
    });
  }

  if ($('close-edit-domain')) $('close-edit-domain').addEventListener('click', closeEditDomainModal);
  if ($('cancel-edit-domain')) $('cancel-edit-domain').addEventListener('click', closeEditDomainModal);

  // Save Edit Domain Form
  if ($('edit-domain-form')) {
    $('edit-domain-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('edit-domain-error', 'edit-domain-success');

      const domain = $('edit-domain-name').value.trim();
      const groupName = $('edit-domain-group-name').value.trim();
      const mode = $('edit-domain-mode') ? $('edit-domain-mode').value || 'proxy' : 'proxy';
      const ports = $('edit-domain-ports').value.trim() || '443';
      const egress = $('edit-domain-egress') ? $('edit-domain-egress').value || 'false' : 'false';
      const subCheckbox = $('edit-domain-include-subdomains');
      const includeSubdomains = subCheckbox ? subCheckbox.checked : false;
      const btn = $('save-edit-domain-btn');

      let deleteWildcard = false;

      if (!domain.startsWith('*.')) {
        if (editModalOriginalHasWildcard && !includeSubdomains) {
          if (!editModalOriginalSettingsMatched) {
            const confirmed = await showConfirmDialog({
              title: 'Unlink Wildcard Rule',
              message: `The wildcard rule *.${domain} has different settings than this apex rule. Are you sure you want to delete it?`,
              confirmText: 'Delete Wildcard',
              isDanger: true,
            });
            if (!confirmed) {
              if (subCheckbox) subCheckbox.checked = true;
              return;
            }
          }
          deleteWildcard = true;
        }
      }

      btn.disabled = true;
      btn.textContent = 'Saving...';

      try {
        const encoded = encodeURIComponent(domain);
        const payload = {
          group_name: groupName,
          mode: mode,
          ports: ports,
          use_egress_proxy: egress,
          include_subdomains: includeSubdomains,
          delete_wildcard_counterpart: deleteWildcard,
        };

        const res = await apiFetch(`/api/domains/${encoded}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('edit-domain-error', data.error || 'Failed to update domain rule.');
          return;
        }

        showSuccess('edit-domain-success', 'Domain rule updated successfully.');
        showToast(`Domain "${domain}" updated.`, 'success');
        setTimeout(() => {
          closeEditDomainModal();
          loadDomains();
        }, 600);
      } catch {
        showError('edit-domain-error', 'An error occurred while updating the domain.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Save Changes';
      }
    });
  }
}

// Edit Domain Modal functions
function openEditDomainModal(domainName) {
  const d = allDomains.find(item => item.domain === domainName);
  if (!d) return;

  $('edit-domain-name').value = d.domain;
  if (editDomainGroupController) {
    editDomainGroupController.refreshOptions();
    editDomainGroupController.setValue(d.group_name || '');
  } else {
    $('edit-domain-group-name').value = d.group_name || '';
  }

  const modeVal = d.mode || 'proxy';
  const modeRadio = document.querySelector(`input[name="edit-domain-mode-radio"][value="${modeVal}"]`);
  if (modeRadio) { modeRadio.checked = true; modeRadio.dispatchEvent(new Event('change')); }
  if ($('edit-domain-mode')) $('edit-domain-mode').value = modeVal;

  if (d.ports === 'all') {
    $('edit-domain-ports').value = 'all';
  } else if (Array.isArray(d.ports)) {
    $('edit-domain-ports').value = d.ports.join(', ');
  } else {
    $('edit-domain-ports').value = d.ports || '443';
  }

  const rawEgress = (d.use_egress_proxy || 'false').toLowerCase();
  const egressVal = (rawEgress === 'true' || rawEgress === 'custom') ? 'true' : 'false';
  const egressRadio = document.querySelector(`input[name="edit-domain-egress-radio"][value="${egressVal}"]`);
  if (egressRadio) egressRadio.checked = true;
  if ($('edit-domain-egress')) $('edit-domain-egress').value = egressVal;
  clearMessages('edit-domain-error', 'edit-domain-success');
  if (typeof updateEgressVisibility === 'function') updateEgressVisibility();

  const subGroup = $('edit-subdomain-group');
  const subCheckbox = $('edit-domain-include-subdomains');

  if (d.domain.startsWith('*.')) {
    if (subGroup) hideEl('edit-subdomain-group');
    editModalOriginalHasWildcard = false;
    editModalOriginalSettingsMatched = false;
  } else {
    if (subGroup) showEl('edit-subdomain-group');
    const wildcardKey = '*.' + d.domain;
    const wildcardRule = allDomains.find(item => item.domain === wildcardKey);
    if (wildcardRule) {
      editModalOriginalHasWildcard = true;
      editModalOriginalSettingsMatched = areRulesIdentical(d, wildcardRule);
      if (subCheckbox) subCheckbox.checked = true;
    } else {
      editModalOriginalHasWildcard = false;
      editModalOriginalSettingsMatched = false;
      if (subCheckbox) subCheckbox.checked = false;
    }
  }

  showEl('edit-domain-modal');
}

function closeEditDomainModal() {
  hideEl('edit-domain-modal');
}

window.openEditDomainModal = openEditDomainModal;
window.closeEditDomainModal = closeEditDomainModal;
window.initDomainListeners = initDomainListeners;
