/**
 * Domains view: rule management, live input preview, grouped/flat views, and bulk actions.
 * Fixes B2 (bulk select scoping), B3 (segmented toggles), B4 (merged mode), B10 (usage sort).
 */

import { html, raw, setHtml, $, $$, escapeHtml, createElement } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatDate, formatCount } from '../core/format.js';
import { TableState } from '../ui/table.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { showMenu } from '../ui/menu.js';
import { createCombobox } from '../ui/combobox.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { createDomainRuleForm } from './domain-rule-form.js';
import { renderGroupedBarChart } from '../ui/chart.js';
import { renderPagination } from '../ui/pagination.js';
import {
  parseDomainTokens,
  isValidDomainToken,
  parsePorts,
  formatPorts,
  mergeApexWildcard,
} from '../domain/rules.js';

export function mount(container) {
  let allDomains = [];
  let groups = [];
  let activeMode = 'proxy'; // proxy | direct | block
  let viewMode = localStorage.getItem('relay_domains_view') || 'flat'; // flat | grouped
  let expandedGroups = new Set(); // Default: all groups collapsed
  let searchQuery = '';

  const tableState = new TableState({
    pageSize: 50,
    sortKey: 'domain',
    sortDir: 'asc',
    getId: (d) => d.domain,
  });

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Page Header -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Domain Rules</h1>
            <p class="text-xs text-txt-muted mt-0.5">Manage SNI routing rules, groups, and access policies</p>
          </div>
          <button id="dom-toggle-add-btn" type="button" class="btn btn-primary btn-sm self-start sm:self-auto">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
            <span>Add Domain Rule</span>
          </button>
        </div>

        <!-- Add Domain Card (Collapsible) -->
        <div id="dom-add-card" class="card hidden animate-slide-down">
          <div class="card-header">
            <h2 class="text-base font-semibold text-txt">New Domain Rule</h2>
            <button id="dom-close-add-btn" type="button" class="btn-icon-sm -mr-2 text-txt-muted hover:text-txt" aria-label="Close">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            </button>
          </div>
          <div class="card-body">
            <form id="dom-add-form" class="space-y-4">
              <div id="dom-add-form-fields"></div>

              <div class="flex items-center justify-end gap-3 pt-2">
                <button id="dom-cancel-add-btn" type="button" class="btn btn-secondary">Cancel</button>
                <button id="dom-submit-add-btn" type="submit" class="btn btn-primary">Save Rules</button>
              </div>
            </form>
          </div>
        </div>

        <!-- Domains List Card -->
        <div class="card">
          <!-- Toolbar -->
          <div class="p-4 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div class="flex items-center gap-3 overflow-x-auto pb-1 md:pb-0">
              <!-- Mode Tabs -->
              <div id="dom-mode-segmented"></div>

              <!-- Grouped / Flat View Toggle -->
              <div id="dom-view-segmented"></div>
            </div>

            <div class="flex items-center gap-3">
              <div class="relative w-full sm:w-64">
                <input
                  id="dom-search-input"
                  type="text"
                  class="input pl-8"
                  placeholder="Filter domains or groups..."
                />
                <svg class="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-txt-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
              </div>
            </div>
          </div>

          <!-- Bulk Actions Bar -->
          <div id="dom-bulk-bar" class="hidden px-5 py-3 bg-primary-soft border-b border-primary-200 dark:border-primary-800 flex flex-wrap items-center justify-between gap-3 animate-fade-in">
            <div class="flex items-center gap-3 text-xs font-semibold text-primary-900 dark:text-primary-100">
              <span id="dom-bulk-count">0 selected</span>
              <button id="dom-bulk-select-all-btn" type="button" class="hidden text-xs text-primary-600 dark:text-primary-400 hover:underline font-medium">
                Select all <span id="dom-bulk-all-count"></span> matching
              </button>
            </div>
            <div class="flex items-center gap-2">
              <button id="dom-bulk-group-btn" type="button" class="btn btn-secondary btn-sm">Assign Group</button>
              <button id="dom-bulk-mode-btn" type="button" class="btn btn-secondary btn-sm">Change Mode</button>
              <button id="dom-bulk-egress-btn" type="button" class="btn btn-secondary btn-sm">Set Egress</button>
              <button id="dom-bulk-delete-btn" type="button" class="btn btn-danger btn-sm">Delete</button>
              <button id="dom-bulk-clear-btn" type="button" class="btn btn-ghost btn-sm text-txt-muted">Deselect</button>
            </div>
          </div>

          <!-- Table Container -->
          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th class="table-th w-10 text-center">
                    <input id="dom-select-all" type="checkbox" class="checkbox mx-auto" aria-label="Select all visible" />
                  </th>
                  <th class="table-th cursor-pointer select-none" data-sort="domain">
                    <div class="flex items-center gap-1.5">
                      <span>Domain</span>
                      <span id="sort-icon-domain" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none" data-sort="group_name">
                    <div class="flex items-center gap-1.5">
                      <span>Group</span>
                      <span id="sort-icon-group_name" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th">Ports</th>
                  <th class="table-th">Egress</th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="usage">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Usage (Total)</span>
                      <span id="sort-icon-usage" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none" data-sort="created_at">
                    <div class="flex items-center gap-1.5">
                      <span>Created</span>
                      <span id="sort-icon-created_at" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th w-16 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="dom-table-body">
                <tr>
                  <td colspan="8" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading domain rules...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Pagination Footer -->
          <div id="dom-pagination" class="card-footer"></div>
        </div>
      </div>
    `
  );

  // Setup Add Form Component
  let addFormObj = null;
  function initAddForm() {
    const fieldsRoot = $('#dom-add-form-fields', container);
    fieldsRoot.innerHTML = '';
    addFormObj = createDomainRuleForm({
      groups,
      isEdit: false,
    });
    fieldsRoot.appendChild(addFormObj.el);
  }

  // Toggle Add card
  const addCard = $('#dom-add-card', container);
  $('#dom-toggle-add-btn', container).addEventListener('click', () => {
    addCard.classList.remove('hidden');
    initAddForm();
    addFormObj?.focusDomain();
  });
  $('#dom-close-add-btn', container).addEventListener('click', () => addCard.classList.add('hidden'));
  $('#dom-cancel-add-btn', container).addEventListener('click', () => addCard.classList.add('hidden'));

  // Submit Add Form
  $('#dom-add-form', container).addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!addFormObj) return;

    const data = addFormObj.getData();
    const tokens = parseDomainTokens(data.domain);
    if (tokens.length === 0) {
      toast.error('Please enter at least one domain');
      return;
    }
    if (data.mode === 'proxy' && (!data.ports || data.ports === '')) {
      toast.error('Please enter valid port numbers (e.g. 443, 8443) or "all"');
      return;
    }

    const submitBtn = $('#dom-submit-add-btn', container);
    submitBtn.disabled = true;
    submitBtn.textContent = 'Saving...';

    try {
      const res = await api.addDomain({
        domain: data.domain,
        group_name: data.group_name,
        mode: data.mode,
        ports: Array.isArray(data.ports) ? data.ports.join(',') : data.ports,
        use_egress_proxy: String(data.use_egress_proxy),
        include_subdomains: Boolean(data.include_subdomains),
      });

      const addedCount = res.added || 0;
      const updatedCount = res.updated || 0;
      const skippedCount = res.skipped || 0;
      const errors = res.errors || [];

      if (errors.length > 0) {
        toast.error(`Saved ${addedCount} domains, but ${errors.length} failed: ${errors[0].reason}`);
      } else {
        toast.success(`Successfully saved ${addedCount + updatedCount} domain rules`);
      }

      addCard.classList.add('hidden');
      await fetchDomains();
    } catch (err) {
      toast.error(err.message || 'Failed to save domain rules');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Save Rules';
    }
  });

  // Mode Segmented Control
  let modeSegmented = null;
  function initModeSegmented() {
    const proxyCount = allDomains.filter((d) => (d.mode || 'proxy') === 'proxy').length;
    const directCount = allDomains.filter((d) => d.mode === 'direct').length;
    const blockCount = allDomains.filter((d) => d.mode === 'block').length;

    const modeContainer = $('#dom-mode-segmented', container);
    modeContainer.innerHTML = '';
    modeSegmented = createSegmentedControl({
      options: [
        { value: 'proxy', label: 'Proxy', count: proxyCount },
        { value: 'direct', label: 'Direct', count: directCount },
        { value: 'block', label: 'Block', count: blockCount },
      ],
      value: activeMode,
      size: 'sm',
      onChange: (val) => {
        activeMode = val;
        tableState.clearSelection();
        tableState.currentPage = 1;
        renderTable();
      },
    });
    modeContainer.appendChild(modeSegmented.el);
  }

  // View Mode Segmented (Flat vs Grouped)
  const viewContainer = $('#dom-view-segmented', container);
  const viewSegmented = createSegmentedControl({
    options: [
      { value: 'flat', label: 'Flat View' },
      { value: 'grouped', label: 'Grouped View' },
    ],
    value: viewMode,
    size: 'sm',
    onChange: (val) => {
      viewMode = val;
      localStorage.setItem('relay_domains_view', val);
      tableState.currentPage = 1;
      renderTable();
    },
  });
  viewContainer.appendChild(viewSegmented.el);

  // Search input
  $('#dom-search-input', container).addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    tableState.clearSelection();
    tableState.currentPage = 1;
    renderTable();
  });

  // Fetch Domains
  async function fetchDomains() {
    try {
      const res = await api.getDomains();
      allDomains = res.domains || [];

      // Extract unique groups
      const groupSet = new Set();
      for (const d of allDomains) {
        if (d.group_name && d.group_name.trim()) {
          groupSet.add(d.group_name.trim());
        }
      }
      groups = Array.from(groupSet).sort();
      if (addFormObj) addFormObj.setGroups(groups);

      initModeSegmented();
      renderTable();
    } catch (err) {
      $('#dom-table-body', container).innerHTML = `
        <tr>
          <td colspan="8" class="table-td text-center py-8 text-danger">
            Failed to load domain rules: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  // Filter & Merge logic
  function getFilteredDomains() {
    // 1. Filter by active mode
    let filtered = allDomains.filter((d) => (d.mode || 'proxy') === activeMode);

    // 2. Search query
    if (searchQuery) {
      filtered = filtered.filter(
        (d) =>
          d.domain.toLowerCase().includes(searchQuery) ||
          (d.group_name && d.group_name.toLowerCase().includes(searchQuery))
      );
    }

    // 3. Merge identical apex + wildcard counterpart rules (fixes B4)
    return mergeApexWildcard(filtered);
  }

  // Render Table
  function renderTable() {
    const tbody = $('#dom-table-body', container);
    const filteredDomains = getFilteredDomains();

    // Sort comparators
    const customComparators = {
      usage: (a, b) => {
        const usageA = (a.total_bytes_sent || 0) + (a.total_bytes_received || 0);
        const usageB = (b.total_bytes_sent || 0) + (b.total_bytes_received || 0);
        return usageA - usageB;
      },
    };

    const sortedDomains = tableState.getSortedItems(filteredDomains, customComparators);
    updateSortIcons();

    if (sortedDomains.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8" class="table-td text-center py-12 text-txt-subtle italic">
            ${searchQuery ? 'No domains matching your search' : 'No domain rules in this mode'}
          </td>
        </tr>
      `;
      renderPagination($('#dom-pagination', container), {
        currentPage: 1,
        totalPages: 1,
        totalItems: 0,
        pageSize: tableState.pageSize,
        onPageChange: () => {},
      });
      updateBulkBar(filteredDomains);
      return;
    }

    if (viewMode === 'flat') {
      const sliceInfo = tableState.getPageSlice(sortedDomains);
      renderFlatRows(tbody, sliceInfo.slice);
      renderPagination($('#dom-pagination', container), {
        currentPage: sliceInfo.currentPage,
        totalPages: sliceInfo.totalPages,
        totalItems: sliceInfo.total,
        pageSize: tableState.pageSize,
        onPageChange: (newPage) => {
          tableState.setPage(newPage);
          renderTable();
        },
      });
      tableState.updateHeaderCheckbox($('#dom-select-all', container), sliceInfo.slice);
    } else {
      renderGroupedRows(tbody, sortedDomains);
      renderPagination($('#dom-pagination', container), {
        currentPage: 1,
        totalPages: 1,
        totalItems: sortedDomains.length,
        pageSize: sortedDomains.length,
        onPageChange: () => {},
      });
      tableState.updateHeaderCheckbox($('#dom-select-all', container), sortedDomains);
    }

    updateBulkBar(filteredDomains);
  }

  function renderFlatRows(tbody, items) {
    tbody.innerHTML = '';
    for (const d of items) {
      tbody.appendChild(createRowElement(d));
    }
  }

  function renderGroupedRows(tbody, items) {
    tbody.innerHTML = '';
    const groupMap = new Map();

    for (const d of items) {
      const g = d.group_name || 'Ungrouped';
      if (!groupMap.has(g)) groupMap.set(g, []);
      groupMap.get(g).push(d);
    }

    for (const [groupName, groupItems] of groupMap.entries()) {
      const isExpanded = expandedGroups.has(groupName);
      const isCollapsed = !isExpanded;
      const groupRow = document.createElement('tr');
      groupRow.className = 'bg-surface-2/80 border-b border-border font-medium select-none';

      const groupSelectedCount = groupItems.filter((i) => tableState.selectedIds.has(i.domain)).length;
      const isAllGroupSelected = groupSelectedCount === groupItems.length && groupItems.length > 0;
      const isSomeGroupSelected = groupSelectedCount > 0 && !isAllGroupSelected;

      groupRow.innerHTML = `
        <td class="table-td w-10 text-center">
          <input type="checkbox" class="checkbox group-checkbox mx-auto" ${isAllGroupSelected ? 'checked' : ''} />
        </td>
        <td colspan="7" class="table-td cursor-pointer">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-2 text-txt">
              <svg class="w-4 h-4 text-txt-subtle transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
              </svg>
              <span class="font-semibold">${escapeHtml(groupName)}</span>
              <span class="badge badge-neutral text-[11px]">${groupItems.length}</span>
            </div>
            <span class="text-xs text-txt-subtle">${isExpanded ? 'Click to collapse' : 'Click to expand'}</span>
          </div>
        </td>
      `;

      const groupCheckbox = groupRow.querySelector('.group-checkbox');
      if (groupCheckbox && isSomeGroupSelected) {
        groupCheckbox.indeterminate = true;
      }

      groupCheckbox?.addEventListener('click', (e) => {
        e.stopPropagation();
        const checked = e.target.checked;
        tableState.toggleSelectAllVisible(groupItems, checked);
        renderTable();
      });

      groupRow.querySelector('td:nth-child(2)')?.addEventListener('click', () => {
        if (expandedGroups.has(groupName)) {
          expandedGroups.delete(groupName);
        } else {
          expandedGroups.add(groupName);
        }
        renderTable();
      });

      tbody.appendChild(groupRow);

      if (isExpanded) {
        for (const d of groupItems) {
          tbody.appendChild(createRowElement(d, true));
        }
      }
    }
  }

  function createRowElement(d, isIndented = false) {
    const isSelected = tableState.selectedIds.has(d.domain);
    const row = document.createElement('tr');
    row.className = `table-row ${isSelected ? 'table-row-selected' : ''}`;

    const isMerged = Boolean(d.is_merged);
    const isEgress = String(d.use_egress_proxy) === 'true';
    const totalBytes = (d.total_bytes_sent || 0) + (d.total_bytes_received || 0);

    let domainDisplay = escapeHtml(d.domain);
    if (isMerged) {
      domainDisplay = `<span class="font-semibold text-txt">${escapeHtml(d.domain)}</span> <span class="badge badge-primary text-[10px] ml-1.5 font-sans font-medium">+ sub domains</span>`;
    }

    let modeBadge = '';
    if (d.mode === 'direct') {
      modeBadge = `<span class="badge badge-info ml-1.5">Direct</span>`;
    } else if (d.mode === 'block') {
      modeBadge = `<span class="badge badge-danger ml-1.5">Block</span>`;
    }

    row.innerHTML = `
      <td class="table-td w-10 text-center">
        <input type="checkbox" class="checkbox row-checkbox mx-auto" ${isSelected ? 'checked' : ''} />
      </td>
      <td class="table-td font-mono text-xs ${isIndented ? 'pl-8' : ''}">
        <div class="flex items-center">
          ${domainDisplay}
          ${modeBadge}
        </div>
      </td>
      <td class="table-td text-xs text-txt-muted">
        ${d.group_name ? `<span class="badge badge-neutral">${escapeHtml(d.group_name)}</span>` : '—'}
      </td>
      <td class="table-td font-mono text-xs text-txt-muted">
        ${formatPorts(d.ports)}
      </td>
      <td class="table-td text-xs">
        ${isEgress ? `<span class="badge badge-success">Enabled</span>` : `<span class="text-txt-subtle">—</span>`}
      </td>
      <td class="table-td text-right font-mono text-xs tabular-nums text-txt">
        ${totalBytes > 0 ? formatBytes(totalBytes) : '<span class="text-txt-subtle">0 B</span>'}
      </td>
      <td class="table-td text-xs text-txt-muted">
        ${formatDate(d.created_at)}
      </td>
      <td class="table-td text-right">
        <button type="button" class="dom-row-menu-btn btn-icon-sm text-txt-muted hover:text-txt" aria-label="Domain actions">
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"/></svg>
        </button>
      </td>
    `;

    // Row selection toggle
    const checkbox = row.querySelector('.row-checkbox');
    checkbox.addEventListener('change', (e) => {
      tableState.toggleSelect(d.domain, e.target.checked);
      renderTable();
    });

    // Row actions menu
    const menuBtn = row.querySelector('.dom-row-menu-btn');
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const menuItems = [
        {
          text: 'Usage Analytics',
          icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
          onClick: () => openDomainUsageDialog(d),
        },
        {
          text: 'Edit Rule',
          icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>`,
          onClick: () => openEditDomainDialog(d),
        },
        { divider: true },
        {
          text: 'Delete Rule',
          danger: true,
          icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>`,
          onClick: () => deleteDomainRule(d),
        },
      ];

      showMenu(menuBtn, menuItems);
    });

    return row;
  }

  // Header checkbox (Select All Visible)
  $('#dom-select-all', container).addEventListener('click', (e) => {
    const filteredDomains = getFilteredDomains();
    const visibleItems =
      viewMode === 'flat' ? tableState.getPageSlice(filteredDomains).slice : filteredDomains;
    tableState.toggleSelectAllVisible(visibleItems, e.target.checked);
    renderTable();
  });

  // Bulk actions bar updates (fixes B2)
  function updateBulkBar(filteredDomains) {
    const bulkBar = $('#dom-bulk-bar', container);
    const bulkCountEl = $('#dom-bulk-count', container);
    const selectAllBtn = $('#dom-bulk-select-all-btn', container);
    const allCountSpan = $('#dom-bulk-all-count', container);

    const selectedCount = tableState.getSelectedCount(filteredDomains.length);

    if (selectedCount > 0) {
      bulkBar.classList.remove('hidden');
      bulkCountEl.textContent = `${selectedCount} selected`;

      // If only current page is selected, offer "Select all N matching"
      if (!tableState.selectAllMatching && selectedCount < filteredDomains.length) {
        selectAllBtn.classList.remove('hidden');
        allCountSpan.textContent = filteredDomains.length;
      } else {
        selectAllBtn.classList.add('hidden');
      }
    } else {
      bulkBar.classList.add('hidden');
    }
  }

  $('#dom-bulk-select-all-btn', container).addEventListener('click', () => {
    tableState.selectAllMatching = true;
    renderTable();
  });

  $('#dom-bulk-clear-btn', container).addEventListener('click', () => {
    tableState.clearSelection();
    renderTable();
  });

  function getSelectedTargetDomains(filteredDomains) {
    const selectedIds = tableState.getSelectedIds(filteredDomains);
    if (!selectedIds.length) return [];

    const domainMap = new Map();
    for (const d of filteredDomains) {
      domainMap.set(d.domain, d);
    }

    const expanded = [];
    for (const id of selectedIds) {
      expanded.push(id);
      const d = domainMap.get(id);
      if (d && d.is_merged && !id.startsWith('*.')) {
        expanded.push('*.' + id);
      }
    }
    return Array.from(new Set(expanded));
  }

  // Bulk Delete
  $('#dom-bulk-delete-btn', container).addEventListener('click', async () => {
    const filteredDomains = getFilteredDomains();
    const selectedDomains = tableState.getSelectedIds(filteredDomains);
    if (!selectedDomains.length) return;

    const targetDomains = getSelectedTargetDomains(filteredDomains);
    const sampleNames = selectedDomains.slice(0, 5).join(', ');
    const extra = selectedDomains.length > 5 ? ` and ${selectedDomains.length - 5} more` : '';

    const confirmed = await dialog.confirm({
      title: `Delete ${selectedDomains.length} Domain Rule(s)`,
      message: `Are you sure you want to permanently remove ${selectedDomains.length} rule(s) (${sampleNames}${extra})?`,
      confirmText: 'Delete Domains',
      danger: true,
    });

    if (!confirmed) return;

    try {
      const res = await api.bulkDeleteDomains(targetDomains);
      toast.success(`Deleted ${res.deleted || targetDomains.length} domain rules`);
      tableState.clearSelection();
      await fetchDomains();
    } catch (err) {
      toast.error(err.message || 'Failed to bulk delete domain rules');
    }
  });

  // Bulk Assign Group
  $('#dom-bulk-group-btn', container).addEventListener('click', async () => {
    const filteredDomains = getFilteredDomains();
    const selectedDomains = tableState.getSelectedIds(filteredDomains);
    if (!selectedDomains.length) return;

    const targetDomains = getSelectedTargetDomains(filteredDomains);

    let selectedGroupName = '';
    const combobox = createCombobox({
      options: groups,
      value: '',
      placeholder: 'Select or type group name...',
      onChange: (val) => {
        selectedGroupName = val;
      },
    });

    const content = createElement(html`
      <div class="flex flex-col gap-3">
        <p class="text-sm text-txt-muted">
          Select an existing group or type a new group name for <span class="font-semibold text-txt">${selectedDomains.length}</span> selected domain(s):
        </p>
        <div class="field pt-1">
          <label class="field-label">Target Group (leave empty to ungroup)</label>
          <div id="bulk-group-combobox-container"></div>
          <span class="field-hint">Choose from existing groups or type a new name.</span>
        </div>
      </div>
    `);

    content.querySelector('#bulk-group-combobox-container').appendChild(combobox.el);

    dialog.open({
      title: 'Assign Group',
      content,
      size: 'md',
      overflowVisible: true,
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Assign Group',
          primary: true,
          onClick: async (_, { close }) => {
            const finalGroup = combobox.getValue().trim();
            close();
            try {
              await api.bulkAssignGroup(targetDomains, finalGroup);
              toast.success(`Assigned group to ${selectedDomains.length} domain(s)`);
              tableState.clearSelection();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to assign group');
            }
          },
        },
      ],
    });
  });

  // Bulk Assign Mode
  $('#dom-bulk-mode-btn', container).addEventListener('click', async () => {
    const filteredDomains = getFilteredDomains();
    const selectedDomains = tableState.getSelectedIds(filteredDomains);
    if (!selectedDomains.length) return;

    const targetDomains = getSelectedTargetDomains(filteredDomains);
    const bUid = 'bulk_mode_' + Math.random().toString(36).slice(2, 9);
    let selectedMode = 'proxy';

    const modeStyles = {
      proxy: {
        active: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500 bg-emerald-500/15 dark:bg-emerald-950/40 ring-1 ring-emerald-500/30 cursor-pointer transition-colors',
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 hover:bg-emerald-500/10 cursor-pointer transition-colors',
      },
      direct: {
        active: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500 dark:border-zinc-400 bg-zinc-500/15 dark:bg-zinc-800/60 ring-1 ring-zinc-500/30 cursor-pointer transition-colors',
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500/20 bg-zinc-500/5 dark:bg-zinc-800/20 hover:border-zinc-500/40 hover:bg-zinc-500/10 cursor-pointer transition-colors',
      },
      block: {
        active: 'flex items-start gap-3 p-3 rounded-xl border border-red-500 bg-red-500/15 dark:bg-red-950/40 ring-1 ring-red-500/30 cursor-pointer transition-colors',
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 hover:bg-red-500/10 cursor-pointer transition-colors',
      },
    };

    const content = createElement(html`
      <div class="flex flex-col gap-3">
        <p class="text-sm text-txt-muted">Select new routing mode for <span class="font-semibold text-txt">${selectedDomains.length}</span> selected rule(s):</p>
        <div class="space-y-2 pt-1">
          <!-- Proxy Option (Green) -->
          <label class="${modeStyles.proxy.active}" id="${bUid}-mode-opt-proxy">
            <input type="radio" name="${bUid}_routing_mode" value="proxy" class="radio radio-emerald mt-0.5 shrink-0 text-emerald-600 focus:ring-emerald-500" checked />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Proxy (Relay)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Relay TLS connections and log SNI traffic.</span>
            </div>
          </label>

          <!-- Direct Option (Gray) -->
          <label class="${modeStyles.direct.inactive}" id="${bUid}-mode-opt-direct">
            <input type="radio" name="${bUid}_routing_mode" value="direct" class="radio radio-zinc mt-0.5 shrink-0 text-zinc-600 focus:ring-zinc-500" />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Direct (Bypass)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Bypass relay and resolve client directly to target.</span>
            </div>
          </label>

          <!-- Block Option (Red) -->
          <label class="${modeStyles.block.inactive}" id="${bUid}-mode-opt-block">
            <input type="radio" name="${bUid}_routing_mode" value="block" class="radio radio-red mt-0.5 shrink-0 text-red-600 focus:ring-red-500" />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Block (Reject)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Drop and reject all DNS and TLS queries.</span>
            </div>
          </label>
        </div>
      </div>
    `);

    const radioInputs = content.querySelectorAll(`input[name="${bUid}_routing_mode"]`);
    radioInputs.forEach((radio) => {
      radio.addEventListener('change', () => {
        if (!radio.checked) return;
        selectedMode = radio.value;
        ['proxy', 'direct', 'block'].forEach((m) => {
          const card = content.querySelector(`#${bUid}-mode-opt-${m}`);
          if (card && modeStyles[m]) {
            card.className = m === selectedMode ? modeStyles[m].active : modeStyles[m].inactive;
          }
        });
      });
    });

    dialog.open({
      title: 'Change Routing Mode',
      content,
      size: 'md',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Apply Mode',
          primary: true,
          onClick: async (_, { close }) => {
            close();
            try {
              await api.bulkAssignMode(targetDomains, selectedMode);
              toast.success(`Updated mode for ${selectedDomains.length} domain(s)`);
              tableState.clearSelection();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to update mode');
            }
          },
        },
      ],
    });
  });

  // Bulk Assign Egress
  $('#dom-bulk-egress-btn', container).addEventListener('click', () => {
    const filteredDomains = getFilteredDomains();
    const selectedDomains = tableState.getSelectedIds(filteredDomains);
    if (!selectedDomains.length) return;

    const targetDomains = getSelectedTargetDomains(filteredDomains);

    const contentEl = document.createElement('div');
    contentEl.className = 'text-sm text-txt-muted leading-relaxed';
    contentEl.textContent = `Choose an egress proxy configuration for ${selectedDomains.length} selected domain(s):`;

    dialog.open({
      title: 'Bulk Egress Proxy Configuration',
      content: contentEl,
      size: 'sm',
      actions: [
        {
          text: 'Cancel',
          className: 'btn btn-secondary',
          value: 'cancel',
          onClick: (_, { close }) => close('cancel'),
        },
        {
          text: 'Disable egress',
          className: 'btn btn-secondary text-danger hover:bg-danger-soft',
          value: 'disable',
          onClick: async (_, { close }) => {
            close('disable');
            try {
              await api.bulkAssignEgress(targetDomains, false);
              toast.success(`Disabled egress proxy for ${selectedDomains.length} domain(s)`);
              tableState.clearSelection();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to update egress proxy settings');
            }
          },
        },
        {
          text: 'Enable egress',
          className: 'btn btn-primary',
          primary: true,
          value: 'enable',
          onClick: async (_, { close }) => {
            close('enable');
            try {
              await api.bulkAssignEgress(targetDomains, true);
              toast.success(`Enabled egress proxy for ${selectedDomains.length} domain(s)`);
              tableState.clearSelection();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to update egress proxy settings');
            }
          },
        },
      ],
      onClose: () => {},
    });
  });

  // Edit Domain Dialog
  function openEditDomainDialog(d) {
    if (!d.is_merged) {
      // Standard single domain edit
      const formObj = createDomainRuleForm({
        initialData: d,
        groups,
        isEdit: true,
      });

      dialog.open({
        title: `Edit Rule: ${d.domain}`,
        content: formObj.el,
        size: 'md',
        actions: [
          { text: 'Cancel', className: 'btn btn-secondary', value: false },
          {
            text: 'Save Changes',
            primary: true,
            onClick: async (_, { close }) => {
              const data = formObj.getData();
              if (data.mode === 'proxy' && (!data.ports || data.ports === '')) {
                toast.error('Please enter valid port numbers (e.g. 443, 8443) or "all"');
                return;
              }
              try {
                await api.updateDomain(d.domain, {
                  group_name: data.group_name,
                  mode: data.mode,
                  ports: Array.isArray(data.ports) ? data.ports.join(',') : data.ports,
                  use_egress_proxy: String(data.use_egress_proxy),
                });
                toast.success(`Domain ${d.domain} updated`);
                close();
                await fetchDomains();
              } catch (err) {
                toast.error(err.message || 'Failed to update domain rule');
              }
            },
          },
        ],
      });
      return;
    }

    // Merged domain edit (Apex + Wildcard)
    const modalContent = document.createElement('div');
    modalContent.className = 'flex flex-col gap-4';

    // Segmented tab switcher & Sync toggle
    const topBar = document.createElement('div');
    topBar.className = 'flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border';

    let activeSubTab = 'apex';
    let isSynced = true;
    let isMirroring = false;

    const tabSegmented = createSegmentedControl({
      options: [
        { value: 'apex', label: `${d.domain} (Apex)` },
        { value: 'wildcard', label: `*.${d.domain} (Subdomains)` },
      ],
      value: activeSubTab,
      size: 'sm',
      onChange: (val) => {
        activeSubTab = val;
        if (val === 'apex') {
          apexWrapper.classList.remove('hidden');
          wildcardWrapper.classList.add('hidden');
        } else {
          apexWrapper.classList.add('hidden');
          wildcardWrapper.classList.remove('hidden');
        }
      },
    });

    const syncBox = document.createElement('div');
    syncBox.className = 'flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-2/60 border border-border shrink-0';
    syncBox.innerHTML = `
      <input type="checkbox" id="edit-sync-toggle" class="checkbox" checked />
      <label for="edit-sync-toggle" class="text-xs font-medium text-txt cursor-pointer select-none">
        Sync both rules
      </label>
      <span id="edit-sync-indicator" class="w-2 h-2 rounded-full bg-emerald-500 shrink-0" title="Synchronized"></span>
    `;

    topBar.appendChild(tabSegmented.el);
    topBar.appendChild(syncBox);
    modalContent.appendChild(topBar);

    const syncCheckbox = syncBox.querySelector('#edit-sync-toggle');
    const syncIndicator = syncBox.querySelector('#edit-sync-indicator');

    syncCheckbox.addEventListener('change', () => {
      isSynced = syncCheckbox.checked;
      if (isSynced) {
        syncIndicator.className = 'w-2 h-2 rounded-full bg-emerald-500 shrink-0';
        syncIndicator.title = 'Synchronized';
        // Mirror active tab to other tab
        const srcData = activeSubTab === 'apex' ? apexForm.getData() : wildcardForm.getData();
        const targetForm = activeSubTab === 'apex' ? wildcardForm : apexForm;
        targetForm.setData({
          mode: srcData.mode,
          ports: srcData.ports,
          group_name: srcData.group_name,
          use_egress_proxy: srcData.use_egress_proxy,
        });
      } else {
        syncIndicator.className = 'w-2 h-2 rounded-full bg-amber-500 shrink-0';
        syncIndicator.title = 'Independent settings';
      }
    });

    // Apex form wrapper
    const apexWrapper = document.createElement('div');
    const apexForm = createDomainRuleForm({
      initialData: { ...d, domain: d.domain },
      groups,
      isEdit: true,
      onChange: () => {
        if (isSynced && !isMirroring) {
          isMirroring = true;
          const data = apexForm.getData();
          wildcardForm.setData({
            mode: data.mode,
            ports: data.ports,
            group_name: data.group_name,
            use_egress_proxy: data.use_egress_proxy,
          });
          isMirroring = false;
        }
      },
    });
    apexWrapper.appendChild(apexForm.el);
    modalContent.appendChild(apexWrapper);

    // Wildcard form wrapper
    const wildcardWrapper = document.createElement('div');
    wildcardWrapper.className = 'hidden flex flex-col gap-3';
    const wildcardForm = createDomainRuleForm({
      initialData: { ...d, domain: `*.${d.domain}` },
      groups,
      isEdit: true,
      onChange: () => {
        if (isSynced && !isMirroring) {
          isMirroring = true;
          const data = wildcardForm.getData();
          apexForm.setData({
            mode: data.mode,
            ports: data.ports,
            group_name: data.group_name,
            use_egress_proxy: data.use_egress_proxy,
          });
          isMirroring = false;
        }
      },
    });
    wildcardWrapper.appendChild(wildcardForm.el);

    // Option to delete wildcard rule from within the wildcard tab
    const wcActions = document.createElement('div');
    wcActions.className = 'pt-3 border-t border-border flex items-center justify-between';
    wcActions.innerHTML = `
      <span class="text-xs text-txt-subtle">Want to delete only the wildcard rule?</span>
      <button type="button" class="btn btn-ghost btn-xs text-danger hover:bg-danger-soft">
        Delete *.${escapeHtml(d.domain)}
      </button>
    `;
    const deleteWcBtn = wcActions.querySelector('button');
    deleteWcBtn.addEventListener('click', async () => {
      const confirmed = await dialog.confirm({
        title: `Delete Wildcard Rule: *.${d.domain}`,
        message: `Are you sure you want to remove the wildcard rule (*.${d.domain})? The apex rule (${d.domain}) will remain active.`,
        confirmText: 'Delete Wildcard Rule',
        danger: true,
      });
      if (!confirmed) return;
      try {
        await api.deleteDomain(`*.${d.domain}`);
        toast.success(`Wildcard rule *.${d.domain} deleted`);
        editDialogObj.close();
        await fetchDomains();
      } catch (err) {
        toast.error(err.message || 'Failed to delete wildcard rule');
      }
    });
    wildcardWrapper.appendChild(wcActions);
    modalContent.appendChild(wildcardWrapper);

    const editDialogObj = dialog.open({
      title: `Edit Rule: ${d.domain} & *.${d.domain}`,
      content: modalContent,
      size: 'md',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Save Changes',
          primary: true,
          onClick: async (_, { close }) => {
            const apexData = apexForm.getData();
            const wildcardData = wildcardForm.getData();

            if (apexData.mode === 'proxy' && (!apexData.ports || apexData.ports === '')) {
              toast.error('Please enter valid port numbers for apex rule (e.g. 443) or "all"');
              return;
            }
            if (wildcardData.mode === 'proxy' && (!wildcardData.ports || wildcardData.ports === '')) {
              toast.error('Please enter valid port numbers for wildcard rule (e.g. 443) or "all"');
              return;
            }

            try {
              if (isSynced) {
                await Promise.all([
                  api.updateDomain(d.domain, {
                    group_name: apexData.group_name,
                    mode: apexData.mode,
                    ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports,
                    use_egress_proxy: String(apexData.use_egress_proxy),
                  }),
                  api.updateDomain(`*.${d.domain}`, {
                    group_name: apexData.group_name,
                    mode: apexData.mode,
                    ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports,
                    use_egress_proxy: String(apexData.use_egress_proxy),
                  }),
                ]);
                toast.success(`Domain ${d.domain} and *.${d.domain} updated`);
              } else {
                await Promise.all([
                  api.updateDomain(d.domain, {
                    group_name: apexData.group_name,
                    mode: apexData.mode,
                    ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports,
                    use_egress_proxy: String(apexData.use_egress_proxy),
                  }),
                  api.updateDomain(`*.${d.domain}`, {
                    group_name: wildcardData.group_name,
                    mode: wildcardData.mode,
                    ports: Array.isArray(wildcardData.ports) ? wildcardData.ports.join(',') : wildcardData.ports,
                    use_egress_proxy: String(wildcardData.use_egress_proxy),
                  }),
                ]);
                toast.success(`Independent configurations saved for ${d.domain} and *.${d.domain}`);
              }
              close();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to update domain rule');
            }
          },
        },
      ],
    });
  }

  // Delete Single Domain
  async function deleteDomainRule(d) {
    const confirmed = await dialog.confirm({
      title: `Delete Rule: ${d.domain}`,
      message: `Are you sure you want to delete the routing rule for ${d.domain}?`,
      confirmText: 'Delete',
      danger: true,
    });

    if (!confirmed) return;

    try {
      await api.deleteDomain(d.domain);
      if (d.is_merged) {
        // Also delete wildcard counterpart
        try {
          await api.deleteDomain(`*.${d.domain}`);
        } catch {
          // Ignore if already gone
        }
      }
      toast.success(`Domain ${d.domain} deleted`);
      await fetchDomains();
    } catch (err) {
      toast.error(err.message || 'Failed to delete domain rule');
    }
  }

  // Domain Usage Analytics Modal
  async function openDomainUsageDialog(d) {
    const content = document.createElement('div');
    content.className = 'space-y-4';
    content.innerHTML = `
      <div class="flex items-center justify-between">
        <div id="dom-usage-segmented"></div>
        <span class="text-xs text-txt-muted font-mono">${escapeHtml(d.domain)}</span>
      </div>
      <div id="dom-usage-chart-box" class="min-h-[200px]"></div>
      <div class="pt-2 border-t border-border">
        <h4 class="text-xs font-semibold uppercase text-txt-muted mb-2">Top Users</h4>
        <div id="dom-usage-users-box" class="max-h-48 overflow-y-auto">
          <div class="text-xs text-txt-subtle italic py-2">Loading users...</div>
        </div>
      </div>
    `;

    let usageRange = '30d';
    let chartObj = null;

    async function loadUsageData() {
      try {
        let chartData = [];
        if (usageRange === 'monthly') {
          const res = await api.getDomainUsageMonthly(d.domain, 12);
          chartData = (res.months || []).map((m) => ({
            label: m.month,
            sent: m.bytes_sent || 0,
            recv: m.bytes_received || 0,
          }));
        } else {
          const res = await api.getDomainUsage(d.domain, 30);
          chartData = (res.days || []).map((item) => ({
            label: formatDate(item.date),
            sent: item.bytes_sent || 0,
            recv: item.bytes_received || 0,
          }));
        }

        if (chartObj) chartObj.destroy();
        chartObj = renderGroupedBarChart(content.querySelector('#dom-usage-chart-box'), {
          data: chartData,
          series: [
            { key: 'sent', label: 'Bytes Sent', color: '#3b82f6' },
            { key: 'recv', label: 'Bytes Received', color: '#10b981' },
          ],
          formatValue: (v) => formatBytes(v),
        });

        // Top users
        const usersRes = await api.getDomainUsageUsers(d.domain, usageRange === 'monthly' ? 'monthly' : 'today');
        const usersBox = content.querySelector('#dom-usage-users-box');
        const userList = usersRes.users || [];

        if (userList.length === 0) {
          usersBox.innerHTML = `<div class="text-xs text-txt-subtle italic py-2">No user traffic recorded</div>`;
        } else {
          usersBox.innerHTML = `
            <table class="table text-xs">
              <thead>
                <tr>
                  <th class="table-th py-1.5">User</th>
                  <th class="table-th py-1.5 text-right">Sent</th>
                  <th class="table-th py-1.5 text-right">Received</th>
                  <th class="table-th py-1.5 text-right">Total</th>
                </tr>
              </thead>
              <tbody>
                ${userList
                  .map(
                    (u) => `
                  <tr>
                    <td class="table-td py-1.5 font-medium">${escapeHtml(u.username)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums">${formatBytes(u.bytes_sent)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums">${formatBytes(u.bytes_received)}</td>
                    <td class="table-td py-1.5 text-right font-mono tabular-nums font-semibold">${formatBytes(
                      (u.bytes_sent || 0) + (u.bytes_received || 0)
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
        console.warn('Domain usage error:', err);
      }
    }

    const seg = createSegmentedControl({
      options: [
        { value: '30d', label: 'Daily (30d)' },
        { value: 'monthly', label: 'Monthly (12m)' },
      ],
      value: usageRange,
      size: 'sm',
      onChange: (val) => {
        usageRange = val;
        loadUsageData();
      },
    });
    content.querySelector('#dom-usage-segmented').appendChild(seg.el);

    dialog.open({
      title: `Usage Analytics: ${d.domain}`,
      content,
      size: 'lg',
      actions: [{ text: 'Close', className: 'btn btn-secondary', value: true }],
      onClose: () => {
        if (chartObj) chartObj.destroy();
      },
    });

    loadUsageData();
  }

  // Sorting header click listeners
  $$('[data-sort]', container).forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      tableState.setSort(key);
      renderTable();
    });
  });

  function updateSortIcons() {
    ['domain', 'group_name', 'usage', 'created_at'].forEach((k) => {
      const icon = $(`#sort-icon-${k}`, container);
      if (!icon) return;
      if (tableState.sortKey === k) {
        icon.textContent = tableState.sortDir === 'asc' ? '↑' : '↓';
        icon.className = 'text-primary-600 text-xs font-bold';
      } else {
        icon.textContent = '↕';
        icon.className = 'text-txt-subtle text-xs';
      }
    });
  }

  // Initial load
  fetchDomains();

  return {
    unmount: () => {
      container.innerHTML = '';
    },
  };
}
