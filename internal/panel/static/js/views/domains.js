/**
 * Domains view: flat + tree (categorized) tabs, routing mode filter, single-domain enable/disable,
 * category/subcategory management, fixed select-all, and bulk actions.
 */

import { html, raw, setHtml, $, $$, escapeHtml, createElement } from '../core/dom.js';
import { api, getApiUrl } from '../core/api.js';
import { formatBytes, formatDate, formatCount } from '../core/format.js';
import { TableState } from '../ui/table.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { showMenu } from '../ui/menu.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { createDomainRuleForm } from './domain-rule-form.js';
import { openUsageReportDialog } from './usage-report.js';
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
  let catalogCategories = [];
  // 'all' | 'proxy' | 'direct' | 'block'
  let activeMode = 'all';
  let activeRange = 'today';
  let searchQuery = '';
  // 'flat' | 'tree'
  let viewTab = 'flat';
  try { viewTab = localStorage.getItem('relay_domains_view') || 'flat'; } catch (_) {}

  // Expanded state for tree view
  let expandedCats = new Set();
  let expandedSubs = new Set();

  let egressEnabled = true;

  const tableState = new TableState({
    pageSize: 50,
    sortKey: 'domain',
    sortDir: 'asc',
    getId: (d) => d.domain,
  });

  // ─── Shell HTML ──────────────────────────────────────────────────────────────
  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Page Header -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Domain Rules</h1>
            <p class="text-xs text-txt-muted mt-0.5">Manage SNI routing rules, categories, and access policies</p>
          </div>
          <div class="flex items-center gap-2 flex-wrap self-start sm:self-auto">
            <button id="dom-manage-cats-btn" type="button" class="btn btn-secondary btn-sm">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
              <span>Categories</span>
            </button>
            <button id="dom-export-json-btn" type="button" class="btn btn-secondary btn-sm">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span>Export JSON</span>
            </button>
            <label id="dom-import-json-label" class="btn btn-secondary btn-sm cursor-pointer" role="button" tabindex="0">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
              <span>Import JSON</span>
              <input id="dom-import-json-input" type="file" accept=".json,application/json" class="hidden" />
            </label>
            <button id="dom-toggle-add-btn" type="button" class="btn btn-primary btn-sm">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
              <span>Add Domain Rule</span>
            </button>
          </div>
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
          <!-- View Tab Switcher -->
          <div class="flex items-center gap-1 border-b border-border px-4 pt-3">
            <button id="dom-tab-flat" type="button" class="dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-primary-500 text-primary-600">
              Flat View
            </button>
            <button id="dom-tab-tree" type="button" class="dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-transparent text-txt-muted hover:text-txt">
              Categorized View
            </button>
          </div>

          <!-- Toolbar -->
          <div class="p-4 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div class="flex items-center gap-3 overflow-x-auto pb-1 md:pb-0">
              <!-- Routing Mode Filter (flat mode only) -->
              <div id="dom-mode-segmented"></div>
              <!-- Collapse All button (tree mode only) -->
              <button id="dom-collapse-all-btn" type="button" class="hidden btn btn-secondary btn-sm">
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>
                <span>Collapse All</span>
              </button>
              <!-- Time Range Selector -->
              <div id="dom-range-segmented"></div>
            </div>
            <div class="flex items-center gap-3">
              <div class="relative w-full sm:w-64">
                <input id="dom-search-input" type="text" class="input pl-8" placeholder="Filter domains..." />
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
              <button id="dom-bulk-mode-btn" type="button" class="btn btn-secondary btn-sm">Change Mode</button>
              <button id="dom-bulk-egress-btn" type="button" class="btn btn-secondary btn-sm">Set Egress</button>
              <button id="dom-bulk-delete-btn" type="button" class="btn btn-danger btn-sm">Delete</button>
              <button id="dom-bulk-clear-btn" type="button" class="btn btn-ghost btn-sm text-txt-muted">Deselect</button>
            </div>
          </div>

          <!-- Flat Table Container -->
          <div id="dom-flat-container" class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th class="table-th w-10 text-center">
                    <input id="dom-select-all" type="checkbox" class="checkbox mx-auto" aria-label="Select all visible" />
                  </th>
                  <th class="table-th cursor-pointer select-none" data-sort="domain">
                    <div class="flex items-center gap-1.5">
                      <span>Domain</span>
                      <span id="sort-icon-domain" class="text-txt-subtle text-xs">↑</span>
                    </div>
                  </th>
                  <th class="table-th">Mode / Egress</th>
                  <th class="table-th">Ports</th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="usage">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Traffic</span>
                      <span id="sort-icon-usage" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="queries">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>DNS Queries</span>
                      <span id="sort-icon-queries" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th w-20 text-right">Active</th>
                  <th class="table-th w-16 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="dom-table-body">
                <tr>
                  <td colspan="9" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading domain rules...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Tree View Container -->
          <div id="dom-tree-container" class="hidden divide-y divide-border"></div>

          <!-- Pagination Footer -->
          <div id="dom-pagination" class="card-footer"></div>
        </div>
      </div>
    `
  );

  // ─── View Tab Switcher ────────────────────────────────────────────────────────
  function applyViewTab(tab) {
    viewTab = tab;
    try { localStorage.setItem('relay_domains_view', tab); } catch (_) {}

    const flatTab = $('#dom-tab-flat', container);
    const treeTab = $('#dom-tab-tree', container);
    const modeSegEl = $('#dom-mode-segmented', container);
    const collapseBtn = $('#dom-collapse-all-btn', container);

    if (tab === 'flat') {
      flatTab.className = 'dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-primary-500 text-primary-600';
      treeTab.className = 'dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-transparent text-txt-muted hover:text-txt';
      $('#dom-flat-container', container).classList.remove('hidden');
      $('#dom-tree-container', container).classList.add('hidden');
      if (modeSegEl) modeSegEl.style.display = '';
      if (collapseBtn) collapseBtn.classList.add('hidden');
    } else {
      flatTab.className = 'dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-transparent text-txt-muted hover:text-txt';
      treeTab.className = 'dom-view-tab px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors border-primary-500 text-primary-600';
      $('#dom-flat-container', container).classList.add('hidden');
      $('#dom-tree-container', container).classList.remove('hidden');
      if (modeSegEl) modeSegEl.style.display = 'none';
      if (collapseBtn) collapseBtn.classList.remove('hidden');
    }
    renderView();
  }

  $('#dom-tab-flat', container).addEventListener('click', () => applyViewTab('flat'));
  $('#dom-tab-tree', container).addEventListener('click', () => applyViewTab('tree'));

  // ─── Collapse All (tree view) ─────────────────────────────────────────────────
  $('#dom-collapse-all-btn', container).addEventListener('click', () => {
    expandedCats.clear();
    expandedSubs.clear();
    renderTreeView();
  });

  // ─── Add Form ─────────────────────────────────────────────────────────────────
  let addFormObj = null;
  function initAddForm() {
    const fieldsRoot = $('#dom-add-form-fields', container);
    fieldsRoot.innerHTML = '';
    addFormObj = createDomainRuleForm({ categories: catalogCategories, isEdit: false });
    fieldsRoot.appendChild(addFormObj.el);
  }

  const addCard = $('#dom-add-card', container);
  $('#dom-toggle-add-btn', container).addEventListener('click', () => {
    addCard.classList.remove('hidden');
    initAddForm();
    addFormObj?.focusDomain();
  });
  $('#dom-close-add-btn', container).addEventListener('click', () => addCard.classList.add('hidden'));
  $('#dom-cancel-add-btn', container).addEventListener('click', () => addCard.classList.add('hidden'));

  $('#dom-add-form', container).addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!addFormObj) return;

    const data = addFormObj.getData();
    const tokens = parseDomainTokens(data.domain);
    if (tokens.length === 0) { toast.error('Please enter at least one domain'); return; }
    if (data.mode === 'proxy' && (!data.ports || data.ports === '')) {
      toast.error('Please enter valid port numbers (e.g. 443, 8443) or "all"'); return;
    }

    const submitBtn = $('#dom-submit-add-btn', container);
    submitBtn.disabled = true;
    submitBtn.textContent = 'Saving...';

    try {
      const res = await api.addDomain({
        domain: data.domain,
        group_name: data.group_name,
        catalog_node: data.catalog_node,
        mode: data.mode,
        ports: Array.isArray(data.ports) ? data.ports.join(',') : data.ports,
        use_egress_proxy: String(data.use_egress_proxy),
        include_subdomains: Boolean(data.include_subdomains),
      });

      const addedCount = res.added || 0;
      const updatedCount = res.updated || 0;
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

  // ─── Mode Filter Segmented ────────────────────────────────────────────────────
  let modeSegmented = null;
  function initModeSegmented() {
    const total = allDomains.length;
    const proxyCount = allDomains.filter((d) => (d.mode || 'proxy') === 'proxy').length;
    const directCount = allDomains.filter((d) => d.mode === 'direct').length;
    const blockCount = allDomains.filter((d) => d.mode === 'block').length;

    const modeContainer = $('#dom-mode-segmented', container);
    modeContainer.innerHTML = '';
    modeSegmented = createSegmentedControl({
      options: [
        { value: 'all', label: 'All', count: total },
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

  // ─── Search ───────────────────────────────────────────────────────────────────
  $('#dom-search-input', container).addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    tableState.clearSelection();
    tableState.currentPage = 1;
    renderView();
  });

  // ─── Fetch ────────────────────────────────────────────────────────────────────
  async function fetchDomains() {
    try {
      try {
        const settings = await api.getSettings();
        egressEnabled = Boolean(settings.egress_proxy_enabled);
      } catch (_) {}

      try {
        const catRes = await api.getCatalog();
        catalogCategories = catRes.categories || [];
        if (addFormObj) addFormObj.setCategories(catalogCategories);
      } catch (_) {}

      const res = await api.getDomains(activeRange);
      allDomains = res.domains || [];

      initModeSegmented();
      initRangeSegmented();
      renderView();
    } catch (err) {
      $('#dom-table-body', container).innerHTML = `
        <tr><td colspan="9" class="table-td text-center py-8 text-danger">
          Failed to load domain rules: ${escapeHtml(err.message)}
        </td></tr>
      `;
    }
  }

  // ─── Routing Mode Badge ───────────────────────────────────────────────────────
  function modeBadgeHtml(mode) {
    switch (mode) {
      case 'proxy':   return `<span class="badge badge-success text-[10px]">Proxy</span>`;
      case 'direct':  return `<span class="badge badge-info text-[10px]">Direct</span>`;
      case 'block':   return `<span class="badge badge-danger text-[10px]">Block</span>`;
      default:        return `<span class="badge badge-success text-[10px]">Proxy</span>`;
    }
  }

  function egressBadgeHtml() {
    return `<span class="badge text-[10px] shrink-0 font-medium bg-amber-500/20 text-amber-800 dark:text-amber-300 border border-amber-500/40">Egress</span>`;
  }

  // ─── Filter logic ─────────────────────────────────────────────────────────────
  function getFilteredDomains() {
    let filtered = activeMode === 'all'
      ? [...allDomains]
      : allDomains.filter((d) => (d.mode || 'proxy') === activeMode);

    if (searchQuery) {
      filtered = filtered.filter(
        (d) =>
          d.domain.toLowerCase().includes(searchQuery) ||
          (d.group_name && d.group_name.toLowerCase().includes(searchQuery)) ||
          (d.catalog_node && d.catalog_node.toLowerCase().includes(searchQuery))
      );
    }

    return mergeApexWildcard(filtered);
  }

  // ─── Render dispatcher ────────────────────────────────────────────────────────
  function renderView() {
    if (viewTab === 'flat') {
      renderTable();
    } else {
      renderTreeView();
    }
  }

  // ─── Flat Table ───────────────────────────────────────────────────────────────
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
      sent: (a, b) => (a.total_bytes_sent || 0) - (b.total_bytes_sent || 0),
      received: (a, b) => (a.total_bytes_received || 0) - (b.total_bytes_received || 0),
      queries: (a, b) => (a.total_dns_queries || 0) - (b.total_dns_queries || 0),
    };

    const sortedDomains = tableState.getSortedItems(filteredDomains, customComparators);
    updateSortIcons();

    if (sortedDomains.length === 0) {
      tbody.innerHTML = `
        <tr><td colspan="9" class="table-td text-center py-12 text-txt-subtle italic">
          ${searchQuery ? 'No domains matching your search' : 'No domain rules'}
        </td></tr>
      `;
      renderPagination($('#dom-pagination', container), { currentPage: 1, totalPages: 1, totalItems: 0, pageSize: tableState.pageSize, onPageChange: () => {} });
      updateBulkBar(filteredDomains);
      return;
    }

    const sliceInfo = tableState.getPageSlice(sortedDomains);
    renderFlatRows(tbody, sliceInfo.slice);
    renderPagination($('#dom-pagination', container), {
      currentPage: sliceInfo.currentPage,
      totalPages: sliceInfo.totalPages,
      totalItems: sliceInfo.total,
      pageSize: tableState.pageSize,
      onPageChange: (newPage) => { tableState.setPage(newPage); renderTable(); },
    });
    tableState.updateHeaderCheckbox($('#dom-select-all', container), sliceInfo.slice);

    updateBulkBar(filteredDomains);
    applyEgressVisibility();
  }

  function applyEgressVisibility() {
    // Egress is now shown inline in the Mode/Egress column — only hide the bulk button when disabled
    const bulkEgressBtn = $('#dom-bulk-egress-btn', container);
    if (bulkEgressBtn) bulkEgressBtn.style.display = egressEnabled ? '' : 'none';
  }

  function renderFlatRows(tbody, items) {
    tbody.innerHTML = '';
    for (const d of items) {
      tbody.appendChild(createRowElement(d));
    }
  }

  function createRowElement(d) {
    const isSelected = tableState.selectedIds.has(d.domain);
    const row = document.createElement('tr');
    const isEnabled = d.enabled !== false; // default true
    row.className = `table-row ${isSelected ? 'table-row-selected' : ''} ${!isEnabled ? 'opacity-50' : ''}`;

    const isMerged = Boolean(d.is_merged);
    const isEgress = String(d.use_egress_proxy) === 'true';
    const totalBytes = (d.total_bytes_sent || 0) + (d.total_bytes_received || 0);

    // Build subcategory label for merged domains
    let subLabel = '';
    if (d.catalog_node) {
      // Find the subcategory name from catalog
      for (const cat of catalogCategories) {
        const sub = (cat.subcategories || []).find((s) => s.id === d.catalog_node);
        if (sub) { subLabel = sub.name; break; }
        if (cat.id === d.catalog_node) { subLabel = cat.name; break; }
      }
    } else if (d.group_name) {
      subLabel = d.group_name;
    }

    let domainDisplay = escapeHtml(d.domain);
    if (isMerged) {
      domainDisplay = `<span class="font-semibold text-txt">${escapeHtml(d.domain)}</span> <span class="badge badge-primary text-[10px] ml-1.5 font-sans font-medium">+ subdomains</span>${subLabel ? ` <span class="text-[10px] text-txt-muted font-sans ml-0.5">${escapeHtml(subLabel)}</span>` : ''}`;
    }

    row.innerHTML = `
      <td class="table-td w-10 text-center">
        <input type="checkbox" class="checkbox row-checkbox mx-auto" ${isSelected ? 'checked' : ''} />
      </td>
      <td class="table-td font-mono text-xs">
        <div class="flex items-center gap-1.5 flex-wrap">
          ${domainDisplay}
        </div>
      </td>
      <td class="table-td text-xs">
        <div class="flex items-center gap-1.5 flex-wrap">
          ${modeBadgeHtml(d.mode || 'proxy')}
          ${egressEnabled && isEgress ? egressBadgeHtml() : ''}
        </div>
      </td>
      <td class="table-td font-mono text-xs text-txt-muted">
        ${formatPorts(d.ports)}
      </td>
      <td class="table-td text-right font-mono text-xs tabular-nums">
        <span class="${totalBytes > 0 ? 'text-txt' : 'text-txt-subtle'}">
          ${totalBytes > 0 ? formatBytes(totalBytes) : '0 B'}
        </span>
      </td>
      <td class="table-td text-right font-mono text-xs tabular-nums text-txt-muted">
        ${(d.total_dns_queries || 0) > 0 ? formatCount(d.total_dns_queries) : '<span class="text-txt-subtle">0</span>'}
      </td>
      <td class="table-td text-right">
        <label class="relative inline-flex items-center cursor-pointer" title="${isEnabled ? 'Disable domain' : 'Enable domain'}">
          <input type="checkbox" class="dom-enable-toggle sr-only" ${isEnabled ? 'checked' : ''} />
          <div class="w-8 h-4 rounded-full transition-colors ${isEnabled ? 'bg-emerald-500' : 'bg-surface-3 border border-border'} relative">
            <div class="absolute top-0.5 ${isEnabled ? 'left-4' : 'left-0.5'} w-3 h-3 bg-white rounded-full shadow transition-all"></div>
          </div>
        </label>
      </td>
      <td class="table-td text-right">
        <button type="button" class="dom-row-menu-btn btn-icon-sm text-txt-muted hover:text-txt" aria-label="Domain actions">
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"/></svg>
        </button>
      </td>
    `;

    // Row checkbox
    const checkbox = row.querySelector('.row-checkbox');
    checkbox.addEventListener('change', (e) => {
      tableState.toggleSelect(d.domain, e.target.checked);
      row.className = `table-row ${e.target.checked ? 'table-row-selected' : ''} ${!isEnabled ? 'opacity-50' : ''}`;
      const filteredDomains = getFilteredDomains();
      tableState.updateHeaderCheckbox($('#dom-select-all', container), tableState.getPageSlice(tableState.getSortedItems(filteredDomains, {})).slice);
      updateBulkBar(filteredDomains);
    });

    // Enable toggle
    const enableToggle = row.querySelector('.dom-enable-toggle');
    enableToggle.addEventListener('change', async (e) => {
      const enabled = e.target.checked;
      try {
        await api.toggleDomain(d.domain, enabled);
        if (d.is_merged) {
          try { await api.toggleDomain(`*.${d.domain}`, enabled); } catch (_) {}
        }
        toast.success(`Domain ${d.domain} ${enabled ? 'enabled' : 'disabled'}`);
        await fetchDomains();
      } catch (err) {
        toast.error(err.message || 'Failed to toggle domain');
        e.target.checked = !enabled;
      }
    });

    // Row actions menu
    const menuBtn = row.querySelector('.dom-row-menu-btn');
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      showMenu(menuBtn, [
        {
          text: 'Usage Analytics',
          icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
          onClick: () => openUsageReportDialog({ kind: 'domain', name: d.domain }),
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
      ]);
    });

    return row;
  }

  // ─── Header select-all ─────────────────────────────────────────────────────────
  $('#dom-select-all', container).addEventListener('click', (e) => {
    const filteredDomains = getFilteredDomains();
    const sortedDomains = tableState.getSortedItems(filteredDomains, {});
    const visibleItems = tableState.getPageSlice(sortedDomains).slice;
    tableState.toggleSelectAllVisible(visibleItems, e.target.checked);
    renderTable();
  });

  // ─── Bulk Bar ─────────────────────────────────────────────────────────────────
  function updateBulkBar(filteredDomains) {
    const bulkBar = $('#dom-bulk-bar', container);
    const bulkCountEl = $('#dom-bulk-count', container);
    const selectAllBtn = $('#dom-bulk-select-all-btn', container);
    const allCountSpan = $('#dom-bulk-all-count', container);

    const targetList = filteredDomains || getFilteredDomains();
    const selectedCount = tableState.selectedIds.size;

    if (selectedCount > 0) {
      bulkBar.classList.remove('hidden');
      bulkCountEl.textContent = `${selectedCount} selected`;

      if (viewTab === 'flat') {
        const sortedDomains = tableState.getSortedItems(targetList, {});
        const sliceInfo = tableState.getPageSlice(sortedDomains);
        const visibleIds = sliceInfo.slice.map((d) => d.domain);
        const allVisibleSelected = visibleIds.length > 0 && visibleIds.every((id) => tableState.selectedIds.has(id));

        if (!tableState.selectAllMatching && allVisibleSelected && selectedCount < targetList.length) {
          selectAllBtn.classList.remove('hidden');
          allCountSpan.textContent = targetList.length;
        } else {
          selectAllBtn.classList.add('hidden');
        }
      } else {
        selectAllBtn.classList.add('hidden');
      }
    } else {
      bulkBar.classList.add('hidden');
    }
  }

  $('#dom-bulk-select-all-btn', container).addEventListener('click', () => {
    tableState.selectAllMatching = true;
    renderView();
  });

  $('#dom-bulk-clear-btn', container).addEventListener('click', () => {
    tableState.clearSelection();
    renderView();
  });

  function getSelectedTargetDomains(filteredDomains) {
    const targetList = filteredDomains || getFilteredDomains();
    const selectedIds = tableState.getSelectedIds(targetList.length ? targetList : allDomains);
    if (!selectedIds.length) return [];

    const domainMap = new Map();
    for (const d of allDomains) {
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

  // ─── Bulk Delete ──────────────────────────────────────────────────────────────
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

  // ─── Bulk Change Mode ─────────────────────────────────────────────────────────
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
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 cursor-pointer transition-colors',
      },
      direct: {
        active: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500 dark:border-zinc-400 bg-zinc-500/15 dark:bg-zinc-800/60 ring-1 ring-zinc-500/30 cursor-pointer transition-colors',
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500/20 bg-zinc-500/5 dark:bg-zinc-800/20 hover:border-zinc-500/40 cursor-pointer transition-colors',
      },
      block: {
        active: 'flex items-start gap-3 p-3 rounded-xl border border-red-500 bg-red-500/15 dark:bg-red-950/40 ring-1 ring-red-500/30 cursor-pointer transition-colors',
        inactive: 'flex items-start gap-3 p-3 rounded-xl border border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 cursor-pointer transition-colors',
      },
    };

    const content = createElement(html`
      <div class="flex flex-col gap-3">
        <p class="text-sm text-txt-muted">Select new routing mode for <span class="font-semibold text-txt">${selectedDomains.length}</span> selected rule(s):</p>
        <div class="space-y-2 pt-1">
          <label class="${modeStyles.proxy.active}" id="${bUid}-mode-opt-proxy">
            <input type="radio" name="${bUid}_routing_mode" value="proxy" class="radio radio-emerald mt-0.5 shrink-0" checked />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Proxy (Relay)</span>
              <span class="text-xs text-txt-muted mt-0.5">Relay TLS connections and log SNI traffic.</span>
            </div>
          </label>
          <label class="${modeStyles.direct.inactive}" id="${bUid}-mode-opt-direct">
            <input type="radio" name="${bUid}_routing_mode" value="direct" class="radio radio-zinc mt-0.5 shrink-0" />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Direct (Bypass)</span>
              <span class="text-xs text-txt-muted mt-0.5">Bypass relay and resolve client directly to target.</span>
            </div>
          </label>
          <label class="${modeStyles.block.inactive}" id="${bUid}-mode-opt-block">
            <input type="radio" name="${bUid}_routing_mode" value="block" class="radio radio-red mt-0.5 shrink-0" />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Block (Reject)</span>
              <span class="text-xs text-txt-muted mt-0.5">Drop and reject all DNS and TLS queries.</span>
            </div>
          </label>
        </div>
      </div>
    `);

    content.querySelectorAll(`input[name="${bUid}_routing_mode"]`).forEach((radio) => {
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

  // ─── Bulk Egress ──────────────────────────────────────────────────────────────
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
        { text: 'Cancel', className: 'btn btn-secondary', value: 'cancel', onClick: (_, { close }) => close('cancel') },
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

  // ─── Edit Dialog ──────────────────────────────────────────────────────────────
  function openEditDomainDialog(d) {
    if (!d.is_merged) {
      const formObj = createDomainRuleForm({ initialData: d, categories: catalogCategories, isEdit: true });

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
              try {
                await api.updateDomain(d.domain, {
                  group_name: data.group_name,
                  catalog_node: data.catalog_node,
                  mode: data.mode,
                  ports: Array.isArray(data.ports) ? data.ports.join(',') : data.ports,
                  use_egress_proxy: String(data.use_egress_proxy),
                  include_subdomains: Boolean(data.include_subdomains),
                  delete_wildcard_counterpart: data.include_subdomains === false,
                });
                toast.success(`Rule for ${d.domain} updated`);
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

    // Merged apex + wildcard edit
    let isSynced = true;
    let isMirroring = false;

    const apexWrapper = document.createElement('div');
    const apexForm = createDomainRuleForm({
      initialData: { ...d, domain: d.domain },
      categories: catalogCategories,
      isEdit: true,
      onChange: () => {
        if (isSynced && !isMirroring) {
          isMirroring = true;
          const data = apexForm.getData();
          wildcardForm.setData({ mode: data.mode, ports: data.ports, catalog_node: data.catalog_node, group_name: data.group_name, use_egress_proxy: data.use_egress_proxy });
          isMirroring = false;
        }
      },
    });
    apexWrapper.appendChild(apexForm.el);

    const wildcardWrapper = document.createElement('div');
    wildcardWrapper.className = 'hidden flex flex-col gap-3';
    const wildcardForm = createDomainRuleForm({
      initialData: { ...d, domain: `*.${d.domain}` },
      categories: catalogCategories,
      isEdit: true,
      onChange: () => {
        if (isSynced && !isMirroring) {
          isMirroring = true;
          const data = wildcardForm.getData();
          apexForm.setData({ mode: data.mode, ports: data.ports, catalog_node: data.catalog_node, group_name: data.group_name, use_egress_proxy: data.use_egress_proxy });
          isMirroring = false;
        }
      },
    });
    wildcardWrapper.appendChild(wildcardForm.el);

    const syncToggle = document.createElement('div');
    syncToggle.innerHTML = `
      <div class="flex items-center gap-3 p-3 rounded-xl bg-surface-2/50 border border-border">
        <label class="relative inline-flex items-center cursor-pointer gap-2 select-none">
          <input id="sync-toggle-cb" type="checkbox" class="checkbox" checked />
          <span class="text-xs font-medium text-txt">Sync apex + wildcard settings</span>
        </label>
      </div>
    `;
    const syncCb = syncToggle.querySelector('#sync-toggle-cb');
    syncCb.addEventListener('change', () => {
      isSynced = syncCb.checked;
      wildcardWrapper.className = isSynced ? 'hidden flex flex-col gap-3' : 'flex flex-col gap-3';
    });

    const contentWrap = document.createElement('div');
    contentWrap.className = 'space-y-4';
    contentWrap.appendChild(syncToggle);
    contentWrap.appendChild(apexWrapper);
    contentWrap.appendChild(wildcardWrapper);

    dialog.open({
      title: `Edit Merged Rule: ${d.domain}`,
      content: contentWrap,
      size: 'lg',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Save Changes',
          primary: true,
          onClick: async (_, { close }) => {
            const apexData = apexForm.getData();
            const wildcardData = isSynced ? apexData : wildcardForm.getData();
            try {
              if (isSynced) {
                await Promise.all([
                  api.updateDomain(d.domain, { catalog_node: apexData.catalog_node, group_name: apexData.group_name, mode: apexData.mode, ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports, use_egress_proxy: String(apexData.use_egress_proxy) }),
                  api.updateDomain(`*.${d.domain}`, { catalog_node: apexData.catalog_node, group_name: apexData.group_name, mode: apexData.mode, ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports, use_egress_proxy: String(apexData.use_egress_proxy) }),
                ]);
              } else {
                await Promise.all([
                  api.updateDomain(d.domain, { catalog_node: apexData.catalog_node, group_name: apexData.group_name, mode: apexData.mode, ports: Array.isArray(apexData.ports) ? apexData.ports.join(',') : apexData.ports, use_egress_proxy: String(apexData.use_egress_proxy) }),
                  api.updateDomain(`*.${d.domain}`, { catalog_node: wildcardData.catalog_node, group_name: wildcardData.group_name, mode: wildcardData.mode, ports: Array.isArray(wildcardData.ports) ? wildcardData.ports.join(',') : wildcardData.ports, use_egress_proxy: String(wildcardData.use_egress_proxy) }),
                ]);
              }
              toast.success(`Rules for ${d.domain} updated`);
              close();
              await fetchDomains();
            } catch (err) {
              toast.error(err.message || 'Failed to update domain rules');
            }
          },
        },
      ],
    });
  }

  // ─── Delete ───────────────────────────────────────────────────────────────────
  async function deleteDomainRule(d) {
    const confirmed = await dialog.confirm({
      title: `Delete Rule: ${d.domain}`,
      message: `Are you sure you want to permanently remove the rule for "${d.domain}"?${d.is_merged ? ' This will also delete the wildcard (*.domain) counterpart.' : ''}`,
      confirmText: 'Delete Rule',
      danger: true,
    });

    if (!confirmed) return;

    try {
      await api.deleteDomain(d.domain);
      if (d.is_merged) {
        try { await api.deleteDomain(`*.${d.domain}`); } catch { }
      }
      toast.success(`Domain ${d.domain} deleted`);
      await fetchDomains();
    } catch (err) {
      toast.error(err.message || 'Failed to delete domain rule');
    }
  }

  // ─── Tree View ────────────────────────────────────────────────────────────────

  // Helper: sum traffic bytes across a list of domain objects
  function sumBytes(domains) {
    return domains.reduce((s, d) => s + (d.total_bytes_sent || 0) + (d.total_bytes_received || 0), 0);
  }
  function sumDnsQueries(domains) {
    return domains.reduce((s, d) => s + (d.total_dns_queries || 0), 0);
  }

  // Helper: toggle all domains in a node
  async function toggleNodeDomains(nodeId, enabled, domainsInNode) {
    const allTargets = [];
    for (const d of domainsInNode) {
      allTargets.push(d.domain);
      if (d.is_merged) allTargets.push(`*.${d.domain}`);
    }
    for (const domain of allTargets) {
      try { await api.toggleDomain(domain, enabled); } catch (_) {}
    }
    toast.success(`${enabled ? 'Enabled' : 'Disabled'} ${domainsInNode.length} domain(s)`);
    await fetchDomains();
  }

  function renderTreeView() {
    const treeContainer = $('#dom-tree-container', container);
    treeContainer.innerHTML = '';

    // Sort categories alphabetically
    const sortedCats = [...catalogCategories].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    // Collect all domains with a catalog_node
    const domainsInCats = new Set();
    let renderedBlocksCount = 0;

    for (const cat of sortedCats) {
      const allSubs = [...(cat.subcategories || [])].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

      // In search mode, filter subcategories to only those with matching domains
      let matchedSubs = allSubs;
      if (searchQuery) {
        matchedSubs = allSubs.filter((sub) => {
          const subDomains = allDomains.filter((d) => d.catalog_node === sub.id);
          return subDomains.some((d) =>
            d.domain.toLowerCase().includes(searchQuery) ||
            (d.group_name && d.group_name.toLowerCase().includes(searchQuery))
          );
        });

        const directCatDoms = allDomains.filter((d) => d.catalog_node === cat.id);
        const hasDirectMatch = directCatDoms.some((d) =>
          d.domain.toLowerCase().includes(searchQuery) ||
          (d.group_name && d.group_name.toLowerCase().includes(searchQuery))
        );

        if (matchedSubs.length === 0 && !hasDirectMatch) {
          // Track domains for uncategorized calculation even when hidden
          for (const sub of allSubs) {
            allDomains.filter((d) => d.catalog_node === sub.id).forEach((d) => domainsInCats.add(d.domain));
          }
          allDomains.filter((d) => d.catalog_node === cat.id).forEach((d) => domainsInCats.add(d.domain));
          continue;
        }

        // Auto-expand category and matching subcategories
        expandedCats.add(cat.id);
        matchedSubs.forEach((sub) => expandedSubs.add(sub.id));
      }

      const catEl = buildCategoryBlock(cat, matchedSubs, domainsInCats);
      treeContainer.appendChild(catEl);
      renderedBlocksCount++;
    }

    // Uncategorized
    const uncatDomains = allDomains.filter((d) => !domainsInCats.has(d.domain) && !domainsInCats.has(`*.${d.domain}`));
    const filteredUncat = searchQuery
      ? uncatDomains.filter((d) => d.domain.toLowerCase().includes(searchQuery) || (d.group_name && d.group_name.toLowerCase().includes(searchQuery)))
      : uncatDomains;

    const mergedUncat = mergeApexWildcard(filteredUncat).sort((a, b) => a.domain.localeCompare(b.domain));

    if (mergedUncat.length > 0) {
      if (searchQuery) expandedCats.add('__uncat__');
      const uncatEl = buildUncategorizedBlock(mergedUncat);
      treeContainer.appendChild(uncatEl);
      renderedBlocksCount++;
    }

    if (renderedBlocksCount === 0 && searchQuery) {
      const emptyEl = document.createElement('div');
      emptyEl.className = 'py-16 text-center text-txt-subtle';
      emptyEl.innerHTML = `
        <div class="flex flex-col items-center justify-center gap-2">
          <svg class="w-8 h-8 text-txt-subtle/50" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
          </svg>
          <span class="text-sm">No domains or categories match "<strong>${escapeHtml(searchQuery)}</strong>"</span>
        </div>
      `;
      treeContainer.appendChild(emptyEl);
    }

    // No pagination in tree view — hide
    $('#dom-pagination', container).innerHTML = '';
    // Update bulk bar in tree view
    updateBulkBar(getFilteredDomains());
  }

  function buildCategoryBlock(cat, subs, domainsInCats) {
    const isExpanded = expandedCats.has(cat.id);

    // Gather ALL domains in this category (for usage stats + group toggle + selection)
    const allCatDomains = [];
    for (const sub of (cat.subcategories || [])) {
      const subDoms = allDomains.filter((d) => d.catalog_node === sub.id);
      subDoms.forEach((d) => { allCatDomains.push(d); domainsInCats.add(d.domain); });
    }
    // also direct cat-level (no subcategory)
    const directDoms = allDomains.filter((d) => d.catalog_node === cat.id);
    directDoms.forEach((d) => { allCatDomains.push(d); domainsInCats.add(d.domain); });

    const catTotalBytes = sumBytes(allCatDomains);
    const catDnsQueries = sumDnsQueries(allCatDomains);
    const allEnabled = allCatDomains.length > 0 && allCatDomains.every((d) => d.enabled !== false);

    const isCatAllSelected = allCatDomains.length > 0 && allCatDomains.every((d) => tableState.selectedIds.has(d.domain));
    const isCatSomeSelected = !isCatAllSelected && allCatDomains.some((d) => tableState.selectedIds.has(d.domain));

    const catEl = document.createElement('div');
    catEl.className = 'border-b border-border last:border-b-0';

    const catHeader = document.createElement('div');
    catHeader.className = 'flex items-center justify-between px-4 py-3 bg-surface-2/60 hover:bg-surface-hover transition-colors cursor-pointer select-none';

    catHeader.innerHTML = `
      <div class="flex items-center gap-3 min-w-0 flex-1">
        <input type="checkbox" class="cat-select-cb checkbox checkbox-sm shrink-0" title="Select all in category" ${isCatAllSelected ? 'checked' : ''} />
        <svg class="w-4 h-4 text-txt-muted transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''} cat-chevron" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        <span class="text-sm font-semibold text-txt truncate">${escapeHtml(cat.name)}</span>
        <span class="text-xs font-mono text-txt-subtle truncate">${escapeHtml(cat.id)}</span>
        <span class="badge badge-neutral text-[10px] font-mono">${cat.enabled_domain_count || 0}/${cat.domain_count || 0}</span>
        ${catTotalBytes > 0 ? `<span class="text-[10px] text-txt-muted font-mono tabular-nums">${formatBytes(catTotalBytes)}</span>` : ''}
        ${catDnsQueries > 0 ? `<span class="text-[10px] text-txt-subtle tabular-nums">${formatCount(catDnsQueries)} DNS</span>` : ''}
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <label class="relative inline-flex items-center cursor-pointer cat-group-toggle" title="${allEnabled ? 'Disable all in category' : 'Enable all in category'}">
          <input type="checkbox" class="cat-enabled-cb sr-only" ${allEnabled ? 'checked' : ''} />
          <div class="w-7 h-3.5 rounded-full transition-colors ${allEnabled ? 'bg-emerald-500' : 'bg-surface-3 border border-border'} relative">
            <div class="absolute top-0.5 ${allEnabled ? 'left-3.5' : 'left-0.5'} w-2.5 h-2.5 bg-white rounded-full shadow transition-all"></div>
          </div>
        </label>
        <button type="button" class="btn btn-ghost btn-xs text-primary-600 cat-add-sub-btn">+ Sub</button>
        <button type="button" class="btn-icon-xs text-txt-muted hover:text-txt cat-edit-btn" title="Edit Category">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
        </button>
        <button type="button" class="btn-icon-xs text-txt-muted hover:text-danger cat-delete-btn" title="Delete Category">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
        </button>
      </div>
    `;

    const catSelectCb = catHeader.querySelector('.cat-select-cb');
    if (isCatSomeSelected) {
      catSelectCb.indeterminate = true;
    }
    catSelectCb.addEventListener('click', (e) => e.stopPropagation());
    catSelectCb.addEventListener('change', (e) => {
      e.stopPropagation();
      const checked = e.target.checked;
      allCatDomains.forEach((d) => {
        if (checked) tableState.selectedIds.add(d.domain);
        else tableState.selectedIds.delete(d.domain);
      });
      renderView();
    });

    catHeader.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('.cat-group-toggle') || e.target.closest('.cat-select-cb')) return;
      if (expandedCats.has(cat.id)) expandedCats.delete(cat.id);
      else expandedCats.add(cat.id);
      renderTreeView();
    });

    // Group toggle
    const groupToggleCb = catHeader.querySelector('.cat-enabled-cb');
    groupToggleCb.addEventListener('change', async (e) => {
      e.stopPropagation();
      const enabled = e.target.checked;
      await toggleNodeDomains(cat.id, enabled, allCatDomains);
    });

    catHeader.querySelector('.cat-add-sub-btn').addEventListener('click', (e) => { e.stopPropagation(); openAddSubcategoryModal(cat); });
    catHeader.querySelector('.cat-edit-btn').addEventListener('click', (e) => { e.stopPropagation(); openEditNodeModal(cat); });
    catHeader.querySelector('.cat-delete-btn').addEventListener('click', (e) => { e.stopPropagation(); confirmDeleteNode(cat); });

    catEl.appendChild(catHeader);

    if (isExpanded) {
      const subsEl = document.createElement('div');
      subsEl.className = 'divide-y divide-border/50';

      for (const sub of subs) {
        const subBlock = buildSubcategoryBlock(sub, cat, domainsInCats);
        subsEl.appendChild(subBlock);
      }

      catEl.appendChild(subsEl);
    }

    return catEl;
  }

  function buildSubcategoryBlock(sub, parentCat, domainsInCats) {
    const isExpanded = expandedSubs.has(sub.id);

    // Get ALL domains for this subcategory (for stats + toggle + selection)
    const allSubDomains = allDomains.filter((d) => d.catalog_node === sub.id);
    allSubDomains.forEach((d) => domainsInCats.add(d.domain));

    // Filtered domains for display
    let displayDomains = searchQuery
      ? allSubDomains.filter((d) =>
          d.domain.toLowerCase().includes(searchQuery) ||
          (d.group_name && d.group_name.toLowerCase().includes(searchQuery))
        )
      : allSubDomains;

    const mergedDomains = mergeApexWildcard(displayDomains).sort((a, b) => a.domain.localeCompare(b.domain));
    const subTotalBytes = sumBytes(allSubDomains);
    const subDnsQueries = sumDnsQueries(allSubDomains);
    const allEnabled = allSubDomains.length > 0 && allSubDomains.every((d) => d.enabled !== false);

    const isSubAllSelected = allSubDomains.length > 0 && allSubDomains.every((d) => tableState.selectedIds.has(d.domain));
    const isSubSomeSelected = !isSubAllSelected && allSubDomains.some((d) => tableState.selectedIds.has(d.domain));

    const subEl = document.createElement('div');
    subEl.className = 'ml-4 border-l-2 border-border/40';

    const subHeader = document.createElement('div');
    subHeader.className = 'flex items-center justify-between px-4 py-2.5 bg-surface hover:bg-surface-2/40 transition-colors cursor-pointer select-none';

    subHeader.innerHTML = `
      <div class="flex items-center gap-2.5 min-w-0 flex-1">
        <input type="checkbox" class="sub-select-cb checkbox checkbox-sm shrink-0" title="Select all in subcategory" ${isSubAllSelected ? 'checked' : ''} />
        <svg class="w-3.5 h-3.5 text-txt-subtle transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''} sub-chevron" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        <span class="text-xs font-semibold text-txt truncate">${escapeHtml(sub.name)}</span>
        <span class="text-[11px] font-mono text-txt-subtle truncate">${escapeHtml(sub.id)}</span>
        <span class="badge badge-neutral text-[10px] font-mono">${allSubDomains.length} domains</span>
        ${subTotalBytes > 0 ? `<span class="text-[10px] text-txt-muted font-mono tabular-nums">${formatBytes(subTotalBytes)}</span>` : ''}
        ${subDnsQueries > 0 ? `<span class="text-[10px] text-txt-subtle tabular-nums">${formatCount(subDnsQueries)} DNS</span>` : ''}
      </div>
      <div class="flex items-center gap-1.5 shrink-0">
        <label class="relative inline-flex items-center cursor-pointer sub-group-toggle" title="${allEnabled ? 'Disable all in subcategory' : 'Enable all in subcategory'}">
          <input type="checkbox" class="sub-enabled-cb sr-only" ${allEnabled ? 'checked' : ''} />
          <div class="w-7 h-3.5 rounded-full transition-colors ${allEnabled ? 'bg-emerald-500' : 'bg-surface-3 border border-border'} relative">
            <div class="absolute top-0.5 ${allEnabled ? 'left-3.5' : 'left-0.5'} w-2.5 h-2.5 bg-white rounded-full shadow transition-all"></div>
          </div>
        </label>
        <button type="button" class="btn-icon-xs text-txt-muted hover:text-txt sub-edit-btn" title="Edit Subcategory">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg>
        </button>
        <button type="button" class="btn-icon-xs text-txt-muted hover:text-danger sub-delete-btn" title="Delete Subcategory">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
        </button>
      </div>
    `;

    const subSelectCb = subHeader.querySelector('.sub-select-cb');
    if (isSubSomeSelected) {
      subSelectCb.indeterminate = true;
    }
    subSelectCb.addEventListener('click', (e) => e.stopPropagation());
    subSelectCb.addEventListener('change', (e) => {
      e.stopPropagation();
      const checked = e.target.checked;
      allSubDomains.forEach((d) => {
        if (checked) tableState.selectedIds.add(d.domain);
        else tableState.selectedIds.delete(d.domain);
      });
      renderView();
    });

    subHeader.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('.sub-group-toggle') || e.target.closest('.sub-select-cb')) return;
      if (expandedSubs.has(sub.id)) expandedSubs.delete(sub.id);
      else expandedSubs.add(sub.id);
      renderTreeView();
    });

    // Subcategory group toggle
    const subToggleCb = subHeader.querySelector('.sub-enabled-cb');
    subToggleCb.addEventListener('change', async (e) => {
      e.stopPropagation();
      const enabled = e.target.checked;
      await toggleNodeDomains(sub.id, enabled, allSubDomains);
    });

    subHeader.querySelector('.sub-edit-btn').addEventListener('click', (e) => { e.stopPropagation(); openEditNodeModal(sub); });
    subHeader.querySelector('.sub-delete-btn').addEventListener('click', (e) => { e.stopPropagation(); confirmDeleteNode(sub); });

    subEl.appendChild(subHeader);

    if (expandedSubs.has(sub.id) && mergedDomains.length > 0) {
      const domsEl = document.createElement('div');
      domsEl.className = 'divide-y divide-border/30';

      for (const d of mergedDomains) {
        domsEl.appendChild(createTreeDomainRow(d));
      }

      subEl.appendChild(domsEl);
    }

    return subEl;
  }

  function buildUncategorizedBlock(mergedDomains) {
    const isExpanded = expandedCats.has('__uncat__');

    const isUncatAllSelected = mergedDomains.length > 0 && mergedDomains.every((d) => tableState.selectedIds.has(d.domain));
    const isUncatSomeSelected = !isUncatAllSelected && mergedDomains.some((d) => tableState.selectedIds.has(d.domain));

    const el = document.createElement('div');
    el.className = 'border-b border-border last:border-b-0';

    const header = document.createElement('div');
    header.className = 'flex items-center justify-between px-4 py-3 bg-surface-2/30 hover:bg-surface-hover transition-colors cursor-pointer select-none';

    header.innerHTML = `
      <div class="flex items-center gap-3 min-w-0">
        <input type="checkbox" class="uncat-select-cb checkbox checkbox-sm shrink-0" title="Select all uncategorized" ${isUncatAllSelected ? 'checked' : ''} />
        <svg class="w-4 h-4 text-txt-muted transition-transform duration-150 ${isExpanded ? 'rotate-90' : ''}" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
        <span class="text-sm font-semibold text-txt-muted">Uncategorized</span>
        <span class="badge badge-neutral text-[10px] font-mono">${mergedDomains.length}</span>
      </div>
    `;

    const uncatSelectCb = header.querySelector('.uncat-select-cb');
    if (isUncatSomeSelected) {
      uncatSelectCb.indeterminate = true;
    }
    uncatSelectCb.addEventListener('click', (e) => e.stopPropagation());
    uncatSelectCb.addEventListener('change', (e) => {
      e.stopPropagation();
      const checked = e.target.checked;
      mergedDomains.forEach((d) => {
        if (checked) tableState.selectedIds.add(d.domain);
        else tableState.selectedIds.delete(d.domain);
      });
      renderView();
    });

    header.addEventListener('click', (e) => {
      if (e.target.closest('.uncat-select-cb')) return;
      if (expandedCats.has('__uncat__')) expandedCats.delete('__uncat__');
      else expandedCats.add('__uncat__');
      renderTreeView();
    });

    el.appendChild(header);

    if (isExpanded) {
      if (mergedDomains.length === 0) {
        const emptyEl = document.createElement('div');
        emptyEl.className = 'px-8 py-4 text-xs text-txt-subtle italic';
        emptyEl.textContent = 'All domains are categorized';
        el.appendChild(emptyEl);
      } else {
        const domsEl = document.createElement('div');
        domsEl.className = 'divide-y divide-border/30';
        for (const d of mergedDomains) {
          domsEl.appendChild(createTreeDomainRow(d));
        }
        el.appendChild(domsEl);
      }
    }

    return el;
  }

  function createTreeDomainRow(d) {
    const isSelected = tableState.selectedIds.has(d.domain);
    const isEnabled = d.enabled !== false;
    const isMerged = Boolean(d.is_merged);
    const isEgress = String(d.use_egress_proxy) === 'true';
    const totalBytes = (d.total_bytes_sent || 0) + (d.total_bytes_received || 0);

    const row = document.createElement('div');
    row.className = `flex items-center justify-between px-8 py-2.5 hover:bg-surface-2/30 transition-colors ${isSelected ? 'bg-primary-soft/40' : ''} ${!isEnabled ? 'opacity-50' : ''}`;

    row.innerHTML = `
      <div class="flex items-center gap-2.5 min-w-0 flex-1">
        <input type="checkbox" class="tree-dom-cb checkbox checkbox-sm shrink-0" ${isSelected ? 'checked' : ''} />
        <span class="font-mono text-xs text-txt truncate ${!isEnabled ? 'line-through text-txt-muted' : ''}">${escapeHtml(d.domain)}</span>
        ${isMerged ? `<span class="badge badge-primary text-[10px] font-sans shrink-0">+ sub</span>` : ''}
        ${modeBadgeHtml(d.mode || 'proxy')}
        ${egressEnabled && isEgress ? egressBadgeHtml() : ''}
      </div>
      <div class="flex items-center gap-2 shrink-0 ml-3">
        <span class="text-[11px] text-txt-subtle font-mono">${formatPorts(d.ports)}</span>
        ${totalBytes > 0 ? `<span class="text-[10px] font-mono tabular-nums text-txt-muted">${formatBytes(totalBytes)}</span>` : ''}
        ${(d.total_dns_queries || 0) > 0 ? `<span class="text-[10px] text-txt-subtle tabular-nums">${formatCount(d.total_dns_queries)} DNS</span>` : ''}
        <label class="relative inline-flex items-center cursor-pointer" title="${isEnabled ? 'Disable' : 'Enable'}">
          <input type="checkbox" class="tree-enable-toggle sr-only" ${isEnabled ? 'checked' : ''} />
          <div class="w-7 h-3.5 rounded-full transition-colors ${isEnabled ? 'bg-emerald-500' : 'bg-surface-3 border border-border'} relative">
            <div class="absolute top-0.5 ${isEnabled ? 'left-3.5' : 'left-0.5'} w-2.5 h-2.5 bg-white rounded-full shadow transition-all"></div>
          </div>
        </label>
        <button type="button" class="tree-row-menu-btn btn-icon-sm text-txt-muted hover:text-txt" aria-label="Domain actions">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"/></svg>
        </button>
      </div>
    `;

    // Row selection checkbox
    const domCb = row.querySelector('.tree-dom-cb');
    domCb.addEventListener('change', (e) => {
      e.stopPropagation();
      tableState.toggleSelect(d.domain, e.target.checked);
      renderView();
    });

    // Enable toggle
    const enableToggle = row.querySelector('.tree-enable-toggle');
    enableToggle.addEventListener('change', async (e) => {
      const enabled = e.target.checked;
      try {
        await api.toggleDomain(d.domain, enabled);
        if (d.is_merged) {
          try { await api.toggleDomain(`*.${d.domain}`, enabled); } catch (_) {}
        }
        toast.success(`Domain ${d.domain} ${enabled ? 'enabled' : 'disabled'}`);
        await fetchDomains();
      } catch (err) {
        toast.error(err.message || 'Failed to toggle domain');
        e.target.checked = !enabled;
      }
    });

    // Row menu
    const menuBtn = row.querySelector('.tree-row-menu-btn');
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      showMenu(menuBtn, [
        {
          text: 'Usage Analytics',
          icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
          onClick: () => openUsageReportDialog({ kind: 'domain', name: d.domain }),
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
      ]);
    });

    return row;
  }

  // ─── Category Management Modals ───────────────────────────────────────────────
  function openCategoryManagerDialog() {
    const wrapper = document.createElement('div');
    wrapper.className = 'space-y-4';

    function renderModalTree() {
      wrapper.innerHTML = '';
      const addBtn = document.createElement('button');
      addBtn.type = 'button';
      addBtn.className = 'btn btn-secondary btn-sm w-full';
      addBtn.innerHTML = `<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg> Add Category`;
      addBtn.addEventListener('click', () => openAddCategoryModal().then(() => fetchDomains().then(renderModalTree)));
      wrapper.appendChild(addBtn);

      if (catalogCategories.length === 0) {
        const empty = document.createElement('p');
        empty.className = 'text-xs text-txt-subtle text-center py-4';
        empty.textContent = 'No categories yet. Add one to get started.';
        wrapper.appendChild(empty);
        return;
      }

      const treeEl = document.createElement('div');
      treeEl.className = 'rounded-xl border border-border overflow-hidden divide-y divide-border bg-surface';

      const sortedCats = [...catalogCategories].sort((a, b) => (a.name || '').localeCompare(b.name || ''));

      for (const cat of sortedCats) {
        const catRow = document.createElement('div');
        catRow.className = 'p-3 flex items-center justify-between gap-2 bg-surface-2/40 hover:bg-surface-2/80 transition-colors';
        catRow.innerHTML = `
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-sm font-semibold text-txt truncate">${escapeHtml(cat.name)}</span>
            <span class="text-[11px] font-mono text-txt-subtle truncate">${escapeHtml(cat.id)}</span>
            <span class="badge badge-neutral text-[10px]">${(cat.subcategories || []).length} subs</span>
          </div>
          <div class="flex items-center gap-1 shrink-0">
            <button type="button" class="btn btn-ghost btn-xs text-primary-600 modal-add-sub-btn">+ Sub</button>
            <button type="button" class="btn-icon-xs text-txt-muted hover:text-txt modal-edit-cat-btn"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg></button>
            <button type="button" class="btn-icon-xs text-txt-muted hover:text-danger modal-delete-cat-btn"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button>
          </div>
        `;

        catRow.querySelector('.modal-add-sub-btn').addEventListener('click', () =>
          openAddSubcategoryModal(cat).then(() => fetchDomains().then(renderModalTree))
        );
        catRow.querySelector('.modal-edit-cat-btn').addEventListener('click', () =>
          openEditNodeModal(cat).then(() => fetchDomains().then(renderModalTree))
        );
        catRow.querySelector('.modal-delete-cat-btn').addEventListener('click', () =>
          confirmDeleteNode(cat).then(() => fetchDomains().then(renderModalTree))
        );

        treeEl.appendChild(catRow);

        const subs = [...(cat.subcategories || [])].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
        for (const sub of subs) {
          const subRow = document.createElement('div');
          subRow.className = 'pl-8 pr-3 py-2.5 flex items-center justify-between gap-2 border-l-2 border-primary-300/40 ml-4 hover:bg-surface-hover transition-colors';
          subRow.innerHTML = `
            <div class="flex items-center gap-2 min-w-0">
              <span class="text-xs font-medium text-txt truncate">${escapeHtml(sub.name)}</span>
              <span class="text-[11px] font-mono text-txt-subtle truncate">${escapeHtml(sub.id)}</span>
            </div>
            <div class="flex items-center gap-1 shrink-0">
              <button type="button" class="btn-icon-xs text-txt-muted hover:text-txt modal-edit-sub-btn"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/></svg></button>
              <button type="button" class="btn-icon-xs text-txt-muted hover:text-danger modal-delete-sub-btn"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button>
            </div>
          `;

          subRow.querySelector('.modal-edit-sub-btn').addEventListener('click', () =>
            openEditNodeModal(sub).then(() => fetchDomains().then(renderModalTree))
          );
          subRow.querySelector('.modal-delete-sub-btn').addEventListener('click', () =>
            confirmDeleteNode(sub).then(() => fetchDomains().then(renderModalTree))
          );

          treeEl.appendChild(subRow);
        }
      }

      wrapper.appendChild(treeEl);
    }

    renderModalTree();

    dialog.open({
      title: 'Manage Categories & Subcategories',
      content: wrapper,
      size: 'md',
      actions: [{ text: 'Close', className: 'btn btn-secondary', value: false }],
    });
  }

  function openAddCategoryModal() {
    return new Promise((resolve) => {
      const content = document.createElement('div');
      content.className = 'space-y-4';
      content.innerHTML = `
        <div class="field">
          <label class="field-label" for="add-cat-name-input">Category Name</label>
          <input id="add-cat-name-input" type="text" class="input" placeholder="e.g. Streaming & Media" />
        </div>
        <div class="field">
          <label class="field-label" for="add-cat-id-input">Category ID (unique, lowercase)</label>
          <input id="add-cat-id-input" type="text" class="input font-mono" placeholder="e.g. streaming" />
        </div>
      `;

      const nameInput = content.querySelector('#add-cat-name-input');
      const idInput = content.querySelector('#add-cat-id-input');

      nameInput.addEventListener('input', () => {
        if (!idInput.dataset.manual) {
          idInput.value = nameInput.value.toLowerCase().replace(/[^a-z0-9_-]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
        }
      });
      idInput.addEventListener('input', () => { idInput.dataset.manual = 'true'; });

      dialog.open({
        title: 'Add Catalog Category',
        content,
        size: 'sm',
        actions: [
          { text: 'Cancel', className: 'btn btn-secondary', value: false, onClick: (_, { close }) => { close(); resolve(); } },
          {
            text: 'Create Category',
            primary: true,
            onClick: async (_, { close }) => {
              const name = nameInput.value.trim();
              const id = idInput.value.trim().toLowerCase();
              if (!name || !id) { toast.error('Both name and ID are required'); return; }
              try {
                await api.createCatalogNode({ id, name, parent_id: '' });
                toast.success(`Category "${name}" created`);
                close();
                resolve();
              } catch (err) {
                toast.error(err.message || 'Failed to create category');
              }
            },
          },
        ],
      });
    });
  }

  function openAddSubcategoryModal(parentCat) {
    return new Promise((resolve) => {
      const content = document.createElement('div');
      content.className = 'space-y-4';
      content.innerHTML = `
        <div class="field">
          <label class="field-label">Parent Category</label>
          <input type="text" class="input bg-surface-2" value="${escapeHtml(parentCat.name)} (${escapeHtml(parentCat.id)})" readonly />
        </div>
        <div class="field">
          <label class="field-label" for="add-sub-name-input">Subcategory Name</label>
          <input id="add-sub-name-input" type="text" class="input" placeholder="e.g. Netflix" />
        </div>
        <div class="field">
          <label class="field-label" for="add-sub-id-input">Subcategory ID</label>
          <div class="flex items-center">
            <span class="px-3 py-2 bg-surface-2 border border-r-0 border-border rounded-l-lg text-xs font-mono text-txt-muted">${escapeHtml(parentCat.id)}.</span>
            <input id="add-sub-id-input" type="text" class="input font-mono rounded-l-none" placeholder="netflix" />
          </div>
        </div>
      `;

      const nameInput = content.querySelector('#add-sub-name-input');
      const idInput = content.querySelector('#add-sub-id-input');

      nameInput.addEventListener('input', () => {
        if (!idInput.dataset.manual) {
          idInput.value = nameInput.value.toLowerCase().replace(/[^a-z0-9_-]/g, '_').replace(/_+/g, '_').replace(/^_|_$/g, '');
        }
      });
      idInput.addEventListener('input', () => { idInput.dataset.manual = 'true'; });

      dialog.open({
        title: `Add Subcategory to ${parentCat.name}`,
        content,
        size: 'sm',
        actions: [
          { text: 'Cancel', className: 'btn btn-secondary', value: false, onClick: (_, { close }) => { close(); resolve(); } },
          {
            text: 'Create Subcategory',
            primary: true,
            onClick: async (_, { close }) => {
              const name = nameInput.value.trim();
              const subSlug = idInput.value.trim().toLowerCase();
              if (!name || !subSlug) { toast.error('Both name and ID are required'); return; }
              const id = `${parentCat.id}.${subSlug}`;
              try {
                await api.createCatalogNode({ id, name, parent_id: parentCat.id });
                toast.success(`Subcategory "${name}" created`);
                close();
                expandedCats.add(parentCat.id);
                resolve();
              } catch (err) {
                toast.error(err.message || 'Failed to create subcategory');
              }
            },
          },
        ],
      });
    });
  }

  function openEditNodeModal(node) {
    return new Promise((resolve) => {
      const content = document.createElement('div');
      content.className = 'space-y-4';
      content.innerHTML = `
        <div class="field">
          <label class="field-label">Node ID</label>
          <input type="text" class="input bg-surface-2 font-mono" value="${escapeHtml(node.id)}" readonly />
        </div>
        <div class="field">
          <label class="field-label" for="edit-node-name-input">Display Name</label>
          <input id="edit-node-name-input" type="text" class="input" value="${escapeHtml(node.name)}" />
        </div>
      `;

      const nameInput = content.querySelector('#edit-node-name-input');

      dialog.open({
        title: `Edit ${node.parent_id ? 'Subcategory' : 'Category'}`,
        content,
        size: 'sm',
        actions: [
          { text: 'Cancel', className: 'btn btn-secondary', value: false, onClick: (_, { close }) => { close(); resolve(); } },
          {
            text: 'Save Changes',
            primary: true,
            onClick: async (_, { close }) => {
              const name = nameInput.value.trim();
              if (!name) { toast.error('Name cannot be empty'); return; }
              try {
                await api.updateCatalogNode(node.id, { name });
                toast.success('Updated successfully');
                close();
                resolve();
              } catch (err) {
                toast.error(err.message || 'Failed to update');
              }
            },
          },
        ],
      });
    });
  }

  function confirmDeleteNode(node) {
    return new Promise((resolve) => {
      const isSub = Boolean(node.parent_id);
      dialog.confirm({
        title: `Delete ${isSub ? 'Subcategory' : 'Category'}: ${node.name}`,
        message: `Are you sure you want to delete "${node.name}" (${node.id})? Existing domain rules assigned to it will remain intact and become uncategorized.`,
        confirmText: 'Delete Node',
        danger: true,
      }).then(async (confirmed) => {
        if (!confirmed) { resolve(); return; }
        try {
          await api.deleteCatalogNode(node.id);
          toast.success(`Deleted "${node.name}"`);
          resolve();
        } catch (err) {
          toast.error(err.message || 'Failed to delete');
          resolve();
        }
      });
    });
  }

  // Categories button
  $('#dom-manage-cats-btn', container).addEventListener('click', () => {
    openCategoryManagerDialog();
  });

  // ─── Range Segmented ──────────────────────────────────────────────────────────
  let rangeSegObj = null;
  function initRangeSegmented() {
    const el = $('#dom-range-segmented', container);
    if (!el || rangeSegObj) return;
    rangeSegObj = createSegmentedControl({
      options: [
        { value: 'today', label: 'Today' },
        { value: '7d', label: '7d' },
        { value: '30d', label: '30d' },
        { value: 'monthly', label: 'Monthly' },
        { value: 'all', label: 'All' },
      ],
      value: activeRange,
      size: 'sm',
      onChange: (val) => { activeRange = val; fetchDomains(); },
    });
    el.innerHTML = '';
    el.appendChild(rangeSegObj.el);
  }

  // ─── Sort header ──────────────────────────────────────────────────────────────
  $$('[data-sort]', container).forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      tableState.setSort(key);
      renderTable();
    });
  });

  function updateSortIcons() {
    ['domain', 'usage', 'queries'].forEach((k) => {
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

  // ─── Init ─────────────────────────────────────────────────────────────────────
  // Apply initial view tab
  applyViewTab(viewTab);

  // Initial data load
  fetchDomains();

  // JSON Export
  $('#dom-export-json-btn', container).addEventListener('click', () => {
    window.location.href = getApiUrl('api/domains/export.json');
  });

  // JSON Import
  $('#dom-import-json-input', container).addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      const payload = JSON.parse(text);
      const res = await api.importDomainsJson(payload);
      const failedMsg = res.failed > 0 ? ` (${res.failed} invalid items skipped)` : '';
      toast.success(`Imported: ${res.domains_added || 0} added, ${res.domains_updated || 0} updated${failedMsg}`);
      if (res.errors && res.errors.length > 0) {
        console.warn('JSON import errors:', res.errors);
      }
      await fetchDomains();
    } catch (err) {
      toast.error('JSON import failed: ' + (err.message || 'Unknown error'));
    } finally {
      e.target.value = '';
    }
  });

  return {
    unmount: () => { container.innerHTML = ''; },
  };
}
