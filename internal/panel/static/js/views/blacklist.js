/**
 * Blacklist view: IP & CIDR blocking, batch addition, and filter-scoped bulk deletion.
 * Fixes B2 (bulk select scoping).
 */

import { html, raw, setHtml, $, $$, escapeHtml } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatDate } from '../core/format.js';
import { TableState } from '../ui/table.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';

export function mount(container) {
  let entries = [];
  let searchQuery = '';

  const tableState = new TableState({
    pageSize: 50,
    sortKey: 'created_at',
    sortDir: 'desc',
    getId: (item) => item.id,
  });

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Header -->
        <div>
          <h1 class="text-2xl font-bold text-txt">Global Blacklist</h1>
          <p class="text-xs text-txt-muted mt-0.5">Block malicious client IPs or CIDR subnets from connecting to the relay or resolver</p>
        </div>

        <!-- Add Blacklist Card -->
        <div class="card p-5">
          <h2 class="text-base font-semibold text-txt mb-2">Add IP or CIDR Subnet</h2>
          <form id="bl-add-form" class="space-y-3">
            <div class="field">
              <label class="field-label" for="bl-input">IP Address / CIDR Range(s)</label>
              <textarea
                id="bl-input"
                class="textarea font-mono text-sm"
                rows="2"
                placeholder="192.0.2.1&#10;198.51.100.0/24&#10;2001:db8::/32"
                required
              ></textarea>
              <span class="field-hint">Supports multiple IPv4/IPv6 addresses and CIDR subnets separated by newlines or commas.</span>
            </div>
            <div class="flex justify-end">
              <button id="bl-submit-btn" type="submit" class="btn btn-danger btn-sm">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>
                <span>Add to Blacklist</span>
              </button>
            </div>
          </form>
        </div>

        <!-- Blacklist Entries Card -->
        <div class="card">
          <div class="p-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div class="flex items-center gap-2">
              <h2 class="text-base font-semibold text-txt">Blocked Entries</h2>
              <span id="bl-count-badge" class="badge badge-neutral tabular-nums">0 entries</span>
            </div>
            <div class="relative w-full sm:w-64">
              <input
                id="bl-search-input"
                type="text"
                class="input pl-8 text-sm"
                placeholder="Search IPs or CIDRs..."
              />
              <svg class="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-txt-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
            </div>
          </div>

          <!-- Bulk Bar -->
          <div id="bl-bulk-bar" class="hidden px-5 py-3 bg-danger-soft border-b border-danger-border flex items-center justify-between gap-3 animate-fade-in">
            <span id="bl-bulk-count" class="text-xs font-semibold text-danger">0 selected</span>
            <div class="flex items-center gap-2">
              <button id="bl-bulk-delete-btn" type="button" class="btn btn-danger btn-sm">Delete Selected</button>
              <button id="bl-bulk-clear-btn" type="button" class="btn btn-ghost btn-sm text-txt-muted">Deselect</button>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th class="table-th w-10 text-center">
                    <input id="bl-select-all" type="checkbox" class="checkbox mx-auto" aria-label="Select all visible" />
                  </th>
                  <th class="table-th">Blocked IP / Range</th>
                  <th class="table-th">Added Date</th>
                  <th class="table-th w-16 text-right">Action</th>
                </tr>
              </thead>
              <tbody id="bl-table-body">
                <tr>
                  <td colspan="4" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading blacklist...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div id="bl-pagination" class="card-footer">
            <div id="bl-page-info" class="text-xs text-txt-muted">Showing 0 of 0</div>
            <div class="flex items-center gap-2">
              <button id="bl-prev-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Previous</button>
              <span id="bl-page-num" class="text-xs font-medium text-txt px-2">Page 1</span>
              <button id="bl-next-page-btn" type="button" class="btn btn-secondary btn-sm" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>
    `
  );

  // Search input
  $('#bl-search-input', container).addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    tableState.clearSelection();
    tableState.currentPage = 1;
    renderTable();
  });

  // Add Entries
  $('#bl-add-form', container).addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = $('#bl-input', container);
    const rawVal = input.value.trim();
    if (!rawVal) return;

    const submitBtn = $('#bl-submit-btn', container);
    submitBtn.disabled = true;

    try {
      const res = await api.addBlacklist(rawVal);
      toast.success(`Added ${res.added || 1} entry to blacklist`);
      input.value = '';
      await fetchBlacklist();
    } catch (err) {
      toast.error(err.message || 'Failed to add blacklist entries');
    } finally {
      submitBtn.disabled = false;
    }
  });

  // Fetch Blacklist
  async function fetchBlacklist() {
    try {
      const res = await api.getBlacklist();
      entries = res.entries || [];
      $('#bl-count-badge', container).textContent = `${entries.length} entries`;
      renderTable();
    } catch (err) {
      $('#bl-table-body', container).innerHTML = `
        <tr>
          <td colspan="4" class="table-td text-center py-8 text-danger">
            Failed to load blacklist: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  function getFilteredEntries() {
    if (!searchQuery) return entries;
    return entries.filter((e) => e.entry.toLowerCase().includes(searchQuery));
  }

  function renderTable() {
    const tbody = $('#bl-table-body', container);
    const filtered = getFilteredEntries();
    const sorted = tableState.getSortedItems(filtered);

    if (sorted.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="4" class="table-td text-center py-12 text-txt-subtle italic">
            ${searchQuery ? 'No matching blacklist entries found' : 'No IPs or CIDRs are currently blacklisted'}
          </td>
        </tr>
      `;
      updatePagination(0, 0, 0, 1, 1);
      updateBulkBar(filtered);
      return;
    }

    const sliceInfo = tableState.getPageSlice(sorted);
    tbody.innerHTML = '';

    for (const item of sliceInfo.slice) {
      const isSelected = tableState.selectedIds.has(item.id);
      const row = document.createElement('tr');
      row.className = `table-row ${isSelected ? 'table-row-selected' : ''}`;

      row.innerHTML = `
        <td class="table-td w-10 text-center">
          <input type="checkbox" class="checkbox row-checkbox mx-auto" ${isSelected ? 'checked' : ''} />
        </td>
        <td class="table-td font-mono text-xs font-semibold text-danger">
          ${escapeHtml(item.entry)}
        </td>
        <td class="table-td text-xs text-txt-muted tabular-nums">
          ${formatDate(item.created_at)}
        </td>
        <td class="table-td text-right">
          <button type="button" class="del-btn btn-icon-sm text-txt-subtle hover:text-danger hover:bg-danger-soft" title="Remove from blacklist">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
          </button>
        </td>
      `;

      row.querySelector('.row-checkbox').addEventListener('change', (e) => {
        tableState.toggleSelect(item.id, e.target.checked);
        renderTable();
      });

      row.querySelector('.del-btn').addEventListener('click', async () => {
        const confirmed = await dialog.confirm({
          title: 'Remove Blacklist Entry',
          message: `Are you sure you want to unblock "${item.entry}"?`,
          confirmText: 'Unblock IP',
        });
        if (!confirmed) return;

        try {
          await api.deleteBlacklist(item.id);
          toast.success(`Removed ${item.entry} from blacklist`);
          await fetchBlacklist();
        } catch (err) {
          toast.error(err.message || 'Failed to remove entry');
        }
      });

      tbody.appendChild(row);
    }

    updatePagination(
      sliceInfo.startIdx,
      sliceInfo.endIdx,
      sliceInfo.total,
      sliceInfo.currentPage,
      sliceInfo.totalPages
    );
    tableState.updateHeaderCheckbox($('#bl-select-all', container), sliceInfo.slice);
    updateBulkBar(filtered);
  }

  // Header select all (visible only, fixes B2)
  $('#bl-select-all', container).addEventListener('click', (e) => {
    const filtered = getFilteredEntries();
    const visible = tableState.getPageSlice(filtered).slice;
    tableState.toggleSelectAllVisible(visible, e.target.checked);
    renderTable();
  });

  function updateBulkBar(filtered) {
    const bulkBar = $('#bl-bulk-bar', container);
    const countEl = $('#bl-bulk-count', container);
    const selectedCount = tableState.getSelectedCount(filtered.length);

    if (selectedCount > 0) {
      bulkBar.classList.remove('hidden');
      countEl.textContent = `${selectedCount} selected`;
    } else {
      bulkBar.classList.add('hidden');
    }
  }

  $('#bl-bulk-clear-btn', container).addEventListener('click', () => {
    tableState.clearSelection();
    renderTable();
  });

  // Bulk Delete
  $('#bl-bulk-delete-btn', container).addEventListener('click', async () => {
    const filtered = getFilteredEntries();
    const ids = tableState.getSelectedIds(filtered);
    if (!ids.length) return;

    const confirmed = await dialog.confirm({
      title: `Delete ${ids.length} Blacklist Entries`,
      message: `Are you sure you want to remove ${ids.length} blocked entry(ies)?`,
      confirmText: 'Unblock Selected',
      danger: true,
    });
    if (!confirmed) return;

    try {
      const res = await api.bulkDeleteBlacklist(ids);
      toast.success(`Unblocked ${res.deleted || ids.length} entries`);
      tableState.clearSelection();
      await fetchBlacklist();
    } catch (err) {
      toast.error(err.message || 'Failed to bulk delete blacklist entries');
    }
  });

  // Pagination
  function updatePagination(start, end, total, page, totalPages) {
    $('#bl-page-info', container).textContent =
      total > 0 ? `Showing ${start}–${end} of ${total}` : 'Showing 0 of 0';
    $('#bl-page-num', container).textContent = `Page ${page} of ${totalPages}`;

    $('#bl-prev-page-btn', container).disabled = page <= 1;
    $('#bl-next-page-btn', container).disabled = page >= totalPages;
  }

  $('#bl-prev-page-btn', container).addEventListener('click', () => {
    if (tableState.currentPage > 1) {
      tableState.currentPage--;
      renderTable();
    }
  });

  $('#bl-next-page-btn', container).addEventListener('click', () => {
    tableState.currentPage++;
    renderTable();
  });

  // Initial load
  fetchBlacklist();

  return {
    unmount: () => {
      container.innerHTML = '';
    },
  };
}
