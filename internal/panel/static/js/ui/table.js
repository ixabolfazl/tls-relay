/**
 * Data table state manager for sorting, pagination, and filter-scoped selection.
 */

export class TableState {
  constructor({
    pageSize = 50,
    sortKey = '',
    sortDir = 'asc',
    getId = (item) => item.id || item.domain || item.key,
  } = {}) {
    this.pageSize = pageSize;
    this.currentPage = 1;
    this.sortKey = sortKey;
    this.sortDir = sortDir;
    this.getId = getId;
    this.selectedIds = new Set();
    this.selectAllMatching = false;
  }

  setPage(page) {
    const p = parseInt(page, 10);
    this.currentPage = Number.isFinite(p) && p > 0 ? p : 1;
  }

  setSort(key) {
    if (this.sortKey === key) {
      this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      this.sortKey = key;
      this.sortDir = 'asc';
    }
  }

  getSortedItems(items, customComparators = {}) {
    if (!this.sortKey || !items.length) return [...items];

    const key = this.sortKey;
    const dir = this.sortDir === 'asc' ? 1 : -1;
    const cmp = customComparators[key];

    return [...items].sort((a, b) => {
      if (cmp) return cmp(a, b) * dir;

      let valA = a[key];
      let valB = b[key];

      if (valA === undefined || valA === null) valA = '';
      if (valB === undefined || valB === null) valB = '';

      if (typeof valA === 'number' && typeof valB === 'number') {
        return (valA - valB) * dir;
      }
      return String(valA).localeCompare(String(valB), undefined, { numeric: true }) * dir;
    });
  }

  getPageSlice(items) {
    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / this.pageSize));
    if (this.currentPage > totalPages) this.currentPage = totalPages;
    if (this.currentPage < 1) this.currentPage = 1;

    const startIdx = (this.currentPage - 1) * this.pageSize;
    const endIdx = Math.min(startIdx + this.pageSize, total);

    return {
      slice: items.slice(startIdx, endIdx),
      startIdx: total > 0 ? startIdx + 1 : 0,
      endIdx,
      total,
      currentPage: this.currentPage,
      totalPages,
    };
  }

  // Selection scoped to current visible / filtered set (B2 fix)
  toggleSelect(id, isSelected) {
    if (isSelected) {
      this.selectedIds.add(id);
    } else {
      this.selectedIds.delete(id);
      this.selectAllMatching = false;
    }
  }

  toggleSelectAllVisible(visibleItems, checked) {
    if (checked) {
      for (const item of visibleItems) {
        this.selectedIds.add(this.getId(item));
      }
    } else {
      for (const item of visibleItems) {
        this.selectedIds.delete(this.getId(item));
      }
      this.selectAllMatching = false;
    }
  }

  clearSelection() {
    this.selectedIds.clear();
    this.selectAllMatching = false;
  }

  getSelectedCount(filteredTotalCount = 0) {
    if (this.selectAllMatching) return filteredTotalCount;
    return this.selectedIds.size;
  }

  getSelectedIds(allFilteredItems = []) {
    if (this.selectAllMatching && allFilteredItems.length > 0) {
      return allFilteredItems.map(this.getId);
    }
    return Array.from(this.selectedIds);
  }

  updateHeaderCheckbox(headerCheckboxEl, visibleItems) {
    if (!headerCheckboxEl || !visibleItems.length) {
      if (headerCheckboxEl) {
        headerCheckboxEl.checked = false;
        headerCheckboxEl.indeterminate = false;
      }
      return;
    }

    const visibleIds = visibleItems.map(this.getId);
    const selectedVisibleCount = visibleIds.filter((id) => this.selectedIds.has(id)).length;

    if (selectedVisibleCount === 0) {
      headerCheckboxEl.checked = false;
      headerCheckboxEl.indeterminate = false;
    } else if (selectedVisibleCount === visibleIds.length) {
      headerCheckboxEl.checked = true;
      headerCheckboxEl.indeterminate = false;
    } else {
      headerCheckboxEl.checked = false;
      headerCheckboxEl.indeterminate = true;
    }
  }
}
