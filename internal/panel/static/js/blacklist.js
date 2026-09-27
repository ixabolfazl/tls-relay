/* =========================================================================
   TLS Relay Admin Panel — blacklist.js
   Global Blacklist management: list, add, delete.
   ========================================================================= */

"use strict";

async function loadBlacklist() {
  try {
    const res = await apiFetch('/api/blacklist');
    if (!res.ok) return;
    const data = await res.json();
    allBlacklistEntries = data.entries || [];
    updateMetrics();
    renderBlacklist();
  } catch { /* handled */ }
}

function renderBlacklist() {
  const query = ($('blacklist-search').value || '').trim().toLowerCase();
  const filtered = allBlacklistEntries.filter(e => e.entry.toLowerCase().includes(query));

  const tbody = $('blacklist-tbody');
  const empty = $('blacklist-empty');
  const table = $('blacklist-table');
  tbody.innerHTML = '';

  if (filtered.length === 0) {
    empty.textContent = allBlacklistEntries.length === 0 ? 'No blacklist entries configured.' : 'No entries match your search.';
    empty.classList.remove('hidden');
    table.classList.add('hidden');
    updateBulkBar();
    return;
  }
  empty.classList.add('hidden');
  table.classList.remove('hidden');

  filtered.sort((a, b) => a.entry.localeCompare(b.entry));

  for (const e of filtered) {
    const tr = document.createElement('tr');
    const isChecked = selectedBlacklistIds.has(e.id);

    tr.innerHTML = `
      <td class="checkbox-cell">
        <input type="checkbox" class="blacklist-chk" data-id="${e.id}" ${isChecked ? 'checked' : ''} />
      </td>
      <td class="code-cell">${escapeHtml(e.entry)}</td>
      <td>${escapeHtml(formatTimestamp(e.created_at))}</td>
      <td class="text-right">
        <div class="action-btns-row" style="justify-content: flex-end;">
          <button type="button" class="btn-icon btn-icon-danger btn-delete-blacklist" data-id="${e.id}" title="Delete entry">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
          </button>
        </div>
      </td>`;
    tbody.appendChild(tr);
  }

  tbody.querySelectorAll('.btn-delete-blacklist').forEach(btn => {
    btn.addEventListener('click', () => deleteBlacklistEntry(parseInt(btn.dataset.id)));
  });

  tbody.querySelectorAll('.blacklist-chk').forEach(chk => {
    chk.addEventListener('change', (e) => {
      const id = parseInt(e.target.dataset.id);
      if (e.target.checked) selectedBlacklistIds.add(id);
      else selectedBlacklistIds.delete(id);
      updateSelectAllCheckboxes();
      updateBulkBar();
    });
  });

  updateSelectAllCheckboxes();
  updateBulkBar();
}

function initBlacklistListeners() {
  if ($('blacklist-search')) {
    $('blacklist-search').addEventListener('input', renderBlacklist);
  }

  // Add blacklist form submit handler
  if ($('add-blacklist-form')) {
    $('add-blacklist-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('add-blacklist-error', 'add-blacklist-success');

      const rawEntry = $('blacklist-entry').value.trim();

      try {
        const res = await apiFetch('/api/blacklist', {
          method: 'POST',
          body: JSON.stringify({ entry: rawEntry }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('add-blacklist-error', data.error || 'Failed to add blacklist entry.');
          return;
        }
        const addedCount = data.added || 1;
        showSuccess('add-blacklist-success', `Successfully added ${addedCount} blacklist entry/entries.`);
        showToast(`Added ${addedCount} blacklist entry/entries.`, 'success');
        $('blacklist-entry').value = '';
        loadBlacklist();
      } catch {
        showError('add-blacklist-error', 'An error occurred while adding entries.');
      }
    });
  }
}

window.initBlacklistListeners = initBlacklistListeners;

async function deleteBlacklistEntry(id) {
  const confirmed = await showConfirmDialog({
    title: 'Remove Blacklist Entry',
    message: 'Are you sure you want to remove this entry from the global blacklist?',
    confirmText: 'Remove Entry',
    isDanger: true,
  });
  if (!confirmed) return;

  try {
    const res = await apiFetch(`/api/blacklist/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Delete failed.', 'error');
      return;
    }
    selectedBlacklistIds.delete(id);
    showToast('Blacklist entry removed.', 'success');
    loadBlacklist();
  } catch {
    showToast('Failed to remove blacklist entry.', 'error');
  }
}
