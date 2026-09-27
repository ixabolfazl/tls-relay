/* =========================================================================
   TLS Relay Admin Panel — users.js
   User management: user CRUD, user IP management, and magic link reset.
   ========================================================================= */

"use strict";

async function loadUsers(range) {
  try {
    if (typeof loadSettings === 'function' && window.serverDomain === undefined) {
      loadSettings().catch(() => {});
    }
    const url = range ? `/api/users?range=${range}` : '/api/users';
    const res = await apiFetch(url);
    if (!res.ok) return;
    const data = await res.json();
    allUsers = data.users || [];
    updateMetrics();
    renderUsers();
    renderUsageUsersTable();
  } catch { /* handled */ }
}

function renderUsers() {
  const query = ($('user-search').value || '').trim().toLowerCase();
  const filtered = allUsers.filter(u => u.username.toLowerCase().includes(query));

  const tbody = $('user-tbody');
  const empty = $('user-empty');
  const table = $('user-table');
  tbody.innerHTML = '';

  if (filtered.length === 0) {
    empty.textContent = allUsers.length === 0 ? 'No users created yet.' : 'No users match your search.';
    empty.classList.remove('hidden');
    table.classList.add('hidden');
    return;
  }
  empty.classList.add('hidden');
  table.classList.remove('hidden');

  filtered.sort((a, b) => a.username.localeCompare(b.username));

  for (const u of filtered) {
    const tr = document.createElement('tr');
    const enabledBadge = u.enabled
      ? '<span class="status-badge status-allowed" style="margin-left: 6px; font-size: 0.725rem;">Enabled</span>'
      : '<span class="status-badge status-blocked" style="margin-left: 6px; font-size: 0.725rem;">Disabled</span>';

    const isOnline = typeof allPresenceUsers !== 'undefined' && Array.isArray(allPresenceUsers) &&
      allPresenceUsers.some(pu => (pu.user_id === u.id || pu.username === u.username) && pu.status === 'Online');
    const onlineDot = isOnline
      ? '<span class="presence-dot-inline status-online" title="User is currently online"></span> '
      : '<span class="presence-dot-inline status-offline" title="User is offline"></span> ';

    const fullMagicUrl = getMagicLinkUrl(u.magic_link);
    const lastSeenFormatted = formatTimestamp(u.last_seen_at);
    const totalBytesCombined = (u.total_bytes_sent || 0) + (u.total_bytes_received || 0);

    tr.innerHTML = `
      <td class="code-cell">
        <div class="flex-align-center">
          ${onlineDot}
          <strong style="font-size: 0.9rem;">${escapeHtml(u.username)}</strong>
          ${enabledBadge}
        </div>
      </td>
      <td><span class="text-hint">${escapeHtml(lastSeenFormatted)}</span></td>
      <td>
        <div class="user-usage-cell flex-align-center">
          <span class="code-badge" style="white-space: nowrap;">${formatBytes(totalBytesCombined)}</span>
          <span class="text-hint" style="font-size: 0.775rem; margin-left: 6px; white-space: nowrap;">(Max ${u.max_ips} IPs)</span>
        </div>
      </td>
      <td>
        <div class="magic-token-display flex-align-center-gap-xs">
          <code class="magic-link-code" style="max-width: 140px; overflow: hidden; text-overflow: ellipsis; display: inline-block; vertical-align: middle;" title="${escapeHtml(fullMagicUrl)}">${escapeHtml(u.magic_link)}</code>
          <button type="button" class="btn btn-secondary btn-xs btn-copy-link-quick" data-link="${escapeHtml(fullMagicUrl)}" title="Copy Magic Link">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
        </div>
      </td>
      <td class="text-right">
        <div class="action-dropdown">
          <button type="button" class="btn-action-trigger" title="Actions">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="1.5"></circle><circle cx="12" cy="5" r="1.5"></circle><circle cx="12" cy="19" r="1.5"></circle></svg>
          </button>
          <div class="action-dropdown-menu">
            <button type="button" class="action-dropdown-item btn-edit-user" data-user-id="${u.id}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
              Edit User
            </button>
            <button type="button" class="action-dropdown-item btn-view-ips" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              View IPs
            </button>
            <button type="button" class="action-dropdown-item btn-copy-token" data-token="${escapeHtml(u.magic_link)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              Copy Token
            </button>
            <button type="button" class="action-dropdown-item btn-copy-link" data-link="${escapeHtml(fullMagicUrl)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>
              Copy Magic Link
            </button>
            <button type="button" class="action-dropdown-item btn-reset-link" data-user-id="${u.id}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"></path><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
              Reset Token
            </button>
            <div class="action-dropdown-divider"></div>
            <button type="button" class="action-dropdown-item btn-toggle-user" data-user-id="${u.id}" data-enabled="${u.enabled}">
              ${u.enabled
                ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"></path><line x1="12" y1="2" x2="12" y2="12"></line></svg> Disable User`
                : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg> Enable User`
              }
            </button>
            <button type="button" class="action-dropdown-item danger-item btn-delete-user" data-user-id="${u.id}" data-username="${escapeHtml(u.username)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              Delete User
            </button>
          </div>
        </div>
      </td>`;
    tbody.appendChild(tr);
  }

  // 3-Dots Dropdown Trigger Listeners
  tbody.querySelectorAll('.btn-action-trigger').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const menu = btn.nextElementSibling;
      const isOpen = menu.classList.contains('show');
      closeAllActionDropdowns();

      if (!isOpen) {
        const rect = btn.getBoundingClientRect();
        menu.classList.add('show');
        btn.classList.add('active');

        const menuRect = menu.getBoundingClientRect();
        const menuWidth = menuRect.width || 185;
        const menuHeight = menuRect.height || 220;
        const spaceBelow = window.innerHeight - rect.bottom;

        menu.style.position = 'fixed';
        menu.style.zIndex = '99999';

        const rightOffset = window.innerWidth - rect.right;
        const leftPos = rect.right - menuWidth;
        if (leftPos < 10) {
          menu.style.left = '10px';
          menu.style.right = 'auto';
        } else {
          menu.style.right = `${Math.max(10, rightOffset)}px`;
          menu.style.left = 'auto';
        }

        if (spaceBelow < menuHeight && rect.top > menuHeight) {
          menu.style.top = `${rect.top - menuHeight - 4}px`;
        } else {
          menu.style.top = `${rect.bottom + 4}px`;
        }
      }
    });
  });

  // Action listeners inside dropdown menu
  tbody.querySelectorAll('.btn-view-ips').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      loadUserIPs(parseInt(btn.dataset.userId), btn.dataset.username);
    });
  });
  tbody.querySelectorAll('.btn-copy-token').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      const tokenText = btn.dataset.token;
      try {
        await copyToClipboard(tokenText);
        showToast('Token copied to clipboard.', 'success');
      } catch (err) {
        showToast('Could not copy token: ' + err.message, 'error');
      }
    });
  });
  tbody.querySelectorAll('.btn-copy-link, .btn-copy-link-quick').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      const linkText = btn.dataset.link;
      try {
        await copyToClipboard(linkText);
        showToast('Magic link copied to clipboard.', 'success');
      } catch (err) {
        showToast('Could not copy link: ' + err.message, 'error');
      }
    });
  });
  tbody.querySelectorAll('.btn-edit-user').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      const userId = parseInt(btn.dataset.userId);
      const user = allUsers.find(item => item.id === userId);
      if (user) openEditUserModal(user);
    });
  });
  tbody.querySelectorAll('.btn-reset-link').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      resetMagicLink(parseInt(btn.dataset.userId));
    });
  });
  tbody.querySelectorAll('.btn-toggle-user').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      toggleUser(parseInt(btn.dataset.userId), btn.dataset.enabled === 'true');
    });
  });
  tbody.querySelectorAll('.btn-delete-user').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.action-dropdown-menu.show').forEach(m => m.classList.remove('show'));
      deleteUser(parseInt(btn.dataset.userId), btn.dataset.username);
    });
  });
}

// Edit User Modal Functions
function openEditUserModal(user) {
  $('edit-user-id').value = user.id;
  $('edit-user-username').value = user.username;
  $('edit-user-magiclink').value = user.magic_link || '';
  $('edit-user-maxips').value = user.max_ips || 3;
  $('edit-user-enabled').checked = !!user.enabled;
  clearMessages('edit-user-error');
  showEl('edit-user-modal');
}

function closeEditUserModal() {
  hideEl('edit-user-modal');
}

function initUserListeners() {
  if ($('user-search')) {
    $('user-search').addEventListener('input', renderUsers);
  }

  // User Subtab Toggle
  if ($('user-subtab-toggle')) {
    $('user-subtab-toggle').querySelectorAll('.segmented-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        $('user-subtab-toggle').querySelectorAll('.segmented-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const subtab = btn.dataset.subtab || 'all';
        if (subtab === 'online') {
          hideEl('user-subtab-all');
          showEl('user-subtab-online');
          if (typeof fetchPresence === 'function') fetchPresence();
        } else {
          hideEl('user-subtab-online');
          showEl('user-subtab-all');
        }
      });
    });
  }

  if ($('close-edit-user-modal')) {
    $('close-edit-user-modal').addEventListener('click', closeEditUserModal);
  }
  if ($('cancel-edit-user-btn')) {
    $('cancel-edit-user-btn').addEventListener('click', closeEditUserModal);
  }
  if ($('edit-user-modal')) {
    $('edit-user-modal').addEventListener('click', (e) => {
      if (e.target === $('edit-user-modal')) closeEditUserModal();
    });
  }

  if ($('edit-user-form')) {
    $('edit-user-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('edit-user-error');
      const userId = $('edit-user-id').value;
      const username = $('edit-user-username').value.trim();
      const magicLink = $('edit-user-magiclink').value.trim();
      const maxIps = parseInt($('edit-user-maxips').value) || 3;
      const enabled = $('edit-user-enabled').checked;

      if (!username) {
        showError('edit-user-error', 'Username cannot be empty.');
        return;
      }

      try {
        const res = await apiFetch(`/api/users/${userId}`, {
          method: 'PUT',
          body: JSON.stringify({ username, max_ips: maxIps, enabled, magic_link: magicLink }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('edit-user-error', data.error || 'Failed to update user.');
          return;
        }
        showToast(`User "${username}" updated successfully.`, 'success');
        closeEditUserModal();
        loadUsers();
      } catch {
        showError('edit-user-error', 'Error updating user.');
      }
    });
  }

  // Create user form submit handler
  if ($('add-user-form')) {
    $('add-user-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      clearMessages('add-user-error', 'add-user-success');

      const username = $('user-username').value.trim();
      const magicLink = $('user-magiclink') ? $('user-magiclink').value.trim() : '';
      const maxIps = parseInt($('user-maxips').value) || 3;

      if (!username) {
        showError('add-user-error', 'Username is required.');
        return;
      }

      try {
        const res = await apiFetch('/api/users', {
          method: 'POST',
          body: JSON.stringify({ username, max_ips: maxIps, magic_link: magicLink }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('add-user-error', data.error || 'Failed to create user.');
          return;
        }
        showSuccess('add-user-success', `User "${username}" created successfully.`);
        showToast(`User "${username}" created.`, 'success');
        $('user-username').value = '';
        if ($('user-magiclink')) $('user-magiclink').value = '';
        $('user-maxips').value = '3';
        loadUsers();
      } catch {
        showError('add-user-error', 'An error occurred while creating user.');
      }
    });
  }

  if ($('add-user-ip-form')) {
    $('add-user-ip-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!currentUserIPsUserId) return;
      clearMessages('add-user-ip-error', 'add-user-ip-success');

      const ipStr = $('manual-user-ip').value.trim();
      const btn = $('add-user-ip-btn');
      btn.disabled = true;

      try {
        const res = await apiFetch(`/api/users/${currentUserIPsUserId}/ips`, {
          method: 'POST',
          body: JSON.stringify({ ip: ipStr }),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          showError('add-user-ip-error', data.error || 'Failed to add IP address.');
          return;
        }
        showSuccess('add-user-ip-success', `IP ${ipStr} added successfully.`);
        $('manual-user-ip').value = '';
        loadUserIPs(currentUserIPsUserId, currentUserIPsUsername);
      } catch {
        showError('add-user-ip-error', 'An error occurred while registering IP.');
      } finally {
        btn.disabled = false;
      }
    });
  }

  if ($('close-user-ips')) {
    $('close-user-ips').addEventListener('click', () => {
      hideEl('user-ips-panel');
      currentUserIPsUserId = null;
      currentUserIPsUsername = null;
    });
  }

  if ($('edit-user-gen-token-btn')) {
    $('edit-user-gen-token-btn').addEventListener('click', () => {
      if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        $('edit-user-magiclink').value = crypto.randomUUID();
      } else {
        $('edit-user-magiclink').value = 'usr-' + Math.random().toString(36).substring(2, 12);
      }
    });
  }

  if ($('edit-user-maxips-presets')) {
    $('edit-user-maxips-presets').querySelectorAll('.preset-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        $('edit-user-maxips').value = btn.dataset.val;
      });
    });
  }
}

window.initUserListeners = initUserListeners;

async function toggleUser(userId, currentlyEnabled) {
  try {
    const res = await apiFetch(`/api/users/${userId}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: !currentlyEnabled }),
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Failed to update user.', 'error');
      return;
    }
    showToast(`User status updated to ${!currentlyEnabled ? 'Enabled' : 'Disabled'}.`, 'success');
    loadUsers();
  } catch {
    showToast('Network error while updating user.', 'error');
  }
}

async function deleteUser(userId, username) {
  const confirmed = await showConfirmDialog({
    title: 'Delete User Account',
    message: `Are you sure you want to delete user "${username}"? All registered IPs for this user will be removed.`,
    confirmText: 'Delete User',
    isDanger: true,
  });
  if (!confirmed) return;

  try {
    const res = await apiFetch(`/api/users/${userId}`, { method: 'DELETE' });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Delete failed.', 'error');
      return;
    }
    showToast(`User "${username}" deleted.`, 'success');
    loadUsers();
  } catch {
    showToast('Failed to delete user.', 'error');
  }
}

async function resetMagicLink(userId) {
  const confirmed = await showConfirmDialog({
    title: 'Reset Magic Link',
    message: 'Generate a new magic link? The previous link will stop working immediately.',
    confirmText: 'Reset Link',
    isDanger: true,
  });
  if (!confirmed) return;

  try {
    const res = await apiFetch(`/api/users/${userId}/magic-link/reset`, { method: 'POST' });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.error || 'Failed to reset magic link.', 'error');
      return;
    }
    showToast('Magic link regenerated successfully.', 'success');
    loadUsers();
  } catch {
    showToast('Failed to reset magic link.', 'error');
  }
}

// User IPs Panel
async function loadUserIPs(userId, username) {
  currentUserIPsUserId = userId;
  currentUserIPsUsername = username;
  $('user-ips-title').textContent = `IPs — ${username}`;
  showEl('user-ips-panel');
  clearMessages('add-user-ip-error', 'add-user-ip-success');

  try {
    const res = await apiFetch(`/api/users/${userId}/ips`);
    if (!res.ok) return;
    const data = await res.json();
    const ips = data.ips || [];
    const tbody = $('user-ips-tbody');
    tbody.innerHTML = '';

    if (ips.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No IPs registered yet.</td></tr>';
      return;
    }

    for (const ip of ips) {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="code-cell">${escapeHtml(ip.ip_address)}</td>
        <td><span class="text-hint">${escapeHtml(formatTimestamp(ip.created_at))}</span></td>
        <td><span class="text-hint">${escapeHtml(formatTimestamp(ip.last_used_at))}</span></td>
        <td class="text-right">
          <div class="action-btns-row" style="justify-content: flex-end;">
            <button type="button" class="btn-icon btn-icon-danger btn-delete-ip" data-ip="${escapeHtml(ip.ip_address)}" title="Delete IP">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          </div>
        </td>`;
      tbody.appendChild(tr);
    }

    tbody.querySelectorAll('.btn-delete-ip').forEach(btn => {
      btn.addEventListener('click', () => deleteUserIP(userId, btn.dataset.ip, username));
    });
  } catch { /* handled */ }
}

function closeAllActionDropdowns() {
  document.querySelectorAll('.action-dropdown-menu.show').forEach(m => {
    m.classList.remove('show');
    m.style.position = '';
    m.style.top = '';
    m.style.left = '';
  });
  document.querySelectorAll('.btn-action-trigger.active').forEach(b => b.classList.remove('active'));
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('.action-dropdown')) {
    closeAllActionDropdowns();
  }
});

window.addEventListener('scroll', closeAllActionDropdowns, true);
