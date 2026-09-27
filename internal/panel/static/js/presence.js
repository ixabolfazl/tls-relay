/* =========================================================================
   TLS Relay Admin Panel — presence.js
   Online presence monitoring, active IP mapping, last-seen timestamp updates.
   ========================================================================= */

"use strict";

function startPresencePolling() {
  stopPresencePolling();
  fetchPresence();
  presencePollInterval = setInterval(fetchPresence, 5000);
}

function stopPresencePolling() {
  if (presencePollInterval) {
    clearInterval(presencePollInterval);
    presencePollInterval = null;
  }
}

async function fetchPresence() {
  try {
    const res = await apiFetch('api/presence');
    if (!res.ok) return;
    const data = await res.json();
    allPresenceUsers = data.users || [];

    if ($('presence-online-count')) $('presence-online-count').textContent = data.total_online || 0;
    if ($('presence-offline-count')) $('presence-offline-count').textContent = data.total_offline || 0;
    if ($('presence-total-count')) $('presence-total-count').textContent = data.total_users || 0;
    if ($('presence-active-conns')) $('presence-active-conns').textContent = data.active_connections || 0;

    renderPresence();
    if (typeof renderUsers === 'function') renderUsers();
  } catch {
    // Ignore periodic polling errors
  }
}

function renderPresence() {
  const tbody = $('presence-tbody');
  if (!tbody) return;

  const searchInput = $('presence-search');
  const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

  const onlineOnly = allPresenceUsers.filter(u => u.status === 'Online');

  const filtered = onlineOnly.filter(u => {
    if (!query) return true;
    if (u.username && u.username.toLowerCase().includes(query)) return true;
    if (u.active_ips && u.active_ips.some(ip => ip.toLowerCase().includes(query))) return true;
    return false;
  });

  const empty = $('presence-empty');
  if (filtered.length === 0) {
    tbody.innerHTML = '';
    if (empty) {
      empty.textContent = 'No online users currently active.';
      empty.classList.remove('hidden');
    }
    return;
  }
  if (empty) empty.classList.add('hidden');

  tbody.innerHTML = filtered.map(u => {
    const statusBadge = `<span class="badge-status-online">Online</span>`;
    const activeIpsStr = (u.active_ips && u.active_ips.length > 0)
      ? u.active_ips.map(ip => `<code class="text-success" style="font-weight:600">${escapeHtml(ip)}</code>`).join(', ')
      : '<em style="color: var(--text-tertiary)">—</em>';
    const lastSeen = formatTimestamp(u.last_seen_at);
    const activeConns = u.active_connections ?? 0;

    return `
      <tr>
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td>${activeIpsStr}</td>
        <td>${activeConns}</td>
        <td>${statusBadge}</td>
        <td>${lastSeen}</td>
      </tr>
    `;
  }).join('');
}

function initPresenceListeners() {
  if ($('presence-search')) {
    $('presence-search').addEventListener('input', renderPresence);
  }
}

window.initPresenceListeners = initPresenceListeners;
