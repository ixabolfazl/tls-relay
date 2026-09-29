/**
 * Users view: account management, IP allowlists, magic links, and live presence monitoring.
 */

import { html, raw, setHtml, $, $$, escapeHtml } from '../core/dom.js';
import { api } from '../core/api.js';
import { formatBytes, formatDate, formatDateTime, formatRelativeTime, formatCount } from '../core/format.js';
import { Poller } from '../core/poller.js';
import { TableState } from '../ui/table.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { showMenu } from '../ui/menu.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { store } from '../core/store.js';
import { openUsageReportDialog } from './usage-report.js';
import { copyText } from '../core/clipboard.js';
import { renderPagination } from '../ui/pagination.js';

export function mount(container) {
  let isMounted = true;
  let activeFilter = 'all'; // 'all' | 'online'
  let activeRange = 'today';
  let allUsers = [];
  let presenceData = { users: [], total_online: 0, total_users: 0, active_connections: 0 };
  let searchQuery = '';

  const tableState = new TableState({
    pageSize: 50,
    sortKey: 'username',
    sortDir: 'asc',
    getId: (u) => u.id,
  });

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Header -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 class="text-2xl font-bold text-txt">Users & Access</h1>
            <p class="text-xs text-txt-muted mt-0.5">Manage user credentials, connection limits, and live presence</p>
          </div>
        </div>

        <!-- Create User Card -->
        <div class="card p-5">
          <form id="create-user-form" class="flex flex-col md:flex-row items-end gap-3.5">
            <div class="field flex-1 w-full">
              <label class="field-label" for="new-username">Username</label>
              <input
                id="new-username"
                type="text"
                class="input"
                placeholder="e.g. alice, work-laptop"
                required
                autocomplete="off"
              />
            </div>

            <div class="field flex-1 w-full">
              <label class="field-label" for="new-user-token">Token (Optional)</label>
              <input
                id="new-user-token"
                type="text"
                class="input font-mono text-xs"
                placeholder="Leave empty to auto-generate"
                autocomplete="off"
              />
            </div>

            <div class="field w-full md:w-36">
              <label class="field-label" for="new-user-max-ips">Max IPs</label>
              <input
                id="new-user-max-ips"
                type="number"
                class="input tabular-nums"
                min="0"
                max="1000"
                value="${store.getState().settings?.default_max_ips ?? 3}"
                placeholder="0 = unlimited"
              />
            </div>

            <button id="create-user-submit-btn" type="submit" class="btn btn-primary w-full md:w-auto shrink-0">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
              <span>Create User</span>
            </button>
          </form>
        </div>

        <!-- Accounts Table Card -->
        <div class="card">
          <div class="p-4 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div class="flex items-center gap-3 overflow-x-auto pb-1 md:pb-0">
              <div id="users-filter-segmented"></div>
              <div id="users-range-segmented"></div>
            </div>
            <div class="relative w-full sm:w-64">
              <input
                id="users-search-input"
                type="text"
                class="input pl-8 text-sm"
                placeholder="Search users or tokens..."
              />
              <svg class="w-4 h-4 absolute left-2.5 top-1/2 -translate-y-1/2 text-txt-subtle pointer-events-none" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
            </div>
          </div>

          <div class="overflow-x-auto">
            <table class="table">
              <thead>
                <tr>
                  <th class="table-th w-8"></th>
                  <th class="table-th cursor-pointer select-none" data-sort="username">
                    <div class="flex items-center gap-1.5">
                      <span>User</span>
                      <span id="sort-icon-username" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th">Status</th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="conns">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Active Conns</span>
                      <span id="sort-icon-conns" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th">Active IPs</th>
                  <th class="table-th cursor-pointer select-none text-center" data-sort="ip_count">
                    <div class="flex items-center justify-center gap-1.5">
                      <span>Reg IPs</span>
                      <span id="sort-icon-ip_count" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none" data-sort="last_seen_at">
                    <div class="flex items-center gap-1.5">
                      <span>Last Seen</span>
                      <span id="sort-icon-last_seen_at" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="sent">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Sent</span>
                      <span id="sort-icon-sent" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="received">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Received</span>
                      <span id="sort-icon-received" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="usage">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>Total</span>
                      <span id="sort-icon-usage" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th cursor-pointer select-none text-right" data-sort="queries">
                    <div class="flex items-center justify-end gap-1.5">
                      <span>DNS Queries</span>
                      <span id="sort-icon-queries" class="text-txt-subtle text-xs">↕</span>
                    </div>
                  </th>
                  <th class="table-th">Token</th>
                  <th class="table-th w-16 text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="users-table-body">
                <tr>
                  <td colspan="13" class="table-td text-center py-12 text-txt-subtle">
                    <div class="flex flex-col items-center justify-center gap-2">
                      <div class="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
                      <span>Loading user accounts...</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div id="users-pagination" class="card-footer"></div>
        </div>
      </div>
    `
  );

  // Search input
  $('#users-search-input', container).addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    tableState.currentPage = 1;
    renderAccountsTable();
  });

  // Create User
  $('#create-user-form', container).addEventListener('submit', async (e) => {
    e.preventDefault();
    const usernameInput = $('#new-username', container);
    const tokenInput = $('#new-user-token', container);
    const maxIpsInput = $('#new-user-max-ips', container);
    const submitBtn = $('#create-user-submit-btn', container);

    const username = usernameInput.value.trim();
    if (!username) return;

    const defaultMaxIPs = store.getState().settings?.default_max_ips ?? 3;
    const rawMaxIPs = maxIpsInput.value.trim();
    const maxIpsVal = rawMaxIPs === '' ? defaultMaxIPs : parseInt(rawMaxIPs, 10);
    if (isNaN(maxIpsVal) || maxIpsVal < 0 || maxIpsVal > 1000) {
      toast.warning('Max IPs must be between 0 (unlimited) and 1000');
      maxIpsInput.focus();
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating...';

    try {
      await api.createUser({
        username,
        magic_link: tokenInput.value.trim() || undefined,
        max_ips: maxIpsVal,
      });

      toast.success(`User "${username}" created successfully`);
      usernameInput.value = '';
      tokenInput.value = '';
      maxIpsInput.value = String(defaultMaxIPs);

      await fetchUsers();
    } catch (err) {
      toast.error(err.message || 'Failed to create user');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create User';
    }
  });

  function getPresenceForUser(u) {
    if (!presenceData?.users) return null;
    return (
      presenceData.users.find((p) => p.user_id && p.user_id === u.id) ||
      presenceData.users.find((p) => p.username && p.username.toLowerCase() === u.username.toLowerCase()) ||
      null
    );
  }

  function getOnlineUserCount() {
    const onlineSet = new Set(
      (presenceData.users || [])
        .filter((p) => p.status === 'Online')
        .map((p) => (p.user_id ? String(p.user_id) : p.username.toLowerCase()))
    );
    return allUsers.filter((u) => onlineSet.has(String(u.id)) || onlineSet.has(u.username.toLowerCase())).length;
  }

  let filterSegObj = null;
  function initUsersFilterSegmented() {
    const el = $('#users-filter-segmented', container);
    if (!el) return;
    const onlineCount = getOnlineUserCount();
    const options = [
      { value: 'all', label: 'All', count: allUsers.length },
      { value: 'online', label: 'Online', count: onlineCount },
    ];
    if (!filterSegObj) {
      filterSegObj = createSegmentedControl({
        options,
        value: activeFilter,
        size: 'sm',
        onChange: (val) => {
          activeFilter = val;
          tableState.currentPage = 1;
          renderAccountsTable();
        },
      });
      el.appendChild(filterSegObj.el);
    } else {
      filterSegObj.updateOptions(options);
    }
  }

  // Fetch all users
  async function fetchUsers() {
    if (!isMounted) return;
    try {
      const [usersRes, presRes] = await Promise.all([api.getUsers(activeRange), api.getPresence()]);
      if (!isMounted) return;
      allUsers = usersRes.users || [];
      presenceData = presRes || { users: [], total_online: 0, total_users: 0, active_connections: 0 };

      initUsersFilterSegmented();
      initUsersRangeSegmented();
      renderAccountsTable();
      presencePoller.start();
    } catch (err) {
      if (!isMounted) return;
      $('#users-table-body', container).innerHTML = `
        <tr>
          <td colspan="13" class="table-td text-center py-8 text-danger">
            Failed to load users: ${escapeHtml(err.message)}
          </td>
        </tr>
      `;
    }
  }

  // Generate Magic Link URL helper
  function getMagicLinkUrl(token) {
    const settings = store.getState().settings;
    let base = window.location.origin;

    if (settings?.serverDomain || settings?.server_domain) {
      let d = (settings.serverDomain || settings.server_domain).trim();
      d = d.replace(/^https?:\/\//, '').replace(/\/+$/, '');
      if (d) {
        base = `http://${d}`;
      }
    }

    return `${base}/connect/${token}`;
  }

  // Render Accounts Table
  function renderAccountsTable() {
    const tbody = $('#users-table-body', container);

    let filtered = allUsers;
    if (activeFilter === 'online') {
      filtered = filtered.filter((u) => {
        const p = getPresenceForUser(u);
        return p && p.status === 'Online';
      });
    }

    if (searchQuery) {
      filtered = filtered.filter(
        (u) =>
          u.username.toLowerCase().includes(searchQuery) ||
          (u.magic_link && u.magic_link.toLowerCase().includes(searchQuery))
      );
    }

    const customComparators = {
      username: (a, b) => a.username.localeCompare(b.username),
      conns: (a, b) => {
        const cA = getPresenceForUser(a)?.active_connections || 0;
        const cB = getPresenceForUser(b)?.active_connections || 0;
        return cA - cB;
      },
      ip_count: (a, b) => (a.ip_count || 0) - (b.ip_count || 0),
      usage: (a, b) => {
        const uA = (a.total_bytes_sent || 0) + (a.total_bytes_received || 0);
        const uB = (b.total_bytes_sent || 0) + (b.total_bytes_received || 0);
        return uA - uB;
      },
      sent: (a, b) => (a.total_bytes_sent || 0) - (b.total_bytes_sent || 0),
      received: (a, b) => (a.total_bytes_received || 0) - (b.total_bytes_received || 0),
      queries: (a, b) => (a.total_dns_queries || 0) - (b.total_dns_queries || 0),
      last_seen_at: (a, b) => {
        const tA = a.last_seen_at ? new Date(a.last_seen_at).getTime() : 0;
        const tB = b.last_seen_at ? new Date(b.last_seen_at).getTime() : 0;
        return tA - tB;
      },
    };

    const sorted = tableState.getSortedItems(filtered, customComparators);
    updateSortIcons();

    if (sorted.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="13" class="table-td text-center py-12 text-txt-subtle italic">
            ${searchQuery ? 'No users matching your search' : activeFilter === 'online' ? 'No users currently online' : 'No user accounts created yet'}
          </td>
        </tr>
      `;
      renderPagination($('#users-pagination', container), {
        currentPage: 1,
        totalPages: 1,
        totalItems: 0,
        pageSize: tableState.pageSize,
        onPageChange: () => {},
      });
      return;
    }

    const sliceInfo = tableState.getPageSlice(sorted);
    tbody.innerHTML = '';

    for (const u of sliceInfo.slice) {
      const p = getPresenceForUser(u);
      const isOnline = p && p.status === 'Online';
      const activeConns = p?.active_connections || 0;
      const activeIpsList = Array.isArray(p?.active_ips) ? p.active_ips : [];
      const activeIpsDisplay = activeIpsList.length > 0 ? activeIpsList.join(', ') : '—';
      const totalBandwidth = (u.total_bytes_sent || 0) + (u.total_bytes_received || 0);
      const isEnabled = u.enabled !== false;
      const defaultMaxIPs = store.getState().settings?.default_max_ips ?? 3;
      const maxIps = u.max_ips !== undefined ? u.max_ips : defaultMaxIPs;
      const ipCount = u.ip_count ?? 0;
      const maxIpsStr = maxIps === 0 ? '∞' : String(maxIps);
      const regIpsDisplay = `${ipCount} / ${maxIpsStr}`;

      const row = document.createElement('tr');
      row.className = 'table-row';
      row.dataset.userId = u.id;

      const tokenTruncated = u.magic_link
        ? `${u.magic_link.slice(0, 6)}...${u.magic_link.slice(-4)}`
        : '—';

      row.innerHTML = `
        <td class="table-td w-8 text-center">
          <span class="user-online-dot inline-block w-2.5 h-2.5 rounded-full ${
            isOnline ? 'bg-emerald-500 ring-2 ring-emerald-500/20' : 'bg-slate-300 dark:bg-slate-600'
          }" title="${isOnline ? 'Online' : 'Offline'}"></span>
        </td>
        <td class="table-td font-medium text-txt">
          <span>${escapeHtml(u.username)}</span>
        </td>
        <td class="table-td text-xs">
          ${
            isEnabled
              ? `<span class="badge badge-success text-[11px]">Active</span>`
              : `<span class="badge badge-danger text-[11px]">Disabled</span>`
          }
        </td>
        <td class="table-td text-right font-mono text-xs tabular-nums text-txt font-semibold">
          <span class="user-active-conns">${formatCount(activeConns)}</span>
        </td>
        <td class="table-td font-mono text-xs text-primary-600 dark:text-primary-400 max-w-[140px] truncate" title="${escapeHtml(activeIpsDisplay)}">
          <span class="user-active-ips">${escapeHtml(activeIpsDisplay)}</span>
        </td>
        <td class="table-td text-center font-mono text-xs tabular-nums text-txt-muted">
          <button type="button" class="user-ips-btn hover:text-txt underline decoration-dotted" title="View/edit registered IPs">
            ${escapeHtml(regIpsDisplay)}
          </button>
        </td>
        <td class="table-td text-xs text-txt-muted tabular-nums">
          ${formatRelativeTime(u.last_seen_at)}
        </td>
        <td class="table-td text-right font-mono text-xs tabular-nums text-txt-muted">
          ${(u.total_bytes_sent || 0) > 0 ? formatBytes(u.total_bytes_sent) : '<span class="text-txt-subtle">0 B</span>'}
        </td>
        <td class="table-td text-right font-mono text-xs tabular-nums text-txt-muted">
          ${(u.total_bytes_received || 0) > 0 ? formatBytes(u.total_bytes_received) : '<span class="text-txt-subtle">0 B</span>'}
        </td>
        <td class="table-td text-right text-xs font-mono tabular-nums text-txt font-semibold">
          ${totalBandwidth > 0 ? formatBytes(totalBandwidth) : '<span class="text-txt-subtle">0 B</span>'}
        </td>
        <td class="table-td text-right font-mono text-xs tabular-nums text-txt-muted">
          ${(u.total_dns_queries || 0) > 0 ? formatCount(u.total_dns_queries) : '<span class="text-txt-subtle">0</span>'}
        </td>
        <td class="table-td font-mono text-xs text-txt-muted">
          <div class="flex items-center gap-1.5">
            <span>${escapeHtml(tokenTruncated)}</span>
            ${
              u.magic_link
                ? `<button type="button" class="copy-token-btn btn-icon-sm -my-1 text-txt-subtle hover:text-txt" title="Copy token">
                     <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                   </button>`
                : ''
            }
          </div>
        </td>
        <td class="table-td text-right">
          <button type="button" class="user-menu-btn btn-icon-sm text-txt-muted hover:text-txt" aria-label="User actions">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z"/></svg>
          </button>
        </td>
      `;

      // Click registered IPs button
      const ipsBtn = row.querySelector('.user-ips-btn');
      if (ipsBtn) {
        ipsBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          openUserIPsDialog(u);
        });
      }

      // Copy token/URL inline
      const copyTokenBtn = row.querySelector('.copy-token-btn');
      if (copyTokenBtn) {
        copyTokenBtn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const link = getMagicLinkUrl(u.magic_link);
          const ok = await copyText(link);
          if (ok) {
            toast.success('Connection link copied to clipboard');
            const originalHTML = copyTokenBtn.innerHTML;
            copyTokenBtn.innerHTML = `<svg class="w-3.5 h-3.5 text-emerald-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>`;
            setTimeout(() => {
              copyTokenBtn.innerHTML = originalHTML;
            }, 1500);
          } else {
            toast.error(`Failed to copy link automatically. Link: ${link}`, { duration: 8000 });
          }
        });
      }

      // Actions Menu
      const menuBtn = row.querySelector('.user-menu-btn');
      menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const menuItems = [
          {
            text: 'Edit User',
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>`,
            onClick: () => openEditUserDialog(u),
          },
          {
            text: 'Registered IPs',
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/></svg>`,
            onClick: () => openUserIPsDialog(u),
          },
          {
            text: 'Usage Analytics',
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
            onClick: () => openUsageReportDialog({ kind: 'user', id: u.id, name: u.username, onReset: fetchUsers }),
          },
          {
            text: 'Copy Magic Link',
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>`,
            onClick: async () => {
              if (u.magic_link) {
                const link = getMagicLinkUrl(u.magic_link);
                const ok = await copyText(link);
                if (ok) {
                  toast.success('Magic link copied to clipboard');
                } else {
                  toast.error(`Failed to copy link automatically. Link: ${link}`, { duration: 8000 });
                }
              } else {
                toast.error('User has no magic token configured');
              }
            },
          },
          {
            text: 'Reset Token',
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>`,
            onClick: () => resetUserToken(u),
          },
          {
            text: isEnabled ? 'Disable User' : 'Enable User',
            icon: isEnabled
              ? `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>`
              : `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
            onClick: () => toggleUserEnabled(u),
          },
          { divider: true },
          {
            text: 'Delete User',
            danger: true,
            icon: `<svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>`,
            onClick: () => deleteUser(u),
          },
        ];

        showMenu(menuBtn, menuItems);
      });

      tbody.appendChild(row);
    }

    renderPagination($('#users-pagination', container), {
      currentPage: sliceInfo.currentPage,
      totalPages: sliceInfo.totalPages,
      totalItems: sliceInfo.total,
      pageSize: tableState.pageSize,
      onPageChange: (newPage) => {
        tableState.setPage(newPage);
        renderAccountsTable();
      },
    });
  }

  // Edit User Dialog
  function openEditUserDialog(u) {
    const content = document.createElement('form');
    content.className = 'flex flex-col gap-4';
    content.innerHTML = `
      <div class="field">
        <label class="field-label" for="edit-username">Username</label>
        <input id="edit-username" type="text" class="input" value="${escapeHtml(u.username)}" required />
      </div>

      <div class="field">
        <div class="flex items-center justify-between">
          <label class="field-label" for="edit-token">Token</label>
          <button id="edit-generate-token-btn" type="button" class="text-xs text-primary-600 hover:underline font-medium">Generate Random</button>
        </div>
        <input id="edit-token" type="text" class="input font-mono text-xs" value="${escapeHtml(u.magic_link || '')}" />
      </div>

      <div class="field">
        <label class="field-label" for="edit-max-ips">Max Simultaneous IPs</label>
        <input id="edit-max-ips" type="number" class="input tabular-nums" min="0" max="1000" value="${u.max_ips !== undefined ? u.max_ips : 3}" />
        <span class="field-hint">0 = Unlimited IPs allowed (max 1000)</span>
      </div>

      <div class="flex items-center gap-3 p-3 rounded-xl border border-border bg-surface-2/60">
        <input id="edit-enabled-switch" type="checkbox" class="checkbox shrink-0" ${u.enabled !== false ? 'checked' : ''} />
        <label for="edit-enabled-switch" class="flex flex-col cursor-pointer select-none">
          <span class="text-sm font-medium text-txt">Account Enabled</span>
          <span class="text-xs text-txt-subtle">Disabled accounts cannot route traffic or resolve DNS</span>
        </label>
      </div>
    `;

    content.querySelector('#edit-generate-token-btn').addEventListener('click', () => {
      const arr = new Uint8Array(16);
      window.crypto.getRandomValues(arr);
      content.querySelector('#edit-token').value = Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
    });

    dialog.open({
      title: `Edit User: ${u.username}`,
      content,
      size: 'md',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Save Changes',
          primary: true,
          onClick: async (_, { close }) => {
            const newUsername = content.querySelector('#edit-username').value.trim();
            const newToken = content.querySelector('#edit-token').value.trim();
            const rawMaxIps = content.querySelector('#edit-max-ips').value.trim();
            const newMaxIps = rawMaxIps === '' ? (u.max_ips ?? 3) : parseInt(rawMaxIps, 10);
            const newEnabled = content.querySelector('#edit-enabled-switch').checked;

            if (isNaN(newMaxIps) || newMaxIps < 0 || newMaxIps > 1000) {
              toast.warning('Max IPs must be between 0 (unlimited) and 1000');
              return;
            }

            try {
              await api.updateUser(u.id, {
                username: newUsername,
                magic_link: newToken || undefined,
                max_ips: newMaxIps,
                enabled: newEnabled,
              });
              toast.success(`User updated successfully`);
              close();
              await fetchUsers();
            } catch (err) {
              toast.error(err.message || 'Failed to update user');
            }
          },
        },
      ],
    });
  }

  // User Registered IPs Dialog (Fixes B1 & B14)
  async function openUserIPsDialog(u) {
    const content = document.createElement('div');
    content.className = 'space-y-4';
    content.innerHTML = `
      <form id="add-ip-form" class="flex items-center gap-2">
        <input
          id="new-ip-input"
          type="text"
          class="input font-mono text-xs flex-1"
          placeholder="Enter IPv4 or IPv6 (e.g. 1.2.3.4 or 2001:db8::1)"
          required
        />
        <button type="submit" class="btn btn-primary btn-sm shrink-0">Add IP</button>
      </form>

      <div class="border border-border rounded-xl overflow-hidden">
        <table class="table text-xs">
          <thead>
            <tr>
              <th class="table-th py-2">IP Address</th>
              <th class="table-th py-2">Registered</th>
              <th class="table-th py-2">Last Used</th>
              <th class="table-th py-2 w-12 text-right"></th>
            </tr>
          </thead>
          <tbody id="user-ips-table-body">
            <tr>
              <td colspan="4" class="table-td text-center py-6 text-txt-subtle italic">Loading IPs...</td>
            </tr>
          </tbody>
        </table>
      </div>
    `;

    async function loadIPs() {
      const tbody = content.querySelector('#user-ips-table-body');
      try {
        const res = await api.getUserIPs(u.id);
        const ips = res.ips || [];

        if (ips.length === 0) {
          tbody.innerHTML = `
            <tr>
              <td colspan="4" class="table-td text-center py-6 text-txt-subtle italic">No IPs registered for this user</td>
            </tr>
          `;
          return;
        }

        tbody.innerHTML = '';
        for (const ipObj of ips) {
          const row = document.createElement('tr');
          row.className = 'table-row';
          row.innerHTML = `
            <td class="table-td font-mono font-medium">${escapeHtml(ipObj.ip_address)}</td>
            <td class="table-td text-txt-muted">${formatDate(ipObj.created_at)}</td>
            <td class="table-td text-txt-muted">${formatRelativeTime(ipObj.last_used_at)}</td>
            <td class="table-td text-right">
              <button type="button" class="del-ip-btn btn-icon-sm text-danger hover:bg-danger-soft" title="Remove IP">
                <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
              </button>
            </td>
          `;

          // Delete IP handler
          row.querySelector('.del-ip-btn').addEventListener('click', async () => {
            try {
              await api.deleteUserIP(u.id, ipObj.ip_address);
              toast.success(`Removed IP ${ipObj.ip_address}`);
              await loadIPs();
              await fetchUsers();
            } catch (err) {
              toast.error(err.message || 'Failed to remove IP');
            }
          });

          tbody.appendChild(row);
        }
      } catch (err) {
        tbody.innerHTML = `
          <tr>
            <td colspan="4" class="table-td text-center py-4 text-danger">${escapeHtml(err.message)}</td>
          </tr>
        `;
      }
    }

    content.querySelector('#add-ip-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const ipInput = content.querySelector('#new-ip-input');
      const ip = ipInput.value.trim();
      if (!ip) return;

      try {
        await api.addUserIP(u.id, ip);
        toast.success(`Added IP ${ip}`);
        ipInput.value = '';
        await loadIPs();
        await fetchUsers();
      } catch (err) {
        toast.error(err.message || 'Failed to add IP');
      }
    });

    dialog.open({
      title: `Registered IPs for ${u.username}`,
      content,
      size: 'lg',
      actions: [{ text: 'Close', className: 'btn btn-secondary', value: true }],
    });

    loadIPs();
  }

  // Reset Token
  async function resetUserToken(u) {
    const content = document.createElement('div');
    content.className = 'flex flex-col gap-4 text-sm text-txt-muted leading-relaxed';
    content.innerHTML = `
      <p>
        Resetting the token generates a new access token. This only blocks <strong>new registrations</strong> with the old token; already-registered IPs will keep access.
      </p>
      <div class="flex items-center gap-3 p-3 rounded-xl border border-danger/30 bg-danger/5">
        <input id="reset-clear-ips-checkbox" type="checkbox" class="checkbox shrink-0" />
        <label for="reset-clear-ips-checkbox" class="flex flex-col cursor-pointer select-none">
          <span class="text-sm font-medium text-txt">Also remove all registered IPs (revokes current access)</span>
          <span class="text-xs text-txt-subtle">Immediately revokes access and disconnects active connections for this user</span>
        </label>
      </div>
    `;

    dialog.open({
      title: `Reset Token: ${u.username}`,
      content,
      size: 'sm',
      actions: [
        { text: 'Cancel', className: 'btn btn-secondary', value: false },
        {
          text: 'Reset Token',
          className: 'btn btn-danger',
          primary: true,
          onClick: async (_, { close }) => {
            const clearIps = content.querySelector('#reset-clear-ips-checkbox').checked;
            try {
              const res = await api.resetMagicLink(u.id, { clear_ips: clearIps });
              if (clearIps) {
                toast.success(`Token reset and ${res.cleared_ips ?? 0} registered IPs removed`);
              } else {
                toast.success('Token has been reset');
              }
              close();
              await fetchUsers();
            } catch (err) {
              toast.error(err.message || 'Failed to reset token');
            }
          },
        },
      ],
    });
  }

  // Toggle User Enabled
  async function toggleUserEnabled(u) {
    const nextState = u.enabled === false;
    try {
      await api.updateUser(u.id, { enabled: nextState });
      toast.success(`User ${u.username} ${nextState ? 'enabled' : 'disabled'}`);
      await fetchUsers();
    } catch (err) {
      toast.error(err.message || 'Failed to update user status');
    }
  }

  // Delete User
  async function deleteUser(u) {
    const confirmed = await dialog.confirm({
      title: `Delete User: ${u.username}`,
      message: `Are you sure you want to permanently delete user "${u.username}" and all registered IPs?`,
      confirmText: 'Delete User',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await api.deleteUser(u.id);
      toast.success(`User ${u.username} deleted`);
      await fetchUsers();
    } catch (err) {
      toast.error(err.message || 'Failed to delete user');
    }
  }

  // In-place presence poller (fixes F13, preserves DOM state)
  async function pollPresence() {
    if (!isMounted) return;
    try {
      const pres = await api.getPresence();
      if (!isMounted) return;
      presenceData = pres;

      // Update filter counts
      if (filterSegObj) {
        filterSegObj.updateOptions([
          { value: 'all', label: 'All', count: allUsers.length },
          { value: 'online', label: 'Online', count: getOnlineUserCount() },
        ]);
      }

      // In-place patch rendered table rows without rebuilding table or losing state
      $$('#users-table-body tr[data-user-id]', container).forEach((row) => {
        const uId = row.dataset.userId;
        const u = allUsers.find((x) => String(x.id) === String(uId));
        if (!u) return;

        const p = getPresenceForUser(u);
        const isOnline = p && p.status === 'Online';
        const activeConns = p?.active_connections || 0;
        const activeIpsList = Array.isArray(p?.active_ips) ? p.active_ips : [];
        const activeIpsDisplay = activeIpsList.length > 0 ? activeIpsList.join(', ') : '—';

        const dot = row.querySelector('.user-online-dot');
        if (dot) {
          dot.className = `user-online-dot inline-block w-2.5 h-2.5 rounded-full ${
            isOnline ? 'bg-emerald-500 ring-2 ring-emerald-500/20' : 'bg-slate-300 dark:bg-slate-600'
          }`;
          dot.title = isOnline ? 'Online' : 'Offline';
        }

        const connsEl = row.querySelector('.user-active-conns');
        if (connsEl) {
          connsEl.textContent = formatCount(activeConns);
        }

        const ipsEl = row.querySelector('.user-active-ips');
        if (ipsEl) {
          ipsEl.textContent = activeIpsDisplay;
          const cell = ipsEl.closest('td');
          if (cell) cell.title = activeIpsDisplay;
        }
      });
    } catch (err) {
      console.warn('Presence poll error:', err);
    }
  }

  const presencePoller = new Poller(pollPresence, 5000, { immediate: false });

  // Sorting
  $$('[data-sort]', container).forEach((th) => {
    th.addEventListener('click', () => {
      tableState.setSort(th.dataset.sort);
      renderAccountsTable();
    });
  });

  let usersRangeSegObj = null;
  function initUsersRangeSegmented() {
    const el = $('#users-range-segmented', container);
    if (!el || usersRangeSegObj) return;
    usersRangeSegObj = createSegmentedControl({
      options: [
        { value: 'today', label: 'Today' },
        { value: '7d', label: '7d' },
        { value: '30d', label: '30d' },
        { value: 'monthly', label: 'Monthly' },
        { value: 'all', label: 'All' },
      ],
      value: activeRange,
      size: 'sm',
      onChange: (val) => {
        activeRange = val;
        fetchUsers();
      },
    });
    el.appendChild(usersRangeSegObj.el);
  }

  function updateSortIcons() {
    ['username', 'conns', 'ip_count', 'last_seen_at', 'sent', 'received', 'usage', 'queries'].forEach((k) => {
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
  fetchUsers();

  return {
    unmount: () => {
      isMounted = false;
      presencePoller.stop();
      container.innerHTML = '';
    },
  };
}
