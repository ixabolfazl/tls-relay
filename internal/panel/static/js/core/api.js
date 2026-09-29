/**
 * API client with relative URL resolution, CSRF handling, and error wrapping.
 */

export class ApiError extends Error {
  constructor(status, message, data = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Resolves an API path relative to current panel path.
 * Guaranteed to never start with absolute '/' so panel prefixes (/admin, /custom) work seamlessly.
 */
export function getApiUrl(path) {
  let clean = path.replace(/^\/+/, '');
  let base = window.location.pathname;
  if (base.endsWith('/index.html')) {
    base = base.slice(0, -10);
  }
  if (!base.endsWith('/')) {
    base += '/';
  }
  return base + clean;
}

export function getCsrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)relay_csrf=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : '';
}

export async function apiFetch(path, options = {}) {
  const url = getApiUrl(path);
  const method = (options.method || 'GET').toUpperCase();

  const headers = new Headers();
  headers.set('Accept', 'application/json');

  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  // Set CSRF token on mutating requests (except login)
  if (method !== 'GET' && method !== 'HEAD' && !path.includes('login')) {
    const csrf = getCsrfToken();
    if (csrf) {
      headers.set('X-CSRF-Token', csrf);
    }
  }

  // Merge user provided headers safely (B12 fix)
  if (options.headers) {
    const customHeaders = new Headers(options.headers);
    for (const [key, value] of customHeaders.entries()) {
      headers.set(key, value);
    }
  }

  const fetchOptions = {
    ...options,
    method,
    headers,
    credentials: 'include',
  };

  let res;
  try {
    res = await fetch(url, fetchOptions);
  } catch (networkErr) {
    throw new ApiError(0, 'Network request failed: ' + networkErr.message);
  }

  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('auth:required'));
    throw new ApiError(401, 'Unauthorized');
  }

  let data = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  } else {
    const text = await res.text();
    data = { message: text };
  }

  if (!res.ok) {
    const errorMsg = data?.error || data?.message || `Request failed with status ${res.status}`;
    throw new ApiError(res.status, errorMsg, data);
  }

  return data;
}

// Concrete API helper methods
export const api = {
  // Auth
  login: (credentials) => apiFetch('api/login', { method: 'POST', body: JSON.stringify(credentials) }),
  logout: () => apiFetch('api/logout', { method: 'POST' }),

  // Stats & Dashboard
  getStats: (range = 'today') => apiFetch(`api/stats?range=${encodeURIComponent(range)}`),
  getRequestStatsDaily: (type, range = 'today') =>
    apiFetch(`api/request-stats/daily?type=${encodeURIComponent(type)}&range=${encodeURIComponent(range)}`),

  // Domains
  getDomains: (range = '') =>
    apiFetch(range ? `api/domains?range=${encodeURIComponent(range)}` : 'api/domains'),
  addDomain: (payload) => apiFetch('api/domains', { method: 'POST', body: JSON.stringify(payload) }),
  updateDomain: (domain, payload) =>
    apiFetch(`api/domains/${encodeURIComponent(domain)}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteDomain: (domain) =>
    apiFetch(`api/domains/${encodeURIComponent(domain)}`, { method: 'DELETE' }),
  bulkDeleteDomains: (domains) =>
    apiFetch('api/domains/bulk-delete', { method: 'POST', body: JSON.stringify({ domains }) }),
  bulkAssignGroup: (domains, group_name) =>
    apiFetch('api/domains/bulk-assign-group', { method: 'POST', body: JSON.stringify({ domains, group_name }) }),
  bulkAssignEgress: (domains, use_egress_proxy) =>
    apiFetch('api/domains/bulk-assign-egress', {
      method: 'POST',
      body: JSON.stringify({ domains, use_egress_proxy: String(use_egress_proxy) }),
    }),
  bulkAssignMode: (domains, mode) =>
    apiFetch('api/domains/bulk-assign-mode', { method: 'POST', body: JSON.stringify({ domains, mode }) }),
  getDomainUsage: (domain, days = 30) =>
    apiFetch(`api/domains/${encodeURIComponent(domain)}/usage?days=${encodeURIComponent(days)}`),
  getDomainUsageMonthly: (domain, months = 12) =>
    apiFetch(`api/domains/${encodeURIComponent(domain)}/usage/monthly?months=${encodeURIComponent(months)}`),
  getDomainUsageUsers: (domain, range = 'today') =>
    apiFetch(`api/domains/${encodeURIComponent(domain)}/usage/users?range=${encodeURIComponent(range)}`),

  // Blacklist
  getBlacklist: () => apiFetch('api/blacklist'),
  addBlacklist: (payload) =>
    apiFetch('api/blacklist', {
      method: 'POST',
      body: JSON.stringify(typeof payload === 'string' ? { entry: payload } : payload),
    }),
  deleteBlacklist: (id) => apiFetch(`api/blacklist/${id}`, { method: 'DELETE' }),
  bulkDeleteBlacklist: (ids) =>
    apiFetch('api/blacklist/bulk-delete', { method: 'POST', body: JSON.stringify({ ids }) }),

  // Users
  getUsers: (range = '') =>
    apiFetch(range ? `api/users?range=${encodeURIComponent(range)}` : 'api/users'),
  createUser: (payload) => apiFetch('api/users', { method: 'POST', body: JSON.stringify(payload) }),
  updateUser: (id, payload) =>
    apiFetch(`api/users/${id}`, { method: 'PUT', body: JSON.stringify(payload) }),
  deleteUser: (id) => apiFetch(`api/users/${id}`, { method: 'DELETE' }),
  getUserIPs: (id) => apiFetch(`api/users/${id}/ips`),
  addUserIP: (id, ip) =>
    apiFetch(`api/users/${id}/ips`, { method: 'POST', body: JSON.stringify({ ip }) }),
  deleteUserIP: (id, ip) =>
    apiFetch(`api/users/${id}/ips/${encodeURIComponent(ip)}`, { method: 'DELETE' }), // B1/B14 fix
  resetMagicLink: (id, payload) =>
    apiFetch(`api/users/${id}/magic-link/reset`, {
      method: 'POST',
      body: payload ? JSON.stringify(payload) : undefined,
    }),
  getUserUsage: (id, range = 'today') =>
    apiFetch(`api/users/${id}/usage?range=${encodeURIComponent(range)}`),
  resetUserUsage: (id) => apiFetch(`api/users/${id}/usage/reset`, { method: 'POST' }),
  getUserUsageDomains: (id, range = 'today') =>
    apiFetch(`api/users/${id}/usage/domains?range=${encodeURIComponent(range)}`),

  // Presence
  getPresence: () => apiFetch('api/presence'),

  // Logs
  getRequestLogs: (params = {}) => {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') {
        q.set(k, v);
      }
    }
    const qs = q.toString();
    return apiFetch(qs ? `api/request-logs?${qs}` : 'api/request-logs');
  },
  clearRequestLogs: () => apiFetch('api/request-logs/clear', { method: 'POST' }),

  // Settings
  getSettings: () => apiFetch('api/settings'),
  updateSettings: (payload) =>
    apiFetch('api/settings', { method: 'PUT', body: JSON.stringify(payload) }),
  testProxy: (payload = {}) =>
    apiFetch('api/settings/test-proxy', { method: 'POST', body: JSON.stringify(payload) }),
  updateAdminCredentials: (payload) =>
    apiFetch('api/admin/credentials', { method: 'PUT', body: JSON.stringify(payload) }),
  serviceRestart: () => apiFetch('api/service/restart', { method: 'POST' }),
  importData: (jsonData) => apiFetch('api/import', { method: 'POST', body: JSON.stringify(jsonData) }),
};
