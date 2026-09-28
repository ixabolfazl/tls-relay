/**
 * Hash-based single page application client router.
 */

import { $, $$ } from './dom.js';
import { store } from './store.js';

const ROUTES = {
  dashboard: () => import('../views/dashboard.js'),
  domains: () => import('../views/domains.js'),
  users: () => import('../views/users.js'),
  blacklist: () => import('../views/blacklist.js'),
  'request-logs': () => import('../views/logs.js'),
  logs: () => import('../views/logs.js'),
  usage: () => import('../views/usage.js'),
  settings: () => import('../views/settings.js'),
};

let currentViewInstance = null;
let currentRouteName = null;

export async function navigate(routeName, replace = false) {
  let cleanRoute = (routeName || 'dashboard').replace(/^#\/?/, '').trim();
  if (cleanRoute === 'logs') cleanRoute = 'request-logs';
  if (!ROUTES[cleanRoute]) cleanRoute = 'dashboard';

  if (replace) {
    window.location.replace(`#${cleanRoute}`);
  } else if (window.location.hash !== `#${cleanRoute}`) {
    window.location.hash = cleanRoute;
  }

  if (currentRouteName === cleanRoute && currentViewInstance) {
    return;
  }

  // Unmount active view
  if (currentViewInstance && currentViewInstance.unmount) {
    try {
      currentViewInstance.unmount();
    } catch (e) {
      console.warn('View unmount error:', e);
    }
    currentViewInstance = null;
  }

  currentRouteName = cleanRoute;
  store.setState({ currentRoute: cleanRoute });

  // Highlight navigation item in topbar/nav
  updateNavSelection(cleanRoute);

  const viewContainer = $('#view');
  if (!viewContainer) return;

  viewContainer.innerHTML = `
    <div class="h-64 flex flex-col items-center justify-center gap-3 text-txt-subtle">
      <div class="w-7 h-7 border-2 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
      <span class="text-xs font-medium">Loading view...</span>
    </div>
  `;

  try {
    const module = await ROUTES[cleanRoute]();
    viewContainer.innerHTML = '';
    currentViewInstance = module.mount(viewContainer, { route: cleanRoute });
  } catch (err) {
    console.error('Route load error:', err);
    viewContainer.innerHTML = `
      <div class="card p-8 text-center max-w-md mx-auto my-12">
        <h3 class="text-base font-bold text-danger mb-1">Failed to load view</h3>
        <p class="text-xs text-txt-muted mb-4">${err.message}</p>
        <button type="button" class="btn btn-secondary btn-sm" onclick="location.reload()">Reload Page</button>
      </div>
    `;
  }
}

function updateNavSelection(activeRoute) {
  $$('.nav-tab-link').forEach((link) => {
    const route = link.dataset.route;
    const isSelected = route === activeRoute || (route === 'request-logs' && activeRoute === 'logs');

    link.setAttribute('aria-selected', isSelected ? 'true' : 'false');
    link.classList.toggle('bg-surface-2', isSelected);
    link.classList.toggle('text-txt', isSelected);
    link.classList.toggle('shadow-sm', isSelected);
    link.classList.toggle('font-semibold', isSelected);
    link.classList.toggle('text-txt-muted', !isSelected);
  });
}

export function initRouter() {
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.slice(1);
    navigate(hash);
  });

  const initialRoute = window.location.hash.slice(1) || 'dashboard';
  navigate(initialRoute);
}
