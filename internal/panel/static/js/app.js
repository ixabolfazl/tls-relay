/**
 * Application entry point: authentication gate, shell mounting, and lifecycle events.
 */

import { $, setHtml } from './core/dom.js';
import { api } from './core/api.js';
import { store } from './core/store.js';
import { initRouter, navigate } from './core/router.js';
import { getTheme, toggleTheme } from './core/theme.js';
import { toast } from './ui/toast.js';

let routerInitialized = false;

async function checkAuthAndBoot() {
  const splash = $('#splash-screen');
  const loginRoot = $('#login-root');
  const appShell = $('#app-shell');

  try {
    const settings = await api.getSettings();
    store.setState({ authenticated: true, settings });

    // Hide splash & login, show app shell
    if (splash) splash.classList.add('hidden');
    if (loginRoot) loginRoot.classList.add('hidden');
    if (appShell) appShell.classList.remove('hidden');

    // Admin username badge
    const adminUserBadge = $('#topbar-admin-username');
    if (adminUserBadge && settings.admin_username) {
      adminUserBadge.textContent = settings.admin_username;
    }

    if (!routerInitialized) {
      initRouter();
      routerInitialized = true;
    } else {
      const initialRoute = window.location.hash.slice(1) || 'dashboard';
      navigate(initialRoute);
    }
  } catch (err) {
    // 401 Unauthorized or unauthenticated
    store.setState({ authenticated: false });
    if (splash) splash.classList.add('hidden');
    if (appShell) appShell.classList.add('hidden');
    if (loginRoot) loginRoot.classList.remove('hidden');

    const loginModule = await import('./views/login.js');
    loginModule.mount(loginRoot, {
      onLoginSuccess: () => {
        checkAuthAndBoot();
      },
    });
  }
}

function initShellEvents() {
  // Theme toggle
  const themeBtn = $('#theme-toggle-btn');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const next = toggleTheme();
      toast.info(`Switched to ${next} mode`, 2000);
    });
  }

  // Logout button
  const logoutBtn = $('#logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
      try {
        await api.logout();
      } catch {
        // Ignore logout network errors
      }
      store.setState({ authenticated: false });
      window.location.reload();
    });
  }

  // Global auth requirement listener (dispatched on 401)
  window.addEventListener('auth:required', () => {
    if (store.getState().authenticated) {
      toast.warning('Session expired. Please sign in again.');
      store.setState({ authenticated: false });
      checkAuthAndBoot();
    }
  });
}

// Start application
document.addEventListener('DOMContentLoaded', () => {
  initShellEvents();
  checkAuthAndBoot();
});
