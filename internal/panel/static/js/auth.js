/* =========================================================================
   TLS Relay Admin Panel — auth.js
   Authentication lifecycle: login validation, logout, session check.
   ========================================================================= */

"use strict";

function showLoginPage() {
  stopPresencePolling();
  stopStatsPolling();
  stopReqLogPolling();
  stopUsagePolling();
  showEl('login-page');
  hideEl('dashboard');
}

function showDashboard() {
  hideEl('login-page');
  showEl('dashboard');
  loadSettings();
  loadDomains();
  loadUsers();
  loadBlacklist();
  stopPresencePolling();
  startStatsPolling();
}

async function checkAuth() {
  try {
    const res = await fetch(getApiUrl('api/domains'), { credentials: 'include' });
    if (res.ok) {
      showDashboard();
    } else {
      showLoginPage();
    }
  } catch {
    showLoginPage();
  }
}

// Login form submit handler
if ($('login-form')) {
  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages('login-error');
    const btn = $('login-btn');
    btn.disabled = true;
    btn.textContent = 'Signing in…';

    const user = $('login-user').value.trim();
    const pass = $('login-pass').value;

    try {
      const res = await fetch(getApiUrl('api/login'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass }),
      });
      if (res.ok) {
        showDashboard();
      } else {
        const data = await res.json().catch(() => ({}));
        showError('login-error', data.error || 'Invalid credentials.');
      }
    } catch (err) {
      showError('login-error', 'Network error. Please check server connectivity.');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Sign In';
    }
  });
}

// Logout click handler
if ($('logout-btn')) {
  $('logout-btn').addEventListener('click', async () => {
    await fetch(getApiUrl('api/logout'), { method: 'POST', credentials: 'include' });
    showLoginPage();
  });
}
