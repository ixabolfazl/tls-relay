/* =========================================================================
   TLS Relay Admin Panel — init.js
   Boot sequence, manual refresh buttons wiring, and DOM event dispatching.
   ========================================================================= */

"use strict";

function initManualRefreshButtons() {
  if ($('refresh-dashboard-btn')) {
    $('refresh-dashboard-btn').addEventListener('click', async () => {
      const btn = $('refresh-dashboard-btn');
      btn.disabled = true;
      try {
        await loadDashboardStats();
      } catch (err) {
        console.error('refresh-dashboard-btn error:', err);
      } finally {
        btn.disabled = false;
      }
    });
  }

  if ($('refresh-presence-btn')) {
    $('refresh-presence-btn').addEventListener('click', async () => {
      const btn = $('refresh-presence-btn');
      btn.disabled = true;
      try {
        await fetchPresence();
      } catch (err) {
        console.error('refresh-presence-btn error:', err);
      } finally {
        btn.disabled = false;
      }
    });
  }

  if ($('refresh-usage-btn')) {
    $('refresh-usage-btn').addEventListener('click', async () => {
      const btn = $('refresh-usage-btn');
      btn.disabled = true;
      try {
        await updateUsageTabRange(currentUsageTabRange || 'today');
      } catch (err) {
        console.error('refresh-usage-btn error:', err);
      } finally {
        btn.disabled = false;
      }
    });
  }
}

function initTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      if (tabName) {
        switchTab(tabName);
      }
    });
  });
}

// ---------------------------------------------------------------------------
// Boot Initialization Sequence
// ---------------------------------------------------------------------------
async function bootApp() {
  try { initTheme(); } catch (e) { console.error('initTheme error:', e); }
  try { initTabs(); } catch (e) { console.error('initTabs error:', e); }

  // Load all individual tab page partials asynchronously
  if (typeof loadAllTabPages === 'function') {
    try {
      await loadAllTabPages();
    } catch (e) {
      console.error('loadAllTabPages error:', e);
    }
  }

  // Fetch app settings early so egress visibility is resolved before tab initializations
  if (typeof fetchAppSettings === 'function') {
    try {
      await fetchAppSettings();
    } catch (e) {
      console.error('fetchAppSettings error:', e);
    }
  }

  // Initialize UI components and listeners across all loaded tabs
  const inits = [
    ['initSegmentedControls', typeof initSegmentedControls === 'function' ? initSegmentedControls : null],
    ['initGroupSelectors', typeof initGroupSelectors === 'function' ? initGroupSelectors : null],
    ['initEgressProxyRadioGroup', typeof initEgressProxyRadioGroup === 'function' ? initEgressProxyRadioGroup : null],
    ['initBulkActionModals', typeof initBulkActionModals === 'function' ? initBulkActionModals : null],
    ['initDomainViewToggle', typeof initDomainViewToggle === 'function' ? initDomainViewToggle : null],
    ['initDomainListeners', typeof initDomainListeners === 'function' ? initDomainListeners : null],
    ['initUserListeners', typeof initUserListeners === 'function' ? initUserListeners : null],
    ['initBlacklistListeners', typeof initBlacklistListeners === 'function' ? initBlacklistListeners : null],
    ['initPresenceListeners', typeof initPresenceListeners === 'function' ? initPresenceListeners : null],
    ['initSettingsTab', typeof initSettingsTab === 'function' ? initSettingsTab : null],
    ['initUsageTab', typeof initUsageTab === 'function' ? initUsageTab : null],
    ['initUsageTabSubtabsAndControls', typeof initUsageTabSubtabsAndControls === 'function' ? initUsageTabSubtabsAndControls : null],
    ['initDashboardRequestStats', typeof initDashboardRequestStats === 'function' ? initDashboardRequestStats : null],
    ['initRequestLogsTab', typeof initRequestLogsTab === 'function' ? initRequestLogsTab : null],
    ['initQuickAddDomainModal', typeof initQuickAddDomainModal === 'function' ? initQuickAddDomainModal : null],
    ['initManualRefreshButtons', typeof initManualRefreshButtons === 'function' ? initManualRefreshButtons : null],
  ];

  for (const [name, fn] of inits) {
    if (typeof fn === 'function') {
      try {
        fn();
      } catch (err) {
        console.error(`${name} error:`, err);
      }
    }
  }

  // Check authentication & initiate dashboard polling or show login page
  try {
    checkAuth();
  } catch (e) {
    console.error('checkAuth error:', e);
    if (typeof showLoginPage === 'function') showLoginPage();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootApp);
} else {
  bootApp();
}
