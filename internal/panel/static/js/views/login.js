/**
 * Login view handler with lockout countdown and error feedback.
 */

import { html, setHtml, $ } from '../core/dom.js';
import { api, ApiError } from '../core/api.js';
import { store } from '../core/store.js';

export function mount(container, { onLoginSuccess } = {}) {
  setHtml(
    container,
    html`
      <div class="min-h-screen flex items-center justify-center p-4 bg-bg">
        <div class="card max-w-sm w-full p-8 shadow-card animate-slide-up">
          <div class="flex flex-col items-center mb-6">
            <div class="w-12 h-12 rounded-xl bg-primary flex items-center justify-center text-white mb-3 shadow-md">
              <svg class="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
              </svg>
            </div>
            <h1 class="text-xl font-bold text-txt">TLS Relay Admin</h1>
            <p class="text-xs text-txt-muted mt-1">Sign in to manage relay and DNS services</p>
          </div>

          <div id="login-error" class="hidden mb-4 p-3 rounded-lg bg-danger-soft border border-danger-border text-xs text-danger font-medium"></div>

          <form id="login-form" class="flex flex-col gap-4">
            <div class="field">
              <label class="field-label" for="login-username">Username</label>
              <input
                id="login-username"
                name="username"
                type="text"
                class="input"
                placeholder="admin"
                required
                autocomplete="username"
              />
            </div>

            <div class="field">
              <label class="field-label" for="login-password">Password</label>
              <input
                id="login-password"
                name="password"
                type="password"
                class="input"
                placeholder="••••••••"
                required
                autocomplete="current-password"
              />
            </div>

            <button id="login-submit-btn" type="submit" class="btn btn-primary w-full mt-2">
              Sign In
            </button>
          </form>
        </div>
      </div>
    `
  );

  const form = $('#login-form', container);
  const usernameInput = $('#login-username', container);
  const passwordInput = $('#login-password', container);
  const errorBox = $('#login-error', container);
  const submitBtn = $('#login-submit-btn', container);

  setTimeout(() => usernameInput?.focus(), 50);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    errorBox.classList.add('hidden');
    errorBox.textContent = '';
    submitBtn.disabled = true;
    submitBtn.textContent = 'Signing in...';

    try {
      const res = await api.login({
        username: usernameInput.value.trim(),
        password: passwordInput.value,
      });

      if (res.status === 'ok') {
        store.setState({ authenticated: true });
        if (onLoginSuccess) onLoginSuccess();
      } else {
        errorBox.textContent = res.error || 'Authentication failed';
        errorBox.classList.remove('hidden');
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        errorBox.textContent = 'Too many failed attempts. Please wait 5 minutes before retrying.';
      } else {
        errorBox.textContent = err.message || 'Invalid username or password';
      }
      errorBox.classList.remove('hidden');
      passwordInput.value = '';
      passwordInput.focus();
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Sign In';
    }
  });

  return {
    unmount: () => {
      container.innerHTML = '';
    },
  };
}
