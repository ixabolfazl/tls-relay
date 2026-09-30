/**
 * Toast notifications with auto-dismiss and accessibility support.
 */

import { html, raw, createElement } from '../core/dom.js';

let toastRoot = null;
const MAX_TOASTS = 4;

function getToastRoot() {
  if (!toastRoot) {
    toastRoot = document.getElementById('toast-root');
    if (!toastRoot) {
      toastRoot = document.createElement('div');
      toastRoot.id = 'toast-root';
      toastRoot.className = 'fixed bottom-5 right-5 z-50 flex flex-col gap-2 pointer-events-none max-w-sm w-full';
      toastRoot.setAttribute('aria-live', 'polite');
      document.body.appendChild(toastRoot);
    }
  }
  return toastRoot;
}

const ICONS = {
  success: `<svg class="w-5 h-5 text-emerald-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
  error: `<svg class="w-5 h-5 text-rose-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
  warning: `<svg class="w-5 h-5 text-amber-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>`,
  info: `<svg class="w-5 h-5 text-sky-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
};

export function showToast(message, type = 'info', duration = 4000) {
  const root = getToastRoot();

  let durMs = typeof duration === 'object' && duration !== null ? duration.duration : duration;
  if (durMs === undefined || durMs === null || isNaN(durMs)) {
    durMs = type === 'error' ? 6000 : 4000;
  }

  // Prune older toasts if over limit
  while (root.children.length >= MAX_TOASTS) {
    root.removeChild(root.firstElementChild);
  }

  const toastEl = createElement(html`
    <div class="pointer-events-auto flex items-start gap-3 p-3.5 bg-surface text-txt border border-border rounded-xl shadow-popover animate-slide-up transition-all duration-200" role="alert">
      ${raw(ICONS[type] || ICONS.info)}
      <div class="flex-1 text-sm font-medium leading-5 pt-0.5">${message}</div>
      <button type="button" class="btn-icon-sm -mr-1 -mt-1 text-txt-subtle hover:text-txt" aria-label="Dismiss">
        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
      </button>
    </div>
  `);

  const closeBtn = toastEl.querySelector('button');
  const dismiss = () => {
    toastEl.classList.add('opacity-0', 'translate-y-2');
    setTimeout(() => {
      if (toastEl.parentNode === root) {
        root.removeChild(toastEl);
      }
    }, 200);
  };

  closeBtn.addEventListener('click', dismiss);

  if (durMs > 0) {
    setTimeout(dismiss, durMs);
  }

  root.appendChild(toastEl);
}

function normalizeDur(dur, defaultDur) {
  if (dur === undefined || dur === null) return defaultDur;
  if (typeof dur === 'object') return dur.duration || defaultDur;
  return dur;
}

export const toast = {
  success: (msg, dur) => showToast(msg, 'success', normalizeDur(dur, 4000)),
  error: (msg, dur) => showToast(msg, 'error', normalizeDur(dur, 6000)),
  warning: (msg, dur) => showToast(msg, 'warning', normalizeDur(dur, 4000)),
  info: (msg, dur) => showToast(msg, 'info', normalizeDur(dur, 4000)),
};
