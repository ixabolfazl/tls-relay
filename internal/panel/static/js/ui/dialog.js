/**
 * Native HTML5 dialog manager with modal promises, backdrop handling, and ESC support.
 */

import { html, raw, createElement } from '../core/dom.js';

export function openDialog({ title, content, actions = [], onClose = null, size = 'md', overflowVisible = false } = {}) {
  const sizeClasses = {
    sm: 'w-full max-w-md',
    md: 'w-full max-w-lg',
    lg: 'w-full max-w-2xl',
    xl: 'w-full max-w-4xl',
  };
  const sizeClass = sizeClasses[size] || sizeClasses.md;

  const dialog = document.createElement('dialog');
  dialog.className = 'fixed inset-0 m-auto flex items-center justify-center p-4 bg-transparent outline-none w-full max-w-full';

  const modalEl = createElement(html`
    <div class="dialog-content ${sizeClass} max-h-[85vh] flex flex-col ${overflowVisible ? '!overflow-visible' : 'overflow-hidden'}" role="document">
      ${title
        ? html`
            <div class="px-6 py-4 border-b border-border flex items-center justify-between shrink-0">
              <h3 class="text-base font-semibold text-txt">${title}</h3>
              <button type="button" class="dialog-close-btn btn-icon-sm -mr-2 text-txt-muted hover:text-txt" aria-label="Close">
                <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
              </button>
            </div>
          `
        : ''}
      <div class="dialog-body p-6 flex-1 min-h-0 ${overflowVisible ? 'overflow-visible' : 'overflow-y-auto'}">${typeof content === 'string' ? raw(content) : ''}</div>
      ${actions.length > 0
        ? html`
            <div class="dialog-actions px-6 py-4 bg-surface-2/40 border-t border-border flex items-center justify-end gap-3 shrink-0 ${overflowVisible ? 'rounded-b-2xl' : ''}"></div>
          `
        : ''}
    </div>
  `);

  if (content instanceof HTMLElement) {
    modalEl.querySelector('.dialog-body').appendChild(content);
  }

  const actionsContainer = modalEl.querySelector('.dialog-actions');
  if (actionsContainer && actions.length > 0) {
    for (const act of actions) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = act.className || (act.primary ? 'btn btn-primary' : 'btn btn-secondary');
      btn.textContent = act.text || 'OK';
      btn.addEventListener('click', (e) => {
        if (act.onClick) {
          act.onClick(e, { close: () => closeDialog(act.value) });
        } else {
          closeDialog(act.value);
        }
      });
      actionsContainer.appendChild(btn);
    }
  }

  dialog.appendChild(modalEl);
  document.body.appendChild(dialog);

  let resultValue = undefined;
  let resolved = false;

  let resolvePromise;
  const promise = new Promise((res) => {
    resolvePromise = res;
  });

  const closeDialog = (val) => {
    if (resolved) return;
    resolved = true;
    resultValue = val !== undefined ? val : resultValue;
    dialog.close();
    if (dialog.parentNode) {
      dialog.parentNode.removeChild(dialog);
    }
    if (onClose) onClose(resultValue);
    resolvePromise(resultValue);
  };

  const closeBtn = modalEl.querySelector('.dialog-close-btn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => closeDialog(false));
  }

  // Backdrop click closes modal
  dialog.addEventListener('click', (e) => {
    if (e.target === dialog) {
      closeDialog(false);
    }
  });

  // Native cancel (ESC key)
  dialog.addEventListener('cancel', (e) => {
    e.preventDefault();
    closeDialog(false);
  });

  dialog.showModal();

  return {
    dialog,
    modalEl,
    close: closeDialog,
    promise,
  };
}

export function confirmDialog({
  title = 'Confirmation',
  message,
  confirmText = 'Confirm',
  cancelText = 'Cancel',
  danger = false,
  isDanger = false,
} = {}) {
  const isDestructive = danger || isDanger;
  const contentEl = document.createElement('div');
  contentEl.className = 'text-sm text-txt-muted leading-relaxed';
  if (typeof message === 'string') {
    contentEl.textContent = message;
  } else if (message instanceof HTMLElement) {
    contentEl.appendChild(message);
  }

  return new Promise((resolve) => {
    openDialog({
      title,
      content: contentEl,
      size: 'sm',
      actions: [
        {
          text: cancelText,
          className: 'btn btn-secondary',
          value: false,
        },
        {
          text: confirmText,
          className: isDestructive ? 'btn btn-danger' : 'btn btn-primary',
          value: true,
        },
      ],
      onClose: (val) => resolve(Boolean(val)),
    });
  });
}

export function promptDialog({
  title = 'Prompt',
  message = '',
  placeholder = '',
  defaultValue = '',
  confirmText = 'Save',
  cancelText = 'Cancel',
} = {}) {
  const wrapper = document.createElement('div');
  wrapper.className = 'flex flex-col gap-3';
  if (message) {
    const p = document.createElement('p');
    p.className = 'text-sm text-txt-muted';
    p.textContent = message;
    wrapper.appendChild(p);
  }

  const input = document.createElement('input');
  input.type = 'text';
  input.className = 'input';
  input.placeholder = placeholder;
  input.value = defaultValue;
  wrapper.appendChild(input);

  return new Promise((resolve) => {
    const dialogObj = openDialog({
      title,
      content: wrapper,
      size: 'sm',
      actions: [
        {
          text: cancelText,
          className: 'btn btn-secondary',
          value: null,
        },
        {
          text: confirmText,
          className: 'btn btn-primary',
          onClick: () => dialogObj.close(input.value.trim()),
        },
      ],
      onClose: (val) => resolve(val !== undefined ? val : null),
    });

    setTimeout(() => {
      input.focus();
      input.select();
    }, 50);

    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        dialogObj.close(input.value.trim());
      }
    });
  });
}

export const dialog = {
  open: openDialog,
  confirm: confirmDialog,
  prompt: promptDialog,
};
