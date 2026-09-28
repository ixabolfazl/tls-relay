/**
 * Dropdown and context menu manager with viewport edge flipping and keyboard navigation.
 */

import { html, raw, createElement } from '../core/dom.js';

let activeMenu = null;

export function showMenu(triggerEl, items = []) {
  closeActiveMenu();

  const menuEl = document.createElement('div');
  menuEl.className = 'menu fixed z-50';
  menuEl.setAttribute('role', 'menu');
  menuEl.setAttribute('tabindex', '-1');

  for (const item of items) {
    if (item.divider) {
      const div = document.createElement('div');
      div.className = 'menu-divider';
      menuEl.appendChild(div);
      continue;
    }

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `menu-item ${item.danger ? 'menu-item-danger' : ''}`;
    btn.setAttribute('role', 'menuitem');

    let content = '';
    if (item.icon) {
      content += `<span class="shrink-0 w-4 h-4">${item.icon}</span>`;
    }
    content += `<span>${item.text}</span>`;
    btn.innerHTML = content;

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeActiveMenu();
      if (item.onClick) item.onClick(e);
    });

    menuEl.appendChild(btn);
  }

  document.body.appendChild(menuEl);

  // Position relative to trigger element
  const rect = triggerEl.getBoundingClientRect();
  const menuRect = menuEl.getBoundingClientRect();

  let top = rect.bottom + 4;
  let left = rect.right - menuRect.width;

  // Flip vertical if overflowing bottom
  if (top + menuRect.height > window.innerHeight - 8) {
    top = Math.max(8, rect.top - menuRect.height - 4);
  }

  // Flip horizontal if overflowing left
  if (left < 8) {
    left = Math.max(8, rect.left);
  }

  menuEl.style.top = `${top}px`;
  menuEl.style.left = `${left}px`;

  const menuButtons = Array.from(menuEl.querySelectorAll('.menu-item'));
  let focusedIndex = -1;

  const handleKeyDown = (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      closeActiveMenu();
      triggerEl.focus();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      focusedIndex = (focusedIndex + 1) % menuButtons.length;
      menuButtons[focusedIndex]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      focusedIndex = (focusedIndex - 1 + menuButtons.length) % menuButtons.length;
      menuButtons[focusedIndex]?.focus();
    } else if (e.key === 'Home') {
      e.preventDefault();
      focusedIndex = 0;
      menuButtons[focusedIndex]?.focus();
    } else if (e.key === 'End') {
      e.preventDefault();
      focusedIndex = menuButtons.length - 1;
      menuButtons[focusedIndex]?.focus();
    }
  };

  const handleOutsideClick = (e) => {
    if (!menuEl.contains(e.target) && !triggerEl.contains(e.target)) {
      closeActiveMenu();
    }
  };

  const handleScrollOrResize = () => {
    closeActiveMenu();
  };

  window.addEventListener('keydown', handleKeyDown);
  document.addEventListener('pointerdown', handleOutsideClick, true);
  window.addEventListener('scroll', handleScrollOrResize, true);
  window.addEventListener('resize', handleScrollOrResize);

  activeMenu = {
    el: menuEl,
    trigger: triggerEl,
    destroy: () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.removeEventListener('pointerdown', handleOutsideClick, true);
      window.removeEventListener('scroll', handleScrollOrResize, true);
      window.removeEventListener('resize', handleScrollOrResize);
      if (menuEl.parentNode) {
        menuEl.parentNode.removeChild(menuEl);
      }
    },
  };

  // Focus first button on next tick
  requestAnimationFrame(() => {
    menuButtons[0]?.focus();
  });
}

export function closeActiveMenu() {
  if (activeMenu) {
    activeMenu.destroy();
    activeMenu = null;
  }
}
