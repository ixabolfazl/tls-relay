/**
 * Segmented control component and initializer.
 */

import { html, raw, setHtml } from '../core/dom.js';

export function createSegmentedControl({
  options = [], // [{ value, label, count }]
  value,
  onChange,
  size = 'md',
} = {}) {
  const container = document.createElement('div');
  const sizeClasses = size === 'sm' ? 'p-0.5 text-xs' : 'p-1 text-sm';
  container.className = `inline-flex items-center rounded-lg bg-surface-2 border border-border ${sizeClasses}`;
  container.setAttribute('role', 'tablist');

  let currentValue = value !== undefined ? value : options[0]?.value;

  function render() {
    container.innerHTML = '';
    for (const opt of options) {
      const isSelected = opt.value === currentValue;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.setAttribute('role', 'tab');
      btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      btn.dataset.value = opt.value;

      const baseBtnClasses = 'flex items-center gap-1.5 font-medium rounded-md transition-all duration-150 cursor-pointer select-none';
      const sizeBtnClasses = size === 'sm' ? 'px-2.5 py-1' : 'px-3 py-1.5';
      const stateClasses = isSelected
        ? 'bg-surface text-txt shadow-sm font-semibold'
        : 'text-txt-muted hover:text-txt hover:bg-surface-3/50';

      btn.className = `${baseBtnClasses} ${sizeBtnClasses} ${stateClasses}`;

      let labelHtml = `<span>${opt.label}</span>`;
      if (opt.count !== undefined && opt.count !== null) {
        labelHtml += `<span class="px-1.5 py-0.2 text-[11px] font-semibold rounded-full ${isSelected ? 'bg-surface-2 text-txt' : 'bg-surface-3 text-txt-muted'}">${opt.count}</span>`;
      }
      btn.innerHTML = labelHtml;

      btn.addEventListener('click', () => {
        if (currentValue !== opt.value) {
          currentValue = opt.value;
          render();
          if (onChange) onChange(currentValue);
        }
      });

      container.appendChild(btn);
    }
  }

  render();

  return {
    el: container,
    getValue: () => currentValue,
    setValue: (newVal) => {
      if (currentValue !== newVal) {
        currentValue = newVal;
        render();
      }
    },
    updateOptions: (newOptions) => {
      options = newOptions;
      render();
    },
  };
}

/**
 * Binds an existing segmented element in DOM.
 */
export function bindSegmentedControl(element, onChange) {
  if (!element) return null;

  const buttons = Array.from(element.querySelectorAll('button[data-value], button[data-mode], button[data-view], button[data-val]'));

  const getValue = () => {
    const active = element.querySelector('[aria-selected="true"], .active');
    if (!active) return '';
    return active.dataset.value || active.dataset.mode || active.dataset.view || active.dataset.val || '';
  };

  const setValue = (val) => {
    buttons.forEach((btn) => {
      const bVal = btn.dataset.value || btn.dataset.mode || btn.dataset.view || btn.dataset.val;
      const isSelected = String(bVal) === String(val);
      btn.setAttribute('aria-selected', isSelected ? 'true' : 'false');
      btn.classList.toggle('bg-surface', isSelected);
      btn.classList.toggle('text-txt', isSelected);
      btn.classList.toggle('shadow-sm', isSelected);
      btn.classList.toggle('font-semibold', isSelected);
      btn.classList.toggle('text-txt-muted', !isSelected);
    });
  };

  buttons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const val = btn.dataset.value || btn.dataset.mode || btn.dataset.view || btn.dataset.val;
      setValue(val);
      if (onChange) onChange(val);
    });
  });

  return {
    getValue,
    setValue,
  };
}
