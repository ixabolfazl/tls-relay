/**
 * Searchable combobox component with custom input / new item creation.
 */

import { html, raw, createElement } from '../core/dom.js';

export function createCombobox({
  options = [], // array of strings or { value, label }
  value = '',
  placeholder = 'Select or type a group...',
  allowCustom = true,
  onChange,
} = {}) {
  const container = document.createElement('div');
  container.className = 'relative w-full';

  let normalizedOptions = (options || []).map((opt) =>
    typeof opt === 'string' ? { value: opt, label: opt } : opt
  );
  let currentValue = value || '';
  let isOpen = false;

  const wrapper = createElement(html`
    <div class="relative w-full">
      <div class="relative flex items-center">
        <input
          type="text"
          class="input pr-8"
          placeholder="${placeholder}"
          value="${currentValue}"
          autocomplete="off"
        />
        <button type="button" class="absolute right-2 text-txt-subtle hover:text-txt p-1 cursor-pointer" aria-label="Toggle options">
          <svg class="w-4 h-4 transition-transform duration-150" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
          </svg>
        </button>
      </div>
      <div class="menu absolute left-0 right-0 top-full mt-1 max-h-56 overflow-y-auto hidden z-50"></div>
    </div>
  `);

  const input = wrapper.querySelector('input');
  const toggleBtn = wrapper.querySelector('button');
  const arrowSvg = toggleBtn.querySelector('svg');
  const dropdown = wrapper.querySelector('.menu');

  function updateDropdown(filterText = '') {
    dropdown.innerHTML = '';
    const cleanFilter = (filterText || '').toLowerCase().trim();

    const filtered = normalizedOptions.filter((opt) =>
      opt.label.toLowerCase().includes(cleanFilter)
    );

    let hasMatch = false;
    for (const opt of filtered) {
      if (opt.value.toLowerCase() === cleanFilter) hasMatch = true;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `menu-item ${opt.value === currentValue ? 'bg-primary-soft/50 font-medium text-primary-600' : ''}`;
      btn.textContent = opt.label;
      btn.addEventListener('mousedown', (e) => {
        e.preventDefault();
        selectValue(opt.value);
      });
      dropdown.appendChild(btn);
    }

    if (allowCustom && cleanFilter && !hasMatch) {
      const createBtn = document.createElement('button');
      createBtn.type = 'button';
      createBtn.className = 'menu-item text-primary-600 font-medium';
      createBtn.innerHTML = `<span>Create "<strong>${filterText.trim()}</strong>"</span>`;
      createBtn.addEventListener('mousedown', (e) => {
        e.preventDefault();
        selectValue(filterText.trim());
      });
      dropdown.appendChild(createBtn);
    }

    if (dropdown.children.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'px-3.5 py-2 text-xs text-txt-subtle italic';
      empty.textContent = normalizedOptions.length === 0 ? 'No existing groups (type to create)' : 'No matching groups';
      dropdown.appendChild(empty);
    }
  }

  function open() {
    if (isOpen) return;
    isOpen = true;
    updateDropdown(input.value);
    dropdown.classList.remove('hidden');
    arrowSvg.classList.add('rotate-180');
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    dropdown.classList.add('hidden');
    arrowSvg.classList.remove('rotate-180');
  }

  function selectValue(val) {
    currentValue = val;
    input.value = val;
    close();
    if (onChange) onChange(currentValue);
  }

  input.addEventListener('focus', open);
  input.addEventListener('click', open);
  input.addEventListener('input', () => {
    open();
    updateDropdown(input.value);
    currentValue = input.value;
    if (onChange) onChange(currentValue);
  });

  toggleBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (isOpen) {
      close();
    } else {
      open();
      input.focus();
    }
  });

  document.addEventListener('pointerdown', (e) => {
    if (!wrapper.contains(e.target)) {
      close();
    }
  });

  container.appendChild(wrapper);

  return {
    el: container,
    getValue: () => currentValue,
    setValue: (val) => {
      currentValue = val || '';
      input.value = currentValue;
    },
    setOptions: (newOpts) => {
      normalizedOptions = (newOpts || []).map((opt) =>
        typeof opt === 'string' ? { value: opt, label: opt } : opt
      );
      if (isOpen) {
        updateDropdown(input.value);
      }
    },
  };
}
