/**
 * Reusable domain rule form used in add domain view and edit domain modal.
 * Fixes F10 (deduplicating mode radios, group combobox, ports, egress toggles).
 */

import { html, raw, createElement } from '../core/dom.js';
import { parsePorts, formatPorts, parseDomainTokens, isValidDomainToken } from '../domain/rules.js';
import { createCombobox } from '../ui/combobox.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { store } from '../core/store.js';
import { toast } from '../ui/toast.js';

export function createDomainRuleForm({
  initialData = {}, // { domain, group_name, mode, ports, use_egress_proxy, include_subdomains }
  groups = [],
  isEdit = false,
  layout = isEdit ? 'stacked' : 'grid',
  onChange = null,
} = {}) {
  const settings = store.getState().settings;
  const isEgressGlobalEnabled = Boolean(settings?.egress_proxy_enabled);

  // Generate unique ID prefix to prevent collisions between add and edit forms
  const uid = 'drf_' + Math.random().toString(36).slice(2, 9);

  let currentMode = initialData.mode || 'proxy';
  const originalEgress =
    initialData.use_egress_proxy !== undefined
      ? String(initialData.use_egress_proxy)
      : 'false';
  let currentEgress = originalEgress === 'true';
  let currentGroup = initialData.group_name || '';

  let initialPortsValue = '443';
  if (isEdit && initialData.ports !== undefined && initialData.ports !== null) {
    if (initialData.ports === 'all') {
      initialPortsValue = 'all';
    } else if (Array.isArray(initialData.ports)) {
      initialPortsValue = initialData.ports.length > 0 ? initialData.ports.join(', ') : '443';
    } else {
      initialPortsValue = String(initialData.ports);
    }
  }

  const formWrapper = createElement(html`
    <div class="flex flex-col gap-4">
      <!-- 1. Domain(s) & Group -->
      ${!isEdit
        ? html`
            <div class="field">
              <div class="flex items-center justify-between gap-2 mb-1.5">
                <label class="field-label !mb-0" for="${uid}-domain-input">Domain(s)</label>
                <button
                  id="${uid}-clean-btn"
                  type="button"
                  class="btn btn-secondary btn-xs inline-flex items-center gap-1.5 text-xs text-primary-600 hover:text-primary-700 font-medium px-2.5 py-1 rounded-md border border-border shadow-xs hover:bg-surface-2 transition-all cursor-pointer"
                  title="Extract hostnames from URLs/cURL commands and deduplicate"
                >
                  <svg class="w-3.5 h-3.5 text-primary-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
                  </svg>
                  <span>Auto-extract & clean</span>
                </button>
              </div>
              <textarea
                id="${uid}-domain-input"
                class="textarea font-mono text-sm"
                rows="3"
                placeholder="example.com&#10;api.example.com&#10;*.cdn.net"
              >${initialData.domain || ''}</textarea>
              <span class="field-hint">Enter one or more domains separated by newlines, commas, or spaces.</span>

              <!-- Live Preview Box directly under domain input list -->
              <div id="${uid}-preview-box" class="hidden mt-2.5 p-3 rounded-lg bg-surface-2/70 border border-border space-y-2">
                <div class="flex items-center justify-between text-xs font-semibold text-txt-muted">
                  <span>Input Preview</span>
                  <span id="${uid}-preview-count" class="text-xs text-txt-subtle font-normal"></span>
                </div>
                <div id="${uid}-preview-list" class="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto"></div>
              </div>
            </div>
          `
        : html`
            <div class="field">
              <label class="field-label">Domain</label>
              <input
                id="${uid}-domain-input"
                type="text"
                class="input font-mono bg-surface-2 font-medium"
                value="${initialData.domain || ''}"
                readonly
              />
            </div>
          `}

      <!-- Group Combobox -->
      <div class="field">
        <label class="field-label">Group (optional)</label>
        <div id="${uid}-group-container"></div>
      </div>

      <!-- 2. Permitted Ports (shown for proxy mode) -->
      <div id="${uid}-ports-field" class="field ${currentMode !== 'proxy' ? 'hidden' : ''}">
        <label class="field-label" for="${uid}-ports-input">Permitted Ports</label>
        <input
          id="${uid}-ports-input"
          type="text"
          class="input font-mono"
          placeholder="443, 8443 or all"
          value="${initialPortsValue}"
        />
        <span class="field-hint">Comma-separated TCP ports (e.g. "443, 8443") or "all".</span>
      </div>

      <!-- 3. Subdomains checkbox (only shown for Add Domain form, never in Edit) -->
      ${!isEdit
        ? html`
            <div class="flex items-center gap-2.5 pt-0.5">
              <input
                id="${uid}-subdomains-checkbox"
                type="checkbox"
                class="checkbox"
                ${initialData.include_subdomains ? 'checked' : ''}
              />
              <label for="${uid}-subdomains-checkbox" class="text-sm font-medium text-txt cursor-pointer select-none">
                Also include all subdomains (<code class="font-mono text-xs text-primary-600">*.domain</code>)
              </label>
            </div>
          `
        : ''}

      <!-- 4. Routing Mode (3 Options in 1 Row for Grid, Stacked for Dialogs/Edit) -->
      <div class="field pt-1 border-t border-border">
        <label class="field-label mb-1">Routing Mode</label>
        <div class="${layout === 'stacked' ? 'space-y-2' : 'grid grid-cols-1 md:grid-cols-3 gap-3'}">
          <!-- Proxy Option (Green) -->
          <label class="flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
            currentMode === 'proxy'
              ? 'border-emerald-500 bg-emerald-500/15 dark:bg-emerald-950/40 ring-1 ring-emerald-500/30'
              : 'border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 hover:bg-emerald-500/10'
          }" id="${uid}-mode-opt-proxy">
            <input type="radio" name="${uid}_routing_mode" value="proxy" class="radio radio-emerald mt-0.5 shrink-0 text-emerald-600 focus:ring-emerald-500" ${
              currentMode === 'proxy' ? 'checked' : ''
            } />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Proxy (Relay)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Relay TLS connections and log SNI traffic.</span>
            </div>
          </label>

          <!-- Direct Option (Gray) -->
          <label class="flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
            currentMode === 'direct'
              ? 'border-zinc-500 dark:border-zinc-400 bg-zinc-500/15 dark:bg-zinc-800/60 ring-1 ring-zinc-500/30'
              : 'border-zinc-500/20 bg-zinc-500/5 dark:bg-zinc-800/20 hover:border-zinc-500/40 hover:bg-zinc-500/10'
          }" id="${uid}-mode-opt-direct">
            <input type="radio" name="${uid}_routing_mode" value="direct" class="radio radio-zinc mt-0.5 shrink-0 text-zinc-600 focus:ring-zinc-500" ${
              currentMode === 'direct' ? 'checked' : ''
            } />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Direct (Bypass)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Bypass relay and resolve client directly to target.</span>
            </div>
          </label>

          <!-- Block Option (Red) -->
          <label class="flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
            currentMode === 'block'
              ? 'border-red-500 bg-red-500/15 dark:bg-red-950/40 ring-1 ring-red-500/30'
              : 'border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 hover:bg-red-500/10'
          }" id="${uid}-mode-opt-block">
            <input type="radio" name="${uid}_routing_mode" value="block" class="radio radio-red mt-0.5 shrink-0 text-red-600 focus:ring-red-500" ${
              currentMode === 'block' ? 'checked' : ''
            } />
            <div class="flex flex-col min-w-0">
              <span class="text-sm font-semibold text-txt">Block (Reject)</span>
              <span class="text-xs text-txt-muted mt-0.5 leading-relaxed">Drop and reject all DNS and TLS queries.</span>
            </div>
          </label>
        </div>
      </div>

      <!-- 5. Egress Proxy Toggle (shown for proxy mode when global egress is configured) -->
      ${isEgressGlobalEnabled
        ? html`
            <div id="${uid}-egress-field" class="flex items-center gap-3 p-3 rounded-xl border border-sky-500/30 bg-sky-500/5 dark:bg-sky-950/20 ${
              currentMode !== 'proxy' ? 'hidden' : ''
            }">
              <input
                id="${uid}-egress-checkbox"
                type="checkbox"
                class="checkbox"
                ${currentEgress ? 'checked' : ''}
              />
              <label for="${uid}-egress-checkbox" class="flex flex-col cursor-pointer select-none">
                <span class="text-sm font-medium text-txt">Use Outbound Egress Proxy</span>
                <span class="text-xs text-txt-subtle">Route outbound traffic through the configured upstream SOCKS5 proxy (host:port)</span>
              </label>
            </div>
          `
        : ''}
    </div>
  `);

  const portsField = formWrapper.querySelector(`#${uid}-ports-field`);
  const egressField = formWrapper.querySelector(`#${uid}-egress-field`);

  const modeStyles = {
    proxy: {
      active: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500 bg-emerald-500/15 dark:bg-emerald-950/40 ring-1 ring-emerald-500/30 cursor-pointer transition-colors',
      inactive: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 hover:bg-emerald-500/10 cursor-pointer transition-colors',
    },
    direct: {
      active: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500 dark:border-zinc-400 bg-zinc-500/15 dark:bg-zinc-800/60 ring-1 ring-zinc-500/30 cursor-pointer transition-colors',
      inactive: 'flex items-start gap-3 p-3 rounded-xl border border-zinc-500/20 bg-zinc-500/5 dark:bg-zinc-800/20 hover:border-zinc-500/40 hover:bg-zinc-500/10 cursor-pointer transition-colors',
    },
    block: {
      active: 'flex items-start gap-3 p-3 rounded-xl border border-red-500 bg-red-500/15 dark:bg-red-950/40 ring-1 ring-red-500/30 cursor-pointer transition-colors',
      inactive: 'flex items-start gap-3 p-3 rounded-xl border border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 hover:bg-red-500/10 cursor-pointer transition-colors',
    },
  };

  function setMode(m) {
    currentMode = m;
    radioInputs.forEach((radio) => {
      radio.checked = radio.value === currentMode;
    });
    ['proxy', 'direct', 'block'].forEach((opt) => {
      const card = formWrapper.querySelector(`#${uid}-mode-opt-${opt}`);
      if (card && modeStyles[opt]) {
        card.className = opt === currentMode ? modeStyles[opt].active : modeStyles[opt].inactive;
      }
    });
    if (currentMode === 'proxy') {
      if (portsField) portsField.classList.remove('hidden');
      if (egressField) egressField.classList.remove('hidden');
    } else {
      if (portsField) portsField.classList.add('hidden');
      if (egressField) egressField.classList.add('hidden');
    }
  }

  // Handle Mode Radios Change
  const radioInputs = formWrapper.querySelectorAll(`input[name="${uid}_routing_mode"]`);
  radioInputs.forEach((radio) => {
    radio.addEventListener('change', () => {
      if (!radio.checked) return;
      setMode(radio.value);
      if (onChange) onChange();
    });
  });

  // Render Group Combobox
  const groupContainer = formWrapper.querySelector(`#${uid}-group-container`);
  const groupCombobox = createCombobox({
    options: groups,
    value: currentGroup,
    placeholder: 'Select or type group name...',
    onChange: (newGroup) => {
      currentGroup = newGroup;
      if (onChange) onChange();
    },
  });
  groupContainer.appendChild(groupCombobox.el);

  const domainInputEl = formWrapper.querySelector(`#${uid}-domain-input`);
  const cleanBtnEl = formWrapper.querySelector(`#${uid}-clean-btn`);
  const previewBoxEl = formWrapper.querySelector(`#${uid}-preview-box`);
  const previewListEl = formWrapper.querySelector(`#${uid}-preview-list`);
  const previewCountEl = formWrapper.querySelector(`#${uid}-preview-count`);

  function updateInputPreview() {
    if (!previewBoxEl || !previewListEl || !domainInputEl) return;
    const text = domainInputEl.value || '';
    const tokens = parseDomainTokens(text);

    if (tokens.length === 0) {
      previewBoxEl.classList.add('hidden');
      previewListEl.innerHTML = '';
      if (previewCountEl) previewCountEl.textContent = '';
      return;
    }

    previewBoxEl.classList.remove('hidden');
    previewListEl.innerHTML = '';

    const seen = new Set();
    let validCount = 0;

    for (const token of tokens) {
      const check = isValidDomainToken(token);
      const isDup = seen.has(token.toLowerCase());
      seen.add(token.toLowerCase());

      const pill = document.createElement('span');
      if (isDup) {
        pill.className = 'badge badge-warning font-mono';
        pill.textContent = `${token} (duplicate)`;
      } else if (!check.valid) {
        pill.className = 'badge badge-danger font-mono';
        pill.textContent = `${token} (${check.reason})`;
      } else {
        pill.className = 'badge badge-neutral font-mono';
        pill.textContent = check.cleanDomain;
        validCount++;
      }
      previewListEl.appendChild(pill);
    }

    if (previewCountEl) {
      previewCountEl.textContent = `${validCount} valid / ${tokens.length} total`;
    }
  }

  function cleanDomainInput() {
    if (!domainInputEl) return;
    const tokens = parseDomainTokens(domainInputEl.value || '');
    const cleanTokens = Array.from(
      new Set(
        tokens
          .map((t) => {
            let cleaned = t.trim();
            try {
              if (cleaned.includes('://')) {
                cleaned = new URL(cleaned).hostname;
              } else if (cleaned.includes('/')) {
                cleaned = cleaned.split('/')[0];
              }
              if (cleaned.includes(':')) {
                cleaned = cleaned.split(':')[0];
              }
            } catch (_) {}
            return isValidDomainToken(cleaned);
          })
          .filter((c) => c.valid)
          .map((c) => c.cleanDomain)
      )
    );

    domainInputEl.value = cleanTokens.join('\n');
    updateInputPreview();
    if (cleanTokens.length > 0) {
      toast.success(`Cleaned ${cleanTokens.length} unique domain${cleanTokens.length > 1 ? 's' : ''}`);
    } else {
      toast.info('No valid domains found to clean');
    }
    if (onChange) onChange();
  }

  if (cleanBtnEl) {
    cleanBtnEl.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      cleanDomainInput();
    });
  }

  if (domainInputEl) {
    domainInputEl.addEventListener('input', () => {
      updateInputPreview();
      if (onChange) onChange();
    });
    if (initialData.domain) {
      updateInputPreview();
    }
  }

  const portsInputEl = formWrapper.querySelector(`#${uid}-ports-input`);
  if (portsInputEl) {
    portsInputEl.addEventListener('input', () => {
      if (onChange) onChange();
    });
  }

  const egressCheckboxEl = formWrapper.querySelector(`#${uid}-egress-checkbox`);
  if (egressCheckboxEl) {
    egressCheckboxEl.addEventListener('change', () => {
      if (onChange) onChange();
    });
  }

  function getData() {
    const domainInput = formWrapper.querySelector(`#${uid}-domain-input`);
    const portsInput = formWrapper.querySelector(`#${uid}-ports-input`);
    const subdomainsCheckbox = formWrapper.querySelector(`#${uid}-subdomains-checkbox`);
    const egressCheckbox = formWrapper.querySelector(`#${uid}-egress-checkbox`);

    let egressVal;
    if (isEdit) {
      if (currentMode === 'proxy' && egressCheckbox) {
        egressVal = String(egressCheckbox.checked);
      } else {
        egressVal = originalEgress;
      }
    } else {
      if (currentMode === 'proxy' && egressCheckbox) {
        egressVal = String(egressCheckbox.checked);
      } else {
        egressVal = 'false';
      }
    }

    const rawPorts = portsInput ? portsInput.value : '';
    const parsedPorts = currentMode === 'proxy' ? parsePorts(rawPorts) : 'all';

    return {
      domain: domainInput ? domainInput.value.trim() : initialData.domain || '',
      mode: currentMode,
      group_name: groupCombobox.getValue().trim(),
      ports: parsedPorts,
      include_subdomains: subdomainsCheckbox ? subdomainsCheckbox.checked : false,
      use_egress_proxy: egressVal,
    };
  }

  function setData(data = {}) {
    if (data.mode !== undefined) {
      setMode(data.mode);
    }
    if (data.group_name !== undefined) {
      groupCombobox.setValue(data.group_name);
      currentGroup = data.group_name;
    }
    if (data.ports !== undefined) {
      const pInput = formWrapper.querySelector(`#${uid}-ports-input`);
      if (pInput) {
        if (data.ports === 'all') {
          pInput.value = 'all';
        } else if (Array.isArray(data.ports)) {
          pInput.value = data.ports.join(', ');
        } else {
          pInput.value = data.ports || '443';
        }
      }
    }
    if (data.use_egress_proxy !== undefined) {
      const eCheckbox = formWrapper.querySelector(`#${uid}-egress-checkbox`);
      if (eCheckbox) eCheckbox.checked = String(data.use_egress_proxy) === 'true';
    }
  }

  return {
    el: formWrapper,
    getData,
    setData,
    setGroups: (newGroups) => groupCombobox.setOptions(newGroups),
    getDomainInput: () => formWrapper.querySelector(`#${uid}-domain-input`),
    setDomain: (val) => {
      const input = formWrapper.querySelector(`#${uid}-domain-input`);
      if (input) {
        input.value = val;
        updateInputPreview();
        if (onChange) onChange();
      }
    },
    focusDomain: () => {
      formWrapper.querySelector(`#${uid}-domain-input`)?.focus();
    },
    cleanDomainInput,
    updateInputPreview,
  };
}
