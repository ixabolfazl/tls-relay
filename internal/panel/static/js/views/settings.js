/**
 * Settings view: two-column navigation, network & security policies,
 * egress proxy testing, backup/import, and service restart with polling.
 * Fixes B8 (cancel button handlers), §7 key asymmetries (dns_unauthorized_passthrough_enabled).
 */

import { html, raw, setHtml, $, $$, escapeHtml } from '../core/dom.js';
import { api, getApiUrl } from '../core/api.js';
import { formatDuration } from '../core/format.js';
import { dialog } from '../ui/dialog.js';
import { toast } from '../ui/toast.js';
import { createSegmentedControl } from '../ui/segmented.js';
import { store } from '../core/store.js';

const TIMEZONES = [
  'UTC',
  'Asia/Tehran',
  'Asia/Dubai',
  'Asia/Istanbul',
  'Europe/London',
  'Europe/Berlin',
  'Europe/Paris',
  'America/New_York',
  'America/Chicago',
  'America/Los_Angeles',
  'Asia/Tokyo',
  'Asia/Singapore',
  'Australia/Sydney',
];

export function mount(container) {
  let settings = {};
  let dnsServers = [];

  setHtml(
    container,
    html`
      <div class="space-y-6">
        <!-- Top Header & Quick Service Action -->
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-2xl bg-surface border border-border">
          <div>
            <h1 class="text-2xl font-bold text-txt">System Settings</h1>
            <p class="text-xs text-txt-muted mt-0.5">Configure relay security, routing rules, upstream proxies, and maintenance</p>
          </div>
          <div class="flex items-center gap-3 self-start sm:self-center">
            <div class="text-left sm:text-right">
              <div class="text-[11px] text-txt-muted">Service Uptime</div>
              <div id="set-service-uptime" class="text-sm font-bold text-txt font-mono tabular-nums">—</div>
            </div>
            <button id="set-restart-service-btn" type="button" class="btn btn-danger btn-sm shrink-0">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
              <span>Restart Service</span>
            </button>
          </div>
        </div>

        <!-- Two Column Layout (Desktop) -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <!-- Left Sticky Sub-Nav -->
          <nav id="settings-sub-nav" class="lg:col-span-3 lg:sticky lg:top-20 card p-2 flex flex-row lg:flex-col overflow-x-auto gap-1 text-sm font-medium z-10">
            <button type="button" data-target="sec-access" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-primary-600 bg-primary-soft font-semibold transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
              <span>Access & Security</span>
            </button>
            <button type="button" data-target="sec-network" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>
              <span>Network</span>
            </button>
            <button type="button" data-target="sec-dns" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>
              <span>DNS Resolvers</span>
            </button>
            <button type="button" data-target="sec-egress" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6"/></svg>
              <span>Egress Proxy</span>
            </button>
            <button type="button" data-target="sec-general" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/></svg>
              <span>General Settings</span>
            </button>
            <button type="button" data-target="sec-creds" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/></svg>
              <span>Admin Credentials</span>
            </button>
            <button type="button" data-target="sec-logging" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
              <span>Logging</span>
            </button>
            <button type="button" data-target="sec-data" class="settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
              <span>Data & Backup</span>
            </button>
          </nav>

          <!-- Right Content Column -->
          <div class="lg:col-span-9 space-y-6">
            <!-- Section 1: Access & Security -->
            <section id="sec-access" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Access & Security Policies</h2>
                  <p class="text-xs text-txt-muted">Control client authorization rules and unknown domain routing behavior</p>
                </div>
              </div>
              <div class="card-body space-y-5">
                <!-- Access Mode Radios (Single Row) -->
                <div class="field">
                  <label class="field-label mb-1">Access Mode</label>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <label class="flex items-start gap-3 p-3 rounded-xl border border-border bg-surface-2/60 hover:bg-surface-hover cursor-pointer transition-colors" id="set-access-mode-opt-user">
                      <input type="radio" name="set_access_mode" value="user" class="radio mt-0.5" />
                      <div class="flex flex-col">
                        <span class="text-sm font-semibold text-txt">User Authorization Mode</span>
                        <span class="text-xs text-txt-muted mt-0.5">Requires client authorization token and magic-link. Only registered IPs can connect.</span>
                      </div>
                    </label>

                    <label class="flex items-start gap-3 p-3 rounded-xl border border-border bg-surface-2/60 hover:bg-surface-hover cursor-pointer transition-colors" id="set-access-mode-opt-public">
                      <input type="radio" name="set_access_mode" value="public" class="radio mt-0.5" />
                      <div class="flex flex-col">
                        <span class="text-sm font-semibold text-txt">Public Mode</span>
                        <span class="text-xs text-txt-muted mt-0.5">Allows all client connections without authentication tokens or IP registration.</span>
                      </div>
                    </label>
                  </div>
                </div>

                <!-- DNS Unauthorized Passthrough Checkbox (Only visible in User Mode, with distinct accent background) -->
                <div id="set-dns-passthrough-container" class="flex items-center gap-3 p-3.5 rounded-xl border border-sky-500/30 bg-sky-500/5 dark:bg-sky-950/20 transition-all">
                  <input id="set-dns-passthrough-switch" type="checkbox" class="checkbox" />
                  <label for="set-dns-passthrough-switch" class="flex flex-col cursor-pointer select-none">
                    <span class="text-sm font-medium text-txt">DNS Unauthorized Passthrough</span>
                    <span class="text-xs text-txt-muted">Forward unauthenticated DNS queries directly to upstream DNS resolver instead of blocking</span>
                  </label>
                </div>

                <!-- Unknown Domain Policy Radios (Single Row with Color Accents) -->
                <div class="field pt-2 border-t border-border">
                  <label class="field-label mb-1">Unknown Domain Policy</label>
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <!-- Reject Option (Red) -->
                    <label class="flex items-start gap-3 p-3 rounded-xl border border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 hover:bg-red-500/10 cursor-pointer transition-colors" id="set-unknown-policy-opt-reject">
                      <input type="radio" name="set_unknown_policy" value="reject" class="radio radio-red mt-0.5 text-red-600 focus:ring-red-500" />
                      <div class="flex flex-col">
                        <span class="text-sm font-semibold text-txt">Block (Reject)</span>
                        <span class="text-xs text-txt-muted mt-0.5">Drop and reject connections to unlisted hostnames.</span>
                      </div>
                    </label>

                    <!-- Allow Option (Green) -->
                    <label class="flex items-start gap-3 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 hover:bg-emerald-500/10 cursor-pointer transition-colors" id="set-unknown-policy-opt-allow_default_port">
                      <input type="radio" name="set_unknown_policy" value="allow_default_port" class="radio radio-emerald mt-0.5 text-emerald-600 focus:ring-emerald-500" />
                      <div class="flex flex-col">
                        <span class="text-sm font-semibold text-txt">Allow (Relay)</span>
                        <span class="text-xs text-txt-muted mt-0.5">Forward unlisted hostnames through relay on permitted ports.</span>
                      </div>
                    </label>
                  </div>
                </div>

                <div class="field max-w-xs">
                  <label class="field-label" for="set-max-conns-input">Max Connections Per Client IP</label>
                  <input id="set-max-conns-input" type="number" class="input tabular-nums" min="1" max="10000" placeholder="200" />
                  <span class="field-hint">Rate limiting per client IP (default: 200).</span>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div class="field">
                    <label class="field-label" for="set-front-max-ip-input">HTTP Front Max Conns Per IP</label>
                    <input id="set-front-max-ip-input" type="number" class="input tabular-nums" min="1" max="10000" placeholder="60" />
                    <span class="field-hint">Port-80 / front router limit per client IP (default: 60).</span>
                  </div>
                  <div class="field">
                    <label class="field-label" for="set-front-max-global-input">HTTP Front Max Global Conns</label>
                    <input id="set-front-max-global-input" type="number" class="input tabular-nums" min="1" max="50000" placeholder="5000" />
                    <span class="field-hint">Port-80 / front router total concurrent limit (default: 5000).</span>
                  </div>
                </div>

                <!-- Domain Lookup Controls -->
                <div class="field pt-2 border-t border-border space-y-3">
                  <label class="field-label mb-1">Public Domain Lookup API (/api/lookup)</label>
                  <div class="flex items-center gap-3 p-3 rounded-xl border border-border bg-surface-2/60">
                    <input id="set-lookup-enabled-switch" type="checkbox" class="checkbox" />
                    <label for="set-lookup-enabled-switch" class="flex flex-col cursor-pointer select-none">
                      <span class="text-sm font-medium text-txt">Enable Domain Lookup API</span>
                      <span class="text-xs text-txt-muted">Allow domain support checks from landing and setup portal pages</span>
                    </label>
                  </div>
                  <div class="flex items-center gap-3 p-3 rounded-xl border border-border bg-surface-2/60">
                    <input id="set-lookup-require-registered-switch" type="checkbox" class="checkbox" />
                    <label for="set-lookup-require-registered-switch" class="flex flex-col cursor-pointer select-none">
                      <span class="text-sm font-medium text-txt">Require Registered Client IP</span>
                      <span class="text-xs text-txt-muted">Restrict domain support check to registered and authorized client IPs only</span>
                    </label>
                  </div>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Security policies take effect immediately upon saving</span>
                <button id="set-save-access-btn" type="button" class="btn btn-primary btn-sm">Save Policies</button>
              </div>
            </section>

            <!-- Section 2: Network -->
            <section id="sec-network" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Network Configuration</h2>
                  <p class="text-xs text-txt-muted">Destination ports allowlist for outbound connection relaying</p>
                </div>
              </div>
              <div class="card-body space-y-4">
                <div class="field">
                  <label class="field-label" for="set-allowed-ports-input">Permitted Destination Ports</label>
                  <input id="set-allowed-ports-input" type="text" class="input font-mono" placeholder="443, 8443, 2053, 2083, 2087, 2096, 9443" />
                  <span class="field-hint">Comma-separated TCP ports permitted for outbound relay (e.g. "443, 8443").</span>
                </div>

                <!-- Quick Presets -->
                <div class="flex flex-wrap items-center gap-2 pt-1">
                  <span class="text-xs text-txt-muted font-medium mr-1">Quick Add:</span>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="443">443</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="8443">8443</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="2053">2053</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="2083">2083</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="2087">2087</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="2096">2096</button>
                  <button type="button" class="port-preset-btn px-2.5 py-1 rounded-md bg-surface-2 border border-border text-xs font-mono text-txt hover:border-primary-500 hover:text-primary-600 transition-colors" data-port="9443">9443</button>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Permitted destination ports update dynamically without service restart</span>
                <button id="set-save-network-btn" type="button" class="btn btn-primary btn-sm">Save Permitted Ports</button>
              </div>
            </section>

            <!-- Section: Upstream DNS Resolvers -->
            <section id="sec-dns" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Upstream DNS Resolvers</h2>
                  <p class="text-xs text-txt-muted">Configure 1–5 upstream servers with ordered fallback priority for resolving unconfigured domains</p>
                </div>
              </div>
              <div class="card-body space-y-4">
                <div id="set-dns-servers-list" class="space-y-3">
                  <!-- Dynamic rows rendered here -->
                </div>

                <div class="flex items-center justify-between pt-1">
                  <button id="set-dns-add-btn" type="button" class="btn btn-secondary btn-sm">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>
                    <span>Add Upstream Server</span>
                  </button>
                  <span class="text-xs text-txt-muted">Order defines priority: Primary &rarr; Secondary &rarr; Fallback</span>
                </div>

                <div class="pt-2 border-t border-border space-y-3">
                  <div class="flex items-center gap-3">
                    <button id="set-test-dns-btn" type="button" class="btn btn-secondary btn-sm">
                      <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                      <span>Test DNS Resolvers</span>
                    </button>
                    <span id="set-dns-test-status" class="text-xs text-txt-muted"></span>
                  </div>
                  <div id="set-dns-test-results" class="space-y-1.5 text-xs empty:hidden"></div>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Order matters: resolvers are tried in sequence until a valid answer is received</span>
                <button id="set-save-dns-btn" type="button" class="btn btn-primary btn-sm">Save Upstream DNS</button>
              </div>
            </section>

            <!-- Section 3: Egress Proxy -->
            <section id="sec-egress" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Upstream Egress Proxy</h2>
                  <p class="text-xs text-txt-muted">Forward relay traffic through an upstream SOCKS5 proxy (host:port)</p>
                </div>
              </div>
              <div class="card-body space-y-4">
                <div class="flex items-center gap-3 p-3.5 rounded-lg border border-border bg-surface-2/40">
                  <input id="set-egress-enabled-switch" type="checkbox" class="checkbox" />
                  <label for="set-egress-enabled-switch" class="flex flex-col cursor-pointer select-none">
                    <span class="text-sm font-medium text-txt">Enable Outbound Egress Proxy</span>
                    <span class="text-xs text-txt-subtle">When enabled, domain rules configured with egress proxy route traffic via this upstream</span>
                  </label>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div class="field md:col-span-3">
                    <label class="field-label" for="set-egress-addr">Proxy Address</label>
                    <input id="set-egress-addr" type="text" class="input font-mono text-xs" placeholder="127.0.0.1:1080" />
                    <span class="field-hint">SOCKS5 proxy (host:port)</span>
                  </div>
                  <div class="field">
                    <label class="field-label" for="set-egress-user">Proxy Username (Optional)</label>
                    <input id="set-egress-user" type="text" class="input text-xs" placeholder="username" />
                  </div>
                  <div class="field md:col-span-2">
                    <label class="field-label" for="set-egress-pass">Proxy Password (Optional)</label>
                    <input id="set-egress-pass" type="password" class="input text-xs" placeholder="••••••••" />
                    <span id="set-egress-pass-hint" class="field-hint hidden">Password currently saved. Leave empty to keep unchanged.</span>
                  </div>
                </div>

                <div class="flex items-center gap-3 pt-2">
                  <button id="set-test-proxy-btn" type="button" class="btn btn-secondary btn-sm">
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
                    <span>Test Proxy Connection</span>
                  </button>
                  <span id="set-proxy-test-result" class="text-xs font-medium"></span>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Test connection before saving to verify upstream latency</span>
                <button id="set-save-egress-btn" type="button" class="btn btn-primary btn-sm">Save Proxy Settings</button>
              </div>
            </section>

            <!-- Section 4: General Settings -->
            <section id="sec-general" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">General Settings</h2>
                  <p class="text-xs text-txt-muted">Timezone configuration, client hostname, and secret panel URL path</p>
                </div>
              </div>
              <div class="card-body space-y-5">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
                  <div class="field">
                    <label class="field-label" for="set-timezone-select">Display Timezone</label>
                    <select id="set-timezone-select" class="select text-sm"></select>
                    <span class="field-hint">Used to format timestamps in logs, dashboards, and tables.</span>
                  </div>

                  <div class="field">
                    <label class="field-label" for="set-server-domain-input">Public Server Domain / IP</label>
                    <input id="set-server-domain-input" type="text" class="input font-mono text-sm" placeholder="relay.example.com or server IP" />
                    <span class="field-hint">Canonical domain used in magic links and client connection strings.</span>
                  </div>
                </div>

                <div class="field pt-3 border-t border-border">
                  <label class="field-label" for="set-panel-path-input">Admin Panel Path Prefix</label>
                  <div class="flex items-center gap-2 max-w-md">
                    <input id="set-panel-path-input" type="text" class="input font-mono text-sm" placeholder="/" />
                    <button id="set-change-path-btn" type="button" class="btn btn-secondary btn-sm shrink-0">Change Path</button>
                  </div>
                  <span class="field-hint">Use a secret path prefix (e.g. "/aB3xK9") to hide admin interface. Redirects automatically upon change.</span>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Timezone and server domain take effect immediately</span>
                <button id="set-save-general-btn" type="button" class="btn btn-primary btn-sm">Save General Settings</button>
              </div>
            </section>

            <!-- Section 5: Admin Panel Credentials (Separate Card) -->
            <section id="sec-creds" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Admin Panel Credentials</h2>
                  <p class="text-xs text-txt-muted">Change username and password used for web admin panel authentication</p>
                </div>
              </div>
              <form id="set-admin-creds-form">
                <div class="card-body space-y-4 max-w-md">
                  <div class="field">
                    <label class="field-label" for="set-admin-current-pass">Current Password</label>
                    <input id="set-admin-current-pass" type="password" class="input text-sm" placeholder="Required to make changes" required />
                  </div>
                  <div class="field">
                    <label class="field-label" for="set-admin-new-user">New Username</label>
                    <input id="set-admin-new-user" type="text" class="input text-sm" placeholder="Leave empty to keep current" />
                  </div>
                  <div class="field">
                    <label class="field-label" for="set-admin-new-pass">New Password</label>
                    <input id="set-admin-new-pass" type="password" class="input text-sm" placeholder="Min 6 characters" minlength="6" />
                  </div>
                </div>
                <div class="card-footer">
                  <span class="text-xs text-txt-subtle">Credentials take effect immediately</span>
                  <button type="submit" class="btn btn-primary btn-sm">Update Credentials</button>
                </div>
              </form>
            </section>

            <!-- Section 6: Logging -->
            <section id="sec-logging" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Logging & Audit Configuration</h2>
                  <p class="text-xs text-txt-muted">Enable real-time connection logging and configure automated log retention</p>
                </div>
              </div>
              <div class="card-body space-y-4">
                <div class="flex items-center gap-3 p-3.5 rounded-lg border border-border bg-surface-2/40">
                  <input id="set-logs-enabled-switch" type="checkbox" class="checkbox" />
                  <label for="set-logs-enabled-switch" class="flex flex-col cursor-pointer select-none">
                    <span class="text-sm font-medium text-txt">Request Logging</span>
                    <span class="text-xs text-txt-subtle">Capture connection handshakes, SNI hostnames, and DNS resolutions into SQLite</span>
                  </label>
                </div>

                <div class="field max-w-xs">
                  <label class="field-label" for="set-logs-retention-select">Log Retention Period</label>
                  <select id="set-logs-retention-select" class="select text-sm">
                    <option value="24h">1 Day (24 Hours)</option>
                    <option value="3d">3 Days</option>
                    <option value="7d">7 Days</option>
                    <option value="14d">14 Days</option>
                    <option value="30d">30 Days</option>
                    <option value="90d">90 Days</option>
                    <option value="180d">180 Days</option>
                    <option value="365d">365 Days</option>
                  </select>
                  <span class="field-hint">Older logs are automatically purged on a periodic schedule.</span>
                </div>
              </div>
              <div class="card-footer">
                <span class="text-xs text-txt-subtle">Changes take effect immediately</span>
                <button id="set-save-logging-btn" type="button" class="btn btn-primary btn-sm">Save Logging</button>
              </div>
            </section>

            <!-- Section 7: Data & Backup -->
            <section id="sec-data" class="card scroll-mt-20">
              <div class="card-header">
                <div>
                  <h2 class="text-base font-semibold text-txt">Data & Backup</h2>
                  <p class="text-xs text-txt-muted">Export rules, users, and download complete database snapshots</p>
                </div>
              </div>
              <div class="card-body space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div class="p-4 rounded-xl border border-border bg-surface-2/40 flex flex-col justify-between gap-3">
                    <div>
                      <h4 class="text-sm font-semibold text-txt">Download SQLite Snapshot</h4>
                      <p class="text-xs text-txt-muted mt-1">Download raw binary .db file including all tables, history, and credentials.</p>
                    </div>
                    <button id="set-backup-db-btn" type="button" class="btn btn-secondary btn-sm self-start">
                      <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                      <span>Download .db Backup</span>
                    </button>
                  </div>

                  <div class="p-4 rounded-xl border border-border bg-surface-2/40 flex flex-col justify-between gap-3">
                    <div>
                      <h4 class="text-sm font-semibold text-txt">JSON Export</h4>
                      <p class="text-xs text-txt-muted mt-1">Export domain rules, users, and blacklist entries into portable JSON format.</p>
                    </div>
                    <button id="set-export-json-btn" type="button" class="btn btn-secondary btn-sm self-start">
                      <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
                      <span>Export JSON</span>
                    </button>
                  </div>
                </div>

                <div class="p-4 rounded-xl border border-dashed border-border flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div>
                    <h4 class="text-sm font-semibold text-txt">Import JSON Rules & Users</h4>
                    <p class="text-xs text-txt-muted mt-0.5">Upload a previously exported JSON file to merge or update rules.</p>
                  </div>
                  <label class="btn btn-primary btn-sm cursor-pointer shrink-0">
                    <input id="set-import-file-input" type="file" accept=".json" class="hidden" />
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
                    <span>Import JSON File</span>
                  </label>
                </div>
              </div>
            </section>
          </div>
        </div>
      </div>
    `
  );

  // Timezones select population
  const tzSelect = $('#set-timezone-select', container);
  for (const tz of TIMEZONES) {
    const opt = document.createElement('option');
    opt.value = tz;
    opt.textContent = tz;
    tzSelect.appendChild(opt);
  }

  function normalizeRetention(val) {
    if (!val) return '7d';
    const s = String(val).trim().toLowerCase();
    if (s === '24h' || s === '1d' || s === '1') return '24h';
    if (s === '72h' || s === '3d' || s === '3') return '3d';
    if (s === '168h' || s === '168h0m0s' || s === '7d' || s === '7') return '7d';
    if (s === '336h' || s === '336h0m0s' || s === '14d' || s === '14') return '14d';
    if (s === '720h' || s === '30d' || s === '30') return '30d';
    if (s === '90d' || s === '90') return '90d';
    if (s === '180d' || s === '180') return '180d';
    if (s === '365d' || s === '365') return '365d';
    return s;
  }

  async function loadSettings() {
    try {
      settings = await api.getSettings();
      store.setState({ settings });

      // 1. Access Mode Radios
      const curAccessMode = settings.access_mode === 'public' ? 'public' : 'user';
      const accessRadios = container.querySelectorAll('input[name="set_access_mode"]');
      accessRadios.forEach((r) => {
        r.checked = r.value === curAccessMode;
      });
      updateAccessRadioStyles(curAccessMode);

      // 2. Unknown Domain Policy Radios
      const curPolicy = settings.unknown_domain_policy === 'reject' ? 'reject' : 'allow_default_port';
      const policyRadios = container.querySelectorAll('input[name="set_unknown_policy"]');
      policyRadios.forEach((r) => {
        r.checked = r.value === curPolicy;
      });
      updatePolicyRadioStyles(curPolicy);

      // DNS Passthrough switch (GET key is dns_unauthorized_passthrough)
      $('#set-dns-passthrough-switch', container).checked = Boolean(settings.dns_unauthorized_passthrough);
      $('#set-max-conns-input', container).value = settings.max_connections_per_ip || 200;
      $('#set-front-max-ip-input', container).value = settings.http_front_max_conns_per_ip || 60;
      $('#set-front-max-global-input', container).value = settings.http_front_max_global_conns || 5000;

      // Lookup policy
      $('#set-lookup-enabled-switch', container).checked = settings.lookup_enabled !== false;
      $('#set-lookup-require-registered-switch', container).checked = Boolean(settings.lookup_require_registered);

      // Network: Permitted Ports
      $('#set-allowed-ports-input', container).value = Array.isArray(settings.allowed_dest_ports)
        ? settings.allowed_dest_ports.join(', ')
        : (settings.allowed_dest_ports || '443, 8443');

      // Upstream DNS Resolvers
      const rawDNS = settings.dns_upstream_addr || '';
      dnsServers = rawDNS ? rawDNS.split(',').map((s) => s.trim()).filter(Boolean) : ['1.1.1.1:53'];
      if (dnsServers.length === 0) dnsServers = ['1.1.1.1:53'];
      renderDNSServers();

      // Egress
      $('#set-egress-enabled-switch', container).checked = Boolean(settings.egress_proxy_enabled);
      $('#set-egress-addr', container).value = settings.egress_proxy_addr || '';
      $('#set-egress-user', container).value = settings.egress_proxy_user || '';
      if (settings.egress_proxy_has_password) {
        $('#set-egress-pass-hint', container).classList.remove('hidden');
      }

      // Logging
      $('#set-logs-enabled-switch', container).checked = Boolean(settings.request_logs_enabled);
      const retentionSelect = $('#set-logs-retention-select', container);
      const normalizedRetention = normalizeRetention(settings.request_logs_retention);
      if (!Array.from(retentionSelect.options).some((opt) => opt.value === normalizedRetention)) {
        const opt = document.createElement('option');
        opt.value = normalizedRetention;
        opt.textContent = `${normalizedRetention}`;
        retentionSelect.appendChild(opt);
      }
      retentionSelect.value = normalizedRetention;

      // General
      if (settings.timezone) {
        $('#set-timezone-select', container).value = settings.timezone;
      }
      $('#set-server-domain-input', container).value = settings.server_domain || '';
      $('#set-panel-path-input', container).value = settings.panel_path || '/';

      // Service Uptime
      $('#set-service-uptime', container).textContent = formatDuration(settings.uptime_seconds);
    } catch (err) {
      toast.error(err.message || 'Failed to load settings');
    }
  }

  function updateAccessRadioStyles(activeVal) {
    ['user', 'public'].forEach((val) => {
      const card = $(`#set-access-mode-opt-${val}`, container);
      if (card) {
        if (val === activeVal) {
          card.className =
            'flex items-start gap-3 p-3 rounded-xl border border-primary-500 bg-primary-soft/40 dark:bg-primary-soft/20 ring-1 ring-primary-500/20 cursor-pointer transition-colors';
        } else {
          card.className =
            'flex items-start gap-3 p-3 rounded-xl border border-border bg-surface-2/60 hover:bg-surface-hover cursor-pointer transition-colors';
        }
      }
    });

    // Toggle DNS Unauthorized Passthrough visibility (only available in User Mode)
    const passthroughContainer = $('#set-dns-passthrough-container', container);
    if (passthroughContainer) {
      passthroughContainer.classList.toggle('hidden', activeVal !== 'user');
    }
  }

  const policyStyles = {
    reject: {
      active: 'flex items-start gap-3 p-3 rounded-xl border border-red-500 bg-red-500/15 dark:bg-red-950/40 ring-1 ring-red-500/30 cursor-pointer transition-colors',
      inactive: 'flex items-start gap-3 p-3 rounded-xl border border-red-500/20 bg-red-500/5 dark:bg-red-950/10 hover:border-red-500/40 hover:bg-red-500/10 cursor-pointer transition-colors',
    },
    allow_default_port: {
      active: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500 bg-emerald-500/15 dark:bg-emerald-950/40 ring-1 ring-emerald-500/30 cursor-pointer transition-colors',
      inactive: 'flex items-start gap-3 p-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 dark:bg-emerald-950/10 hover:border-emerald-500/40 hover:bg-emerald-500/10 cursor-pointer transition-colors',
    },
  };

  function updatePolicyRadioStyles(activeVal) {
    ['reject', 'allow_default_port'].forEach((val) => {
      const card = $(`#set-unknown-policy-opt-${val}`, container);
      if (card && policyStyles[val]) {
        card.className = val === activeVal ? policyStyles[val].active : policyStyles[val].inactive;
      }
    });
  }

  // Radio change handlers
  $$('input[name="set_access_mode"]', container).forEach((radio) => {
    radio.addEventListener('change', () => {
      if (radio.checked) updateAccessRadioStyles(radio.value);
    });
  });

  $$('input[name="set_unknown_policy"]', container).forEach((radio) => {
    radio.addEventListener('change', () => {
      if (radio.checked) updatePolicyRadioStyles(radio.value);
    });
  });

  // Port preset buttons click handler
  $$('.port-preset-btn', container).forEach((btn) => {
    btn.addEventListener('click', () => {
      const port = btn.getAttribute('data-port');
      const input = $('#set-allowed-ports-input', container);
      if (!input || !port) return;

      let currentPorts = input.value
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean);

      if (currentPorts.includes(port)) {
        currentPorts = currentPorts.filter((p) => p !== port);
        toast.info(`Port ${port} removed`);
      } else {
        currentPorts.push(port);
        toast.info(`Port ${port} added`);
      }

      input.value = currentPorts.join(', ');
    });
  });

  // Sub-Navigation Tab Click Handlers (Smooth Scroll & Active State)
  const navBtns = $$('.settings-nav-link', container);
  const sections = $$('section[id^="sec-"]', container);

  function setActiveNavLink(targetId) {
    if (!targetId) return;
    navBtns.forEach((b) => {
      const match = b.getAttribute('data-target') === targetId;
      if (match) {
        b.className = 'settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-primary-600 bg-primary-soft font-semibold transition-colors text-left w-full shrink-0';
      } else {
        b.className = 'settings-nav-link flex items-center gap-2.5 px-3 py-2 rounded-lg text-txt-muted hover:text-txt hover:bg-surface-2 transition-colors text-left w-full shrink-0';
      }
    });
  }

  let isClickScrolling = false;
  let clickScrollTimer = null;

  navBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const targetEl = container.querySelector('#' + targetId);
      if (targetEl) {
        isClickScrolling = true;
        clearTimeout(clickScrollTimer);
        setActiveNavLink(targetId);
        targetEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        clickScrollTimer = setTimeout(() => {
          isClickScrolling = false;
        }, 800);
      }
    });
  });

  // ScrollSpy via IntersectionObserver
  const scrollObserver = new IntersectionObserver(
    (entries) => {
      if (isClickScrolling) return;
      const visible = entries.filter((e) => e.isIntersecting);
      if (visible.length > 0) {
        // Pick the entry closest to top / highest intersection ratio
        visible.sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        setActiveNavLink(visible[0].target.id);
      }
    },
    {
      root: null,
      rootMargin: '-80px 0px -55% 0px',
      threshold: [0.1, 0.25, 0.5],
    }
  );

  sections.forEach((sec) => scrollObserver.observe(sec));

  // Save Logging Settings
  $('#set-save-logging-btn', container).addEventListener('click', async () => {
    const logsEnabled = $('#set-logs-enabled-switch', container).checked;
    const retention = $('#set-logs-retention-select', container).value || '7d';

    try {
      await api.updateSettings({
        request_logs_enabled: logsEnabled,
        request_logs_retention: retention,
      });
      toast.success('Logging settings saved successfully');
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to save logging settings');
    }
  });

  // Save Access Policies
  $('#set-save-access-btn', container).addEventListener('click', async () => {
    const selectedAccessRadio = container.querySelector('input[name="set_access_mode"]:checked');
    const selectedPolicyRadio = container.querySelector('input[name="set_unknown_policy"]:checked');
    const accessMode = selectedAccessRadio ? selectedAccessRadio.value : 'user';
    const unknownPolicy = selectedPolicyRadio ? selectedPolicyRadio.value : 'allow_default_port';
    const dnsPassthrough = $('#set-dns-passthrough-switch', container).checked;
    const lookupEnabled = $('#set-lookup-enabled-switch', container).checked;
    const lookupRequireRegistered = $('#set-lookup-require-registered-switch', container).checked;
    const maxConnsRaw = parseInt($('#set-max-conns-input', container).value, 10);
    const maxConns = isNaN(maxConnsRaw) ? 200 : maxConnsRaw;

    if (maxConns < 1) {
      toast.warning('Max connections per IP must be at least 1');
      $('#set-max-conns-input', container)?.focus();
      return;
    }

    if (accessMode === 'public' && settings?.access_mode !== 'public') {
      const confirmed = await dialog.confirm({
        title: 'Switch to Public Access Mode?',
        message: 'Warning: Switching Access Mode to Public removes client authentication. The relay and DNS will become open to everyone without token authorization or IP registration. Are you sure you want to proceed?',
        confirmText: 'Switch to Public',
        danger: true,
      });
      if (!confirmed) return;
    }

    try {
      const frontMaxIP = parseInt($('#set-front-max-ip-input', container)?.value, 10);
      const frontMaxGlobal = parseInt($('#set-front-max-global-input', container)?.value, 10);
      // Note PUT key asymmetry: dns_unauthorized_passthrough_enabled
      await api.updateSettings({
        access_mode: accessMode,
        unknown_domain_policy: unknownPolicy,
        dns_unauthorized_passthrough_enabled: dnsPassthrough,
        lookup_enabled: lookupEnabled,
        lookup_require_registered: lookupRequireRegistered,
        max_connections_per_ip: maxConns,
        http_front_max_conns_per_ip: !isNaN(frontMaxIP) && frontMaxIP > 0 ? frontMaxIP : undefined,
        http_front_max_global_conns: !isNaN(frontMaxGlobal) && frontMaxGlobal > 0 ? frontMaxGlobal : undefined,
      });
      toast.success('Access policies saved successfully');
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to save access policies');
    }
  });

  // Admin Credentials Update
  $('#set-admin-creds-form', container).addEventListener('submit', async (e) => {
    e.preventDefault();
    const curPass = $('#set-admin-current-pass', container).value;
    const newUser = $('#set-admin-new-user', container).value.trim();
    const newPass = $('#set-admin-new-pass', container).value.trim();

    try {
      await api.updateAdminCredentials({
        current_password: curPass,
        new_username: newUser || undefined,
        new_password: newPass || undefined,
      });
      toast.success('Admin credentials updated successfully');
      $('#set-admin-current-pass', container).value = '';
      $('#set-admin-new-user', container).value = '';
      $('#set-admin-new-pass', container).value = '';
    } catch (err) {
      toast.error(err.message || 'Failed to update admin credentials');
    }
  });

  // Save Permitted Destination Ports
  $('#set-save-network-btn', container).addEventListener('click', async () => {
    const portsVal = $('#set-allowed-ports-input', container).value.trim();
    if (!portsVal) {
      toast.warning('Please specify at least one port');
      return;
    }

    const rawPorts = portsVal.split(',').map((p) => p.trim()).filter(Boolean);
    const parsedPorts = [];
    for (const p of rawPorts) {
      const portNum = parseInt(p, 10);
      if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
        toast.warning(`Invalid port: "${p}". Ports must be integers between 1 and 65535.`);
        $('#set-allowed-ports-input', container)?.focus();
        return;
      }
      parsedPorts.push(portNum);
    }

    const uniquePorts = Array.from(new Set(parsedPorts));
    if (uniquePorts.length === 0) {
      toast.warning('Please specify at least one valid port');
      return;
    }

    try {
      await api.updateSettings({
        allowed_dest_ports: uniquePorts,
      });
      toast.success('Permitted destination ports updated');
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to update permitted ports');
    }
  });

  // --- Upstream DNS Resolvers Handlers ---

  function syncInputsToState() {
    const inputs = $$('.set-dns-addr-input', container);
    inputs.forEach((input) => {
      const idx = parseInt(input.getAttribute('data-index'), 10);
      if (!isNaN(idx) && idx >= 0 && idx < dnsServers.length) {
        dnsServers[idx] = input.value;
      }
    });
  }

  function renderDNSServers() {
    const listEl = $('#set-dns-servers-list', container);
    if (!listEl) return;

    if (dnsServers.length === 0) {
      dnsServers = ['1.1.1.1:53'];
    }

    const items = dnsServers.map((addr, idx) => {
      let roleLabel = 'Primary';
      let badgeClass = 'badge badge-primary';
      if (idx === 1) {
        roleLabel = 'Secondary';
        badgeClass = 'badge badge-neutral';
      } else if (idx > 1) {
        roleLabel = `Fallback ${idx + 1}`;
        badgeClass = 'badge badge-neutral opacity-80';
      }

      return html`
        <div class="flex items-center gap-2 p-2 rounded-lg bg-surface-2/40 border border-border set-dns-row" data-index="${idx}">
          <span class="${badgeClass} font-mono text-xs w-24 justify-center shrink-0">${roleLabel}</span>
          <input
            type="text"
            class="input font-mono text-xs flex-1 set-dns-addr-input"
            placeholder="e.g. 1.1.1.1:53 or 8.8.8.8"
            value="${escapeHtml(addr)}"
            data-index="${idx}"
          />
          <div class="flex items-center gap-1 shrink-0">
            <button
              type="button"
              class="btn btn-secondary btn-sm p-1.5 set-dns-up-btn"
              data-index="${idx}"
              ${idx === 0 ? 'disabled' : ''}
              title="Move Up in priority"
            >
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>
            </button>
            <button
              type="button"
              class="btn btn-secondary btn-sm p-1.5 set-dns-down-btn"
              data-index="${idx}"
              ${idx === dnsServers.length - 1 ? 'disabled' : ''}
              title="Move Down in priority"
            >
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
            </button>
            <button
              type="button"
              class="btn btn-danger btn-sm p-1.5 set-dns-remove-btn"
              data-index="${idx}"
              ${dnsServers.length <= 1 ? 'disabled' : ''}
              title="Remove upstream"
            >
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
            </button>
          </div>
        </div>
      `;
    });

    setHtml(listEl, items.join(''));

    const addBtn = $('#set-dns-add-btn', container);
    if (addBtn) {
      addBtn.disabled = dnsServers.length >= 5;
    }

    $$('.set-dns-addr-input', listEl).forEach((input) => {
      input.addEventListener('input', () => {
        const idx = parseInt(input.getAttribute('data-index'), 10);
        if (!isNaN(idx) && idx >= 0 && idx < dnsServers.length) {
          dnsServers[idx] = input.value;
        }
      });
    });

    $$('.set-dns-up-btn', listEl).forEach((btn) => {
      btn.addEventListener('click', () => {
        syncInputsToState();
        const idx = parseInt(btn.getAttribute('data-index'), 10);
        if (idx > 0) {
          const temp = dnsServers[idx];
          dnsServers[idx] = dnsServers[idx - 1];
          dnsServers[idx - 1] = temp;
          renderDNSServers();
        }
      });
    });

    $$('.set-dns-down-btn', listEl).forEach((btn) => {
      btn.addEventListener('click', () => {
        syncInputsToState();
        const idx = parseInt(btn.getAttribute('data-index'), 10);
        if (idx < dnsServers.length - 1) {
          const temp = dnsServers[idx];
          dnsServers[idx] = dnsServers[idx + 1];
          dnsServers[idx + 1] = temp;
          renderDNSServers();
        }
      });
    });

    $$('.set-dns-remove-btn', listEl).forEach((btn) => {
      btn.addEventListener('click', () => {
        syncInputsToState();
        const idx = parseInt(btn.getAttribute('data-index'), 10);
        if (dnsServers.length > 1) {
          dnsServers.splice(idx, 1);
          renderDNSServers();
        }
      });
    });
  }

  $('#set-dns-add-btn', container).addEventListener('click', () => {
    syncInputsToState();
    if (dnsServers.length >= 5) {
      toast.warning('Maximum 5 upstream DNS resolvers allowed');
      return;
    }
    dnsServers.push('');
    renderDNSServers();
    const inputs = $$('.set-dns-addr-input', container);
    if (inputs.length > 0) {
      inputs[inputs.length - 1].focus();
    }
  });

  $('#set-test-dns-btn', container).addEventListener('click', async () => {
    syncInputsToState();
    const addrs = dnsServers.map((s) => s.trim()).filter(Boolean);
    if (addrs.length === 0) {
      toast.warning('Please enter at least one upstream DNS address');
      return;
    }

    const testBtn = $('#set-test-dns-btn', container);
    const statusEl = $('#set-dns-test-status', container);
    const resultsEl = $('#set-dns-test-results', container);

    testBtn.disabled = true;
    statusEl.textContent = 'Testing connectivity...';
    setHtml(resultsEl, '');

    try {
      const results = await api.testDns({ addrs });
      statusEl.textContent = '';

      if (!Array.isArray(results) || results.length === 0) {
        setHtml(resultsEl, html`<div class="text-txt-muted">No test results returned.</div>`);
        return;
      }

      const rows = results.map((res) => {
        if (res.ok) {
          return html`
            <div class="flex items-center gap-2 text-emerald-600 dark:text-emerald-400 font-medium">
              <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>
              <span class="font-mono">${escapeHtml(res.addr)}</span>
              <span>&mdash; OK (${res.latency_ms || 0} ms)</span>
            </div>
          `;
        }
        return html`
          <div class="flex items-center gap-2 text-danger font-medium">
            <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>
            <span class="font-mono">${escapeHtml(res.addr)}</span>
            <span>&mdash; Failed: ${escapeHtml(res.error || 'Server error')}</span>
          </div>
        `;
      });

      setHtml(resultsEl, rows.join(''));
      const allOk = results.every((r) => r.ok);
      if (allOk) {
        toast.success('All tested upstream DNS resolvers are responding');
      } else {
        toast.warning('Some upstream DNS resolvers failed to respond');
      }
    } catch (err) {
      statusEl.textContent = '';
      setHtml(resultsEl, html`<div class="text-danger">Test failed: ${escapeHtml(err.message)}</div>`);
      toast.error(`DNS test error: ${err.message}`);
    } finally {
      testBtn.disabled = false;
    }
  });

  $('#set-save-dns-btn', container).addEventListener('click', async () => {
    syncInputsToState();
    const addrs = dnsServers.map((s) => s.trim()).filter(Boolean);
    if (addrs.length === 0) {
      toast.warning('Please enter at least one upstream DNS address');
      return;
    }

    try {
      await api.updateSettings({
        dns_upstream_addr: addrs.join(','),
      });
      toast.success('Upstream DNS resolvers saved successfully');
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to save upstream DNS resolvers');
    }
  });

  // Test Egress Proxy (supports real-time typed values without saving first)
  $('#set-test-proxy-btn', container).addEventListener('click', async () => {
    const resultEl = $('#set-proxy-test-result', container);
    const addr = $('#set-egress-addr', container).value.trim();
    const user = $('#set-egress-user', container).value.trim();
    const pass = $('#set-egress-pass', container).value;

    resultEl.className = 'text-xs text-txt-muted';
    resultEl.textContent = 'Testing connection...';

    try {
      const res = await api.testProxy({
        addr,
        user,
        password: pass,
      });
      if (res.ok) {
        resultEl.className = 'text-xs text-emerald-600 dark:text-emerald-400 font-semibold';
        resultEl.textContent = `Success (${res.latency_ms || 0} ms latency)`;
        toast.success(`Proxy connection successful (${res.latency_ms || 0} ms latency)`);
      } else {
        resultEl.className = 'text-xs text-danger font-semibold';
        resultEl.textContent = `Failed: ${res.error || 'Connection failed'}`;
        toast.error(`Proxy test failed: ${res.error || 'Connection failed'}`);
      }
    } catch (err) {
      resultEl.className = 'text-xs text-danger font-semibold';
      resultEl.textContent = `Error: ${err.message}`;
      toast.error(`Proxy test error: ${err.message}`);
    }
  });

  // Save Egress Proxy
  $('#set-save-egress-btn', container).addEventListener('click', async () => {
    const enabled = $('#set-egress-enabled-switch', container).checked;
    const addr = $('#set-egress-addr', container).value.trim();
    const user = $('#set-egress-user', container).value.trim();
    const pass = $('#set-egress-pass', container).value;

    const payload = {
      egress_proxy_enabled: enabled,
      egress_proxy_addr: addr,
      egress_proxy_user: user,
    };
    if (pass) {
      payload.egress_proxy_password = pass;
    }

    try {
      await api.updateSettings(payload);
      toast.success('Egress proxy settings saved');
      $('#set-egress-pass', container).value = '';
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to save egress proxy settings');
    }
  });

  // Save General (Timezone & Server Domain)
  $('#set-save-general-btn', container).addEventListener('click', async () => {
    const tz = $('#set-timezone-select', container).value;
    const serverDomain = $('#set-server-domain-input', container).value.trim();

    try {
      await api.updateSettings({
        timezone: tz,
        server_domain: serverDomain,
      });
      toast.success('General settings saved');
      await loadSettings();
    } catch (err) {
      toast.error(err.message || 'Failed to save settings');
    }
  });

  // Change Admin Panel Path Prefix
  $('#set-change-path-btn', container).addEventListener('click', async () => {
    let newPath = $('#set-panel-path-input', container).value.trim();
    if (!newPath.startsWith('/')) newPath = '/' + newPath;

    const confirmed = await dialog.confirm({
      title: 'Change Admin Panel Path',
      message: `Are you sure you want to move the admin panel to "${newPath}"? You will be redirected immediately to the new URL.`,
      confirmText: 'Change Path & Redirect',
      danger: true,
    });
    if (!confirmed) return;

    try {
      await api.updateSettings({ panel_path: newPath });
      toast.success('Path prefix changed. Redirecting...');
      setTimeout(() => {
        let redirectUrl = newPath.endsWith('/') ? newPath : newPath + '/';
        window.location.href = redirectUrl;
      }, 1000);
    } catch (err) {
      toast.error(err.message || 'Failed to update panel path');
    }
  });

  // Backup SQLite DB
  $('#set-backup-db-btn', container).addEventListener('click', () => {
    window.location.href = getApiUrl('api/backup');
  });

  // Export JSON
  $('#set-export-json-btn', container).addEventListener('click', () => {
    window.location.href = getApiUrl('api/export');
  });

  // Import JSON File
  $('#set-import-file-input', container).addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    try {
      const text = await file.text();
      const jsonData = JSON.parse(text);

      const res = await api.importData(jsonData);
      dialog.open({
        title: 'Import Results Summary',
        content: `
          <div class="space-y-2 text-sm text-txt">
            <p class="font-medium text-emerald-600 dark:text-emerald-400">Data imported successfully!</p>
            <ul class="list-disc list-inside space-y-1 text-xs text-txt-muted">
              <li>Domains: ${res.domains_added || 0} added, ${res.domains_updated || 0} updated</li>
              <li>Blacklist: ${res.blacklist_added || 0} added, ${res.blacklist_updated || 0} updated</li>
              <li>Users: ${res.users_added || 0} added, ${res.users_updated || 0} updated</li>
            </ul>
          </div>
        `,
        actions: [{ text: 'Done', className: 'btn btn-primary', value: true }],
      });
      await loadSettings();
    } catch (err) {
      toast.error('Import failed: ' + (err.message || 'Invalid JSON file'));
    } finally {
      e.target.value = '';
    }
  });

  // Restart Service & Polling dialog (Fixes B8)
  $('#set-restart-service-btn', container).addEventListener('click', async () => {
    const confirmed = await dialog.confirm({
      title: 'Restart TLS Relay Service',
      message: 'Are you sure you want to restart the background service? Connection listeners will drop for 2–3 seconds while restarting.',
      confirmText: 'Restart Service',
      danger: true,
    });
    if (!confirmed) return;

    // Show Progress Dialog
    const progressContent = document.createElement('div');
    progressContent.className = 'flex flex-col items-center justify-center py-6 gap-3';
    progressContent.innerHTML = `
      <div class="w-8 h-8 border-3 border-primary-500 border-t-transparent rounded-full animate-spin"></div>
      <div class="text-sm font-semibold text-txt">Restarting Service...</div>
      <p class="text-xs text-txt-muted text-center max-w-xs">Waiting for relay process to come back online. The page will reload automatically.</p>
    `;

    const progressModal = dialog.open({
      title: 'Service Restart',
      content: progressContent,
      size: 'sm',
    });

    try {
      await api.serviceRestart();
    } catch {
      // Expected if connection closes immediately on restart
    }

    // Poll until backend is healthy again
    let attempts = 0;
    const interval = setInterval(async () => {
      attempts++;
      try {
        const check = await fetch(getApiUrl('api/settings'), { method: 'GET', credentials: 'include' });
        if (check.ok) {
          clearInterval(interval);
          progressModal.close();
          toast.success('Service is back online!');
          setTimeout(() => window.location.reload(), 500);
        }
      } catch {
        // Still down
      }
      if (attempts > 30) {
        clearInterval(interval);
        progressModal.close();
        toast.error('Service took too long to respond. Please refresh manually.');
      }
    }, 1000);
  });

  loadSettings();

  return {
    unmount: () => {
      clearTimeout(clickScrollTimer);
      scrollObserver.disconnect();
      container.innerHTML = '';
    },
  };
}
