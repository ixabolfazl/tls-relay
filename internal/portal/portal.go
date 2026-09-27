// Package portal provides handlers for magic-link based IP registration,
// a public landing page (DNS info, domain lookup, magic link form), client setup
// instructions, and a public domain lookup API. These handlers can run standalone
// or be embedded directly into the main panel HTTP server.
package portal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ixabolfazl/tls-relay/internal/access"
	"github.com/ixabolfazl/tls-relay/internal/rules"
	"github.com/ixabolfazl/tls-relay/internal/sqlitestore"
)

// ---------------------------------------------------------------------------
// Shared CSS (injected into both landing and setup pages)
// ---------------------------------------------------------------------------

const sharedCSS = `
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #f6f7f9;
      --surface: #ffffff;
      --text: #0f1320;
      --text-muted: #6b7280;
      --border: rgba(15,19,32,0.08);
      --accent: #5b6cff;
      --success: #16a34a;
      --error: #dc2626;
      --warn: #d97706;
      --shadow: 0 1px 2px rgba(15,19,32,0.04), 0 8px 24px rgba(15,19,32,0.06);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0a0c12;
        --surface: #12151d;
        --text: #e8eaed;
        --text-muted: #8a8f99;
        --border: rgba(255,255,255,0.08);
        --accent: #8a9bff;
        --success: #4ade80;
        --error: #f87171;
        --warn: #fbbf24;
        --shadow: 0 1px 2px rgba(0,0,0,0.4), 0 12px 32px rgba(0,0,0,0.35);
      }
    }
    body {
      margin: 0;
      padding: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      box-sizing: border-box;
    }
    .container {
      width: 100%;
      max-width: 540px;
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: var(--shadow);
    }
    .label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--text-muted);
      margin-bottom: 6px;
      font-weight: 600;
    }
    .value {
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }
    .mono {
      font-family: "SF Mono", "Consolas", "Liberation Mono", Menlo, monospace;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      font-size: 12px;
      font-weight: 600;
      padding: 3px 9px;
      border-radius: 9999px;
      margin-top: 8px;
    }
    .badge-ok {
      background: rgba(22,163,74,0.12);
      color: var(--success);
    }
    .badge-warn {
      background: rgba(217,119,6,0.12);
      color: var(--warn);
    }
    .dns-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-top: 6px;
    }
    .dns-item {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .dns-name {
      font-size: 13px;
      color: var(--text-muted);
    }
    .dns-val-wrap {
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
    }
    .dns-val {
      font-family: "SF Mono", "Consolas", "Liberation Mono", Menlo, monospace;
      font-size: 14px;
      font-weight: 600;
    }
    .copy-btn {
      background: transparent;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 3px 8px;
      font-size: 11px;
      cursor: pointer;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 4px;
      transition: all 0.15s;
    }
    .copy-btn:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    .copy-btn.copied {
      background: var(--success);
      border-color: var(--success);
      color: #fff;
    }
    .card-title {
      font-size: 15px;
      font-weight: 600;
      margin-bottom: 4px;
    }
    .hint-top {
      font-size: 12px;
      color: var(--text-muted);
      margin: 0 0 12px 0;
    }
    .form-row {
      display: flex;
      gap: 8px;
    }
    .form-row input {
      flex: 1;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 9px 12px;
      font-size: 14px;
      background: var(--bg);
      color: var(--text);
      outline: none;
      transition: border-color 0.15s;
    }
    .form-row input:focus {
      border-color: var(--accent);
    }
    .form-row button {
      background: var(--accent);
      color: #ffffff;
      border: none;
      border-radius: 8px;
      padding: 9px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: opacity 0.15s;
    }
    .form-row button:hover {
      opacity: 0.9;
    }
    .result {
      margin-top: 10px;
      font-size: 13px;
      display: none;
    }
    .result.visible {
      display: block;
    }
    .res-ok   { color: var(--success); }
    .res-bad  { color: var(--error); }
    .res-warn { color: var(--warn); }
    .steps {
      display: flex;
      flex-direction: column;
      gap: 12px;
      margin-top: 6px;
    }
    .step {
      display: flex;
      gap: 10px;
      align-items: flex-start;
      font-size: 13px;
      line-height: 1.5;
    }
    .step-num {
      flex-shrink: 0;
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: var(--accent);
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-top: 1px;
    }
    .step-body {
      color: var(--text-muted);
    }
    .step-body strong {
      color: var(--text);
    }
    .footer-link {
      text-align: center;
      font-size: 12px;
    }
    .footer-link a {
      color: var(--text-muted);
      text-decoration: none;
    }
    .footer-link a:hover {
      color: var(--accent);
    }
`

// ---------------------------------------------------------------------------
// Landing page HTML
// ---------------------------------------------------------------------------

const landingHTMLRaw = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <title>DNS Setup</title>
  <style>` + sharedCSS + `  </style>
</head>
<body>
  <div class="container">

    <!-- IP Card -->
    <div class="card">
      <div class="label">Your IP Address</div>
      <div class="value mono">{{.ClientIP}}</div>
      {{.IPStatusBadge}}
    </div>

    <!-- DNS Servers -->
    <div class="card">
      <div class="label">DNS Addresses</div>
      <div class="dns-list">
        <div class="dns-item">
          <span class="dns-name">Primary DNS</span>
          <div class="dns-val-wrap" onclick="copyDNS('{{.PrimaryDNS}}', this)" title="Click to copy">
            <span class="dns-val">{{.PrimaryDNS}}</span>
            <button class="copy-btn" type="button">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
        <div class="dns-item">
          <span class="dns-name">Secondary DNS</span>
          <div class="dns-val-wrap" onclick="copyDNS('{{.SecondaryDNS}}', this)" title="Click to copy">
            <span class="dns-val">{{.SecondaryDNS}}</span>
            <button class="copy-btn" type="button">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Domain Lookup -->
    <div class="card">
      <div class="card-title">Domain Support Check</div>
      <p class="hint-top">Enter a domain or paste a full URL to check if it is supported by this relay.</p>
      <div class="form-row">
        <input type="text" id="lookup-input" placeholder="e.g. example.com or https://..." autocomplete="off" spellcheck="false" />
        <button id="lookup-btn" onclick="doLookup()">Check</button>
      </div>
      <div id="lookup-result" class="result"></div>
    </div>

    <!-- Magic Link Registration -->
    <div class="card">
      <div class="card-title">Register via Magic Link</div>
      <p class="hint-top">Paste your magic link URL or token to register this IP address.</p>
      <div class="form-row">
        <input type="text" id="magic-input" placeholder="e.g. 550e8400-e29b-41d4-a716-446655440000" autocomplete="off" spellcheck="false" />
        <button id="magic-btn" onclick="doMagicLink()">Register</button>
      </div>
      <div id="magic-result" class="result"></div>
    </div>

    <!-- Setup Guide Link -->
    <div class="card">
      <div class="card-title">Setup Instructions</div>
      <p class="hint-top" style="margin-bottom: 8px;">Configure your operating system or router to use these DNS servers.</p>
      <div class="steps">
        <div class="step">
          <span class="step-num">1</span>
          <span class="step-body">Open your device <strong>Network Settings</strong>.</span>
        </div>
        <div class="step">
          <span class="step-num">2</span>
          <span class="step-body">Change DNS server to <strong class="mono">{{.PrimaryDNS}}</strong>.</span>
        </div>
        <div class="step">
          <span class="step-num">3</span>
          <span class="step-body">Ensure your IP is registered (via Magic Link above).</span>
        </div>
      </div>
    </div>

  </div>

  <script>
  function copyDNS(text, btnElement) {
    if (!text || text === '—') return;
    function markCopied() {
      const btn = btnElement || event.currentTarget;
      if (btn) {
        const span = btn.querySelector('span') || btn;
        const orig = span ? span.textContent : 'Copy';
        btn.classList.add('copied');
        if (span) span.textContent = 'Copied!';
        setTimeout(() => {
          btn.classList.remove('copied');
          if (span) span.textContent = orig;
        }, 2000);
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(markCopied).catch(() => fallbackCopy(text, markCopied));
    } else {
      fallbackCopy(text, markCopied);
    }
  }

  function fallbackCopy(text, cb) {
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      if (document.execCommand('copy')) {
        cb();
      }
    } catch (err) {}
    document.body.removeChild(textArea);
  }

  async function doLookup() {
    const input = document.getElementById('lookup-input');
    const res = document.getElementById('lookup-result');
    const raw = (input.value || '').trim();
    if (!raw) return;

    res.className = 'result visible res-warn';
    res.textContent = 'Checking...';

    try {
      const r = await fetch('/api/lookup?domain=' + encodeURIComponent(raw));
      const data = await r.json();
      if (!r.ok) {
        res.className = 'result visible res-bad';
        res.textContent = data.error || 'Lookup failed';
        return;
      }
      if (data.result === 'proxy') {
        res.className = 'result visible res-ok';
        res.textContent = '✓ Supported: ' + data.domain + ' is routed through the relay.';
      } else if (data.result === 'blocked') {
        res.className = 'result visible res-bad';
        res.textContent = '✕ Blocked: ' + data.domain + ' is explicitly blocked.';
      } else {
        res.className = 'result visible res-warn';
        res.textContent = '— Unsupported: ' + data.domain + ' is not in the relay rule list.';
      }
    } catch (e) {
      res.className = 'result visible res-bad';
      res.textContent = 'Network error. Please try again.';
    }
  }

  async function doMagicLink() {
    const input = document.getElementById('magic-input');
    const res = document.getElementById('magic-result');
    const raw = (input.value || '').trim();
    if (!raw) return;

    res.className = 'result visible res-warn';
    res.textContent = 'Registering IP...';

    let token = raw;
    if (raw.includes('/connect/') || raw.includes('/setup/')) {
      const parts = raw.split('/');
      token = parts[parts.length - 1] || parts[parts.length - 2];
    }

    try {
      const r = await fetch('/connect/' + encodeURIComponent(token), {
        headers: { 'Accept': 'text/plain' }
      });
      const text = await r.text();
      if (r.ok) {
        res.className = 'result visible res-ok';
        res.textContent = '✓ IP successfully registered (' + text.trim() + '). Refreshing...';
        setTimeout(() => location.reload(), 1500);
      } else {
        res.className = 'result visible res-bad';
        res.textContent = '✕ ' + (text.trim() || 'Registration failed (' + r.status + ')');
      }
    } catch (e) {
      res.className = 'result visible res-bad';
      res.textContent = 'Network error. Please try again.';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const li = document.getElementById('lookup-input');
    if (li) li.addEventListener('keydown', e => { if (e.key === 'Enter') doLookup(); });
    const mi = document.getElementById('magic-input');
    if (mi) mi.addEventListener('keydown', e => { if (e.key === 'Enter') doMagicLink(); });
  });
  </script>
</body>
</html>
`

// ---------------------------------------------------------------------------
// Setup/connect success page HTML (shown in browser after magic link visit)
// ---------------------------------------------------------------------------

const setupHTMLRaw = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="color-scheme" content="light dark">
  <title>DNS Setup</title>
  <style>` + sharedCSS + `  </style>
</head>
<body>
  <div class="container">

    <!-- IP Card -->
    <div class="card">
      <div class="label">Your IP Address</div>
      <div class="value mono">{{.ClientIP}}</div>
      <span class="badge badge-ok">✓ Registered</span>
    </div>

    <!-- DNS Addresses -->
    <div class="card">
      <div class="label">DNS Addresses</div>
      <div class="dns-list">
        <div class="dns-item">
          <span class="dns-name">Primary DNS</span>
          <div class="dns-val-wrap" onclick="copyDNS('{{.PrimaryDNS}}', this)" title="Click to copy">
            <span class="dns-val">{{.PrimaryDNS}}</span>
            <button class="copy-btn" type="button">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
        <div class="dns-item">
          <span class="dns-name">Secondary DNS</span>
          <div class="dns-val-wrap" onclick="copyDNS('{{.SecondaryDNS}}', this)" title="Click to copy">
            <span class="dns-val">{{.SecondaryDNS}}</span>
            <button class="copy-btn" type="button">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
              <span>Copy</span>
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Domain Support Check -->
    <div class="card">
      <div class="card-title">Domain Support Check</div>
      <p class="hint-top">Enter a domain to check if it is supported by this relay.</p>
      <div class="form-row">
        <input type="text" id="domain-input" placeholder="e.g. example.com" autocomplete="off" spellcheck="false" />
        <button id="check-btn" onclick="checkDomain()">Check</button>
      </div>
      <div id="result" class="result"></div>
    </div>

    <div class="footer-link"><a href="/">Home</a></div>
  </div>
  <script>
  function copyDNS(text, btnElement) {
    if (!text || text === '—') return;
    function markCopied() {
      const btn = btnElement || event.currentTarget;
      if (btn) {
        const span = btn.querySelector('span') || btn;
        const orig = span ? span.textContent : 'Copy';
        btn.classList.add('copied');
        if (span) span.textContent = 'Copied!';
        setTimeout(() => {
          btn.classList.remove('copied');
          if (span) span.textContent = orig;
        }, 2000);
      }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(markCopied).catch(() => fallbackCopy(text, markCopied));
    } else {
      fallbackCopy(text, markCopied);
    }
  }

  function fallbackCopy(text, cb) {
    var textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
      if (document.execCommand('copy')) {
        cb();
      }
    } catch (err) {}
    document.body.removeChild(textArea);
  }

  async function checkDomain() {
    const input = document.getElementById('domain-input');
    const res = document.getElementById('result');
    const raw = (input.value || '').trim();
    if (!raw) return;

    res.className = 'result visible res-warn';
    res.textContent = 'Checking...';

    try {
      const r = await fetch('/api/lookup?domain=' + encodeURIComponent(raw));
      const data = await r.json();
      if (!r.ok) {
        res.className = 'result visible res-bad';
        res.textContent = data.error || 'Lookup failed';
        return;
      }
      if (data.result === 'proxy') {
        res.className = 'result visible res-ok';
        res.textContent = '✓ Supported: ' + data.domain + ' is routed through the relay.';
      } else if (data.result === 'blocked') {
        res.className = 'result visible res-bad';
        res.textContent = '✕ Blocked: ' + data.domain + ' is explicitly blocked.';
      } else {
        res.className = 'result visible res-warn';
        res.textContent = '— Unsupported: ' + data.domain + ' is not in the relay rule list.';
      }
    } catch (e) {
      res.className = 'result visible res-bad';
      res.textContent = 'Network error. Please try again.';
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('domain-input');
    if (input) {
      input.addEventListener('keydown', e => {
        if (e.key === 'Enter') checkDomain();
      });
    }
  });
  </script>
</body>
</html>
`

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

type rateLimiter struct {
	mu          sync.Mutex
	buckets     map[string]*tokenBucket
	ratePerSec  float64
	burst       int
	cleanupTick time.Time
}

type tokenBucket struct {
	tokens   float64
	lastFill time.Time
}

func newRateLimiter(ratePerSec float64, burst int) *rateLimiter {
	return &rateLimiter{
		buckets:     make(map[string]*tokenBucket),
		ratePerSec:  ratePerSec,
		burst:       burst,
		cleanupTick: time.Now(),
	}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.cleanupTick) > 5*time.Minute {
		for k, b := range rl.buckets {
			if now.Sub(b.lastFill) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.cleanupTick = now
	}

	b, ok := rl.buckets[ip]
	if !ok {
		b = &tokenBucket{tokens: float64(rl.burst), lastFill: now}
		rl.buckets[ip] = b
	}

	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * rl.ratePerSec
	if b.tokens > float64(rl.burst) {
		b.tokens = float64(rl.burst)
	}
	b.lastFill = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Refresher is the interface for triggering cache refreshes after writes.
type Refresher interface {
	RefreshUserIPs(ctx context.Context) error
}

// Server holds dependencies for public portal, magic link, and landing page handlers.
type Server struct {
	mu           sync.RWMutex
	addr         string
	serverIP     string
	serverDomain string
	store        *sqlitestore.Store
	accessStore  *access.AccessStore
	ruleStore    *rules.RuleStore
	refresher    Refresher
	httpServer   *http.Server
	lookupRL     *rateLimiter
}

// New creates a portal Server.
func New(addr string, store *sqlitestore.Store, accessStore *access.AccessStore, refresher Refresher) *Server {
	return &Server{
		addr:        addr,
		store:       store,
		accessStore: accessStore,
		refresher:   refresher,
		lookupRL:    newRateLimiter(10, 20),
	}
}

// SetServerIP sets the public server IP address to display as DNS server address.
func (s *Server) SetServerIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverIP = strings.TrimSpace(ip)
}

// ServerIP returns the configured server IP.
func (s *Server) ServerIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverIP
}

// SetServerDomain sets the public domain name or hostname for client URLs.
func (s *Server) SetServerDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serverDomain = strings.TrimSpace(domain)
}

// ServerDomain returns the configured server domain.
func (s *Server) ServerDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serverDomain
}

// SetRuleStore registers the rule store so /api/lookup can answer domain queries.
func (s *Server) SetRuleStore(rs *rules.RuleStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ruleStore = rs
}

// BaseHost returns the server domain if set, otherwise falls back to the server IP or request host.
func (s *Server) BaseHost(r *http.Request) string {
	s.mu.RLock()
	domain := s.serverDomain
	ip := s.serverIP
	s.mu.RUnlock()

	if domain != "" {
		return domain
	}
	if ip != "" {
		return ip
	}
	if r != nil {
		host, _, err := net.SplitHostPort(r.Host)
		if err == nil && host != "" {
			return host
		}
		if r.Host != "" {
			return r.Host
		}
	}
	return "—"
}

// BaseURL returns the canonical base URL (using http:// for the standard port 80 service).
func (s *Server) BaseURL(r *http.Request) string {
	host := s.BaseHost(r)
	if host == "—" || host == "" {
		return "http://localhost"
	}
	return "http://" + host
}

func (s *Server) getServerIP(r *http.Request) string {
	s.mu.RLock()
	ip := s.serverIP
	s.mu.RUnlock()

	if ip != "" {
		return ip
	}
	if r != nil {
		host, _, err := net.SplitHostPort(r.Host)
		if err == nil && net.ParseIP(host) != nil {
			return host
		}
		if net.ParseIP(r.Host) != nil {
			return r.Host
		}
	}
	return "—"
}

// RegisterHandlersWithLandingAt registers all public routes onto the given mux,
// placing the landing page at "/".
func (s *Server) RegisterHandlersWithLandingAt(mux *http.ServeMux) {
	mux.HandleFunc("GET /connect/{magic_link}", s.handleConnect)
	mux.HandleFunc("GET /setup/{magic_link}", s.handleConnect)
	mux.HandleFunc("GET /setup", s.handleConnect)
	mux.HandleFunc("GET /api/lookup", s.handleLookup)
	mux.HandleFunc("GET /", s.handleLanding)
}

// ListenAndServe starts the portal HTTP server standalone (backward compat).
func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()
	s.RegisterHandlersWithLandingAt(mux)

	s.httpServer = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("portal listen on %s: %w", s.addr, err)
	}
	slog.Info("portal service listening", "addr", s.addr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutCtx)
	}()

	if err := s.httpServer.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("portal server: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	clientIP := extractIP(r.RemoteAddr)
	dnsIP := s.getServerIP(r)

	var isReg bool
	if s.store != nil {
		isReg, _ = s.store.IsIPRegistered(r.Context(), clientIP)
	}
	var badgeHTML string
	if isReg {
		badgeHTML = `<span class="badge badge-ok">✓ Registered</span>`
	} else {
		badgeHTML = `<span class="badge badge-warn">Not Registered</span>`
	}

	out := landingHTMLRaw
	out = strings.ReplaceAll(out, "{{.ClientIP}}", htmlEscape(clientIP))
	out = strings.ReplaceAll(out, "{{.IPStatusBadge}}", badgeHTML)
	out = strings.ReplaceAll(out, "{{.PrimaryDNS}}", htmlEscape(dnsIP))
	out = strings.ReplaceAll(out, "{{.SecondaryDNS}}", htmlEscape(dnsIP))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out))
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	link := r.PathValue("magic_link")
	clientIP := extractIP(r.RemoteAddr)
	ctx := r.Context()

	if link != "" {
		if s.store == nil {
			s.replyConnect(w, r, http.StatusInternalServerError, "", "Storage not initialized")
			return
		}
		user, err := s.store.GetUserByMagicLink(ctx, link)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				slog.Warn("magic link not found", "remote_addr", r.RemoteAddr)
				s.replyConnect(w, r, http.StatusNotFound, "", "Invalid link")
				return
			}
			slog.Error("magic link lookup error", "error", err)
			s.replyConnect(w, r, http.StatusInternalServerError, "", "Internal error")
			return
		}
		if !user.Enabled {
			slog.Warn("magic link user disabled", "user_id", user.ID, "username", user.Username, "remote_addr", r.RemoteAddr)
			s.replyConnect(w, r, http.StatusForbidden, "", "Account disabled")
			return
		}
		ip := net.ParseIP(clientIP)
		if ip == nil {
			slog.Warn("magic link invalid client IP", "client_ip", clientIP, "remote_addr", r.RemoteAddr)
			s.replyConnect(w, r, http.StatusBadRequest, "", "Invalid IP address")
			return
		}
		if s.accessStore != nil && s.accessStore.IsBlacklisted(ip) {
			slog.Warn("magic link IP blacklisted", "client_ip", clientIP, "user_id", user.ID, "remote_addr", r.RemoteAddr)
			s.replyConnect(w, r, http.StatusForbidden, "", "IP blocked")
			return
		}
		if err := s.store.RegisterIP(ctx, user.ID, clientIP, user.MaxIPs); err != nil {
			slog.Error("magic link register IP error", "client_ip", clientIP, "user_id", user.ID, "error", err)
			s.replyConnect(w, r, http.StatusInternalServerError, "", "Internal error")
			return
		}
		if s.refresher != nil {
			if err := s.refresher.RefreshUserIPs(ctx); err != nil {
				slog.Error("magic link refresh user IPs error", "error", err)
			}
		}
		slog.Info("magic link IP registered",
			"client_ip", clientIP,
			"user_id", user.ID,
			"username", user.Username,
			"remote_addr", r.RemoteAddr,
		)
	} else {
		// Standalone /setup call without token — just show setup page.
		ip := net.ParseIP(clientIP)
		if ip == nil {
			s.replyConnect(w, r, http.StatusBadRequest, "", "Invalid IP address")
			return
		}
		if s.accessStore != nil && s.accessStore.IsBlacklisted(ip) {
			s.replyConnect(w, r, http.StatusForbidden, "", "IP blocked")
			return
		}
	}

	s.replyConnect(w, r, http.StatusOK, clientIP, "")
}

func (s *Server) replyConnect(w http.ResponseWriter, r *http.Request, code int, clientIP, errMsg string) {
	ok := code >= 200 && code < 300

	if !isBrowser(r) {
		// CLI (curl/wget/scripts): plain text response.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(code)
		if ok {
			fmt.Fprintln(w, clientIP)
		} else {
			fmt.Fprintln(w, errMsg)
		}
		return
	}

	// Browser: success -> full HTML setup page; error -> plain error.
	if !ok {
		http.Error(w, errMsg, code)
		return
	}

	dnsIP := s.getServerIP(r)
	out := setupHTMLRaw
	out = strings.ReplaceAll(out, "{{.ClientIP}}", htmlEscape(clientIP))
	out = strings.ReplaceAll(out, "{{.PrimaryDNS}}", htmlEscape(dnsIP))
	out = strings.ReplaceAll(out, "{{.SecondaryDNS}}", htmlEscape(dnsIP))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out))
}

// handleLookup is the public domain support lookup API.
// GET /api/lookup?domain=example.com
// Returns: {"domain": "example.com", "result": "proxy"|"blocked"|"unsupported"}
func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	clientIP := extractIP(r.RemoteAddr)
	if !s.lookupRL.allow(clientIP) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "rate limit exceeded"})
		return
	}

	raw := strings.TrimSpace(r.URL.Query().Get("domain"))
	if raw == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "domain parameter required"})
		return
	}

	domain := parseDomainInput(raw)
	if domain == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "invalid domain"})
		return
	}

	result := s.classifyDomain(domain)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"domain": domain,
		"result": result,
	})
}

func (s *Server) classifyDomain(domain string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.ruleStore == nil {
		return "unsupported"
	}
	rule, found := s.ruleStore.LookupRule(domain)
	if !found {
		return "unsupported"
	}
	switch rule.Mode {
	case "proxy", "":
		return "proxy"
	case "block":
		return "blocked"
	default:
		return "unsupported"
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func parseDomainInput(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "//") {
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		}
		u, err := url.Parse(raw)
		if err == nil && u.Host != "" {
			host := u.Hostname()
			host = strings.Trim(host, "[]")
			host = strings.TrimSuffix(host, ".")
			return host
		}
	}
	if idx := strings.IndexAny(raw, "/?#"); idx != -1 {
		raw = raw[:idx]
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimSuffix(raw, ".")
	return raw
}

func isBrowser(r *http.Request) bool {
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return false
	}
	cliKeywords := []string{"curl", "wget", "httpie", "python", "go-http-client", "postman", "insomnia", "axios", "node-fetch"}
	for _, kw := range cliKeywords {
		if strings.Contains(ua, kw) {
			return false
		}
	}
	browserKeywords := []string{"mozilla", "chrome", "safari", "firefox", "edge", "edg", "opera", "opr"}
	for _, kw := range browserKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html")
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}

// HandleConnectForTest exposes the connect handler for use in tests.
func (s *Server) HandleConnectForTest(w http.ResponseWriter, r *http.Request) {
	s.handleConnect(w, r)
}
