# CODEBASE_GUIDE.md — Engineer & Agent Onboarding Guide

## 1. Project Summary
`tls-relay` is a high-performance Go TLS SNI relay proxy featuring a built-in admin dashboard. It routes encrypted TLS traffic (based on Server Name Indication) on port 443 (by default) and plain HTTP traffic (based on Host header inspection) on a shared listener port. Dispatched traffic routes to upstream targets or is processed directly. A modern Tailwind CSS SPA admin console is served via Go's `embed.FS` using a synthetic listener inside `internal/frontrouter`. This frontend interface manages user accounts, user IPs, sub-path redirects, domain rules (proxy/direct/block modes), global blacklists, outbound SOCKS5 proxy configuration, allowed destination ports, and metrics tracking without requiring Node.js, npm, or runtime dependencies. All runtime settings and admin credentials (hashed with bcrypt) are stored in SQLite, completely eliminating the need for `.env` files.

---

## 2. Architecture Map

```
                          [ Client Request ]
                                  │
                       ┌──────────┴──────────┐
                       ▼                     ▼
              [ TLS Relay: 443 ]     [ Shared Listener ]
                       │                     │
                       │                     ▼
                       │             [ frontrouter ]
                       │             Check IP Access
                       │             Parse Host Header
                       │             Check Domain Rules
                       │            /                 \
                       │      (Match)                 (No Match)
                       │        /                         \
                       ▼       ▼                           ▼
                [ httprelay ] [ relay ]                  [ panel ]
                Bidirectional Pipeline                Synthetic Listener
                     (HTTP/TLS)                     Serve Admin Console
```

### Hot Path Packages (Connection Performance Critical)
*   **`internal/relay`**: Manages the core TCP connection pipeline (limits, presence tracker, security validation, and bidirectional byte piping) for TLS SNI proxying.
*   **`internal/relay/egress.go`**: Thread-safe outbound SOCKS5 dialer (`EgressDialer`) supporting dynamic hot-reloading, live latency/connectivity testing, and direct fallback. **v1.5.0**: The global `egress_proxy_enabled` flag is now a strict gate — `DialContextWithOverride` and `ResolveMode` both ignore per-rule `use_egress_proxy=true` when the global switch is off.
*   **`internal/httprelay`**: Mirrored pipeline matching `internal/relay` but adapted for plain HTTP stream routing by examining the decrypted HTTP Host header.
*   **`internal/httphost`**: High-performance HTTP parser reading the request line and extracting the Host header on the shared port.
*   **`internal/frontrouter`**: Gathers all shared listener traffic. Parses headers first, resolves domain configuration, and directs matching relay traffic to `internal/httprelay` or routes unmatched traffic to the `internal/panel` HTTP server.
*   **`internal/dnsresolver`**: Custom DNS resolver filtering client IPs, updating metrics, and routing matching configuration domains authoritatively to the relay IP. Also intercepts `<token>.dnscheck.relay-probe.net.` probe queries (via `DNSCheckRegistry`) so the portal landing page can verify client DNS configuration without touching the hot path. **v1.5.0 behavior**: domains with `mode=direct` are always forwarded to upstream DNS for authorized clients regardless of `unknown_domain_policy`.
*   **`internal/rules`**: Core lookup structure maintaining normalized rules mapping domains to mode (proxy/direct/block) and destination port lists. Uses `atomic.Pointer` for lock-free hot path reads.
*   **`internal/access`**: Fast, thread-safe IP access control check validating clients against registered user IPs and blacklist rules.
*   **`internal/sni`**: Extracts Server Name Indication (SNI) hostnames from raw TLS ClientHello handshakes.

### Cold Path Packages (Admin Panel & Storage Operations)
*   **`cmd/relay/main.go`**: Service entrypoint, CLI flag parsing (`-config`, `-init-admin`, `-user`, `-pass`), runtime settings resolution (SQLite `app_settings` > Env > `config.yaml`), and graceful restart channel management.
*   **`internal/panel`**: Serves the admin panel interface, registers REST endpoints, manages active session cookies, locks out brute-force login attempts, enforces CSRF tokens, and manages dynamic proxy/port settings.
*   **`internal/sqlitestore`**: Backing SQLite database persisting users, IP allocations, configuration settings (`app_settings`), domain rules, blacklist logs, and telemetry metrics.
*   **`internal/portal`**: Services the public landing page, client setup guide, and magic-link connection portal to register clients automatically.
*   **`internal/syncer`**: Coordinates SQLite persistence with in-memory RuleStore and AccessStore snapshots.
*   **`internal/requestlog`**: Buffers and persists diagnostic event logs asynchronously.
*   **`internal/reqstats`**: Aggregates network request totals (DNS/TLS) into internal memory buckets before flushing to SQLite.

---

## 3. Critical Invariants — DO NOT BREAK THESE

*   **Hot-Path SNI Normalization & `NormalizeDomainInput`**: Hot-path SNI normalization is strictly limited to lowercase conversion, trailing-dot trimming, and basic length/character sanity checks. `NormalizeDomainInput` remains write-path-only (never invoke IDNA or URL parsing from `internal/relay/proxy.go` `handleConn`, `internal/httprelay/server.go` `HandleConn`, `internal/dnsresolver/resolver.go` `handleQuery`, or `internal/frontrouter/router.go` `dispatchConn`). Host comparison on the hot path must remain a lock-free lookup on pre-normalized strings.
*   **Lock-Free Hot-Path Reads & ConnTracker Snapshots**: `RuleStore` and `AccessStore` utilize `atomic.Pointer` snapshots to handle configuration swaps. Similarly, `ConnTracker` uses an immutable `ipToUser` snapshot behind `atomic.Pointer` for lock-free user lookups, with connection tracking sharded into 16 mutex-protected shards and atomic user counters. Never replace these patterns with coarse read-write mutexes that block the hot path.
*   **Domain Match Precedence**: Exact match always overrides wildcard match. Among wildcards, the longest suffix wins (e.g. `sub.example.com` matches `*.sub.example.com` before `*.example.com`).
*   **DNS-Rebinding SSRF Protection & Resolve Cache**: Upstream DNS resolution results are cached briefly (30s TTL for positive validations, 10s negative cache for errors/blocked hosts, bounded to 10,000 entries) with `singleflight` deduplication. If ANY returned IP is private or blocked, the host is rejected. Dialing is strictly performed by validated IP addresses (using multi-IP dialing with `relay.DialAny`) to prevent DNS-rebinding attacks.
*   **SQLite as Primary Source of Truth & SIGHUP Live Reload**: Application settings live in SQLite (`app_settings` table). The CLI reads and writes configurations via `tls-relay settings get/set` and triggers runtime reloads via `SIGHUP` (or `systemctl reload tls-relay`), taking effect dynamically without restarting listeners or dropping active connections. `config.yaml` serves only as initial seed and fallback defaults. Environment variables in the service environment override SQLite.
*   **Dynamic Port & Proxy Hot-Reloading**: Allowed destination ports (`relay.PortAllowList` and `RuleStore.SetGlobalPorts`) and SOCKS5 egress (`relay.EgressDialer`) are updated dynamically without service restart. Destination port validation uses atomic slices/read locks.
*   **No Plaintext .env Credentials**: Admin credentials and dynamic proxy configs are stored in the SQLite `app_settings` table. Admin passwords must always be hashed with `bcrypt`. Never introduce `.env` dependencies into standard workflows.
*   **Separate Connection Handling Loops**: TLS SNI relaying (`internal/relay/proxy.go`) and HTTP relaying (`internal/httprelay/server.go`) maintain independent connection handlers due to protocol differences. Security validations, presence tracking, and limits must be updated in both files.
*   **Front Router Execution Sequence**: `frontrouter` checks IP access control and extracts the Host header *before* examining domain rule configurations. It routes to the admin panel handler *only* when no rule matches. Changing this sequence will expose the panel to forbidden IPs or route traffic incorrectly.
*   **CSRF Enforcement**: All state-modifying panel endpoints (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` header matching the current session cookie, except the `/api/login` endpoint.
*   **No Node/npm Dependencies**: The frontend toolchain utilizes the standalone official Tailwind CLI executable only. No Node.js runtime, npm dependencies, or node_modules are used locally, in CI, or in production.
*   **Generated CSS Embedded at Build Time**: `static/css/app.css` is generated by `make css` and gitignored. It must exist before compiling or testing Go (`go test`, `go build`).

### Known Limitations & Architecture Caveats
*   **Encrypted Client Hello (ECH)**: Encrypted Client Hello obscures the outer SNI during the TLS handshake. Transparent SNI routing cannot inspect encrypted inner ClientHellos. Domains using mandatory ECH without outer SNI fall back to the default or unknown domain policy.
*   **IP-Based Authentication behind CGNAT**: In `user` access mode, authorization is mapped per client public IPv4 address. When multiple mobile or residential clients share a single carrier-grade NAT (CGNAT) address, registering one client authorizes the shared public IP. Users should set appropriate IP quotas or use dedicated IPs where isolation is critical.

### Settings Keys & Defaults
| Key | Type / Format | Default | Description |
|---|---|---|---|
| `access_mode` | `user` \| `public` | `user` | Global access mode |
| `unknown_domain_policy` | `reject` \| `allow_default_port` | `reject` | Action when no domain rule matches |
| `panel_path` | `/[A-Za-z0-9_-]{1,64}` or `/` | `/admin` | URL path prefix for admin panel |
| `timezone` | IANA Timezone | `UTC` | Timezone for log and stat formatting |
| `server_domain` | hostname | empty | Server hostname for magic links |
| `request_logs_enabled` | bool | `true` | Request logging toggle |
| `request_logs_retention` | duration (`1h`, `24h`, `7d`) | `24h` | Log retention window |
| `max_connections_per_ip` | integer | `100` | Max TCP connections per IP |
| `allowed_dest_ports` | JSON array of ints | `[443, 8443, ...]` | Allowed destination ports |
| `lookup_enabled` | bool | `true` | Enable `/api/lookup` domain support check |
| `lookup_require_registered` | bool | `false` | Require client IP registration for lookup |
| `http_front_max_conns_per_ip` | integer | `60` | Front router max connections per IP |
| `http_front_max_global_conns` | integer | `5000` | Front router max global concurrent connections |
| `egress_proxy_enabled` | bool | `false` | Global SOCKS5 egress proxy enabled |
| `egress_proxy_addr` | `host:port` | empty | SOCKS5 proxy upstream address |

### New API Fields & Query Parameters
*   `GET /api/request-logs?before_id=<id>&limit=<n>`: Cursor pagination for request logs. Returns `{logs, next_before_id, has_more}`. `total` is only returned when no filters are applied and is backed by a 30s cached count.
*   `POST /api/users/{id}/magic-link/reset`: Accepts optional body `{"clear_ips": true}` to revoke all registered IPs for the user in addition to regenerating the token. Response contains `cleared_ips`.
*   `GET /api/settings` & `PUT /api/settings`: Exposes `lookup_enabled`, `lookup_require_registered`, `http_front_max_conns_per_ip`, `http_front_max_global_conns`, and returns `default_max_ips`.
*   `POST /api/dns-check/start` (portal): Issues a short-lived 24-character hex probe token, records it in `DNSCheckRegistry`, and returns `{"token": "<hex>"}`. Rate-limited to 5 req/s per IP.
*   `GET /api/dns-check/result?token=<hex>` (portal): Returns `{"seen": bool, "seen_at": RFC3339, "source_ip": string}`. When `seen` is true the DNS resolver intercepted a probe query for the token, confirming the client routes DNS through the relay.
*   `GET /api/domains/export.txt` (**v1.5.0**): Downloads all domain rules as `text/plain`. Format: `[mode:]domain[:ports] [use_egress=true]`. Proxy mode and port 443 are omitted.
*   `POST /api/domains/import-txt` (**v1.5.0**): Accepts `text/plain` body, one rule per line. Parses `direct:`, `block:`, or `proxy:` prefix, optional `:ports` suffix (or `:all`), `use_egress=true` flag. Skips blank lines and `#` comments. Returns `{domains_added, domains_updated, failed, errors[]}`.

---

## 4. Frontend Conventions & Architecture

### File Layout
```
tailwind.config.js                 # Repo root Tailwind configuration
Makefile                           # Includes `css` and `css-watch` build targets
.gitignore                         # Ignores generated static/css/app.css and .bin/
internal/panel/static/
  index.html                       # Shell: Topbar, navigation, <main id="view">, #toast-root, login screen
  css/
    input.css                      # @tailwind base/components/utilities + semantic CSS variables (COMMITTED)
    app.css                        # Generated minified CSS bundle (GITIGNORED, EMBEDDED)
  js/
    theme-init.js                  # Synchronous theme initialization in <head> to prevent flash of wrong theme
    app.js                         # Main entry (ES module): auth gate, shell setup, router
    core/
      api.js                       # Relative endpoint builder, CSRF injection, typed ApiError
      dom.js                       # Safe HTML tagged-template helper with auto-escaping (XSS safe)
      format.js                    # Timezone-aware date/time formatting, bytes, durations, counts
      poller.js                    # Concurrency-safe, visibility-aware polling helper
      router.js                    # Client-side hash routing with lazy view mounting
      store.js                     # Reactive lightweight application state store
      theme.js                     # Light and dark theme persistence manager
    domain/
      rules.js                     # Domain parsing, validation, port formatting, and rule matching
      status.js                    # Status-to-tone/badge mappings (purge-safe literal class maps)
    ui/
      combobox.js                  # Searchable select with custom item creation
      dialog.js                    # Native <dialog> modals with Promise-based confirmation & prompts
      menu.js                      # Viewport-aware collision-detecting dropdown actions menu
      pagination.js                # Shared pagination helper
      segmented.js                 # Segmented tab and pill controls
      sparkline.js                 # Responsive SVG sparkline chart with ResizeObserver and tooltips
      table.js                     # Table state: sorting, pagination, and filter-scoped bulk selection
      toast.js                     # Accessible toast notification container
    views/
      login.js                     # Login view with lockout handling
      dashboard.js                 # Real-time metrics dashboard and activity sparklines
      domains.js                   # Domain rules management, grouped/flat views, and bulk actions
      users.js                     # User accounts, IP quotas, magic links, and live presence
      blacklist.js                 # IP & CIDR blacklist management
      logs.js                      # Request logs viewer with live filtering and quick-add rules
      usage-report.js              # Bandwidth and DNS query breakdowns by user and domain
      settings.js                  # Access policies, network listeners, egress proxy, and service restart
      domain-rule-form.js          # Shared domain rule creation and edit form
  pages/                           # Served static page partials (asserted by Go tests)
    dashboard.html, domains.html, users.html, blacklist.html, request-logs.html, settings.html
```

### Core Frontend Rules
1. **Path-Prefix Safety**: Never use absolute URLs like `/api/...` or `/static/...`. All requests use relative URLs built via `getApiUrl()` in `core/api.js` so the panel can be hosted under `/`, `/admin`, or any secret custom path prefix.
2. **XSS Safety**: All dynamic values in DOM templates must be rendered through the `html\`\`` tagged template helper or explicitly escaped with `escapeHtml()`.
3. **Overlays**: Native `<dialog>` elements with `showModal()` are appended directly under `document.body` to avoid stacking context and CSS transform/filter clipping issues.
4. **Purge-Safe Tailwind Classes**: Dynamic classes (e.g. status tones and badge colors) must be mapped from complete string literals rather than dynamic string concatenations (e.g. `const TONES = { success: 'bg-emerald-500/10 text-emerald-700' }`).

---

## 5. How to Test Locally

Ensure Go (1.22+) is installed. Run the following commands:

```bash
# 1. Compile CSS (downloads standalone Tailwind CLI to .bin/ if missing)
make css

# 2. Format the codebase
gofmt -w .

# 3. Vet for issues
go vet ./...

# 4. Run tests with race detector
make test

# 5. Build binary
make build
```

---

## 6. How to Extend Safely

### Adding a new Dynamic Setting:
1.  Add the key constant in `internal/sqlitestore/settings.go`.
2.  Update `settingsResponse` and `updateSettingsRequest` in `internal/panel/panel_settings.go`.
3.  Read the setting from SQLite on startup in `cmd/relay/main.go` and apply it to the corresponding component.
4.  Update the UI form in `internal/panel/static/js/views/settings.js`.

### Initializing / Resetting Admin Credentials:
*   From CLI:
    ```bash
    go run ./cmd/relay -config config.yaml -init-admin -user admin -pass mypassword
    ```
*   Or via Web Panel: `PUT /api/admin/credentials` (handled by `handleUpdateAdminCredentials` in `panel_settings.go`).

### Adding a new Domain Rule field:
1.  Add the column inside `internal/sqlitestore/sqlitestore.go` `migrate()`.
2.  Update the struct in `internal/sqlitestore/domain_rules.go` (`DomainRuleRow`) and `internal/panel/panel_domains.go` (`domainEntry`).
3.  Add the column to the queries in `internal/sqlitestore/domain_rules.go` (`ListDomainRules`, `GetDomainRule`, `AllDomainRulesRaw`).
4.  Update `rules.DomainRule` in `internal/rules/domain.go` to handle the parsing/lookup.
5.  Update `domain-rule-form.js` and `views/domains.js`.

### DNS Mode Routing (v1.5.0 Reference)

| Rule mode | DNS query result |
|-----------|------------------|
| `proxy` (default) | Relay IP returned authoritatively |
| `direct` | Forwarded to upstream DNS (real IP) — ignores `unknown_domain_policy` |
| `block` | REFUSED |
| Not configured | Depends on `unknown_domain_policy` (`reject` → REFUSED, `allow_default_port` → forwarded) |

### Egress Proxy Semantics (v1.5.0 Reference)

`egress_proxy_enabled=false` (global switch off) is a **strict gate**: `EgressDialer.DialContextWithOverride` and `ResolveMode` return `direct` for all domains regardless of per-rule `use_egress_proxy` values. Per-rule values remain stored in the DB and automatically take effect when the global switch is enabled again. The UI hides the Egress column, bulk-assign button, and per-row egress cells when the global switch is off.
