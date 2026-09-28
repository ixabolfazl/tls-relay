# CODEBASE_GUIDE.md — Engineer & Agent Onboarding Guide

## 1. Project Summary
`tls-relay` is a high-performance Go TLS SNI relay proxy featuring a built-in admin dashboard. It routes encrypted TLS traffic (based on Server Name Indication) on port 443 (by default) and plain HTTP traffic (based on Host header inspection) on a shared listener port. Dispatched traffic routes to upstream targets or is processed directly. A vanilla-JS admin console is served via Go's `embed.FS` using a synthetic listener inside `internal/frontrouter`. This frontend interface manages user accounts, user IPs, sub-path redirects, domain rules (proxy/direct/block modes), global blacklists, outbound SOCKS5 proxy configuration, allowed destination ports, and metrics tracking without requiring a Node build process or bundler. All runtime settings and admin credentials (hashed with bcrypt) are stored in SQLite, completely eliminating the need for `.env` files.

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
*   **`internal/relay/egress.go`**: Thread-safe outbound SOCKS5 dialer (`EgressDialer`) supporting dynamic hot-reloading, live latency/connectivity testing, and direct fallback.
*   **`internal/httprelay`**: Mirrored pipeline matching `internal/relay` but adapted for plain HTTP stream routing by examining the decrypted HTTP Host header.
*   **`internal/httphost`**: High-performance HTTP parser reading the request line and extracting the Host header on the shared port.
*   **`internal/frontrouter`**: Gathers all shared listener traffic. Parses headers first, resolves domain configuration, and directs matching relay traffic to `internal/httprelay` or routes unmatched traffic to the `internal/panel` HTTP server.
*   **`internal/dnsresolver`**: Custom DNS resolver filtering client IPs, updating metrics, and routing matching configuration domains Authoritatively to the relay IP.
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

*   **`NormalizeDomainInput` is write-path-only**: Never invoke this function from `internal/relay/proxy.go` `handleConn`, `internal/httprelay/server.go` `HandleConn`, `internal/dnsresolver/resolver.go` `handleQuery`, or `internal/frontrouter/router.go` `dispatchConn`. Host comparison on the hot path must remain a lock-free lookup on pre-normalized strings.
*   **Lock-Free Hot-Path Reads**: The `RuleStore` and `AccessStore` utilize `atomic.Pointer` snapshots to handle configuration swaps. Never replace this pattern with read-write mutexes or other locking schemes that block the main relay pipeline.
*   **Domain Match Precedence**: Exact match always overrides wildcard match. Among wildcards, the longest suffix wins (e.g. `sub.example.com` matches `*.sub.example.com` before `*.example.com`).
*   **Dynamic Port & Proxy Hot-Reloading**: Allowed destination ports (`relay.PortAllowList` and `RuleStore.SetGlobalPorts`) and SOCKS5 egress (`relay.EgressDialer`) are updated dynamically without service restart. Destination port validation uses atomic slices/read locks.
*   **No Plaintext .env Credentials**: Admin credentials and dynamic proxy configs are stored in the SQLite `app_settings` table. Admin passwords must always be hashed with `bcrypt`. Never introduce `.env` dependencies into standard workflows.
*   **DNS-Rebinding SSRF Protection**: The `SecurityChecker` resolves hostnames to target IPs *once*, validates *all* returned IPs against private/local/own network spaces, and returns the chosen IP. The caller must dial directly by IP to prevent DNS-rebinding attacks.
*   **Separate Connection Handling Loops**: TLS SNI relaying (`internal/relay/proxy.go`) and HTTP relaying (`internal/httprelay/server.go`) maintain independent connection handlers due to protocol differences. Security validations, presence tracking, and limits must be updated in both files.
*   **Front Router Execution Sequence**: `frontrouter` checks IP access control and extracts the Host header *before* examining domain rule configurations. It routes to the admin panel handler *only* when no rule matches. Changing this sequence will expose the panel to forbidden IPs or route traffic incorrectly.
*   **CSRF Enforcement**: All state-modifying panel endpoints (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` header matching the current session cookie, except the `/api/login` endpoint.

---

## 4. File Map

### Entrypoint & Config
*   **`cmd/relay/main.go`**: Service startup, background syncers, listener binds, signal/restart handling, and CLI flags (`-init-admin`).
*   **`config.yaml`**: Server-level listener ports, timeouts, limits, logging, and DNS upstream configuration.

### Go Backend (internal/panel/ & internal/sqlitestore/)
*   **`internal/panel/panel.go`**: Server struct, route registrations, auth middleware, bcrypt verification, and helpers.
*   **`internal/panel/panel_domains.go`**: Domain rule management endpoints (`GET/POST/PUT/DELETE /api/domains` and bulk changes).
*   **`internal/panel/panel_users.go`**: User administration (`GET/POST/PUT/DELETE /api/users`), user IP registration, reset magic link, and bandwidth stats.
*   **`internal/panel/panel_blacklist.go`**: Blacklist CRUD endpoints (`/api/blacklist`).
*   **`internal/panel/panel_settings.go`**: Global settings controls (`GET/PUT /api/settings`, `POST /api/settings/test-proxy`, `PUT /api/admin/credentials`, `POST /api/service/restart`).
*   **`internal/panel/panel_stats.go`**: Diagnostic metrics retrieval, live connection counts, and trend data.
*   **`internal/panel/panel_reqlogs.go`**: Request log viewer endpoints.
*   **`internal/panel/panel_exportimport.go`**: Configuration backups and JSON migrations.
*   **`internal/sqlitestore/sqlitestore.go`**: SQLite connection pool, schema initialization, and migrations.
*   **`internal/sqlitestore/users.go`**: User table operations.
*   **`internal/sqlitestore/user_ips.go`**: User IP mappings and quota-based eviction logic.
*   **`internal/sqlitestore/blacklist.go`**: Blacklist table queries.
*   **`internal/sqlitestore/domain_rules.go`**: Domain rules storage, mode persistence, and bulk updates.
*   **`internal/sqlitestore/settings.go`**: Key-value table (`app_settings`) for dynamic settings and admin credentials.
*   **`internal/sqlitestore/exportimport.go`**: Transactional data import/export routines.
*   **`internal/sqlitestore/backup.go`**: SQLite VACUUM backup snapshotting.
*   **`internal/sqlitestore/requestlogs.go`**: Request log queries.

### Vanilla Frontend (internal/panel/static/)
*   **`internal/panel/static/index.html`**: Main single-page shell, navigation bar, modals, and container elements.
*   **`internal/panel/static/pages/`**: Modular HTML page templates loaded on-demand:
    *   `dashboard.html`: Live metrics widgets and status cards.
    *   `domains.html`: Domain rules table and creation modal.
    *   `users.html`: User management, magic links, and IP allocation.
    *   `blacklist.html`: IP/CIDR blacklist management.
    *   `settings.html`: Admin credentials, allowed ports, listen ports, outbound SOCKS5 proxy, and service restart.
    *   `usage.html`: Bandwidth trend charts.
    *   `request-logs.html`: Real-time searchable request logs.
*   **`internal/panel/static/js/`**:
    *   `core.js`: Global state variables, select boxes, alerts, and theme definitions.
    *   `auth.js`: Authentication views and session lifecycle.
    *   `domains.js`: Domain rules table editing, parsing, and bulk modes.
    *   `users.js`: User listing, copy magic link, and IP registrations.
    *   `blacklist.js`: Blacklist table rendering.
    *   `presence.js`: Online presence list polling.
    *   `settings.js`: Dynamic settings, proxy test, port management, credential updates, and restart polling.
    *   `usage.js`: Daily bandwidth trend charts.
    *   `requestlogs.js`: Logs tables with inline quick-add buttons.
    *   `dashboard.js`: Live stats widgets.
    *   `init.js`: Document ready trigger launching boot systems.
*   **`internal/panel/static/css/`**:
    *   `variables.css`: HIG custom properties and color palettes.
    *   `base.css`: Global resets, scrollbars, and utility classes.
    *   `layout.css`: Shell layouts, forms, and cards.
    *   `components.css`: Buttons, custom selects, toggles, and modals.
    *   `charts.css`: SVG graphics, legends, and tooltip classes.
    *   `responsive.css`: Media queries (loaded last).
    *   `pages/`: Modular page-specific style sheets (`settings.css`, `dashboard.css`, etc.).

---

## 5. How to Test Locally

Ensure Go (1.22+) is installed. Run the following commands:

```bash
# 1. Format the codebase
gofmt -w .

# 2. Vet for issues
go vet ./...

# 3. Build the binary
go build ./cmd/relay

# 4. Run tests with the race detector
go test ./... -race -cover
```

---

## 6. How to Extend Safely

### Adding a new Dynamic Setting:
1.  Add the key constant in `internal/sqlitestore/settings.go`.
2.  Update `settingsResponse` and `updateSettingsRequest` in `internal/panel/panel_settings.go`.
3.  Read the setting from SQLite on startup in `cmd/relay/main.go` and apply it to the corresponding component.
4.  Update the UI form in `internal/panel/static/pages/settings.html` and the handler in `internal/panel/static/js/settings.js`.

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
5.  Add the UI element in `internal/panel/static/pages/domains.html` and update the handlers inside `static/js/domains.js`.

### Changing SSRF / Security Checker logic:
1.  Modify `internal/relay/security.go`.
2.  **CRITICAL**: Make sure you update the tests inside `internal/relay/security_test.go`.
3.  Confirm the logic changes are reflected correctly in both `internal/relay/proxy.go` and `internal/httprelay/server.go` connection pipelines.

---

## 7. Known Gaps / Suggested Future Work

*   **No JS Test Harness**: The admin panel consists of vanilla JS files loaded directly into the browser. Unit testing via Jest/Puppeteer/Playwright is not configured.
*   **Duplicate Connection Pipelines**: `internal/relay/proxy.go` (`handleConn`) and `internal/httprelay/server.go` (`HandleConn`) duplicate the connection validation pipeline (checking IP access, registering to trackers, enforcing limits, checking rules, resolving destination, and piping data). These could drift apart during updates and should be refactored into a shared pipeline framework.
*   **Front Router & Relay Lookup Race (Resolved)**: Consolidated domain rule lookups into a single atomic snapshot read via `RuleStore.LookupDetailed`, preventing state mismatch during concurrent configuration swaps.
