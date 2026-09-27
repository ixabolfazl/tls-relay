# CODEBASE_GUIDE.md — Engineer & Agent Onboarding Guide

## 1. Project Summary
`tls-relay` is a high-performance Go TLS SNI relay proxy featuring a built-in admin dashboard. It routes encrypted TLS traffic (based on Server Name Indication) on port 443 (by default) and plain HTTP traffic (based on Host header inspection) on a shared listener port. Dispatched traffic routes to upstream targets or is processed directly. A vanilla-JS admin console is served via Go's `embed.FS` using a synthetic listener inside `internal/frontrouter`. This frontend interface manages user accounts, user IPs, sub-path redirects, domain rules (proxy/direct/block modes), global blacklists, and metrics tracking without requiring a Node build process or bundler.

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
*   **`internal/relay`**: Manages the core TCP connection pipeline (limits, presence tracker, socks5 egress dialer, security validation, and bidirectional byte piping) for TLS SNI proxying.
*   **`internal/httprelay`**: Mirrored pipeline matching `internal/relay` but adapted for plain HTTP stream routing by examining the decrypted HTTP Host header.
*   **`internal/httphost`**: High-performance HTTP parser reading the request line and extracting the Host header on the shared port.
*   **`internal/frontrouter`**: Gathers all shared listener traffic. Parses headers first, resolves domain configuration, and directs matching relay traffic to `internal/httprelay` or routes unmatched traffic to the `internal/panel` HTTP server.
*   **`internal/dnsresolver`**: Custom DNS resolver filtering client IPs, updating metrics, and routing matching configuration domains Authoritatively to the relay IP.
*   **`internal/rules`**: Core lookup structure maintaining normalized rules mapping domains to mode (proxy/direct/block) and destination port lists.
*   **`internal/access`**: Fast, thread-safe IP access control check validating clients against registered user IPs and blacklist rules.
*   **`internal/sni`**: Extracts Server Name Indication (SNI) hostnames from raw TLS ClientHello handshakes.

### Cold Path Packages (Admin Panel & Storage Operations)
*   **`internal/panel`**: Serves the admin panel interface, registers REST endpoints, manages active session cookies, locks out brute-force login attempts, and enforces CSRF tokens.
*   **`internal/sqlitestore`**: Backing SQLite database persisting users, IP allocations, configuration settings, blacklist logs, and hourly/daily telemetry metrics.
*   **`internal/portal`**: Services the public landing page, client setup guide, and magic-link connection portal to register clients automatically.
*   **`internal/syncer`**: Coordinates SQLite persistence with in-memory RuleStore and AccessStore snapshots.
*   **`internal/requestlog`**: Buffers and persists diagnostic event logs asynchronously.
*   **`internal/reqstats`**: Aggregates network request totals (DNS/TLS) into internal memory buckets before flushing to SQLite.

---

## 3. Critical Invariants — DO NOT BREAK THESE

*   **`NormalizeDomainInput` is write-path-only**: Never invoke this function from `internal/relay/proxy.go` `handleConn`, `internal/httprelay/server.go` `HandleConn`, `internal/dnsresolver/resolver.go` `handleQuery`, or `internal/frontrouter/router.go` `dispatchConn`. Host comparison on the hot path must remain a lock-free lookup on pre-normalized strings.
*   **Lock-Free Hot-Path Reads**: The `RuleStore` and `AccessStore` utilize `atomic.Pointer` snapshots to handle configuration swaps. Never replace this pattern with read-write mutexes or other locking schemes that block the main relay pipeline.
*   **Domain Match Precedence**: Exact match always overrides wildcard match. Among wildcards, the longest suffix wins (e.g. `sub.example.com` matches `*.sub.example.com` before `*.example.com`).
*   **DNS-Rebinding SSRF Protection**: The `SecurityChecker` resolves hostnames to target IPs *once*, validates *all* returned IPs against private/local/own network spaces, and returns the chosen IP. The caller must dial directly by IP to prevent DNS-rebinding attacks.
*   **Separate Connection Handling Loops**: TLS SNI relaying (`internal/relay/proxy.go`) and HTTP relaying (`internal/httprelay/server.go`) maintain independent connection handlers due to protocol differences. Security validations, presence tracking, and limits must be updated in both files.
*   **Front Router Execution Sequence**: `frontrouter` checks IP access control and extracts the Host header *before* examining domain rule configurations. It routes to the admin panel handler *only* when no rule matches. Changing this sequence will expose the panel to forbidden IPs or route traffic incorrectly.
*   **CSRF Enforcement**: All state-modifying panel endpoints (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` header matching the current session cookie, except the `/api/login` endpoint.

---

## 4. File Map

### Go Backend (internal/panel/ & internal/sqlitestore/)
*   **`internal/panel/panel.go`**: Server struct, route registrations, auth middleware, and general helpers (`randomHex`, `getClientIP`, `formatISO8601`).
*   **`internal/panel/panel_domains.go`**: Domain rule management endpoints (`GET/POST/PUT/DELETE /api/domains` and bulk changes).
*   **`internal/panel/panel_users.go`**: User administration (`GET/POST/PUT/DELETE /api/users`), user IP registration, reset magic link, and user bandwidth statistics.
*   **`internal/panel/panel_blacklist.go`**: Blacklist CRUD endpoints (`/api/blacklist`).
*   **`internal/panel/panel_settings.go`**: Global configuration controls (`GET/PUT /api/settings`).
*   **`internal/panel/panel_stats.go`**: Diagnostic metrics retrieval, live connection counts, and trend data.
*   **`internal/panel/panel_reqlogs.go`**: Logs viewer endpoints.
*   **`internal/panel/panel_exportimport.go`**: Configuration backups and JSON migrations.
*   **`internal/sqlitestore/sqlitestore.go`**: SQLite connection, pool initialization, and migrations.
*   **`internal/sqlitestore/users.go`**: User table operations.
*   **`internal/sqlitestore/user_ips.go`**: User IP mappings and eviction logic.
*   **`internal/sqlitestore/blacklist.go`**: Blacklist table queries.
*   **`internal/sqlitestore/domain_rules.go`**: Domain rules storage, mode persistence, and bulk updates.
*   **`internal/sqlitestore/settings.go`**: Configuration table key-value store.
*   **`internal/sqlitestore/exportimport.go`**: Transactional data import/export routines.
*   **`internal/sqlitestore/backup.go`**: SQLite VACUUM backup snapshotting.
*   **`internal/sqlitestore/requestlogs.go`**: Request log queries.

### Vanilla Frontend (internal/panel/static/)
*   **`internal/panel/static/index.html`**: Single HTML file, semantic structure, zero inline styles.
*   **`internal/panel/static/js/core.js`**: Global state variables, select boxes, alerts, and theme definitions.
*   **`internal/panel/static/js/auth.js`**: Authentication views.
*   **`internal/panel/static/js/domains.js`**: Domain rules table editing, parsing, and bulk modes.
*   **`internal/panel/static/js/users.js`**: User listing, copy magic link, and IP registrations.
*   **`internal/panel/static/js/blacklist.js`**: Blacklist table rendering.
*   **`internal/panel/static/js/presence.js`**: Online presence list polling.
*   **`internal/panel/static/js/settings.js`**: Admin settings fields.
*   **`internal/panel/static/js/usage.js`**: Daily bandwidth trend charts.
*   **`internal/panel/static/js/requestlogs.js`**: Logs tables with inline quick-add buttons.
*   **`internal/panel/static/js/dashboard.js`**: Live stats widgets.
*   **`internal/panel/static/js/init.js`**: Document ready trigger launching boot systems.
*   **`internal/panel/static/css/`**:
    *   `variables.css`: HIG custom properties.
    *   `base.css`: Global resets, scrollbars, and utility classes.
    *   `layout.css`: Shell layouts, forms, and cards.
    *   `components.css`: Buttons, custom selects, toggles, and modals.
    *   `charts.css`: SVG graphics, legends, and tooltip classes.
    *   `responsive.css`: Media queries (loaded last).

---

## 5. How to Test Locally

Ensure Go (1.21+) is installed. Run the following commands:

```bash
# 1. Format the codebase
gofmt -w .

# 2. Vet for issues
go vet ./...

# 3. Build the binary
go build ./...

# 4. Run tests with the race detector
go test ./... -race -cover
```

---

## 6. How to Extend Safely

### Adding a new Domain Rule field:
1.  Add the column inside `internal/sqlitestore/sqlitestore.go` `migrate()`.
2.  Update the struct in `internal/sqlitestore/domain_rules.go` (`DomainRuleRow`) and `internal/panel/panel_domains.go` (`domainEntry`).
3.  Add the column to the queries in `internal/sqlitestore/domain_rules.go` (`ListDomainRules`, `GetDomainRule`, `AllDomainRulesRaw`).
4.  Update `rules.DomainRule` in `internal/rules/domain.go` to handle the parsing/lookup.
5.  Add the UI element in `internal/panel/static/index.html` and update the handlers inside `static/js/domains.js`.

### Adding a new Admin API endpoint:
1.  Register the path inside `internal/panel/panel.go` `registerRoutesWithPrefix()`.
2.  Add the handler function inside the corresponding `internal/panel/panel_*.go` file.
3.  Add a test matching the handler functionality inside `internal/panel/panel_test.go` or a new test file.

### Changing SSRF / Security Checker logic:
1.  Modify `internal/relay/security.go`.
2.  **CRITICAL**: Make sure you update the tests inside `internal/relay/security_test.go`.
3.  Confirm the logic changes are reflected correctly in both `internal/relay/proxy.go` and `internal/httprelay/server.go` connection pipelines.

---

## 7. Known Gaps / Suggested Future Work

*   **No JS Test Harness**: The admin panel consists of vanilla JS files loaded directly into the browser. Unit testing via Jest/Puppeteer/Playwright is not configured.
*   **Duplicate Connection Pipelines**: `internal/relay/proxy.go` (`handleConn`) and `internal/httprelay/server.go` (`HandleConn`) duplicate the connection validation pipeline (checking IP access, registering to trackers, enforcing limits, checking rules, resolving destination, and piping data). These could drift apart during updates and should be refactored into a shared pipeline framework.
*   **Front Router & Relay Lookup Race (Resolved)**: Consolidated domain rule lookups into a single atomic snapshot read via `RuleStore.LookupDetailed`, preventing state mismatch during concurrent configuration swaps.
