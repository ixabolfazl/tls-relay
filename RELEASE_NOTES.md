# Release Notes

## v1.7.1

* **Flat & Categorized Tree Views:** Switch between a unified flat list and a hierarchical tree view (Category → Subcategory → Domains) with full inline edit, delete, and toggle controls.
* **Per-Domain Enable / Disable:** Toggle individual domain rules on or off without deleting them via a new switch control and `PATCH /api/domains/{domain}/toggle` endpoint.
* **Integrated Category Management:** Moved category and subcategory creation and editing from Settings into a dedicated dialog directly on the Domain Rules page.
* **Unified Mode Filtering:** Flat view now displays all routing modes (Proxy, Direct, Block) together with an instant mode filter and badge indicators.
* **Table Selection Fixes:** Resolved select-all and indeterminate checkbox state issues for bulk operations.
* **Simplified Settings:** Streamlined the Default Domains section in Settings to focus exclusively on catalog version status and updates.

---

## v1.7.0

### Default Domain Catalog & Categories
* **Embedded Domain Catalog:** Ships with a curated default domain catalog (`data/default-domains.json`) embedded into the binary and loaded automatically on initial clean installations.
* **Hierarchical Categories & Subcategories:** Domains are organized into categories and subcategories (e.g., `Social Media → Telegram`). Administrators can enable or disable entire categories or subcategories with automatic cascading.
* **Category & Subcategory CRUD:** Added administrative capability to create, rename, and manage custom categories and subcategories directly from the panel and assign domain rules to them.
* **Versioned Catalog & Remote Updates:** Tracks installed catalog versions and checks for upstream catalog updates from GitHub (utilizing the egress proxy dialer when configured). Displays an "Update" badge in the web panel when a newer version is available.
* **Safe Non-Destructive Merge & Preview:** Applying a catalog update is non-destructive—existing domains are updated, missing domains are added, and custom domains are never deleted. A dry-run preview modal displays precise change statistics (added, updated, unchanged) and domain samples before confirmation with version gating.

### Domain Import / Export & Storage Improvements
* **JSON Export / Import v2:** Redesigned the domain export format (`GET /api/domains/export.json`) to v2, exporting domains hierarchically with categories and subcategories. `POST /api/domains/import-json` supports both v2 and legacy v1 payloads seamlessly.
* **TXT Format Removal:** Completely removed legacy TXT export and import endpoints (`/api/domains/export.txt` and `/api/domains/import-txt`) and associated UI elements.
* **ImportData Enabled & Category Preservation:** Fixed full-system data import (`POST /api/import`) to properly honor rule `enabled` state and `catalog_node` associations across migrations and restores.

---

## v1.6.2

* **DNS Resolver Fix:** Fixed an issue where setting `unknown_domain_policy` to `reject` incorrectly blocked DNS queries for unconfigured domains. Authorized clients now always resolve unlisted domains normally via upstream DNS.
* **Relay Policy Scope:** Restricted `Unknown Domain Policy` to strictly govern traffic proxying on relay ports, preventing unintended connection routing without interfering with DNS lookups.
* **Settings UI:** Renamed the setting in the admin panel to **Unknown Domain Relay Policy** with clearer descriptions.

---

## v1.6.1

### Security & Hardening
* **Dedicated Unprivileged Service User:** Systemd service now runs under a dedicated, locked system user and group (`tls-relay:tls-relay`) with `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true`, and strict `ReadWritePaths`.
* **Installation Script Hardening:** `install.sh` and `tls-relay.sh` automatically provision the `tls-relay` system user, fix permissions across `/opt/tls-relay`, `/var/lib/tls-relay`, and `/var/log/tls-relay`, and abort immediately if SHA256 checksums are missing or do not match.
* **Removal of Deprecated `-pass` CLI Flag:** Removed the plaintext `-pass` flag in the CLI to prevent credential leakage via shell history and process inspection. Use `-pass-stdin` or `TLS_RELAY_ADMIN_PASS`.
* **Login Brute-Force Rate Limiting:** Panel authentication rate limiter is now keyed per `IP + username` with exponential backoff on consecutive failed attempts.
* **Proxy Header Spoofing Protection:** `X-Forwarded-Proto` is only trusted when the remote address is a verified loopback proxy (`127.0.0.1` or `::1`).
* **Default Reject Unknown Domain Policy:** Updated default policy to `unknown_domain_policy: "reject"` across code defaults and default configuration template.
* **CI/CD Vulnerability & Test Gates:** `govulncheck` in CI now strictly fails the build on vulnerabilities (`continue-on-error` removed), and release workflow now runs the full test suite before compilation.

### Architecture & Performance
* **Shared Connection Pipeline:** Extracted unified domain evaluation, client IP access validation, and egress dialer dispatch into `internal/relay/pipeline.go`, removing duplicated hot-path code between TLS relay and HTTP relay.
* **Transactional Bulk Operations:** SQLite operations for bulk domain rule deletion, domain group assignment, and blacklist deletion now execute in isolated database transactions (`BeginTx`) with prepared statements.
* **Atomic Rule Upsert:** Adding or updating a domain rule now uses atomic SQL operations, eliminating race conditions and redundant pre-lookups.
* **Import Payload Limits:** Guarded domain/blacklist/user import against memory exhaustion by enforcing maximum entity caps per import payload (10,000 domains, 5,000 blacklist entries, 1,000 users).
* **Dead Code Cleanup:** Cleaned up unused legacy IP rule checking types and redundant methods in `internal/rules` and `internal/dnsresolver`.

### UI & Frontend Fixes
* **Segmented Control Initialization:** Fixed argument passing in `createSegmentedControl` on the Domains page and Usage Report dialog so date/time range pickers (Today/7d/30d) render and toggle properly.
* **Toast Duration Safety:** Normalized `toast.error(msg, dur)` to accept both integer milliseconds and options objects (`{ duration: ms }`).
* **Safe LocalStorage:** Wrapped `localStorage` reads and writes in `try / catch` blocks to avoid unhandled security exceptions in private/incognito browsing modes.

---

## v1.6.0

* **JSON domain export / import:** new `GET /api/domains/export.json` and `POST /api/domains/import-json` endpoints for domain rule backup and restore. Preserves domain groups (`group`) and respects the global egress proxy status (`use_egress` is omitted when globally disabled, and ignored during import if disabled). "Export JSON" and "Import JSON" buttons added to the Domain Rules page header.

---

## v1.5.0

* **Relay log status:** connections that complete the bidirectional pipe now record `status = "relayed"` in the request log (was `"closed"` / `"connected"`).
* **Portal — registered-user cleanup:** the Magic Link registration card and setup step are hidden when the visiting IP is already registered. The lookup card is gated to registered IPs when `lookup_require_registered` is on.
* **Portal — lookup authorization:** `lookup_require_registered` now checks the in-memory `AccessStore` snapshot instead of querying SQLite directly, making it blacklist-aware and mode-aware with zero database overhead.
* **Egress strict gate:** `egress_proxy_enabled=false` now overrides all per-rule `use_egress_proxy=true` settings globally. Per-rule values are preserved in the database and take effect again when the switch is re-enabled. The Domains UI hides the Egress column and bulk action when the global switch is off.
* **TXT import / export:** new `GET /api/domains/export.txt` and `POST /api/domains/import-txt` endpoints. Format: one domain per line, optional `direct:`/`block:` prefix, optional `:port` suffix, optional `use_egress=true` flag. "Export TXT" and "Import TXT" buttons added to the Domain Rules page header.
* **"All ports" checkbox:** the domain rule form now has an "All ports" checkbox that disables the port input and sets it to `all`.
* **DNS fix — direct-mode domains:** domains with `mode=direct` were being REFUSED by the DNS resolver when `unknown_domain_policy=reject`. They are now always forwarded to upstream DNS, bypassing the policy check.

---

## v1.4.2

### DNS Status Check & Portal Fixes
* **Active DNS Probe Resolution:** The portal now actively triggers browser DNS resolution for the probe token using `fetch` (with `no-cors`) and `Image` fallback, ensuring probe queries reach the DNS relay.
* **Absolute API Paths:** Fixed 404 errors on magic link pages (`/connect/<token>`) by switching relative `fetch` paths to absolute (`/api/dns-check/*` and `/api/lookup`).
* **Content-Security-Policy:** Updated portal CSP directives (`connect-src` and `img-src`) to allow probe requests to `*.dnscheck.relay-probe.net`.
* **Safe Probe Domain:** Migrated probe suffix from RFC 6761 `.invalid` to `.dnscheck.relay-probe.net` to avoid suppression by local stub resolvers.
* **Error Visibility:** Replaced silent card hiding with a clear status badge when the check service is unavailable.

---

## v1.4.1

### Portal
* **DNS Status Check on Setup Page:** The DNS status probe card is now displayed on the `/connect` (magic-link setup) page in addition to the main landing page. Clients who follow a magic link can immediately verify that their DNS is correctly pointing to the relay.
* **Content-Security-Policy Fix:** Added a proper `Content-Security-Policy` header (`script-src 'unsafe-inline'`) on both portal pages to resolve the inline-script CSP console error reported by browsers.

### Admin Dashboard
* **Removed Daily Trend Charts:** The "Daily Activity Trend", "Daily Connection Trend", and "Daily Request Trend" sparklines have been removed from the DNS, TLS, and HTTP sections.
* **DNS / TLS / HTTP Sections Redesigned:** Each service section now uses the same KPI card style as the top row — no background color blocks, consistent with the rest of the dashboard.
* **Download and Upload KPI Cards:** The single "Total Bandwidth" card has been split into three: **Total Bandwidth**, **Download** (↓ bytes received), and **Upload** (↑ bytes sent), displayed as separate KPI cards with color-coded labels.
* **Removed Redundant KPI Cards:** The "Total Users" and "Blacklisted" cards have been removed to make room for the new Download/Upload cards.

### Users Table
* **Status Badge Inline:** The user status badge (Active / Disabled) is now shown inline next to the username instead of in a separate column.
* **Removed Reg IPs Column:** The registered IP count (`ip / max`) column has been removed from the table; this detail is still available in the Edit User and Registered IPs dialogs.
* **Removed Token Column:** The truncated magic-link token column has been removed; the token can still be copied or reset via the Actions menu.
* **Traffic Column:** The separate Sent and Received columns have been merged into a single **Traffic** column showing upload (↑) and download (↓) values stacked, with color-coded directional icons.

### Domains Table
* **Removed Created At Column:** The creation date column has been removed from both flat and grouped views.
* **Removed Group Column (Flat View):** The group name badge column has been removed from the flat view; group information is still visible in the grouped view header rows.
* **Traffic Column:** The separate Sent and Received columns have been merged into a single **Traffic** column with the same stacked ↑↓ format as the users table.
* **Grouped View Fix:** The group header row colspan has been corrected to match the reduced column count.

### Egress Proxy Test
* **Exit IP and Country Info:** The "Test Proxy Connection" button now connects through the configured proxy to `cloudflare.com/cdn-cgi/trace` and returns the proxy's **exit IP address**, **country flag emoji**, **country code**, and **round-trip latency**. The latency badge is color-coded: green under 100 ms, amber under 300 ms, and red above.

---

## v1.4.0

### Admin Dashboard
* **Redesigned Overview Dashboard:** Replaced multi-column metric cards with a single full-width panel. Live connection count, global bandwidth, DNS query rate, and relay status are displayed side-by-side with sparkline charts updated every few seconds.
* **DNS Traffic Sparkline:** The dashboard now renders a live DNS query-rate sparkline chart alongside the TLS bandwidth chart, providing immediate visibility into resolver load.
* **Usage Report View:** New `Usage Report` section in the admin panel shows per-user and per-domain bandwidth and DNS query breakdowns with date-range filtering and CSV export.

### DNS & Portal
* **Client DNS Status Check:** The public landing page now includes a "DNS Status" card that automatically verifies whether the visiting device routes DNS through the relay. When the page loads, the portal issues a one-time hex probe token (`POST /api/dns-check/start`), the browser resolves `<token>.dnscheck.relay-probe.net.` against the relay DNS, and the page polls `GET /api/dns-check/result?token=<hex>` until the resolver confirms the probe was received. The card displays a green "✓ DNS is correctly configured" badge on success or an amber warning if the check times out.
* **DNSCheckRegistry:** New in-memory token registry (`internal/dnsresolver/dnscheck.go`) with a TTL-based background sweeper, bounded capacity, and lock-safe token observation recording. Wired into `handleQuery` at intercept priority (after rate limiting, before rule evaluation) with zero hot-path overhead when no probe is in flight.

### User & Domain Management
* **Per-User DNS Usage Tracking:** The DNS resolver now emits per-user query counts when a client IP is registered to a known user, feeding the usage aggregation pipeline.
* **Domain Rule Egress Overrides:** Individual domain rules can now override the global SOCKS5 egress setting per domain.
* **Public Access Mode Registration Cleanup:** In `public` access mode the landing page no longer shows the Magic Link registration card or setup step, since all IPs are admitted automatically.

### API Changes
* `POST /api/dns-check/start` — portal endpoint to issue a DNS probe token (rate-limited: 5 req/s per IP).
* `GET /api/dns-check/result?token=<hex>` — portal endpoint returning `{seen, seen_at, source_ip}`.

---

## v1.3.0

### Security & Hardening
* **SNI Normalization & Validation:** Enforced hot-path SNI normalization (lowercase conversion, trailing-dot trimming, character and length sanity checks) to prevent block-rule bypasses. Rejects malformed hostnames with `rejected_bad_sni`.
* **SSRF Prevention:** Expanded blocked IP ranges to cover `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, `255.255.255.255/32`, `64:ff9b::/96` (NAT64), and `2002::/16` (6to4). Added automatic detection and blocking of the relay server's own IP.
* **Authentication & Session Hardening:** 
  * Implemented constant-time string comparisons for usernames and CSRF tokens via `subtle.ConstantTimeCompare`.
  * Dummy hash bcrypt execution on nonexistent usernames to prevent timing attacks.
  * Invalidation of all other active sessions upon admin credential updates.
  * Cookie security enhanced with `SameSite=Strict`.
* **Ambiguous HTTP Host Rejection:** Rejects requests containing multiple `Host` headers or absolute-form request targets with mismatched authority (`rejected_ambiguous_host`).
* **Route Validation:** Enforced strict regex matching and reserved keyword blacklists for custom admin panel paths.

### Performance & Scalability
* **Lock-Free Connection Tracking:** Converted `ConnTracker` user lookups into an immutable snapshot behind `atomic.Pointer`. Sharded connection tracking into 16 mutex-protected shards with atomic per-user metrics.
* **SQLite Reader/Writer Connection Pool:** Separated read-only operations (logs, stats, list queries) into a dedicated reader pool (`MaxOpenConns(4)` in `mode=ro` with WAL) from the single-writer connection.
* **Resolve Cache & Multi-IP Dialing:** Implemented an in-memory DNS resolution cache (30s TTL, 10,000 bounded entries) with `singleflight` deduplication and multi-address fallback dialing (`DialAny`).
* **Fragmented TLS ClientHello Support:** Assembles multi-record handshake payloads up to 32 KiB across up to 8 records while preserving raw bytes for transparent relaying.
* **Cursor-Based Request Log Pagination:** Introduced `before_id` cursor pagination with composite database indexes and cached total counts for fast UI log browsing.
* **Batched Retention Cleanup:** Retention cleaner now purges expired request logs in 5,000-row batches with throttled intervals to prevent database locking.

### DNS & HTTP Routing
* **HTTPS/SVCB Record Suppression:** Intercepts type 64 (SVCB) and type 65 (HTTPS) DNS queries for proxy domains, answering with authoritative empty `NOERROR` to prevent modern browsers from bypassing SNI routing.
* **Front Router Port-80 Rate Limits:** Configurable per-IP and global concurrency limits (`http_front_max_conns_per_ip`, `http_front_max_global_conns`) acquired prior to reading request bytes.
* **Plain HTTP to HTTPS Redirect:** Automatically redirects HTTP traffic to HTTPS (301/308) for matched proxy domains when port 80 is not in the allowed destination ports but 443 is.

### Management & CLI
* **Direct Binary Subcommands:**
  * `tls-relay settings get [key]`: Inspect runtime settings stored in SQLite.
  * `tls-relay settings set <key> <value>`: Validate and persist settings directly into SQLite.
  * `tls-relay backup <dest-path>`: Generate consistent SQLite snapshots via `VACUUM INTO` (0700 dir, 0600 file).
  * `tls-relay -init-admin`: Secure password provisioning using `TLS_RELAY_ADMIN_PASS` environment variable or `-pass-stdin`.
* **Zero-Downtime SIGHUP Live Reload:** Re-reads database configurations and credentials via `systemctl reload tls-relay` without restarting listeners or dropping active connections.
* **Atomic CLI Self-Updater:** `tls-relay.sh` now downloads release tarballs with SHA256 checksum verification, performs atomic file swaps, updates systemd units, and includes automated rollback if the service fails to become active.

---

## v1.2.0

### Web Admin Panel Modernization
* **Tailwind CSS SPA Architecture:** Redesigned the entire web dashboard using pure Tailwind CSS with zero Node.js/npm runtime dependencies.
* **Modular JavaScript Architecture:** Refactored frontend scripts into modular ES modules (`core/`, `ui/`, `views/`, `domain/`) featuring safe HTML template rendering (`dom.js`) and timezone-aware formatting.
* **Enhanced Domain Rule Management:** 
  * Added hierarchical grouped views by domain tags and flattened list views.
  * Advanced search, filtering, and bulk operations (enable/disable proxy, bulk deletion).
  * Direct port-specification form with real-time validation.
* **Interactive UI Components:**
  * Responsive SVG traffic and connection charts.
  * Searchable combobox dropdowns with inline creation.
  * Keyboard-accessible native `<dialog>` modals and non-intrusive toast notifications.
  * Light and Dark theme persistence without layout shift.
* **Real-time Metrics:** Polling engine for live presence stats, active connection monitors, and daily protocol usage breakdowns.

---

## v1.1.0

### Egress Proxy & System Settings
* **Dynamic SOCKS5 Egress Routing:**
  * Integrated outbound SOCKS5 proxy support with live latency and connectivity testing directly from the admin panel.
  * Support for per-domain egress overrides and global fallback.
* **Zero-Plaintext Storage:** Eliminated `.env` file dependencies by storing admin credentials (bcrypt hashed) and dynamic settings inside SQLite `app_settings`.
* **Multi-Layer Public IP Detection:** Implemented an automated IP detection strategy checking local routing tables, public DNS resolvers, and multiple HTTPS endpoints with fallback.
* **Service & Network Controls:**
  * Configurable listen ports and allowed destination ports from the web interface.
  * Admin credential and login path management from both the CLI and web panel.
