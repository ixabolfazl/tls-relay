# TLS-Relay

[![Release](https://img.shields.io/github/v/release/ixabolfazl/tls-relay?color=00c853\&label=Release)](https://github.com/ixabolfazl/tls-relay/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/ixabolfazl/tls-relay/ci.yml?branch=main\&label=CI)](https://github.com/ixabolfazl/tls-relay/actions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ixabolfazl/tls-relay)](go.mod)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%28amd64%20%7C%20arm64%29-orange)](https://github.com/ixabolfazl/tls-relay/releases)

**TLS-Relay** is a TCP/TLS relay and custom DNS server written in Go.

It routes selected domains through your server without terminating TLS or decrypting application traffic. Routing can be configured per domain, subdomain, or wildcard pattern, with optional SOCKS5 egress.

## Features

* TCP/TLS passthrough
* Custom DNS server
* Domain-based routing
* Exact domain and subdomain matching
* Wildcard rules such as `*.example.com`
* Direct or SOCKS5 outbound routing
* Per-domain SOCKS5 overrides
* HTTP relay
* User and IP access control
* Magic Link client onboarding
* IP/CIDR blacklist
* Web administration panel
* Connection and DNS logs
* Real-time connection and bandwidth monitoring
* Interactive management CLI
* SQLite-based configuration and storage
* TCP BBR optimization
* Configurable connection and DNS limits

## How It Works

```text
                         Client
                           │
                           │ DNS Query
                           ▼
                    ┌───────────────┐
                    │  TLS-Relay    │
                    │   DNS :53     │
                    └───────┬───────┘
                            │
                    Configured Domain
                            │
                            ▼
                    Relay Server IP
                            │
                            ▼
                    ┌───────────────┐
                    │  TLS-Relay    │
                    │   TCP :443    │
                    └───────┬───────┘
                            │
                       Routing Rule
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
              Direct                SOCKS5
                 │                     │
                 └──────────┬──────────┘
                            ▼
                       Destination
```

For configured domains, the DNS server returns the relay server IP. The client then connects to the relay, which uses the TLS SNI to select the appropriate routing rule.

TLS is passed through directly. TLS-Relay does not terminate TLS, generate certificates, or decrypt application traffic.

## Installation

The recommended installation method is the official installer.

Run as `root`:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ixabolfazl/tls-relay/main/install.sh)
```

After installation:

```bash
tls-relay
```

The installer sets up the binary, configuration, SQLite database, systemd service, and required network settings.

## Web Panel

TLS-Relay includes a built-in web administration panel. No separate web server or application is required.

### Dashboard

The dashboard shows:

* Active connections
* Bandwidth usage
* Connection activity
* DNS request activity
* Relay status

### Connection Logs

Connection logs include information such as:

* Client IP
* Destination domain
* Destination port
* Connection status
* Traffic information

Routing rules can also be created directly from matching connection entries.

### DNS Logs

DNS requests can be searched and inspected from the panel.

### User Management

Users can be created and managed from the panel, including their allowed client IPs.

Clients can also be onboarded through Magic Links.

### Access Control

The panel provides management for:

* Allowed client IPs
* IP quotas
* User access
* Global IP/CIDR blacklist

### Settings

Relay, DNS, access-control, destination-port, and outbound proxy settings can be managed from the panel.

Changes to supported runtime settings are applied without restarting the service.

## Management CLI

Run:

```bash
tls-relay
```

to open the interactive management menu.

Available operations include:

* Service status
* Start / stop / restart / reload
* Live logs
* Admin credentials
* Access mode
* SOCKS5 proxy
* Firewall configuration
* TCP BBR
* Update
* SQLite backup
* Uninstall

Common commands:

```bash
tls-relay status
tls-relay reload
tls-relay restart
tls-relay log
tls-relay creds
tls-relay mode
tls-relay proxy
tls-relay firewall
tls-relay bbr
tls-relay update
tls-relay backup
tls-relay uninstall
```

### Direct Binary Subcommands

The `tls-relay` binary provides subcommands to inspect and modify settings directly in the SQLite database or perform consistent backups:

```bash
# View all settings or a specific setting
tls-relay settings get
tls-relay settings get access_mode

# Set a setting with validation
tls-relay settings set access_mode public
tls-relay settings set panel_path /my-secret-panel

# Consistent point-in-time database snapshot via VACUUM INTO
tls-relay backup /opt/tls-relay/backups/snapshot.db

# Initialize or reset admin credentials safely
TLS_RELAY_ADMIN_PASS="mypassword" tls-relay -init-admin -user admin
```

### Zero-Downtime Live Reload

Applying settings changes does not require dropping active connections:

```bash
systemctl reload tls-relay
# or
tls-relay reload
```

This sends `SIGHUP` to the daemon, re-reading SQLite settings (`access_mode`, `unknown_domain_policy`, `panel_path`, `timezone`, `max_connections_per_ip`, `allowed_dest_ports`, `egress_proxy_*`, `http_front_max_*`, `lookup_*`) and re-reading admin credentials (invalidating active sessions) without restarting listeners or terminating in-flight connections.

## TLS Relay

TLS-Relay supports TCP/TLS passthrough on port `443`.

The relay reads the TLS SNI to identify the destination and forwards the TCP connection according to the matching routing rule.

TLS-Relay does **not**:

* Terminate TLS
* Generate certificates
* Require a custom CA
* Decrypt application traffic

The TLS session remains end-to-end between the client and destination.

## Routing

Routing rules are matched by domain.

### Domain Patterns

| Pattern           | Matches                     |
| ----------------- | --------------------------- |
| `example.com`     | Only `example.com`          |
| `api.example.com` | Only `api.example.com`      |
| `*.example.com`   | Subdomains of `example.com` |

Examples:

```text
example.com             → Direct
api.example.com         → Direct
*.download.example.com  → SOCKS5
```

Wildcard rules can be used when multiple subdomains should share the same routing policy.

### Outbound Modes

Each routing rule can use:

**Direct**

```text
TLS-Relay → Destination
```

**SOCKS5**

```text
TLS-Relay → SOCKS5 Proxy → Destination
```

A domain can also override the global SOCKS5 configuration and use its own proxy or force a direct connection.

## SOCKS5 Egress

TLS-Relay can route outbound connections through an external SOCKS5 proxy.

The proxy can be configured from the Web Panel or CLI.

Supported options include:

* Enable / disable SOCKS5
* Proxy address
* Username and password authentication
* Per-domain proxy overrides
* Direct routing overrides
* Runtime configuration changes without restarting the service

Example:

```text
Client
  │
  ▼
TLS-Relay
  │
  ├── Direct ──────► Destination
  │
  └── SOCKS5 ─────► SOCKS5 Proxy ─────► Destination
```

## DNS Server

TLS-Relay includes a custom DNS server on port `53`.

For configured domains and authorized clients, it returns the relay server's public IP.

Other queries are forwarded to the configured upstream resolver.

Default upstream DNS:

```text
1.1.1.1:53
```

The DNS server includes:

* Per-IP rate limiting
* Response size limits
* `ANY` query protection
* Client access control
* Configurable upstream resolver

Example:

```text
Client
   │
   │ DNS query
   ▼
TLS-Relay DNS
   │
   └── example.com
          │
          ▼
    Relay Server IP
```

## HTTP Relay

TLS-Relay can relay plain HTTP traffic on port `80`.

HTTP domains use the same routing configuration as the relay.

Port `80` is also used by the built-in administration panel and client onboarding pages.

## Access Control

TLS-Relay supports two access modes.

### User Mode

User mode is the default.

Only registered client IPs can use the relay and DNS service.

```yaml
access_mode: "user"
```

Clients can be registered through the Web Panel or Magic Links.

### Public Mode

Public mode allows clients to use the relay and DNS service without registration.

```yaml
access_mode: "public"
```

Use of public mode can be combined with the global IP/CIDR blacklist and connection limits.

## Magic Links

Clients can be onboarded using a unique Magic Link:

```text
/connect/<token>
```

The link can be used to register the client without manually entering relay configuration.

Magic Links can be created and managed from the Web Panel.

## Security

TLS-Relay includes several controls for limiting access to the relay and administration panel:

* Randomized administration panel path
* Password-protected administration
* User/IP-based access control
* IP and CIDR blacklist
* DNS query rate limiting
* DNS amplification protections
* Restricted destination ports
* Connection limits
* Client-hello and HTTP-header timeouts
* Idle connection timeouts

The administration panel path can be randomized during installation.


## Updating

Update an existing installation without removing configuration or database:

```bash
tls-relay update
```

The updater verifies SHA256 checksums, performs atomic binary and CLI script replacements, updates the systemd unit file when needed, and tests service startup with automatic rollback if the service fails to become active.

Create a database backup before updating:

```bash
tls-relay backup
```

> **Note for Existing Installations:** Installations running an older version of the management script must run the official installer once to receive the self-updating script and updated unit file:
> ```bash
> bash <(curl -Ls https://raw.githubusercontent.com/ixabolfazl/tls-relay/main/install.sh)
> ```

## Backup

The SQLite database contains persistent configuration and management data.

Create a timestamped backup:

```bash
tls-relay backup
```

Backups are useful before upgrades, migrations, or configuration changes.

## Uninstall

Remove TLS-Relay using:

```bash
tls-relay uninstall
```

The uninstall process stops the service and removes the installed application.

You can choose whether to keep the existing SQLite database.

## Build From Source

Go `1.22+` is required. The build automatically downloads the official standalone Tailwind CSS CLI executable into `.bin/` on first run to compile and embed the admin panel CSS.

Clone the repository:

```bash
git clone https://github.com/ixabolfazl/tls-relay.git
cd tls-relay
```

Build CSS (optional, called automatically by `make build` and `make test`):

```bash
make css
```

Build for the current platform:

```bash
make build
```

Build Linux releases:

```bash
make build-linux
make build-linux-arm64
```

Create release packages:

```bash
make package
```

Run all unit tests:

```bash
make test
```

## License

TLS-Relay is released under the [MIT License](LICENSE).

Copyright © 2026 ixabolfazl
