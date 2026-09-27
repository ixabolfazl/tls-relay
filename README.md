# TLS-Relay

[![Release](https://img.shields.io/github/v/release/ixabolfazl/tls-relay?color=00c853\&label=Release)](https://github.com/ixabolfazl/tls-relay/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/ixabolfazl/tls-relay/ci.yml?branch=main\&label=CI)](https://github.com/ixabolfazl/tls-relay/actions)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ixabolfazl/tls-relay)](go.mod)
[![Platform](https://img.shields.io/badge/Platform-Linux%20\(amd64%20%7C%20arm64\)-orange)](https://github.com/ixabolfazl/tls-relay/releases)

**TLS-Relay** is a high-performance TCP/TLS relay and custom DNS server written in Go.

It routes selected domains through your server without terminating TLS or decrypting user traffic.

---

## Features

* 🚀 **High-performance TCP/TLS relay**
* 🔒 **TLS passthrough** — no TLS termination or custom certificates
* 🌐 **Custom DNS server** for routing configured domains
* 🔀 **Flexible domain-based routing**
* 🎯 **Exact domain and subdomain matching**
* ⭐ **Wildcard domain rules** such as `*.example.com`
* ✈️ **Optional outbound SOCKS5 proxy**
* 📡 **HTTP relay support**
* 👥 **User and IP access management**
* 🔗 **Magic Link** client onboarding
* 🛡️ **IP/CIDR blacklist**
* 📊 **Web administration panel**
* 📈 **Real-time connection and bandwidth monitoring**
* 📝 **Connection and DNS request logs**
* ⚙️ **Command-line management tool**
* 💾 **Persistent SQLite configuration**
* 🔄 **Automatic systemd service management**
* ⚡ **TCP BBR optimization**

---

## How It Works

```text
                         Client
                           │
                           │ DNS Query
                           ▼
                    ┌───────────────┐
                    │  DNS Server   │
                    │     :53       │
                    └───────┬───────┘
                            │
                     Configured Domain
                            │
                            ▼
                    Relay Server IP
                            │
                            ▼
                    ┌───────────────┐
                    │   TLS-Relay   │
                    │     :443      │
                    └───────┬───────┘
                            │
                       Routing Rules
                            │
                  ┌─────────┴─────────┐
                  ▼                   ▼
               Direct               SOCKS5
                  │                   │
                  └─────────┬─────────┘
                            ▼
                       Destination
```

TLS-Relay acts as a relay between the client and destination server.

TLS traffic is passed through without terminating TLS or requiring custom CA certificates.

---

## Installation

The recommended installation method is the official installer.

Run the following command as `root`:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ixabolfazl/tls-relay/main/install.sh)
```

The installer automatically:

* Detects the server architecture
* Downloads the appropriate release
* Configures the required firewall ports
* Configures the DNS service
* Detects the server's public IP
* Configures the relay IP
* Optionally configures an outbound SOCKS5 proxy
* Generates initial admin credentials
* Creates the systemd service
* Enables automatic service restart
* Configures TCP BBR optimization
* Installs the `tls-relay` management command

After installation:

```bash
tls-relay
```

---

## Web Panel

TLS-Relay includes a built-in web administration panel.

The panel provides a single interface for managing the relay and monitoring its activity.

### Dashboard

The dashboard provides:

* Active connection count
* Bandwidth information
* Connection activity
* DNS request activity
* Relay status

### Connection Logs

View and search relay connections and inspect information such as:

* Client IP
* Destination domain
* Destination port
* Connection status
* Traffic information

Rules can be created directly from matching connection entries.

### DNS Logs

The panel provides searchable DNS request logs for monitoring resolver activity.

### User Management

Manage relay users and their allowed IP addresses.

Users can also be onboarded using **Magic Links**, allowing a client to register without manually entering configuration information.

### Access Control

Manage:

* Allowed client IPs
* IP quotas
* Access status
* Global IP/CIDR blacklist

### Configuration

Manage relay and outbound proxy settings directly from the panel.

The panel is embedded into the TLS-Relay binary and does not require a separate web application or web server.

---

## Management CLI

TLS-Relay includes a command-line management tool for managing the service directly from the server.

Run:

```bash
tls-relay
```

This opens the interactive management menu.

The CLI provides:

* Service status and port information
* Start, stop, and restart
* Live service logs
* Admin credentials and panel path management
* Access mode configuration
* Outbound SOCKS5 proxy configuration
* Firewall configuration
* TCP BBR optimization
* Update to the latest release
* SQLite database backup
* Uninstallation

Common commands are also available directly:

```bash
tls-relay status
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

---

## TLS Relay

TLS-Relay supports transparent TLS passthrough on port `443`.

The relay reads the information required to identify the destination and forwards the TCP connection to the selected server.

It does not:

* Terminate TLS
* Generate certificates
* Require a custom CA
* Decrypt application traffic

The TLS session remains end-to-end between the client and destination server.

---

## Routing Rules

TLS-Relay supports flexible domain-based routing rules.

Each rule can specify how connections to a domain should be handled.

### Supported Domain Patterns

| Pattern           | Matches                     |
| ----------------- | --------------------------- |
| `example.com`     | Only `example.com`          |
| `api.example.com` | Only `api.example.com`      |
| `*.example.com`   | Subdomains of `example.com` |

This allows both specific destinations and groups of subdomains to be routed independently.

For example:

```text
example.com             → Direct
api.example.com         → Direct
*.download.example.com  → SOCKS5
```

Wildcard rules can be used to route an entire group of subdomains without creating a separate rule for every domain.

Each domain rule can use one of the following outbound modes:

* **Direct** — connect directly to the destination
* **SOCKS5** — connect through the configured outbound SOCKS5 proxy

For example:

```text
example.com             → Direct
api.example.com         → SOCKS5
*.cdn.example.com       → SOCKS5
```

This allows different domains and subdomains to use different outbound routes.

---

## SOCKS5 Egress

TLS-Relay can optionally route outbound connections through an external SOCKS5 proxy.

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

A SOCKS5 proxy can be enabled globally and overridden by individual routing rules.

For example:

```env
EGRESS_PROXY_ENABLED=true
EGRESS_PROXY_ADDR=127.0.0.1:1080
```

Optional authentication is supported:

```env
EGRESS_PROXY_USER=
EGRESS_PROXY_PASSWORD=
```

This allows selected destinations to use an alternative outbound network path while other traffic remains direct.

---

## DNS Server

TLS-Relay includes a custom DNS server on port `53`.

For configured domains and authorized clients, the DNS server returns the relay server's public IP.

```text
Client
   │
   │ DNS query
   ▼
TLS-Relay DNS
   │
   └── configured-domain.com
              │
              ▼
        Relay Server IP
```

Other DNS queries are forwarded to the configured upstream resolver.

The DNS server includes:

* Per-IP rate limiting
* DNS response size limits
* `ANY` query protection
* Client access control
* Configurable upstream DNS

The default upstream resolver is:

```text
1.1.1.1
```

---

## HTTP Relay

TLS-Relay can also handle plain HTTP traffic on port `80`.

Configured HTTP domains can be relayed to their destination servers according to the configured routing rules.

The same HTTP listener is also used by the built-in administration panel and client onboarding pages.

---

## Access Control

TLS-Relay supports two access modes.

### User Mode

Only registered client IPs can use the relay.

```env
ACCESS_MODE=user
```

### Public Mode

The relay accepts connections without requiring registered client IPs.

```env
ACCESS_MODE=public
```

User mode can be used together with the built-in user management system to control which client IPs are allowed to access the relay.

---

## Magic Links

TLS-Relay supports Magic Link-based client onboarding.

Each user can receive a unique link such as:

```text
/connect/<token>
```

The link can be used to register or configure client access without manually entering the relay information.

Magic Links can be managed from the web panel.

---

## Security

TLS-Relay includes several protections for the relay and administration interface:

* Randomized administration panel path
* Password-protected administration
* User/IP-based access control
* IP and CIDR blacklist
* DNS query rate limiting
* DNS amplification protections
* Restricted destination ports
* Connection limits
* Configurable connection timeouts

The administration panel is not exposed through a predictable default URL path.

---

## Ports

By default, TLS-Relay uses:

| Port  | Protocol | Purpose                |
| ----- | -------- | ---------------------- |
| `53`  | TCP/UDP  | Custom DNS server      |
| `80`  | TCP      | HTTP relay / Web Panel |
| `443` | TCP      | TLS relay              |

Additional destination ports can be allowed through the configuration.

Default supported destination ports include:

```text
443
8443
2053
2083
2087
2096
9443
```

---

## Configuration

TLS-Relay uses:

```text
/opt/tls-relay/.env
/opt/tls-relay/config.yaml
/var/lib/tls-relay/data.db
```

### Environment Variables

Common environment variables:

| Variable                | Description                          |
| ----------------------- | ------------------------------------ |
| `PANEL_ADMIN_USER`      | Administration username              |
| `PANEL_ADMIN_PASSWORD`  | Administration password              |
| `PANEL_PATH`            | Administration panel URL path        |
| `RELAY_IP`              | Public IP returned by the DNS server |
| `ACCESS_MODE`           | `user` or `public`                   |
| `EGRESS_PROXY_ENABLED`  | Enable outbound SOCKS5               |
| `EGRESS_PROXY_ADDR`     | SOCKS5 proxy address                 |
| `EGRESS_PROXY_USER`     | SOCKS5 username                      |
| `EGRESS_PROXY_PASSWORD` | SOCKS5 password                      |

Environment variables take precedence over database and YAML configuration values.

### Example Configuration

```yaml
listen:
  addr: "0.0.0.0"
  ports:
    - 443
  http_ports:
    - 80

allowed_dest_ports:
  - 443
  - 8443
  - 2053
  - 2083
  - 2087
  - 2096
  - 9443

unknown_domain_policy: "allow_default_port"

timeouts:
  client_hello: 5s
  http_header: 5s
  idle: 300s
  tcp_keepalive: 30s

limits:
  max_global_connections: 10000
  max_connections_per_ip: 200

dns:
  addr: "0.0.0.0:53"
  relay_ip: "YOUR_SERVER_PUBLIC_IP"
  upstream_addr: "1.1.1.1:53"
  ttl: 30
  rate_limit:
    qps: 20
    burst: 40

sqlite:
  path: "/var/lib/tls-relay/data.db"
```

---

## Performance

TLS-Relay is designed for high-throughput, long-lived TCP connections.

It includes:

* Efficient TCP connection handling
* Configurable connection limits
* TCP keepalive
* Connection timeouts
* Linux TCP BBR support
* Tunable socket buffers
* High file descriptor limits

The installer can automatically configure BBR and recommended network settings on supported Linux systems.

---

## Service Management

TLS-Relay runs as a systemd service:

```text
tls-relay.service
```

The service is configured to automatically restart when necessary.

Basic systemd commands are also available:

```bash
systemctl status tls-relay
systemctl restart tls-relay
systemctl stop tls-relay
systemctl start tls-relay
```

Logs can be viewed using:

```bash
journalctl -u tls-relay -f
```

The `tls-relay log` command provides the same functionality through the management CLI.

---

## Updating

TLS-Relay can update an existing installation without removing its configuration or database.

Run:

```bash
tls-relay update
```

Before updating, you can create a database backup:

```bash
tls-relay backup
```

---

## Backup

The SQLite database contains persistent relay configuration and management data.

Create a timestamped backup with:

```bash
tls-relay backup
```

Backups can be created before upgrades, migrations, or configuration changes.

---

## Uninstall

To remove TLS-Relay:

```bash
tls-relay uninstall
```

The uninstall process stops the service and removes the installed application.

You can choose whether to preserve the existing database.

---

## Requirements

### Server

* Linux
* `amd64` or `arm64`
* Root access
* Public IPv4 address

Supported distributions include:

* Ubuntu
* Debian
* AlmaLinux
* Rocky Linux
* CentOS
* Arch Linux

The release installer does not require Go to be installed.

---

## Build From Source

For development or custom builds, Go `1.22+` is required.

Clone the repository:

```bash
git clone https://github.com/ixabolfazl/tls-relay.git
cd tls-relay
```

Build:

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

Run tests:

```bash
make test
```

---

## License

TLS-Relay is released under the [MIT License](LICENSE).

Copyright © 2026 ixabolfazl
