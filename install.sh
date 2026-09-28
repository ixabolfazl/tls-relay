#!/bin/bash
# ==============================================================================
# TLS-Relay Automated Installer
# Repository: https://github.com/ixabolfazl/tls-relay
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

GITHUB_REPO="ixabolfazl/tls-relay"
INSTALL_DIR="/opt/tls-relay"
DATA_DIR="/var/lib/tls-relay"
LOG_DIR="/var/log/tls-relay"
SERVICE_FILE="/etc/systemd/system/tls-relay.service"
CLI_BIN="/usr/local/bin/tls-relay"

echo -e "${BOLD}${CYAN}"
echo "=========================================================="
echo "          TLS-Relay & Custom DNS Installer               "
echo "      High-Performance TLS SNI Proxy & DNS Resolver       "
echo "         https://github.com/${GITHUB_REPO}                "
echo "=========================================================="
echo -e "${NC}"

# 1. Root check
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This installer must be run as root. Please run with sudo." >&2
    exit 1
fi

# 2. Check architecture
arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo 'amd64' ;;
        aarch64 | arm64) echo 'arm64' ;;
        *) echo 'unsupported' ;;
    esac
}

ARCH=$(arch)
if [[ "${ARCH}" == "unsupported" ]]; then
    echo -e "${RED}[ERROR]${NC} Unsupported CPU architecture: $(uname -m). Only amd64 and arm64 are supported." >&2
    exit 1
fi
echo -e "${GREEN}✓${NC} Detected architecture: ${BOLD}${ARCH}${NC}"

# 3. Detect OS & install base prerequisites
echo -e "${CYAN}Checking and installing required prerequisites...${NC}"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID=$ID
else
    OS_ID="unknown"
fi

install_deps() {
    case "${OS_ID}" in
        ubuntu|debian|armbian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq >/dev/null 2>&1 || true
            apt-get install -y -qq curl tar openssl systemd socat >/dev/null 2>&1
            ;;
        centos|rhel|almalinux|rocky|fedora)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y -q curl tar openssl systemd socat >/dev/null 2>&1
            else
                yum install -y -q curl tar openssl systemd socat >/dev/null 2>&1
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm curl tar openssl systemd socat >/dev/null 2>&1
            ;;
        *)
            echo -e "${YELLOW}Notice: Unknown OS (${OS_ID}). Ensure curl, tar and openssl are installed.${NC}"
            ;;
    esac
}
install_deps
echo -e "${GREEN}✓${NC} Prerequisites verified."

# 4. Resolve latest version
echo -e "${CYAN}Checking latest release from GitHub (${GITHUB_REPO})...${NC}"
VERSION="$1"
if [[ -z "${VERSION}" ]]; then
    VERSION=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | \
              grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    # Fallback to redirect resolution if rate-limited
    if [[ -z "${VERSION}" ]]; then
        VERSION=$(curl -s -L -I -o /dev/null -w '%{url_effective}' "https://github.com/${GITHUB_REPO}/releases/latest" 2>/dev/null | rev | cut -d'/' -f1 | rev)
    fi
fi

if [[ -z "${VERSION}" || "${VERSION}" == "releases" ]]; then
    echo -e "${RED}[ERROR]${NC} Failed to detect latest version from GitHub."
    echo -e "You can specify a tag manually, for example:"
    echo -e "  bash install.sh v1.0.0"
    exit 1
fi
echo -e "${GREEN}✓${NC} Target release version: ${BOLD}${VERSION}${NC}"

# 5. Free port 53 (systemd-resolved conflict resolver)
echo -e "${CYAN}Checking port 53 and systemd-resolved...${NC}"
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo -e "${YELLOW}Detected active systemd-resolved. Freeing port 53 for Custom DNS Resolver...${NC}"
    systemctl disable --now systemd-resolved >/dev/null 2>&1 || true

    # Clean up /etc/resolv.conf
    rm -f /etc/resolv.conf
    cat > /etc/resolv.conf << 'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
    echo -e "${GREEN}✓${NC} Disabled systemd-resolved and updated /etc/resolv.conf."
fi

# 6. Open Firewall Ports (53, 80, 443)
echo -e "${CYAN}Configuring firewall for required ports (53, 80, 443)...${NC}"
if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
    echo -e "${YELLOW}Configuring UFW rules...${NC}"
    ufw allow 53/tcp comment 'tls-relay DNS TCP' >/dev/null 2>&1 || true
    ufw allow 53/udp comment 'tls-relay DNS UDP' >/dev/null 2>&1 || true
    ufw allow 80/tcp comment 'tls-relay HTTP & Panel' >/dev/null 2>&1 || true
    ufw allow 443/tcp comment 'tls-relay SNI Proxy' >/dev/null 2>&1 || true
    echo -e "${GREEN}✓${NC} UFW ports opened."
elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    echo -e "${YELLOW}Configuring Firewalld rules...${NC}"
    firewall-cmd --permanent --add-port=53/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=53/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo -e "${GREEN}✓${NC} Firewalld ports opened."
elif command -v iptables >/dev/null 2>&1; then
    iptables -I INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
    echo -e "${GREEN}✓${NC} iptables rules added."
fi

# 7. Create necessary directories
mkdir -p "${INSTALL_DIR}" "${DATA_DIR}" "${LOG_DIR}"

# 8. Download release archive
TAR_NAME="tls-relay-linux-${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${TAR_NAME}"
CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${TAR_NAME}.sha256"

TMP_DIR=$(mktemp -d)
echo -e "${CYAN}Downloading ${TAR_NAME} from GitHub...${NC}"
if ! curl -fLR --connect-timeout 20 --retry 3 -o "${TMP_DIR}/${TAR_NAME}" "${DOWNLOAD_URL}"; then
    echo -e "${RED}[ERROR]${NC} Failed to download release archive from: ${DOWNLOAD_URL}"
    rm -rf "${TMP_DIR}"
    exit 1
fi

# Optional checksum verification
if curl -sLf -o "${TMP_DIR}/${TAR_NAME}.sha256" "${CHECKSUM_URL}" 2>/dev/null; then
    echo -e "${CYAN}Verifying SHA256 checksum...${NC}"
    cd "${TMP_DIR}"
    if sha256sum -c "${TAR_NAME}.sha256" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} Checksum verified."
    else
        echo -e "${YELLOW}Warning: Checksum verification failed or mismatch, continuing...${NC}"
    fi
    cd - >/dev/null
fi

# 9. Stop service if already running
if systemctl is-active --quiet tls-relay 2>/dev/null; then
    echo -e "${YELLOW}Stopping existing tls-relay service for update...${NC}"
    systemctl stop tls-relay
fi

# 10. Extract and install files
echo -e "${CYAN}Extracting files to ${INSTALL_DIR}...${NC}"
tar -zxvf "${TMP_DIR}/${TAR_NAME}" -C "${TMP_DIR}" >/dev/null 2>&1

cp -f "${TMP_DIR}/tls-relay" "${INSTALL_DIR}/tls-relay"
chmod +x "${INSTALL_DIR}/tls-relay"

# Copy default config if not present
if [[ ! -f "${INSTALL_DIR}/config.yaml" && -f "${TMP_DIR}/config.yaml" ]]; then
    cp "${TMP_DIR}/config.yaml" "${INSTALL_DIR}/config.yaml"
fi

# Copy CLI script
if [[ -f "${TMP_DIR}/tls-relay.sh" ]]; then
    cp -f "${TMP_DIR}/tls-relay.sh" "${INSTALL_DIR}/tls-relay.sh"
    cp -f "${TMP_DIR}/tls-relay.sh" "${CLI_BIN}"
    chmod +x "${INSTALL_DIR}/tls-relay.sh" "${CLI_BIN}"
fi

# Copy systemd unit file
if [[ -f "${TMP_DIR}/tls-relay.service" ]]; then
    cp -f "${TMP_DIR}/tls-relay.service" "${SERVICE_FILE}"
else
    cat > "${SERVICE_FILE}" << 'EOF'
[Unit]
Description=TLS SNI Relay and DNS Resolver Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/tls-relay
EnvironmentFile=/opt/tls-relay/.env
ExecStart=/opt/tls-relay/tls-relay -config /opt/tls-relay/config.yaml
Restart=always
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
fi

rm -rf "${TMP_DIR}"

# Validate IPv4 format
is_valid_ipv4() {
    local ip="$1"
    local rx='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ $ip =~ $rx ]]; then
        local IFS='.'
        read -r -a octets <<< "$ip"
        for oct in "${octets[@]}"; do
            (( oct >= 0 && oct <= 255 )) || return 1
        done
        return 0
    fi
    return 1
}

# Check if IP is a public (non-private/non-loopback/non-bogon) IPv4
is_public_ipv4() {
    local ip="$1"
    is_valid_ipv4 "$ip" || return 1
    case "$ip" in
        10.*|192.168.*|127.*|169.254.*|0.*) return 1 ;;
        172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) return 1 ;;
        100.6[4-9].*|100.[7-9][0-9].*|100.1[0-1][0-9].*|100.12[0-7].*) return 1 ;;
        *) return 0 ;;
    esac
}

# Fetch server public IP using a resilient multi-layer strategy
get_public_ip() {
    local ip=""

    # 1. Local interface route check (instantaneous, works offline if server has public IP)
    local local_ip
    local_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if is_public_ipv4 "${local_ip}"; then
        echo "${local_ip}"
        return 0
    fi

    # 2. DNS query (fast, bypasses HTTP filters/censorship)
    if command -v dig >/dev/null 2>&1; then
        local dns_ip
        dns_ip=$(dig +short +time=2 +tries=1 myip.opendns.com @208.67.222.222 2>/dev/null | tr -d '"' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
        if is_public_ipv4 "${dns_ip}"; then
            echo "${dns_ip}"
            return 0
        fi
    fi

    # 3. HTTP endpoints with strict regex validation
    local endpoints=(
        "https://checkip.amazonaws.com"
        "https://cloudflare.com/cdn-cgi/trace"
        "https://api4.ipify.org"
        "https://icanhazip.com"
        "https://ifconfig.me/ip"
    )

    for url in "${endpoints[@]}"; do
        local resp extracted
        resp=$(curl -4s --connect-timeout 2 --max-time 4 "$url" 2>/dev/null)
        extracted=$(echo "$resp" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
        if is_public_ipv4 "${extracted}"; then
            echo "${extracted}"
            return 0
        fi
    done

    echo ""
}

# 11. Public IP Detection & Configuration
echo -e "${CYAN}Detecting server public IP...${NC}"
DETECTED_IP=$(get_public_ip)
[[ -z "${DETECTED_IP}" ]] && DETECTED_IP="127.0.0.1"

PUBLIC_IP="${DETECTED_IP}"
# If interactive terminal, allow user to confirm or override
if [[ -t 0 && "${NONINTERACTIVE:-0}" != "1" ]]; then
    read -rp "Server Public IP [default: ${DETECTED_IP}]: " input_ip
    PUBLIC_IP="${input_ip:-$DETECTED_IP}"
fi
echo -e "${GREEN}✓${NC} Using Public IP: ${BOLD}${PUBLIC_IP}${NC}"

# 12. Outbound SOCKS5 Egress Proxy Configuration
EGRESS_ENABLED="false"
EGRESS_ADDR="127.0.0.1:1080"
EGRESS_USER=""
EGRESS_PASS=""

if [[ -f "${INSTALL_DIR}/.env" ]]; then
    # Read existing proxy configuration if updating
    EGRESS_ENABLED=$(grep -E '^EGRESS_PROXY_ENABLED=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "false")
    EGRESS_ADDR=$(grep -E '^EGRESS_PROXY_ADDR=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "127.0.0.1:1080")
    EGRESS_USER=$(grep -E '^EGRESS_PROXY_USER=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
    EGRESS_PASS=$(grep -E '^EGRESS_PROXY_PASSWORD=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
else
    # Fresh install: prompt interactively
    if [[ -t 0 && "${NONINTERACTIVE:-0}" != "1" ]]; then
        echo ""
        read -rp "Do you want to enable Outbound SOCKS5 Egress Proxy (e.g. Cloudflare WARP)? (y/N): " ask_proxy
        if [[ "${ask_proxy,,}" == "y" ]]; then
            EGRESS_ENABLED="true"
            read -rp "SOCKS5 Proxy Address [default: 127.0.0.1:1080]: " input_egress_addr
            EGRESS_ADDR="${input_egress_addr:-127.0.0.1:1080}"
            read -rp "SOCKS5 Username (optional, press Enter if none): " EGRESS_USER
            read -rp "SOCKS5 Password (optional, press Enter if none): " EGRESS_PASS
            echo -e "${GREEN}✓${NC} Outbound SOCKS5 proxy configured: ${BOLD}${EGRESS_ADDR}${NC}"
        else
            echo -e "${CYAN}Outbound SOCKS5 proxy disabled (direct connection).${NC}"
        fi
    fi
fi

# 13. Setup .env file
ADMIN_USER="admin"
ADMIN_PASS=""
ADMIN_PATH=""
IS_NEW_INSTALL=0

if [[ ! -f "${INSTALL_DIR}/.env" ]]; then
    IS_NEW_INSTALL=1
    ADMIN_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 16)
    # Generate random admin panel path for security (e.g. /k8mX2a9L)
    RANDOM_SLUG=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 8)
    ADMIN_PATH="/${RANDOM_SLUG}"
    cat > "${INSTALL_DIR}/.env" << EOF
PANEL_ADMIN_USER=${ADMIN_USER}
PANEL_ADMIN_PASSWORD=${ADMIN_PASS}
PANEL_PATH=${ADMIN_PATH}
RELAY_IP=${PUBLIC_IP}
ACCESS_MODE=user
EGRESS_PROXY_ENABLED=${EGRESS_ENABLED}
EGRESS_PROXY_ADDR=${EGRESS_ADDR}
EGRESS_PROXY_USER=${EGRESS_USER}
EGRESS_PROXY_PASSWORD=${EGRESS_PASS}
EOF
    chmod 600 "${INSTALL_DIR}/.env"
else
    # Preserve existing credentials and path
    ADMIN_USER=$(grep -E '^PANEL_ADMIN_USER=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "admin")
    ADMIN_PASS=$(grep -E '^PANEL_ADMIN_PASSWORD=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "")
    ADMIN_PATH=$(grep -E '^PANEL_PATH=' "${INSTALL_DIR}/.env" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || echo "/admin")
    [[ -z "${ADMIN_PATH}" ]] && ADMIN_PATH="/admin"
    # Update RELAY_IP
    if grep -q '^RELAY_IP=' "${INSTALL_DIR}/.env"; then
        sed -i "s|^RELAY_IP=.*|RELAY_IP=${PUBLIC_IP}|" "${INSTALL_DIR}/.env"
    else
        echo "RELAY_IP=${PUBLIC_IP}" >> "${INSTALL_DIR}/.env"
    fi
fi

# Update config.yaml with detected public IP
if [[ -f "${INSTALL_DIR}/config.yaml" ]]; then
    sed -i -E "s|^([[:space:]]*relay_ip:).*|\1 \"${PUBLIC_IP}\"|" "${INSTALL_DIR}/config.yaml" 2>/dev/null || true
fi

# 13. Enable and Start Systemd Service
echo -e "${CYAN}Reloading systemd and enabling tls-relay service...${NC}"
systemctl daemon-reload
systemctl enable --now tls-relay

sleep 1.5

# 14. Check Service Status
if systemctl is-active --quiet tls-relay; then
    echo -e "${GREEN}✓ tls-relay is running successfully!${NC}"
else
    echo -e "${RED}✗ Warning: tls-relay did not start immediately.${NC}"
    echo -e "Check logs with: ${BOLD}journalctl -u tls-relay -n 50${NC}"
fi

# 15. Optional: TCP BBR Enablement
CURRENT_CC=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
if [[ "${CURRENT_CC}" != "bbr" ]]; then
    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true
    cat > /etc/sysctl.d/99-tls-relay-bbr.conf << 'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
EOF
    sysctl -p /etc/sysctl.d/99-tls-relay-bbr.conf >/dev/null 2>&1 || true
fi

# 16. Print Completion Information
echo ""
echo -e "${BOLD}${GREEN}==========================================================${NC}"
echo -e "${BOLD}${GREEN}        TLS-Relay Installation Completed Successfully!    ${NC}"
echo -e "${BOLD}${GREEN}==========================================================${NC}"
echo ""
echo -e "  ${BOLD}Server Public IP :${NC} ${CYAN}${PUBLIC_IP}${NC}"
echo -e "  ${BOLD}Admin Panel URL  :${NC} ${CYAN}http://${PUBLIC_IP}${ADMIN_PATH}${NC}"
echo -e "  ${BOLD}Username         :${NC} ${GREEN}${ADMIN_USER}${NC}"
if [[ -n "${ADMIN_PASS}" ]]; then
    echo -e "  ${BOLD}Password         :${NC} ${YELLOW}${ADMIN_PASS}${NC}"
fi
echo -e "  ${BOLD}Config Location  :${NC} ${INSTALL_DIR}/config.yaml"
echo -e "  ${BOLD}Env Credentials  :${NC} ${INSTALL_DIR}/.env"
echo -e "  ${BOLD}SQLite Database  :${NC} ${DATA_DIR}/data.db"
echo ""
echo -e "  ${BOLD}Active Network Ports:${NC}"
echo -e "    - Port ${BOLD}53${NC} (UDP/TCP) : Custom DNS Resolver"
echo -e "    - Port ${BOLD}80${NC} (TCP)     : Admin Panel & HTTP Relay & Magic Link"
echo -e "    - Port ${BOLD}443${NC} (TCP)    : Transparent TLS SNI Proxy"
echo ""
echo -e "  ${BOLD}Management Command:${NC}"
echo -e "    Run ${CYAN}tls-relay${NC} in your terminal anytime to open the management menu!"
echo -e "    (e.g., start/stop, view logs, change credentials, switch access mode)"
echo ""
echo -e "${BOLD}${GREEN}==========================================================${NC}"
