#!/bin/bash
# ==============================================================================
# TLS-Relay Management CLI
# Repo: https://github.com/ixabolfazl/tls-relay
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/tls-relay"
ENV_FILE="${INSTALL_DIR}/.env"
CONFIG_FILE="${INSTALL_DIR}/config.yaml"
SERVICE_NAME="tls-relay"
DB_FILE="/var/lib/tls-relay/data.db"
LOG_FILE="/var/log/tls-relay/relay.log"
GITHUB_REPO="ixabolfazl/tls-relay"

# Check root privilege
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR]${NC} This command must be run as root (use sudo)." >&2
        exit 1
    fi
}

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

# Read env variable safely (legacy fallback)
get_env_val() {
    local key="$1"
    if [[ -f "${ENV_FILE}" ]]; then
        grep -E "^${key}=" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'"
    fi
}

# Read config.yaml value safely
get_config_val() {
    local key="$1"
    grep -E "^[[:space:]]*${key}:" "${CONFIG_FILE}" 2>/dev/null | awk '{print $2}' | tr -d '"' | tr -d "'"
}

# Get panel path from config.yaml
get_panel_path() {
    local p
    p=$(sed -n '/^panel:/,/^[a-zA-Z]/p' "${CONFIG_FILE}" 2>/dev/null | grep -E '^[[:space:]]*path:' | awk '{print $2}' | tr -d '"' | tr -d "'")
    echo "${p:-/admin}"
}

# Generate secure random string
gen_random_password() {
    local length="${1:-16}"
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c "${length}"
    else
        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c "${length}"
    fi
}

# Detect CPU architecture
get_arch() {
    case "$(uname -m)" in
        x86_64 | amd64) echo "amd64" ;;
        aarch64 | arm64) echo "arm64" ;;
        *) echo "unsupported" ;;
    esac
}

# Service status display
show_status() {
    echo -e "\n${BOLD}${CYAN}=== TLS-Relay Service Status ===${NC}"
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "Service Status : ${GREEN}● RUNNING (Active)${NC}"
    else
        echo -e "Service Status : ${RED}○ STOPPED (Inactive)${NC}"
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo -e "Auto-Start     : ${GREEN}Enabled at boot${NC}"
    else
        echo -e "Auto-Start     : ${YELLOW}Disabled${NC}"
    fi

    local pub_ip
    pub_ip=$(get_config_val "relay_ip")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_env_val "RELAY_IP")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_public_ip)
    local admin_path
    admin_path=$(get_panel_path)
    local access_mode
    access_mode=$(get_config_val "access_mode")
    [[ -z "${access_mode}" ]] && access_mode=$(get_env_val "ACCESS_MODE")
    [[ -z "${access_mode}" ]] && access_mode="user"

    echo -e "Public IP      : ${BOLD}${pub_ip:-Unknown}${NC}"
    echo -e "Access Mode    : ${BOLD}${access_mode}${NC}"
    echo -e "Admin Panel URL: ${BOLD}http://${pub_ip:-YOUR_IP}${admin_path}${NC}"

    echo -e "\n${BOLD}Listening Ports Check:${NC}"
    for port in 53 80 443; do
        if ss -tuln 2>/dev/null | grep -q ":${port} "; then
            echo -e "  Port ${BOLD}${port}${NC} : ${GREEN}LISTENING${NC}"
        else
            echo -e "  Port ${BOLD}${port}${NC} : ${YELLOW}NOT LISTENING${NC}"
        fi
    done
    echo ""
}

# Start service
start_service() {
    echo -e "${YELLOW}Starting ${SERVICE_NAME}...${NC}"
    systemctl start "${SERVICE_NAME}"
    sleep 1
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${GREEN}✓ ${SERVICE_NAME} started successfully.${NC}"
    else
        echo -e "${RED}✗ Failed to start ${SERVICE_NAME}. Check logs: journalctl -u ${SERVICE_NAME} -n 30${NC}"
    fi
}

# Stop service
stop_service() {
    echo -e "${YELLOW}Stopping ${SERVICE_NAME}...${NC}"
    systemctl stop "${SERVICE_NAME}"
    echo -e "${GREEN}✓ ${SERVICE_NAME} stopped.${NC}"
}

# Restart service
restart_service() {
    echo -e "${YELLOW}Restarting ${SERVICE_NAME}...${NC}"
    systemctl restart "${SERVICE_NAME}"
    sleep 1
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${GREEN}✓ ${SERVICE_NAME} restarted successfully.${NC}"
    else
        echo -e "${RED}✗ Failed to restart ${SERVICE_NAME}. Check logs with 'tls-relay log'.${NC}"
    fi
}

# View live logs
view_logs() {
    echo -e "${CYAN}Streaming live logs (Press Ctrl+C to exit)...${NC}\n"
    journalctl -u "${SERVICE_NAME}" -f -n 50
}

# View & reset admin credentials
manage_credentials() {
    echo -e "\n${BOLD}${CYAN}=== Admin Panel Credentials ===${NC}"
    local admin_path pub_ip
    admin_path=$(get_panel_path)
    pub_ip=$(get_config_val "relay_ip")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_public_ip)

    echo -e "Admin Panel URL: ${BOLD}${GREEN}http://${pub_ip}${admin_path}${NC}"
    echo -e "Login Path     : ${CYAN}${admin_path}${NC}"
    echo -e "Credentials    : Stored securely in SQLite database (bcrypt hash)"
    echo ""
    echo -e "1) Reset admin password with random secure password"
    echo -e "2) Set custom username and password"
    echo -e "3) Reset Admin Login Path (generate random secret URL)"
    echo -e "4) Set custom Admin Login Path"
    echo -e "0) Return to menu"
    echo ""
    read -rp "Select option [0-4]: " cred_choice

    case "${cred_choice}" in
        1)
            local new_pass
            new_pass=$(gen_random_password 16)
            echo -e "${CYAN}Applying new password to database...${NC}"
            "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" -init-admin -user "admin" -pass "${new_pass}"
            echo -e "${GREEN}✓ Admin password reset for user 'admin':${NC} ${BOLD}${new_pass}${NC}"
            ;;
        2)
            read -rp "Enter admin username [default: admin]: " new_user
            new_user="${new_user:-admin}"
            read -rp "Enter new admin password: " new_pass
            if [[ -z "${new_pass}" ]]; then
                echo -e "${RED}Password cannot be empty.${NC}"
                return
            fi
            echo -e "${CYAN}Applying credentials to database...${NC}"
            "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" -init-admin -user "${new_user}" -pass "${new_pass}"
            echo -e "${GREEN}✓ Credentials updated in database for user '${new_user}'.${NC}"
            ;;
        3)
            local rand_path
            rand_path="/$(gen_random_password 8)"
            sed -i -E '/^panel:/,/^[a-zA-Z]/ s|^([[:space:]]*path:).*|\1 "'"${rand_path}"'"|' "${CONFIG_FILE}"
            echo -e "${GREEN}✓ Admin Login Path updated to:${NC} ${BOLD}${rand_path}${NC}"
            echo -e "New Panel URL: ${BOLD}http://${pub_ip}${rand_path}${NC}"
            read -rp "Restart service now to apply? (Y/n): " ans
            if [[ "${ans,,}" != "n" ]]; then
                restart_service
            fi
            ;;
        4)
            read -rp "Enter custom login path (e.g. /my-secret-panel): " custom_path
            if [[ -z "${custom_path}" ]]; then
                echo -e "${RED}Path cannot be empty.${NC}"
                return
            fi
            [[ "${custom_path:0:1}" != "/" ]] && custom_path="/${custom_path}"
            sed -i -E '/^panel:/,/^[a-zA-Z]/ s|^([[:space:]]*path:).*|\1 "'"${custom_path}"'"|' "${CONFIG_FILE}"
            echo -e "${GREEN}✓ Admin Login Path updated to:${NC} ${BOLD}${custom_path}${NC}"
            echo -e "New Panel URL: ${BOLD}http://${pub_ip}${custom_path}${NC}"
            read -rp "Restart service now to apply? (Y/n): " ans
            if [[ "${ans,,}" != "n" ]]; then
                restart_service
            fi
            ;;
        *)
            return
            ;;
    esac
}

# Change Access Mode
change_access_mode() {
    echo -e "\n${BOLD}${CYAN}=== Change Access Mode ===${NC}"
    local curr_mode
    curr_mode=$(get_config_val "access_mode")
    [[ -z "${curr_mode}" ]] && curr_mode="user"
    echo -e "Current mode: ${BOLD}${curr_mode}${NC}\n"
    echo -e "1) ${BOLD}user${NC}   - Only clients registered via Magic Link can relay and resolve DNS (Recommended, secure)"
    echo -e "2) ${BOLD}public${NC} - Open to everyone without registration"
    echo -e "0) Cancel"
    echo ""
    read -rp "Select mode [0-2]: " m_choice

    case "${m_choice}" in
        1)
            sed -i -E "s|^([[:space:]]*access_mode:).*|\1 \"user\"|" "${CONFIG_FILE}"
            echo -e "${GREEN}✓ Access mode set to 'user' in config.yaml.${NC}"
            restart_service
            ;;
        2)
            sed -i -E "s|^([[:space:]]*access_mode:).*|\1 \"public\"|" "${CONFIG_FILE}"
            echo -e "${GREEN}✓ Access mode set to 'public' in config.yaml.${NC}"
            restart_service
            ;;
        *)
            return
            ;;
    esac
}

# Configure Outbound SOCKS5 Proxy
manage_proxy() {
    echo -e "\n${BOLD}${CYAN}=== Outbound SOCKS5 Egress Proxy ===${NC}"
    echo -e "Outbound SOCKS5 Proxy is now dynamically managed directly from the Web Admin Panel!"
    echo -e "You can configure proxy host, port, credentials, and run live connectivity tests"
    echo -e "with zero downtime under the Settings tab."
    local admin_path pub_ip
    admin_path=$(get_panel_path)
    pub_ip=$(get_config_val "relay_ip")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_public_ip)
    echo -e "\nOpen in your browser: ${BOLD}${GREEN}http://${pub_ip}${admin_path}${NC} -> ${CYAN}Settings${NC}"
}

# Firewall port configuration
configure_firewall() {
    echo -e "\n${BOLD}${CYAN}=== Firewall Configuration ===${NC}"
    echo -e "Opening required ports: 53 (TCP/UDP), 80 (TCP), 443 (TCP)..."

    # UFW Check
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        echo -e "${YELLOW}Detected active UFW firewall. Adding rules...${NC}"
        ufw allow 53/tcp comment 'tls-relay DNS TCP'
        ufw allow 53/udp comment 'tls-relay DNS UDP'
        ufw allow 80/tcp comment 'tls-relay HTTP & Panel'
        ufw allow 443/tcp comment 'tls-relay SNI Proxy'
        echo -e "${GREEN}✓ UFW rules configured successfully.${NC}"
        return
    fi

    # Firewalld Check
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo -e "${YELLOW}Detected active Firewalld. Adding rules...${NC}"
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
        echo -e "${GREEN}✓ Firewalld rules configured successfully.${NC}"
        return
    fi

    # iptables fallback
    if command -v iptables >/dev/null 2>&1; then
        echo -e "${YELLOW}Adding iptables rules...${NC}"
        iptables -I INPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
        echo -e "${GREEN}✓ iptables rules added.${NC}"
    else
        echo -e "${YELLOW}No active firewall detected (UFW/Firewalld). Ports appear unrestricted.${NC}"
    fi
}

# Enable TCP BBR & kernel tuning
enable_bbr() {
    echo -e "\n${BOLD}${CYAN}=== TCP BBR & Kernel Network Optimization ===${NC}"
    echo -e "Checking current congestion control..."
    local current_cc
    current_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "Current congestion control: ${BOLD}${current_cc}${NC}"

    if [[ "${current_cc}" == "bbr" ]]; then
        echo -e "${GREEN}✓ TCP BBR is already active on this system.${NC}"
        return
    fi

    read -rp "Enable TCP BBR and apply high-performance network buffers? (Y/n): " ans
    if [[ "${ans,,}" == "n" ]]; then
        return
    fi

    # Load BBR module
    modprobe tcp_bbr 2>/dev/null || true
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf 2>/dev/null || true

    cat > /etc/sysctl.d/99-tls-relay-bbr.conf << 'EOF'
# TLS-Relay BBR & TCP buffer optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.netdev_max_backlog = 100000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fastopen = 3
EOF

    sysctl -p /etc/sysctl.d/99-tls-relay-bbr.conf >/dev/null 2>&1
    local new_cc
    new_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ "${new_cc}" == "bbr" ]]; then
        echo -e "${GREEN}✓ TCP BBR successfully activated!${NC}"
    else
        echo -e "${YELLOW}Notice: BBR kernel module could not be activated (kernel may not support it).${NC}"
    fi
}

# Update binary to latest release
update_app() {
    echo -e "\n${BOLD}${CYAN}=== Check & Apply Update ===${NC}"
    local arch
    arch=$(get_arch)
    if [[ "${arch}" == "unsupported" ]]; then
        echo -e "${RED}[ERROR]${NC} Unsupported CPU architecture."
        return
    fi

    echo -e "Fetching latest release information from GitHub..."
    local latest_tag
    latest_tag=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | \
                 grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "${latest_tag}" ]]; then
        echo -e "${RED}[ERROR]${NC} Failed to fetch release information from GitHub. Check your network or GitHub API limits."
        return
    fi

    echo -e "Latest available version: ${GREEN}${latest_tag}${NC}"
    read -rp "Proceed with update? Your database and config will be preserved. (y/N): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo -e "Update cancelled."
        return
    fi

    local tar_name="tls-relay-linux-${arch}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_tag}/${tar_name}"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo -e "Downloading ${tar_name}..."
    if ! curl -fLR --connect-timeout 15 --retry 3 -o "${tmp_dir}/${tar_name}" "${download_url}"; then
        echo -e "${RED}[ERROR]${NC} Download failed from: ${download_url}"
        rm -rf "${tmp_dir}"
        return
    fi

    echo -e "Extracting update..."
    tar -zxvf "${tmp_dir}/${tar_name}" -C "${tmp_dir}" >/dev/null 2>&1

    if [[ ! -f "${tmp_dir}/tls-relay" ]]; then
        echo -e "${RED}[ERROR]${NC} Update archive did not contain tls-relay binary."
        rm -rf "${tmp_dir}"
        return
    fi

    echo -e "Stopping ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}"

    # Backup current binary
    cp -f "${INSTALL_DIR}/tls-relay" "${INSTALL_DIR}/tls-relay.bak" 2>/dev/null || true

    # Replace binary and CLI
    cp -f "${tmp_dir}/tls-relay" "${INSTALL_DIR}/tls-relay"
    chmod +x "${INSTALL_DIR}/tls-relay"

    if [[ -f "${tmp_dir}/tls-relay.sh" ]]; then
        cp -f "${tmp_dir}/tls-relay.sh" /usr/local/bin/tls-relay
        chmod +x /usr/local/bin/tls-relay
    fi

    rm -rf "${tmp_dir}"

    echo -e "Restarting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}"
    sleep 1

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo -e "${GREEN}✓ Update to ${latest_tag} completed successfully!${NC}"
    else
        echo -e "${RED}✗ Service failed to start after update. Rolling back...${NC}"
        cp -f "${INSTALL_DIR}/tls-relay.bak" "${INSTALL_DIR}/tls-relay"
        systemctl start "${SERVICE_NAME}"
    fi
}

# Backup database
backup_database() {
    echo -e "\n${BOLD}${CYAN}=== Database Backup ===${NC}"
    if [[ ! -f "${DB_FILE}" ]]; then
        echo -e "${RED}[ERROR]${NC} Database file not found at ${DB_FILE}"
        return
    fi

    local backup_dir="${INSTALL_DIR}/backups"
    mkdir -p "${backup_dir}"
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_dest="${backup_dir}/data_${timestamp}.db"

    cp "${DB_FILE}" "${backup_dest}"
    echo -e "${GREEN}✓ Database backup saved to:${NC} ${BOLD}${backup_dest}${NC}"
    ls -lh "${backup_dest}"
}

# Uninstall
uninstall_tls_relay() {
    echo -e "\n${BOLD}${RED}=== Uninstall TLS-Relay ===${NC}"
    read -rp "Are you sure you want to completely remove TLS-Relay? (y/N): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo "Aborted."
        return
    fi

    echo -e "${YELLOW}Stopping and disabling service...${NC}"
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    systemctl daemon-reload

    rm -f /usr/local/bin/tls-relay

    read -rp "Delete database and configuration data (/opt/tls-relay, /var/lib/tls-relay)? (y/N): " wipe_data
    if [[ "${wipe_data,,}" == "y" ]]; then
        rm -rf "${INSTALL_DIR}"
        rm -rf "/var/lib/tls-relay"
        rm -rf "/var/log/tls-relay"
        echo -e "${GREEN}✓ Application files and databases removed.${NC}"
    else
        echo -e "${YELLOW}Preserved ${INSTALL_DIR} and /var/lib/tls-relay for future use.${NC}"
    fi

    echo -e "${GREEN}✓ TLS-Relay uninstalled.${NC}"
    exit 0
}

# Interactive Menu
show_menu() {
    while true; do
        clear
        echo -e "${BOLD}${CYAN}"
        echo "=================================================="
        echo "         TLS-Relay Management CLI"
        echo "     https://github.com/ixabolfazl/tls-relay"
        echo "=================================================="
        echo -e "${NC}"

        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            echo -e " Service Status: ${GREEN}● RUNNING${NC}"
        else
            echo -e " Service Status: ${RED}○ STOPPED${NC}"
        fi
        echo ""
        echo -e "  ${BOLD}1.${NC} Show Service Status & Ports"
        echo -e "  ${BOLD}2.${NC} Start Service"
        echo -e "  ${BOLD}3.${NC} Stop Service"
        echo -e "  ${BOLD}4.${NC} Restart Service"
        echo -e "  ${BOLD}5.${NC} View Live Logs"
        echo -e "  ------------------------------------"
        echo -e "  ${BOLD}6.${NC} View / Change Admin Credentials & Path"
        echo -e "  ${BOLD}7.${NC} Change Access Mode (User / Public)"
        echo -e "  ${BOLD}8.${NC} Configure Outbound SOCKS5 Proxy"
        echo -e "  ${BOLD}9.${NC} Open Firewall Ports (53, 80, 443)"
        echo -e "  ${BOLD}10.${NC} Enable TCP BBR Optimization"
        echo -e "  ------------------------------------"
        echo -e " ${BOLD}11.${NC} Update to Latest Release"
        echo -e " ${BOLD}12.${NC} Backup SQLite Database"
        echo -e " ${BOLD}13.${NC} Uninstall TLS-Relay"
        echo -e "  ------------------------------------"
        echo -e "  ${BOLD}0.${NC} Exit"
        echo ""
        read -rp "Please enter your selection [0-13]: " choice

        case "${choice}" in
            1) show_status ;;
            2) start_service ;;
            3) stop_service ;;
            4) restart_service ;;
            5) view_logs ;;
            6) manage_credentials ;;
            7) change_access_mode ;;
            8) manage_proxy ;;
            9) configure_firewall ;;
            10) enable_bbr ;;
            11) update_app ;;
            12) backup_database ;;
            13) uninstall_tls_relay ;;
            0) exit 0 ;;
            *) echo -e "${RED}Invalid selection.${NC}" ;;
        esac

        echo ""
        read -rp "Press Enter to return to menu..." _dummy
    done
}

# Direct CLI arguments handling
check_root

if [[ $# -gt 0 ]]; then
    case "$1" in
        status) show_status ;;
        start) start_service ;;
        stop) stop_service ;;
        restart) restart_service ;;
        log|logs) view_logs ;;
        creds|credentials) manage_credentials ;;
        mode) change_access_mode ;;
        proxy) manage_proxy ;;
        firewall) configure_firewall ;;
        bbr) enable_bbr ;;
        update) update_app ;;
        backup) backup_database ;;
        uninstall) uninstall_tls_relay ;;
        help|--help|-h)
            echo "Usage: tls-relay [command]"
            echo "Commands: status, start, stop, restart, log, creds, mode, proxy, firewall, bbr, update, backup, uninstall"
            ;;
        *)
            echo "Unknown command: $1. Run 'tls-relay help' or just 'tls-relay' for interactive menu."
            exit 1
            ;;
    esac
    exit 0
fi

# No args passed -> interactive menu
show_menu
