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

# Fetch server public IP
get_public_ip() {
    local ip
    ip=$(curl -4s --connect-timeout 4 https://api.ipify.org 2>/dev/null || \
         curl -4s --connect-timeout 4 https://icanhazip.com 2>/dev/null || \
         curl -4s --connect-timeout 4 https://ifconfig.me 2>/dev/null || echo "")
    echo "${ip}" | tr -d '[:space:]'
}

# Read env variable safely
get_env_val() {
    local key="$1"
    if [[ -f "${ENV_FILE}" ]]; then
        grep -E "^${key}=" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2- | tr -d '"' | tr -d "'"
    fi
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
    pub_ip=$(get_env_val "RELAY_IP")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_public_ip)
    local admin_path
    admin_path=$(get_env_val "PANEL_PATH")
    [[ -z "${admin_path}" ]] && admin_path="/admin"
    local access_mode
    access_mode=$(get_env_val "ACCESS_MODE")
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
    local curr_user curr_pass
    curr_user=$(get_env_val "PANEL_ADMIN_USER")
    curr_pass=$(get_env_val "PANEL_ADMIN_PASSWORD")
    local panel_path
    panel_path=$(get_env_val "PANEL_PATH")
    [[ -z "${panel_path}" ]] && panel_path="/admin"
    local pub_ip
    pub_ip=$(get_env_val "RELAY_IP")
    [[ -z "${pub_ip}" ]] && pub_ip=$(get_public_ip)

    echo -e "Admin Panel URL: ${BOLD}${GREEN}http://${pub_ip}${panel_path}${NC}"
    echo -e "Current User   : ${GREEN}${curr_user:-admin}${NC}"
    echo -e "Current Pass   : ${YELLOW}${curr_pass:-(not set)}${NC}"
    echo -e "Login Path     : ${CYAN}${panel_path}${NC}"
    echo ""
    echo -e "1) Reset with random password"
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
            sed -i "s/^PANEL_ADMIN_PASSWORD=.*/PANEL_ADMIN_PASSWORD=${new_pass}/" "${ENV_FILE}"
            echo -e "${GREEN}✓ Password updated to:${NC} ${BOLD}${new_pass}${NC}"
            read -rp "Restart service now to apply? (Y/n): " ans
            if [[ "${ans,,}" != "n" ]]; then
                restart_service
            fi
            ;;
        2)
            read -rp "Enter new admin username [default: admin]: " new_user
            new_user="${new_user:-admin}"
            read -rp "Enter new admin password: " new_pass
            if [[ -z "${new_pass}" ]]; then
                echo -e "${RED}Password cannot be empty.${NC}"
                return
            fi
            if grep -q "^PANEL_ADMIN_USER=" "${ENV_FILE}"; then
                sed -i "s/^PANEL_ADMIN_USER=.*/PANEL_ADMIN_USER=${new_user}/" "${ENV_FILE}"
            else
                echo "PANEL_ADMIN_USER=${new_user}" >> "${ENV_FILE}"
            fi
            if grep -q "^PANEL_ADMIN_PASSWORD=" "${ENV_FILE}"; then
                sed -i "s/^PANEL_ADMIN_PASSWORD=.*/PANEL_ADMIN_PASSWORD=${new_pass}/" "${ENV_FILE}"
            else
                echo "PANEL_ADMIN_PASSWORD=${new_pass}" >> "${ENV_FILE}"
            fi
            echo -e "${GREEN}✓ Credentials updated.${NC}"
            read -rp "Restart service now to apply? (Y/n): " ans
            if [[ "${ans,,}" != "n" ]]; then
                restart_service
            fi
            ;;
        3)
            local rand_path
            rand_path="/$(gen_random_password 8)"
            if grep -q "^PANEL_PATH=" "${ENV_FILE}"; then
                sed -i "s|^PANEL_PATH=.*|PANEL_PATH=${rand_path}|" "${ENV_FILE}"
            else
                echo "PANEL_PATH=${rand_path}" >> "${ENV_FILE}"
            fi
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
            if grep -q "^PANEL_PATH=" "${ENV_FILE}"; then
                sed -i "s|^PANEL_PATH=.*|PANEL_PATH=${custom_path}|" "${ENV_FILE}"
            else
                echo "PANEL_PATH=${custom_path}" >> "${ENV_FILE}"
            fi
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
    curr_mode=$(get_env_val "ACCESS_MODE")
    [[ -z "${curr_mode}" ]] && curr_mode="user"
    echo -e "Current mode: ${BOLD}${curr_mode}${NC}\n"
    echo -e "1) ${BOLD}user${NC}   - Only clients registered via Magic Link can relay and resolve DNS (Recommended, secure)"
    echo -e "2) ${BOLD}public${NC} - Open to everyone without registration"
    echo -e "0) Cancel"
    echo ""
    read -rp "Select mode [0-2]: " m_choice

    case "${m_choice}" in
        1)
            sed -i "s/^ACCESS_MODE=.*/ACCESS_MODE=user/" "${ENV_FILE}"
            echo -e "${GREEN}✓ Access mode set to 'user'.${NC}"
            restart_service
            ;;
        2)
            sed -i "s/^ACCESS_MODE=.*/ACCESS_MODE=public/" "${ENV_FILE}"
            echo -e "${GREEN}✓ Access mode set to 'public'.${NC}"
            restart_service
            ;;
        *)
            return
            ;;
    esac
}

# Helper to set or replace key in .env
set_or_replace_env() {
    local k="$1"
    local v="$2"
    if grep -q "^${k}=" "${ENV_FILE}" 2>/dev/null; then
        sed -i "s|^${k}=.*|${k}=${v}|" "${ENV_FILE}"
    else
        echo "${k}=${v}" >> "${ENV_FILE}"
    fi
}

# Configure Outbound SOCKS5 Proxy
manage_proxy() {
    echo -e "\n${BOLD}${CYAN}=== Outbound SOCKS5 Egress Proxy ===${NC}"
    local p_enabled p_addr p_user p_pass
    p_enabled=$(get_env_val "EGRESS_PROXY_ENABLED")
    [[ -z "${p_enabled}" ]] && p_enabled="false"
    p_addr=$(get_env_val "EGRESS_PROXY_ADDR")
    [[ -z "${p_addr}" ]] && p_addr="127.0.0.1:1080"
    p_user=$(get_env_val "EGRESS_PROXY_USER")
    p_pass=$(get_env_val "EGRESS_PROXY_PASSWORD")

    if [[ "${p_enabled}" == "true" ]]; then
        echo -e "Proxy Status  : ${GREEN}ENABLED${NC}"
    else
        echo -e "Proxy Status  : ${YELLOW}DISABLED (Direct Outbound)${NC}"
    fi
    echo -e "Proxy Address : ${BOLD}${p_addr}${NC}"
    echo -e "Proxy User    : ${p_user:-[none]}"
    echo ""
    echo -e "1) Enable / Update SOCKS5 Proxy"
    echo -e "2) Disable SOCKS5 Proxy (Direct Outbound)"
    echo -e "0) Return to menu"
    echo ""
    read -rp "Select option [0-2]: " p_choice

    case "${p_choice}" in
        1)
            read -rp "Enter SOCKS5 Proxy Address [default: ${p_addr}]: " new_addr
            new_addr="${new_addr:-$p_addr}"
            read -rp "Enter SOCKS5 Username (optional, press Enter if none): " new_user
            read -rp "Enter SOCKS5 Password (optional, press Enter if none): " new_pass

            set_or_replace_env "EGRESS_PROXY_ENABLED" "true"
            set_or_replace_env "EGRESS_PROXY_ADDR" "${new_addr}"
            set_or_replace_env "EGRESS_PROXY_USER" "${new_user}"
            set_or_replace_env "EGRESS_PROXY_PASSWORD" "${new_pass}"

            echo -e "${GREEN}✓ Outbound SOCKS5 proxy enabled: ${BOLD}${new_addr}${NC}"
            read -rp "Restart service now to apply? (Y/n): " ans
            if [[ "${ans,,}" != "n" ]]; then
                restart_service
            fi
            ;;
        2)
            set_or_replace_env "EGRESS_PROXY_ENABLED" "false"
            echo -e "${GREEN}✓ Outbound SOCKS5 proxy disabled.${NC}"
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
