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
    local local_ip
    local_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if is_public_ipv4 "${local_ip}"; then
        echo "${local_ip}"
        return 0
    fi

    if command -v dig >/dev/null 2>&1; then
        local dns_ip
        dns_ip=$(dig +short +time=2 +tries=1 myip.opendns.com @208.67.222.222 2>/dev/null | tr -d '"' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
        if is_public_ipv4 "${dns_ip}"; then
            echo "${dns_ip}"
            return 0
        fi
    fi

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

# Read setting via `tls-relay settings get` with fallback to config.yaml and env
get_setting_val() {
    local key="$1"
    local val=""
    if [[ -x "${INSTALL_DIR}/tls-relay" && -f "${CONFIG_FILE}" ]]; then
        val=$("${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings get "${key}" 2>/dev/null | grep -E "^${key}=" | head -n1 | cut -d'=' -f2-)
    fi
    if [[ -z "${val}" ]]; then
        val=$(get_config_val "${key}")
    fi
    if [[ -z "${val}" ]]; then
        val=$(get_env_val "${key^^}")
    fi
    echo "${val}"
}

# Get panel path from settings get with fallback to config.yaml
get_panel_path() {
    local p
    if [[ -x "${INSTALL_DIR}/tls-relay" && -f "${CONFIG_FILE}" ]]; then
        p=$("${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings get panel_path 2>/dev/null | grep -E "^panel_path=" | head -n1 | cut -d'=' -f2-)
    fi
    if [[ -z "${p}" ]]; then
        p=$(sed -n '/^panel:/,/^[a-zA-Z]/p' "${CONFIG_FILE}" 2>/dev/null | grep -E '^[[:space:]]*path:' | awk '{print $2}' | tr -d '"' | tr -d "'")
    fi
    echo "${p:-/admin}"
}

# Client-side validation of panel path
validate_panel_path_client() {
    local p="$1"
    if [[ -z "${p}" ]]; then
        echo "Path cannot be empty"
        return 1
    fi
    [[ "${p:0:1}" != "/" ]] && p="/${p}"
    if [[ "${p}" == "/" ]]; then
        echo "${p}"
        return 0
    fi
    if [[ ! "${p}" =~ ^/[A-Za-z0-9_-]{1,64}$ ]]; then
        echo "Invalid panel path format (must match ^/[A-Za-z0-9_-]{1,64}$ or /)"
        return 1
    fi
    local slug="${p#/}"
    local slug_lower="${slug,,}"
    case "${slug_lower}" in
        api|connect|setup|static|css|js|pages|index.html)
            echo "Panel path '${p}' is reserved by the system"
            return 1
            ;;
    esac
    echo "${p}"
    return 0
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
    access_mode=$(get_setting_val "access_mode")
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

# Reload service configuration via SIGHUP (falls back to restart)
reload_service() {
    echo -e "${YELLOW}Reloading ${SERVICE_NAME}...${NC}"
    if systemctl reload "${SERVICE_NAME}" 2>/dev/null; then
        echo -e "${GREEN}✓ ${SERVICE_NAME} reloaded successfully without dropping connections.${NC}"
    else
        echo -e "${YELLOW}Reload failed or unsupported; falling back to service restart...${NC}"
        restart_service
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
            TLS_RELAY_ADMIN_PASS="${new_pass}" "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" -init-admin -user "admin"
            echo -e "${GREEN}✓ Admin password reset for user 'admin':${NC} ${BOLD}${new_pass}${NC}"
            reload_service
            ;;
        2)
            read -rp "Enter admin username [default: admin]: " new_user
            new_user="${new_user:-admin}"
            read -rp "Enter new admin password: " new_pass
            if [[ -z "${new_pass}" ]]; then
                echo -e "${RED}Password cannot be empty.${NC}"
                return
            fi
            if [[ ${#new_pass} -lt 6 ]]; then
                echo -e "${RED}Password must be at least 6 characters.${NC}"
                return
            fi
            echo -e "${CYAN}Applying credentials to database...${NC}"
            TLS_RELAY_ADMIN_PASS="${new_pass}" "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" -init-admin -user "${new_user}"
            echo -e "${GREEN}✓ Credentials updated in database for user '${new_user}'.${NC}"
            reload_service
            ;;
        3)
            local rand_path
            rand_path="/$(gen_random_password 8)"
            echo -e "${CYAN}Applying new panel path to database...${NC}"
            if "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings set panel_path "${rand_path}"; then
                echo -e "${GREEN}✓ Admin Login Path updated to:${NC} ${BOLD}${rand_path}${NC}"
                echo -e "New Panel URL: ${BOLD}http://${pub_ip}${rand_path}${NC}"
                reload_service
            else
                echo -e "${RED}[ERROR] Failed updating panel path.${NC}"
            fi
            ;;
        4)
            read -rp "Enter custom login path (e.g. /my-secret-panel): " custom_path
            [[ "${custom_path:0:1}" != "/" ]] && custom_path="/${custom_path}"
            local val_res
            if ! val_res=$(validate_panel_path_client "${custom_path}"); then
                echo -e "${RED}[ERROR] ${val_res}${NC}"
                return
            fi
            custom_path="${val_res}"
            echo -e "${CYAN}Applying custom panel path to database...${NC}"
            if "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings set panel_path "${custom_path}"; then
                echo -e "${GREEN}✓ Admin Login Path updated to:${NC} ${BOLD}${custom_path}${NC}"
                echo -e "New Panel URL: ${BOLD}http://${pub_ip}${custom_path}${NC}"
                reload_service
            else
                echo -e "${RED}[ERROR] Failed updating panel path.${NC}"
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
    curr_mode=$(get_setting_val "access_mode")
    [[ -z "${curr_mode}" ]] && curr_mode="user"
    echo -e "Current mode: ${BOLD}${curr_mode}${NC}\n"
    echo -e "1) ${BOLD}user${NC}   - Only clients registered via Magic Link can relay and resolve DNS (Recommended, secure)"
    echo -e "2) ${BOLD}public${NC} - Open to everyone without registration"
    echo -e "0) Cancel"
    echo ""
    read -rp "Select mode [0-2]: " m_choice

    case "${m_choice}" in
        1)
            echo -e "${CYAN}Setting access mode to 'user' in database...${NC}"
            "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings set access_mode "user"
            echo -e "${GREEN}✓ Access mode set to 'user'.${NC}"
            reload_service
            ;;
        2)
            echo -e "${CYAN}Setting access mode to 'public' in database...${NC}"
            "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" settings set access_mode "public"
            echo -e "${GREEN}✓ Access mode set to 'public'.${NC}"
            reload_service
            ;;
        *)
            return
            ;;
    esac
}

# Configure Outbound SOCKS5 Proxy
manage_proxy() {
    echo -e "\n${BOLD}${CYAN}=== Outbound SOCKS5 Egress Proxy ===${NC}"
    local egress_enabled
    egress_enabled=$(get_setting_val "egress_proxy_enabled")
    local egress_addr
    egress_addr=$(get_setting_val "egress_proxy_addr")
    echo -e "Current Status : ${BOLD}${egress_enabled:-false}${NC}"
    if [[ -n "${egress_addr}" ]]; then
        echo -e "Proxy Address  : ${BOLD}${egress_addr}${NC}"
    fi

    echo -e "\nOutbound SOCKS5 Proxy is dynamically managed directly from the Web Admin Panel!"
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

    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        echo -e "${YELLOW}Detected active UFW firewall. Adding rules...${NC}"
        ufw allow 53/tcp comment 'tls-relay DNS TCP'
        ufw allow 53/udp comment 'tls-relay DNS UDP'
        ufw allow 80/tcp comment 'tls-relay HTTP & Panel'
        ufw allow 443/tcp comment 'tls-relay SNI Proxy'
        echo -e "${GREEN}✓ UFW rules configured successfully.${NC}"
        return
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        echo -e "${YELLOW}Detected active firewalld. Adding rules...${NC}"
        firewall-cmd --permanent --add-port=53/tcp
        firewall-cmd --permanent --add-port=53/udp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --reload
        echo -e "${GREEN}✓ Firewalld rules configured successfully.${NC}"
        return
    fi

    if command -v iptables >/dev/null 2>&1; then
        echo -e "${YELLOW}Adding iptables rules...${NC}"
        iptables -I INPUT -p tcp --dport 53 -j ACCEPT
        iptables -I INPUT -p udp --dport 53 -j ACCEPT
        iptables -I INPUT -p tcp --dport 80 -j ACCEPT
        iptables -I INPUT -p tcp --dport 443 -j ACCEPT
        echo -e "${GREEN}✓ iptables rules added.${NC}"
        return
    fi

    echo -e "${YELLOW}No supported firewall (UFW, Firewalld, iptables) detected.${NC}"
}

# Enable TCP BBR Optimization
enable_bbr() {
    echo -e "\n${BOLD}${CYAN}=== TCP BBR Optimization ===${NC}"
    local curr_cc
    curr_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "Current congestion control: ${BOLD}${curr_cc:-unknown}${NC}"

    if [[ "${curr_cc}" == "bbr" ]]; then
        echo -e "${GREEN}✓ TCP BBR is already active on this system.${NC}"
        return
    fi

    echo -e "Enabling TCP BBR and high-performance network buffers..."
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

    local new_cc
    new_cc=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    if [[ "${new_cc}" == "bbr" ]]; then
        echo -e "${GREEN}✓ TCP BBR successfully enabled!${NC}"
    else
        echo -e "${RED}✗ Failed to enable BBR. Ensure your Linux kernel version is 4.9 or higher.${NC}"
    fi
}

# Update binary and scripts to latest release
update_app() {
    echo -e "\n${BOLD}${CYAN}=== Check & Apply Update ===${NC}"
    local arch
    arch=$(get_arch)
    if [[ "${arch}" == "unsupported" ]]; then
        echo -e "${RED}[ERROR]${NC} Unsupported CPU architecture: $(uname -m)."
        return 1
    fi

    echo -e "Fetching latest release information from GitHub..."
    local latest_tag
    latest_tag=$(curl -sL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" 2>/dev/null | \
                 grep '"tag_name":' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    if [[ -z "${latest_tag}" ]]; then
        latest_tag=$(curl -s -L -I -o /dev/null -w '%{url_effective}' "https://github.com/${GITHUB_REPO}/releases/latest" 2>/dev/null | rev | cut -d'/' -f1 | rev)
    fi

    if [[ -z "${latest_tag}" || "${latest_tag}" == "releases" ]]; then
        echo -e "${RED}[ERROR]${NC} Failed to fetch release information from GitHub. Check your network or GitHub API limits."
        return 1
    fi

    echo -e "Latest available version: ${GREEN}${latest_tag}${NC}"
    local old_ver
    old_ver=$("${INSTALL_DIR}/tls-relay" -version 2>/dev/null || echo "unknown")
    echo -e "Current installed version: ${BOLD}${old_ver}${NC}"

    read -rp "Proceed with update? Your database and config will be preserved. (y/N): " confirm
    if [[ "${confirm,,}" != "y" ]]; then
        echo -e "Update cancelled."
        return 0
    fi

    local tar_name="tls-relay-linux-${arch}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_tag}/${tar_name}"
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/download/${latest_tag}/${tar_name}.sha256"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    echo -e "Downloading ${tar_name}..."
    if ! curl -fLR --connect-timeout 15 --retry 3 -o "${tmp_dir}/${tar_name}" "${download_url}"; then
        echo -e "${RED}[ERROR]${NC} Download failed from: ${download_url}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    # Verify SHA256 Checksum
    if curl -sLf -o "${tmp_dir}/${tar_name}.sha256" "${checksum_url}" 2>/dev/null; then
        echo -e "Verifying SHA256 checksum..."
        (
            cd "${tmp_dir}"
            if ! sha256sum -c "${tar_name}.sha256"; then
                echo -e "${RED}[ERROR] SHA256 checksum mismatch! Aborting update.${NC}"
                exit 1
            fi
        )
        if [[ $? -ne 0 ]]; then
            rm -rf "${tmp_dir}"
            return 1
        fi
        echo -e "${GREEN}✓ Checksum verified successfully.${NC}"
    else
        echo -e "${YELLOW}[WARNING] Checksum file not available on GitHub.${NC}"
        read -rp "Proceed without checksum verification? (y/N): " confirm_no_sum
        if [[ "${confirm_no_sum,,}" != "y" ]]; then
            echo -e "Update aborted by user."
            rm -rf "${tmp_dir}"
            return 1
        fi
    fi

    echo -e "Extracting archive..."
    if ! tar -zxvf "${tmp_dir}/${tar_name}" -C "${tmp_dir}"; then
        echo -e "${RED}[ERROR] Failed to extract archive.${NC}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    # Verify all 3 required components exist before modifying system
    if [[ ! -f "${tmp_dir}/tls-relay" || ! -f "${tmp_dir}/tls-relay.sh" || ! -f "${tmp_dir}/tls-relay.service" ]]; then
        echo -e "${RED}[ERROR] Update archive is missing required files (tls-relay, tls-relay.sh, or tls-relay.service). Aborting.${NC}"
        rm -rf "${tmp_dir}"
        return 1
    fi

    echo -e "Stopping ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}"

    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"

    # Backup current versions
    cp -f "${INSTALL_DIR}/tls-relay" "${INSTALL_DIR}/tls-relay.bak" 2>/dev/null || true
    cp -f "${INSTALL_DIR}/tls-relay.sh" "${INSTALL_DIR}/tls-relay.sh.bak" 2>/dev/null || true
    if [[ -f "${unit_file}" ]]; then
        cp -f "${unit_file}" "${INSTALL_DIR}/${SERVICE_NAME}.service.bak" 2>/dev/null || true
    fi

    # Atomic installation using install to temporary file + mv
    echo -e "Installing new binary and CLI scripts..."
    install -m 755 "${tmp_dir}/tls-relay" "${INSTALL_DIR}/tls-relay.new" && mv -f "${INSTALL_DIR}/tls-relay.new" "${INSTALL_DIR}/tls-relay"
    install -m 755 "${tmp_dir}/tls-relay.sh" "${INSTALL_DIR}/tls-relay.sh.new" && mv -f "${INSTALL_DIR}/tls-relay.sh.new" "${INSTALL_DIR}/tls-relay.sh"
    install -m 755 "${tmp_dir}/tls-relay.sh" "/usr/local/bin/tls-relay.new" && mv -f "/usr/local/bin/tls-relay.new" "/usr/local/bin/tls-relay"

    # Update systemd unit if changed
    if [[ -f "${unit_file}" ]]; then
        if ! cmp -s "${tmp_dir}/tls-relay.service" "${unit_file}"; then
            echo -e "Updating systemd unit file..."
            install -m 644 "${tmp_dir}/tls-relay.service" "${unit_file}.new" && mv -f "${unit_file}.new" "${unit_file}"
            systemctl daemon-reload
        fi
    else
        install -m 644 "${tmp_dir}/tls-relay.service" "${unit_file}"
        systemctl daemon-reload
    fi

    # Ensure system user and file ownership for tls-relay user
    if ! id -u tls-relay >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin -M -d /opt/tls-relay tls-relay 2>/dev/null || useradd -r -s /bin/false -M -d /opt/tls-relay tls-relay 2>/dev/null || true
    fi
    chown -R tls-relay:tls-relay "${INSTALL_DIR}" /var/lib/tls-relay /var/log/tls-relay 2>/dev/null || true

    echo -e "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}"

    # Wait up to 10 seconds for service to become active
    local is_active=0
    for i in {1..10}; do
        if systemctl is-active --quiet "${SERVICE_NAME}"; then
            is_active=1
            break
        fi
        sleep 1
    done

    if [[ ${is_active} -eq 0 ]]; then
        echo -e "${RED}[ERROR] Service failed to start within 10s! Rolling back...${NC}"
        [[ -f "${INSTALL_DIR}/tls-relay.bak" ]] && cp -f "${INSTALL_DIR}/tls-relay.bak" "${INSTALL_DIR}/tls-relay"
        [[ -f "${INSTALL_DIR}/tls-relay.sh.bak" ]] && cp -f "${INSTALL_DIR}/tls-relay.sh.bak" "${INSTALL_DIR}/tls-relay.sh"
        [[ -f "${INSTALL_DIR}/tls-relay.sh.bak" ]] && cp -f "${INSTALL_DIR}/tls-relay.sh.bak" "/usr/local/bin/tls-relay"
        if [[ -f "${INSTALL_DIR}/${SERVICE_NAME}.service.bak" ]]; then
            cp -f "${INSTALL_DIR}/${SERVICE_NAME}.service.bak" "${unit_file}"
            systemctl daemon-reload
        fi
        systemctl start "${SERVICE_NAME}"
        rm -rf "${tmp_dir}"
        echo -e "${YELLOW}Rollback completed.${NC}"
        return 1
    fi

    local new_ver
    new_ver=$("${INSTALL_DIR}/tls-relay" -version 2>/dev/null || echo "${latest_tag}")
    echo -e "${GREEN}✓ Update successful:${NC} ${BOLD}${old_ver}${NC} -> ${BOLD}${new_ver}${NC}"

    rm -rf "${tmp_dir}"

    if [[ -t 0 ]]; then
        echo -e "${CYAN}Relaunching CLI with updated script...${NC}"
        exec /usr/local/bin/tls-relay
    else
        echo "Update completed. Please run tls-relay again."
    fi
}

# Backup database consistently using SQLite VACUUM INTO
backup_database() {
    echo -e "\n${BOLD}${CYAN}=== Database Backup ===${NC}"
    local backup_dir="${INSTALL_DIR}/backups"
    (
        umask 077
        mkdir -p "${backup_dir}"
        chmod 0700 "${backup_dir}"
    )
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_dest="${backup_dir}/data_${timestamp}.db"

    echo -e "${CYAN}Creating consistent point-in-time database snapshot via SQLite VACUUM INTO...${NC}"
    if "${INSTALL_DIR}/tls-relay" -config "${CONFIG_FILE}" backup "${backup_dest}"; then
        chmod 0600 "${backup_dest}"
        echo -e "${GREEN}✓ Database backup saved to:${NC} ${BOLD}${backup_dest}${NC}"
        ls -lh "${backup_dest}"
    else
        echo -e "${RED}[ERROR] Backup failed.${NC}"
    fi
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

# Main function wrapping script execution
main() {
    check_root

    if [[ $# -gt 0 ]]; then
        case "$1" in
            status) show_status ;;
            start) start_service ;;
            stop) stop_service ;;
            restart) restart_service ;;
            reload) reload_service ;;
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
                echo "Commands: status, start, stop, restart, reload, log, creds, mode, proxy, firewall, bbr, update, backup, uninstall"
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
}

main "$@"
exit $?
