#!/bin/bash
#
# Geo-Blocking Script for Mail Servers
# Blocks entire countries at the firewall level using nftables
#
# Usage: ./geoblock-setup.sh
#
# This script will:
# 1. Download IP ranges for specified countries
# 2. Configure nftables to block those countries
# 3. Whitelist your IP address
# 4. Make the configuration persistent across reboots
#

set -e  # Exit on error

# Configuration
# -------------
# Countries to block (ISO 2-letter codes)
# Find more codes at: https://www.ipdeny.com/ipblocks/
BLOCKED_COUNTRIES=("ro" "ru" "pl" "kz")
COUNTRY_NAMES=("Romania" "Russia" "Poland" "Kazakhstan")

# Your IP address to whitelist (will be auto-detected if left empty)
WHITELIST_IP=""

# Additional IPs/networks to whitelist (space-separated)
# Example: ADDITIONAL_WHITELIST="1.2.3.4 5.6.7.0/24"
ADDITIONAL_WHITELIST=""

# Specific attacker IPs to block (space-separated)
# Example: ATTACKER_IPS="1.2.3.4 5.6.7.8"
ATTACKER_IPS=""

# Advanced Configuration
TEMP_DIR="/tmp/geoblock-$$"
NFTABLES_DIR="/etc/nftables"
NFTABLES_FILE="${NFTABLES_DIR}/geoblock.nft"
SERVICE_NAME="nftables-geoblock"
IP_SOURCE="https://www.ipdeny.com/ipblocks/data/aggregated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
# ---------

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing_deps=()

    for cmd in nft curl systemctl; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=($cmd)
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Install with: pacman -S nftables curl systemd (Arch)"
        log_info "Or: apt install nftables curl systemd (Debian/Ubuntu)"
        exit 1
    fi

    log_success "All dependencies found"
}

detect_ip() {
    if [ -z "$WHITELIST_IP" ]; then
        log_info "Auto-detecting your public IP..."
        WHITELIST_IP=$(curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me 2>/dev/null || echo "")

        if [ -z "$WHITELIST_IP" ]; then
            log_error "Could not auto-detect IP. Please set WHITELIST_IP manually in the script."
            exit 1
        fi

        log_success "Detected IP: $WHITELIST_IP"
    else
        log_info "Using configured IP: $WHITELIST_IP"
    fi
}

download_country_ips() {
    log_info "Creating temporary directory..."
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"

    log_info "Downloading IP ranges for ${#BLOCKED_COUNTRIES[@]} countries..."

    for i in "${!BLOCKED_COUNTRIES[@]}"; do
        local country="${BLOCKED_COUNTRIES[$i]}"
        local name="${COUNTRY_NAMES[$i]}"
        local url="${IP_SOURCE}/${country}-aggregated.zone"
        local file="${country}.zone"

        log_info "  Downloading ${name} (${country})..."
        if curl -s "$url" -o "$file"; then
            local count=$(wc -l < "$file")
            log_success "    Downloaded $count networks"
        else
            log_error "    Failed to download ${name}"
            exit 1
        fi
    done
}

create_nftables_config() {
    log_info "Creating nftables configuration..."

    # Start building the nftables config
    cat > /tmp/nftables-config.nft << 'EOF'
#!/usr/sbin/nft -f

# Geo-blocking table
table inet geoblock {
EOF

    # Add country sets
    for country in "${BLOCKED_COUNTRIES[@]}"; do
        cat >> /tmp/nftables-config.nft << EOF
    set country-${country} {
        type ipv4_addr
        flags interval
    }

EOF
    done

    # Add attacker set if needed
    if [ -n "$ATTACKER_IPS" ]; then
        cat >> /tmp/nftables-config.nft << EOF
    set attackers-ipv4 {
        type ipv4_addr
        flags interval
    }

    set attackers-ipv6 {
        type ipv6_addr
        flags interval
    }

EOF
    fi

    # Add prerouting chain with rules
    cat >> /tmp/nftables-config.nft << EOF
    chain prerouting {
        type filter hook prerouting priority -150; policy accept;

        # Block specific attackers first
EOF

    if [ -n "$ATTACKER_IPS" ]; then
        cat >> /tmp/nftables-config.nft << EOF
        ip saddr @attackers-ipv4 drop
        ip6 saddr @attackers-ipv6 drop

EOF
    fi

    # Add whitelist rules
    cat >> /tmp/nftables-config.nft << EOF
        # Whitelist your IP
        ip saddr $WHITELIST_IP accept

EOF

    if [ -n "$ADDITIONAL_WHITELIST" ]; then
        for ip in $ADDITIONAL_WHITELIST; do
            if [[ $ip == *":"* ]]; then
                echo "        ip6 saddr $ip accept" >> /tmp/nftables-config.nft
            else
                echo "        ip saddr $ip accept" >> /tmp/nftables-config.nft
            fi
        done
        echo "" >> /tmp/nftables-config.nft
    fi

    # Add country blocking rules
    cat >> /tmp/nftables-config.nft << EOF
        # Block countries
EOF

    for country in "${BLOCKED_COUNTRIES[@]}"; do
        echo "        ip saddr @country-${country} drop" >> /tmp/nftables-config.nft
    done

    # Close the config
    cat >> /tmp/nftables-config.nft << EOF
    }
}
EOF

    log_success "nftables configuration created"
}

apply_nftables_config() {
    log_info "Applying nftables configuration..."

    # Apply the basic structure first
    nft -f /tmp/nftables-config.nft

    log_success "Basic structure applied"

    # Load country IP ranges
    for i in "${!BLOCKED_COUNTRIES[@]}"; do
        local country="${BLOCKED_COUNTRIES[$i]}"
        local name="${COUNTRY_NAMES[$i]}"
        local file="${TEMP_DIR}/${country}.zone"
        local count=$(wc -l < "$file")

        log_info "Loading ${name} IPs ($count networks)..."

        # Load IPs in batches for better performance
        while IFS= read -r ip; do
            nft add element inet geoblock country-${country} { $ip } 2>/dev/null || true
        done < "$file"

        log_success "  ${name} loaded"
    done

    # Add attacker IPs if specified
    if [ -n "$ATTACKER_IPS" ]; then
        log_info "Adding specific attacker IPs..."
        for ip in $ATTACKER_IPS; do
            if [[ $ip == *":"* ]]; then
                nft add element inet geoblock attackers-ipv6 { $ip }
                log_success "  Blocked IPv6: $ip"
            else
                nft add element inet geoblock attackers-ipv4 { $ip }
                log_success "  Blocked IPv4: $ip"
            fi
        done
    fi
}

make_persistent() {
    log_info "Making configuration persistent..."

    # Create nftables directory
    mkdir -p "$NFTABLES_DIR"

    # Save current ruleset
    nft list ruleset > "$NFTABLES_FILE"
    chmod 600 "$NFTABLES_FILE"

    log_success "Configuration saved to $NFTABLES_FILE"

    # Create systemd service
    log_info "Creating systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=nftables geo-blocking rules
Documentation=https://wiki.nftables.org/
After=network.target
Before=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/nft -f ${NFTABLES_FILE}
ExecReload=/usr/bin/nft -f ${NFTABLES_FILE}
ExecStop=/usr/bin/nft delete table inet geoblock
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start the service
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"

    log_success "Systemd service created and enabled"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
    rm -f /tmp/nftables-config.nft
    log_success "Cleanup complete"
}

show_summary() {
    echo ""
    echo "======================================"
    echo "  GEO-BLOCKING SETUP COMPLETE"
    echo "======================================"
    echo ""
    echo "Blocked Countries:"
    for i in "${!BLOCKED_COUNTRIES[@]}"; do
        local country="${BLOCKED_COUNTRIES[$i]}"
        local name="${COUNTRY_NAMES[$i]}"
        local file="${TEMP_DIR}/${country}.zone"
        if [ -f "$file" ]; then
            local count=$(wc -l < "$file")
            printf "  %-20s %6s networks\n" "${name}:" "$count"
        fi
    done
    echo ""
    echo "Whitelisted IPs:"
    echo "  Your IP: $WHITELIST_IP"
    if [ -n "$ADDITIONAL_WHITELIST" ]; then
        for ip in $ADDITIONAL_WHITELIST; do
            echo "  Additional: $ip"
        done
    fi
    echo ""

    if [ -n "$ATTACKER_IPS" ]; then
        echo "Blocked Attackers:"
        for ip in $ATTACKER_IPS; do
            echo "  $ip"
        done
        echo ""
    fi

    echo "Configuration:"
    echo "  Rules file: $NFTABLES_FILE"
    echo "  Service: ${SERVICE_NAME}.service"
    echo ""
    echo "Management Commands:"
    echo "  View rules:      nft list ruleset"
    echo "  Check service:   systemctl status ${SERVICE_NAME}"
    echo "  Reload rules:    systemctl reload ${SERVICE_NAME}"
    echo "  Disable blocking: systemctl stop ${SERVICE_NAME}"
    echo "  Remove blocking: systemctl disable ${SERVICE_NAME} && nft delete table inet geoblock"
    echo ""
    echo "To add more countries later, edit this script and run it again."
    echo ""
}

create_management_script() {
    log_info "Creating management helper script..."

    cat > /usr/local/bin/geoblock-manage << 'MGMT_EOF'
#!/bin/bash
#
# Geo-blocking Management Script
#

NFTABLES_FILE="/etc/nftables/geoblock.nft"
SERVICE_NAME="nftables-geoblock"

case "$1" in
    status)
        echo "=== Geo-blocking Status ==="
        systemctl status ${SERVICE_NAME} --no-pager
        echo ""
        echo "=== Active Rules ==="
        nft list table inet geoblock 2>/dev/null || echo "No geo-blocking table found"
        ;;

    reload)
        echo "Reloading geo-blocking rules..."
        systemctl reload ${SERVICE_NAME}
        echo "Done"
        ;;

    disable)
        echo "Disabling geo-blocking..."
        nft delete table inet geoblock 2>/dev/null || true
        systemctl stop ${SERVICE_NAME}
        echo "Geo-blocking disabled (will re-enable on reboot)"
        echo "To permanently remove: systemctl disable ${SERVICE_NAME}"
        ;;

    enable)
        echo "Enabling geo-blocking..."
        systemctl start ${SERVICE_NAME}
        echo "Done"
        ;;

    add-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 add-ip <IP_ADDRESS>"
            exit 1
        fi
        echo "Adding $2 to whitelist..."
        if [[ $2 == *":"* ]]; then
            nft add rule inet geoblock prerouting ip6 saddr $2 accept position 0
        else
            nft add rule inet geoblock prerouting ip saddr $2 accept position 0
        fi
        nft list ruleset > ${NFTABLES_FILE}
        echo "Done. IP $2 whitelisted."
        ;;

    block-ip)
        if [ -z "$2" ]; then
            echo "Usage: $0 block-ip <IP_ADDRESS>"
            exit 1
        fi
        echo "Blocking $2..."
        if [[ $2 == *":"* ]]; then
            nft add element inet geoblock attackers-ipv6 { $2 } 2>/dev/null || {
                nft add set inet geoblock attackers-ipv6 '{ type ipv6_addr; flags interval; }'
                nft add element inet geoblock attackers-ipv6 { $2 }
                nft insert rule inet geoblock prerouting ip6 saddr @attackers-ipv6 drop position 0
            }
        else
            nft add element inet geoblock attackers-ipv4 { $2 } 2>/dev/null || {
                nft add set inet geoblock attackers-ipv4 '{ type ipv4_addr; flags interval; }'
                nft add element inet geoblock attackers-ipv4 { $2 }
                nft insert rule inet geoblock prerouting ip saddr @attackers-ipv4 drop position 0
            }
        fi
        nft list ruleset > ${NFTABLES_FILE}
        echo "Done. IP $2 blocked."
        ;;

    stats)
        echo "=== Geo-blocking Statistics ==="
        nft list table inet geoblock | grep "set country-" | while read -r line; do
            set_name=$(echo "$line" | awk '{print $2}')
            # Count would require iteration - simplified output
            echo "$set_name: configured"
        done
        ;;

    *)
        echo "Geo-blocking Management Tool"
        echo ""
        echo "Usage: $0 {status|reload|enable|disable|add-ip|block-ip|stats}"
        echo ""
        echo "Commands:"
        echo "  status     - Show current status and rules"
        echo "  reload     - Reload rules from config file"
        echo "  enable     - Enable geo-blocking"
        echo "  disable    - Temporarily disable geo-blocking"
        echo "  add-ip IP  - Add IP to whitelist"
        echo "  block-ip IP - Block specific IP"
        echo "  stats      - Show blocking statistics"
        exit 1
        ;;
esac
MGMT_EOF

    chmod +x /usr/local/bin/geoblock-manage
    log_success "Management script installed: /usr/local/bin/geoblock-manage"
}

# Main Execution
# --------------

main() {
    echo ""
    echo "======================================"
    echo "  Mail Server Geo-Blocking Setup"
    echo "======================================"
    echo ""

    check_root
    check_dependencies
    detect_ip
    download_country_ips
    create_nftables_config
    apply_nftables_config
    make_persistent
    create_management_script
    cleanup
    show_summary

    log_success "All done! Your server is now protected."
    echo ""
}

# Run main function
main "$@"
