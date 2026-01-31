#!/bin/bash

# IP Unban Script - Removes bans for specified IP ranges
# Usage: ./unban_ips.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Starting IP unban process..."

# IPv4 ranges to unban
IPV4_RANGES=(
    "66.132.159.0/24"
    "162.142.125.0/24"
    "167.94.138.0/24"
    "167.94.145.0/24"
    "167.94.146.0/24"
    "167.248.133.0/24"
    "199.45.154.0/24"
    "199.45.155.0/24"
    "206.168.34.0/24"
    "206.168.35.0/24"
)

# IPv6 ranges to unban
IPV6_RANGES=(
    "2602:80d:1000:b0cc:e::/80"
    "2620:96:e000:b0cc:e::/80"
    "2602:80d:1003::/112"
    "2602:80d:1004::/112"
)

# Unban IPv4 ranges
echo "Removing IPv4 bans..."
for range in "${IPV4_RANGES[@]}"; do
    echo "  Unblocking $range"
    iptables -D INPUT -s "$range" -j DROP 2>/dev/null
    iptables -D OUTPUT -d "$range" -j DROP 2>/dev/null
done

# Unban IPv6 ranges
echo "Removing IPv6 bans..."
for range in "${IPV6_RANGES[@]}"; do
    echo "  Unblocking $range"
    ip6tables -D INPUT -s "$range" -j DROP 2>/dev/null
    ip6tables -D OUTPUT -d "$range" -j DROP 2>/dev/null
done

echo ""
echo "IP unban rules have been removed!"
echo "Note: This script removes the specific rules but doesn't affect saved configurations."