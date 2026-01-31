#!/bin/bash

# AS Number Unban Script - Removes AS-based IP blocks
# Usage: ./unban_as_numbers.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Removing AS number bans..."

# Remove iptables rules that use the ipsets
echo "Removing iptables rules..."
iptables -D INPUT -m set --match-set blocked_as src -j DROP 2>/dev/null
iptables -D OUTPUT -m set --match-set blocked_as dst -j DROP 2>/dev/null
ip6tables -D INPUT -m set --match-set blocked_as6 src -j DROP 2>/dev/null
ip6tables -D OUTPUT -m set --match-set blocked_as6 dst -j DROP 2>/dev/null

# Flush and destroy ipsets
echo "Clearing ipsets..."
ipset flush blocked_as 2>/dev/null
ipset flush blocked_as6 2>/dev/null
ipset destroy blocked_as 2>/dev/null
ipset destroy blocked_as6 2>/dev/null

echo ""
echo "AS number bans have been removed!"