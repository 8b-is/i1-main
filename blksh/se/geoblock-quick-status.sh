#!/bin/bash
#
# Quick status checker for geo-blocking
#

echo "======================================"
echo "  Geo-Blocking Quick Status"
echo "======================================"
echo ""

# Check if table exists
if ! nft list table inet geoblock &>/dev/null; then
    echo "❌ Geo-blocking is NOT active"
    echo ""
    echo "To enable: systemctl start nftables-geoblock"
    exit 1
fi

echo "✅ Geo-blocking is ACTIVE"
echo ""

# Count blocked countries
echo "Blocked Countries:"
nft list table inet geoblock | grep "set country-" | while read -r line; do
    set_name=$(echo "$line" | awk '{print $2}')
    country=$(echo "$set_name" | sed 's/country-//' | tr '[:lower:]' '[:upper:]')
    echo "  • $country"
done
echo ""

# Show whitelisted IPs
echo "Whitelisted IPs:"
nft list ruleset | grep "saddr.*accept" | sed 's/.*saddr //; s/ accept//' | while read -r ip; do
    if [ "$ip" != "@"* ]; then
        echo "  • $ip"
    fi
done
echo ""

# Show if any attackers are blocked
if nft list set inet geoblock attackers-ipv4 &>/dev/null || nft list set inet geoblock attackers-ipv6 &>/dev/null; then
    echo "Specific Attackers Blocked:"
    nft list set inet geoblock attackers-ipv4 2>/dev/null | grep "elements" -A 100 | grep -v "elements" | grep -v "^}" | sed 's/^[ \t]*/  • /'
    nft list set inet geoblock attackers-ipv6 2>/dev/null | grep "elements" -A 100 | grep -v "elements" | grep -v "^}" | sed 's/^[ \t]*/  • /'
    echo ""
fi

# Service status
echo "Service Status:"
if systemctl is-active --quiet nftables-geoblock; then
    echo "  ✅ Service is running"
else
    echo "  ⚠️  Service is not running (rules still active)"
fi

if systemctl is-enabled --quiet nftables-geoblock; then
    echo "  ✅ Enabled on boot"
else
    echo "  ❌ Not enabled on boot"
fi
echo ""

# Recent activity (if logging is enabled)
echo "Management:"
echo "  View all rules:  nft list ruleset"
echo "  Manage:          geoblock-manage status"
echo "  Disable:         geoblock-manage disable"
echo ""
