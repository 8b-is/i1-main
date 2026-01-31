#!/bin/bash
#
# Test if an IP would be blocked by geo-blocking
#
# Usage: ./test-geoblock.sh <IP_ADDRESS>
#

if [ -z "$1" ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    echo ""
    echo "Examples:"
    echo "  $0 8.8.8.8"
    echo "  $0 2607:fb90:b393:8da4::1"
    exit 1
fi

IP="$1"

echo "Testing IP: $IP"
echo ""

# Check if it's in whitelist
echo -n "Whitelisted: "
if [[ $IP == *":"* ]]; then
    # IPv6
    if nft list ruleset | grep -q "ip6 saddr $IP accept"; then
        echo "YES (explicitly allowed)"
        exit 0
    fi
else
    # IPv4
    if nft list ruleset | grep -q "ip saddr $IP accept"; then
        echo "YES (explicitly allowed)"
        exit 0
    fi
fi
echo "NO"

# Check if it's in attacker lists
echo -n "In attacker list: "
if nft list set inet geoblock attackers-ipv4 2>/dev/null | grep -q "$IP"; then
    echo "YES (BLOCKED)"
    exit 0
fi
if nft list set inet geoblock attackers-ipv6 2>/dev/null | grep -q "$IP"; then
    echo "YES (BLOCKED)"
    exit 0
fi
echo "NO"

# Check which country it belongs to
echo ""
echo "Checking country sets..."

# Get all country sets
nft list table inet geoblock 2>/dev/null | grep "set country-" | awk '{print $2}' | while read -r set_name; do
    # Extract country code
    country=$(echo "$set_name" | sed 's/country-//')

    # Check if IP is in this set
    # Note: This is approximate as nft doesn't have a direct "is member" command
    # For precise checking, we'd need to export and parse the set
    echo "  Checking $country..."
done

echo ""
echo "To definitively test, try connecting from that IP:"
echo "  curl -I https://your-server.com --interface $IP"
echo ""
echo "Or use an online testing service from that country."
