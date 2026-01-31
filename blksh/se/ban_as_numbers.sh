#!/bin/bash

# AS Number Ban Script - Blocks IP ranges associated with AS numbers
# Usage: ./ban_as_numbers.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Check if ipset is installed
if ! command -v ipset &> /dev/null; then
    echo "ipset is not installed. Please install it first."
    exit 1
fi

# Check if whois is installed
if ! command -v whois &> /dev/null; then
    echo "whois is not installed. Please install it first."
    exit 1
fi

# AS numbers to ban
AS_NUMBERS=(
    "AS398722"
    "AS398705"
    "AS398324"
    "AS210558"
)

echo "Starting AS number ban process..."

# Create ipset for blocked AS numbers if it doesn't exist
ipset create blocked_as hash:net family inet hashsize 4096 maxelem 100000 2>/dev/null || true
ipset create blocked_as6 hash:net family inet6 hashsize 4096 maxelem 100000 2>/dev/null || true

# Add iptables rules to use the ipset (if not already present)
iptables -C INPUT -m set --match-set blocked_as src -j DROP 2>/dev/null || \
    iptables -I INPUT -m set --match-set blocked_as src -j DROP
iptables -C OUTPUT -m set --match-set blocked_as dst -j DROP 2>/dev/null || \
    iptables -I OUTPUT -m set --match-set blocked_as dst -j DROP

ip6tables -C INPUT -m set --match-set blocked_as6 src -j DROP 2>/dev/null || \
    ip6tables -I INPUT -m set --match-set blocked_as6 src -j DROP
ip6tables -C OUTPUT -m set --match-set blocked_as6 dst -j DROP 2>/dev/null || \
    ip6tables -I OUTPUT -m set --match-set blocked_as6 dst -j DROP

# Process each AS number
for as in "${AS_NUMBERS[@]}"; do
    echo "Processing $as..."
    
    # Query RADB for IPv4 ranges
    echo "  Fetching IPv4 ranges..."
    ipv4_ranges=$(whois -h whois.radb.net -- "-i origin $as" 2>/dev/null | grep -E '^route:' | awk '{print $2}' | sort -u)
    
    if [ -n "$ipv4_ranges" ]; then
        while IFS= read -r range; do
            if [ -n "$range" ]; then
                echo "    Adding IPv4: $range"
                ipset add blocked_as "$range" 2>/dev/null || echo "      (already exists or invalid)"
            fi
        done <<< "$ipv4_ranges"
    else
        echo "    No IPv4 ranges found"
    fi
    
    # Query RADB for IPv6 ranges
    echo "  Fetching IPv6 ranges..."
    ipv6_ranges=$(whois -h whois.radb.net -- "-i origin $as" 2>/dev/null | grep -E '^route6:' | awk '{print $2}' | sort -u)
    
    if [ -n "$ipv6_ranges" ]; then
        while IFS= read -r range; do
            if [ -n "$range" ]; then
                echo "    Adding IPv6: $range"
                ipset add blocked_as6 "$range" 2>/dev/null || echo "      (already exists or invalid)"
            fi
        done <<< "$ipv6_ranges"
    else
        echo "    No IPv6 ranges found"
    fi
    
    echo ""
done

# Show statistics
echo "Ban statistics:"
echo "  IPv4 entries in blocked_as: $(ipset list blocked_as | grep -c '^[0-9]')"
echo "  IPv6 entries in blocked_as6: $(ipset list blocked_as6 | grep -c '^[0-9a-f:.]')"

echo ""
echo "AS number bans have been applied!"
echo ""
echo "To save ipset rules permanently:"
echo "  - Debian/Ubuntu: apt-get install ipset-persistent"
echo "  - RHEL/CentOS: Add 'ipset save > /etc/sysconfig/ipset' to startup"
echo ""
echo "To view blocked ranges: ipset list blocked_as | less"
echo "To view blocked IPv6 ranges: ipset list blocked_as6 | less"