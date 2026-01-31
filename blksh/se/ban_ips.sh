#!/bin/bash

# IP Ban Script - Blocks specified IP ranges and AS numbers
# Usage: ./ban_ips.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

echo "Starting IP ban process..."

# IPv4 ranges to ban
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

# IPv6 ranges to ban
IPV6_RANGES=(
    "2602:80d:1000:b0cc:e::/80"
    "2620:96:e000:b0cc:e::/80"
    "2602:80d:1003::/112"
    "2602:80d:1004::/112"
)

# AS numbers to ban
AS_NUMBERS=(
    "AS398722"
    "AS398705"
    "AS398324"
)

# Ban IPv4 ranges
echo "Banning IPv4 ranges..."
for range in "${IPV4_RANGES[@]}"; do
    echo "  Blocking $range"
    iptables -A INPUT -s "$range" -j DROP
    iptables -A OUTPUT -d "$range" -j DROP
done

# Ban IPv6 ranges
echo "Banning IPv6 ranges..."
for range in "${IPV6_RANGES[@]}"; do
    echo "  Blocking $range"
    ip6tables -A INPUT -s "$range" -j DROP
    ip6tables -A OUTPUT -d "$range" -j DROP
done

# Ban AS numbers (requires additional tools like ipset and BGP data)
echo "Preparing AS number bans..."
echo "Note: AS number blocking requires ipset and BGP route data."
echo "You'll need to:"
echo "1. Install ipset: apt-get install ipset (Debian/Ubuntu) or yum install ipset (RHEL/CentOS)"
echo "2. Fetch IP ranges for each AS from sources like whois.radb.net or bgp.he.net"
echo ""
echo "Example commands for AS blocking:"
for as in "${AS_NUMBERS[@]}"; do
    as_num="${as#AS}"
    echo "  # For $as:"
    echo "  whois -h whois.radb.net -- '-i origin $as' | grep -Eo '([0-9.]+){4}/[0-9]+' | head -10"
    echo "  # Then add each IP range to ipset and iptables"
done

echo ""
echo "IP ban rules have been applied!"
echo "To save rules permanently:"
echo "  - Debian/Ubuntu: apt-get install iptables-persistent && netfilter-persistent save"
echo "  - RHEL/CentOS: service iptables save && service ip6tables save"