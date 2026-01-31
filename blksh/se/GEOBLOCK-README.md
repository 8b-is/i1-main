# Mail Server Geo-Blocking Script

This script provides automated geo-blocking at the firewall level using nftables. It's designed for mail servers but works for any server that needs country-level blocking.

## Features

- ✅ Blocks entire countries by IP range
- ✅ Automatically whitelists your IP
- ✅ Supports IPv4 and IPv6
- ✅ Persistent across reboots
- ✅ Efficient (uses nftables sets)
- ✅ Easy management with included tools
- ✅ No impact on mailcow or other services

## Quick Start

### 1. Edit the Configuration

Open the script and modify these variables at the top:

```bash
# Countries to block (ISO 2-letter codes)
BLOCKED_COUNTRIES=("ro" "ru" "pl" "kz")
COUNTRY_NAMES=("Romania" "Russia" "Poland" "Kazakhstan")

# Your IP to whitelist (auto-detects if empty)
WHITELIST_IP=""

# Additional IPs to whitelist
ADDITIONAL_WHITELIST="1.2.3.4 5.6.7.0/24"

# Specific attackers to block
ATTACKER_IPS="1.2.3.4 2607:fb90:b393:8da4::1"
```

### 2. Run the Script

```bash
chmod +x geoblock-setup.sh
./geoblock-setup.sh
```

The script will:
1. Download IP ranges for specified countries
2. Configure nftables to block them
3. Whitelist your IP
4. Make it persistent across reboots
5. Install management tools

## Country Codes

Find country codes at: https://www.ipdeny.com/ipblocks/

Common examples:
- `cn` - China
- `ru` - Russia
- `ro` - Romania
- `pl` - Poland
- `kz` - Kazakhstan
- `br` - Brazil
- `in` - India
- `vn` - Vietnam
- `kr` - South Korea
- `ua` - Ukraine

## Management

After installation, use the management tool:

```bash
# Show status and active rules
geoblock-manage status

# Temporarily disable blocking
geoblock-manage disable

# Re-enable blocking
geoblock-manage enable

# Reload rules from config
geoblock-manage reload

# Add IP to whitelist
geoblock-manage add-ip 1.2.3.4

# Block a specific IP immediately
geoblock-manage block-ip 1.2.3.4

# Show statistics
geoblock-manage stats
```

## Manual Management

### View Active Rules
```bash
nft list ruleset
nft list table inet geoblock
```

### Check Service Status
```bash
systemctl status nftables-geoblock
```

### Reload Configuration
```bash
systemctl reload nftables-geoblock
```

### Temporarily Disable
```bash
nft delete table inet geoblock
# Will re-enable on next boot
```

### Permanently Remove
```bash
systemctl disable nftables-geoblock
systemctl stop nftables-geoblock
nft delete table inet geoblock
rm /etc/nftables/geoblock.nft
rm /etc/systemd/system/nftables-geoblock.service
```

## Adding More Countries Later

1. Edit `geoblock-setup.sh`
2. Add country codes to `BLOCKED_COUNTRIES` array
3. Add country names to `COUNTRY_NAMES` array
4. Run the script again: `./geoblock-setup.sh`

The script is idempotent - safe to run multiple times.

## Emergency Access

If you get locked out:

### Option 1: Console Access
```bash
nft delete table inet geoblock
```

### Option 2: Before Running Script
Make sure to:
1. Set `WHITELIST_IP` to your current IP
2. Add any additional IPs to `ADDITIONAL_WHITELIST`
3. Test from those IPs after setup

### Option 3: Recovery Mode
Boot into recovery mode and:
```bash
systemctl disable nftables-geoblock
rm /etc/nftables/geoblock.nft
```

## How It Works

### Architecture
```
Internet → nftables (geo-blocking) → iptables/docker → Your Services
```

The script creates an nftables table called `geoblock` with:
- **Sets**: One per country containing all IP ranges
- **Chain**: Prerouting hook (earliest possible filtering)
- **Rules**:
  1. Allow whitelisted IPs
  2. Drop blocked countries
  3. Drop specific attackers

### Performance
- Uses nftables `interval` sets (efficient O(log n) lookups)
- Processes packets at kernel level
- Minimal CPU/memory overhead
- Can handle millions of packets per second

### Persistence
- nftables rules saved to `/etc/nftables/geoblock.nft`
- Systemd service loads rules at boot
- Starts before Docker (protects all services)

## Troubleshooting

### Script Fails to Download IPs
- Check internet connectivity
- Verify https://www.ipdeny.com/ is accessible
- Try manual download: `curl -I https://www.ipdeny.com/ipblocks/`

### Can't Access Server After Setup
- Connect via console/KVM
- Run: `nft delete table inet geoblock`
- Check your IP is correct: `curl https://api.ipify.org`

### Service Won't Start
```bash
# Check for errors
journalctl -u nftables-geoblock -n 50

# Validate config file
nft -f /etc/nftables/geoblock.nft

# Check syntax
nft -c -f /etc/nftables/geoblock.nft
```

### Rules Not Blocking
```bash
# Verify table exists
nft list tables

# Check rules are loaded
nft list table inet geoblock

# Verify sets have data
nft list set inet geoblock country-ru
```

## Integration with Mailcow

This script works alongside mailcow's built-in netfilter:
- Mailcow netfilter: Application-level blocking (fail2ban)
- This script: Network-level blocking (countries)

Both work together for defense in depth.

### Does Not Interfere With:
- Mailcow's Docker network
- Postfix/Dovecot
- Nginx reverse proxy
- Let's Encrypt (ACME)
- Existing iptables rules

## Testing

### Verify Blocking Works
```bash
# Test from a VPN in blocked country
# OR use online tools:
# https://www.uptrends.com/tools/uptime (has servers in many countries)

# Check if IP would be blocked:
./test-ip.sh 5.2.128.1  # Romanian IP
```

### Test Whitelist
```bash
# Your IP should always work
curl -I https://your-mailserver.com

# Check from whitelisted IP
ssh your-whitelisted-ip "curl -I https://your-mailserver.com"
```

## Updating IP Ranges

IP ranges change over time. Update monthly:

```bash
# Re-run the script
cd /root
./geoblock-setup.sh

# Or create a cron job
cat >> /etc/cron.monthly/geoblock-update << 'EOF'
#!/bin/bash
/root/geoblock-setup.sh >> /var/log/geoblock-update.log 2>&1
EOF
chmod +x /etc/cron.monthly/geoblock-update
```

## Advanced Configuration

### Block Entire Continents

Add to script:
```bash
# Add after downloading countries
wget -O as.zone https://www.ipdeny.com/ipblocks/data/aggregated/as-aggregated.zone  # Asia
wget -O af.zone https://www.ipdeny.com/ipblocks/data/aggregated/af-aggregated.zone  # Africa
```

### Allow Specific Services from Blocked Countries

Add to nftables config before country blocks:
```nft
# Allow HTTPS from everywhere
tcp dport 443 accept

# Then block countries
ip saddr @country-ru drop
```

### IPv6 Support

The script supports IPv6. To download IPv6 ranges:
```bash
# IPv6 ranges available at:
curl https://www.ipdeny.com/ipv6/ipaddresses/aggregated/ru-aggregated.zone
```

## Security Notes

### What This Blocks
- ✅ All HTTP/HTTPS attacks
- ✅ SSH brute force from blocked countries
- ✅ SMTP/IMAP/POP3 from blocked countries
- ✅ Port scans
- ✅ Any network connection from blocked IPs

### What This Doesn't Block
- ❌ VPN/proxy users from blocked countries
- ❌ Tor exit nodes (need separate blocking)
- ❌ Compromised servers in allowed countries
- ❌ Application-level attacks (use fail2ban)

### Best Practices
1. Always whitelist your IP before blocking
2. Test after setup
3. Monitor logs for false positives
4. Update IP ranges monthly
5. Document your configuration
6. Keep a console/KVM access available

## Files Created

```
/etc/nftables/geoblock.nft              # nftables rules
/etc/systemd/system/nftables-geoblock.service  # Systemd service
/usr/local/bin/geoblock-manage          # Management tool
/root/geoblock-setup.sh                 # This setup script
```

## Logs

```bash
# View service logs
journalctl -u nftables-geoblock

# Check for blocked connections (requires additional logging)
# To enable packet logging, add to nftables config:
# counter log prefix "GEOBLOCK: " drop
```

## Support

For issues or questions:
- Check nftables wiki: https://wiki.nftables.org/
- Mailcow documentation: https://docs.mailcow.email/
- IP block source: https://www.ipdeny.com/

## License

This script is provided as-is for educational and security purposes.
Use at your own risk. Always maintain backup access to your server.

## Changelog

### Version 1.0
- Initial release
- Support for IPv4 blocking
- IPv6 attacker blocking
- Automatic IP whitelisting
- Systemd integration
- Management tool included
