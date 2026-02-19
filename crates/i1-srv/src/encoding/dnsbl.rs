//! DNSBL encoding: maps IPs to DNS blocklist responses.
//!
//! Standard DNSBL pattern: reverse the IP octets and query under the zone.
//! Example: checking 1.2.3.4 queries `4.3.2.1.bl.i1.is`
//!
//! Return codes (A record values):
//! - 127.0.0.1 = Listed (generic block)
//! - 127.0.0.2 = Malicious (confirmed attacker)
//! - 127.0.0.3 = Suspicious (patrol-detected, not yet confirmed)
//! - 127.0.0.4 = Web scanner
//! - 127.0.0.5 = Brute-force (SSH/SMTP)
//! - 127.0.0.10 = Community reported
//! - NXDOMAIN = Clean (not listed)

use std::net::Ipv4Addr;

/// DNSBL return codes indicating threat classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DnsblCode {
    /// Generic block (manually added).
    Listed = 1,
    /// Confirmed malicious (repeated offender, known bad).
    Malicious = 2,
    /// Suspicious (patrol threshold exceeded, not confirmed).
    Suspicious = 3,
    /// Web scanner (404 probing, path traversal).
    WebScanner = 4,
    /// Brute-force attacker (SSH, SMTP auth failures).
    BruteForce = 5,
    /// Community-reported threat.
    Community = 10,
}

impl DnsblCode {
    /// Convert to the 127.0.0.X response address.
    #[must_use]
    pub const fn to_ipv4(self) -> Ipv4Addr {
        Ipv4Addr::new(127, 0, 0, self as u8)
    }

    /// Human-readable label for this code.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Listed => "listed",
            Self::Malicious => "malicious",
            Self::Suspicious => "suspicious",
            Self::WebScanner => "web-scanner",
            Self::BruteForce => "brute-force",
            Self::Community => "community-reported",
        }
    }
}

/// Reverse an IPv4 address for DNSBL lookup.
///
/// Converts `1.2.3.4` into `4.3.2.1` (without zone suffix).
#[must_use]
pub fn reverse_ipv4(ip: &Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

/// Build the full DNSBL query name for an IP under a zone.
///
/// Example: `build_query_name("1.2.3.4", "bl.i1.is.")` -> `"4.3.2.1.bl.i1.is."`
pub fn build_query_name(ip: &str, zone: &str) -> crate::Result<String> {
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|e| crate::SrvError::Encoding(format!("invalid IPv4 address '{ip}': {e}")))?;
    let reversed = reverse_ipv4(&addr);
    Ok(format!("{reversed}.{zone}"))
}

/// Parse a DNSBL query name back into an IP address.
///
/// Example: `parse_query_name("4.3.2.1.bl.i1.is.", "bl.i1.is.")` -> Ok("1.2.3.4")
pub fn parse_query_name(query: &str, zone: &str) -> crate::Result<String> {
    let prefix = query
        .strip_suffix(zone)
        .and_then(|s| s.strip_suffix('.'))
        .ok_or_else(|| {
            crate::SrvError::Encoding(format!("query '{query}' not under zone '{zone}'"))
        })?;

    let octets: Vec<&str> = prefix.split('.').collect();
    if octets.len() != 4 {
        return Err(crate::SrvError::Encoding(format!(
            "expected 4 octets in reversed IP, got {}",
            octets.len()
        )));
    }

    Ok(format!(
        "{}.{}.{}.{}",
        octets[3], octets[2], octets[1], octets[0]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnsbl_codes() {
        assert_eq!(DnsblCode::Listed.to_ipv4(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(
            DnsblCode::Malicious.to_ipv4(),
            Ipv4Addr::new(127, 0, 0, 2)
        );
        assert_eq!(
            DnsblCode::BruteForce.to_ipv4(),
            Ipv4Addr::new(127, 0, 0, 5)
        );
        assert_eq!(
            DnsblCode::Community.to_ipv4(),
            Ipv4Addr::new(127, 0, 0, 10)
        );
    }

    #[test]
    fn test_reverse_ipv4() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        assert_eq!(reverse_ipv4(&ip), "4.3.2.1");

        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(reverse_ipv4(&ip), "100.1.168.192");
    }

    #[test]
    fn test_build_query_name() {
        let name = build_query_name("1.2.3.4", "bl.i1.is.").unwrap();
        assert_eq!(name, "4.3.2.1.bl.i1.is.");
    }

    #[test]
    fn test_parse_query_name() {
        let ip = parse_query_name("4.3.2.1.bl.i1.is.", "bl.i1.is.").unwrap();
        assert_eq!(ip, "1.2.3.4");
    }

    #[test]
    fn test_roundtrip() {
        let original = "203.0.113.42";
        let query = build_query_name(original, "bl.i1.is.").unwrap();
        let parsed = parse_query_name(&query, "bl.i1.is.").unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_invalid_ip() {
        assert!(build_query_name("not.an.ip", "bl.i1.is.").is_err());
    }
}
