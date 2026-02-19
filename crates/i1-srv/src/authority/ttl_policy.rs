//! TTL policy constants for DNS records.
//!
//! TTLs are set high for resilience: cached records provide protection
//! even when i1-srv nodes are unreachable. Signal records use near-zero
//! TTLs so clients can detect when their cache is stale.

/// TTL for NS referral records (maximum practical).
/// Keeps zone delegation alive in caches for 24 hours.
pub const NS_TTL: u32 = 86400;

/// TTL for static node A/AAAA records.
/// Stable IP addresses rarely change.
pub const NODE_STATIC_TTL: u32 = 86400;

/// TTL for dynamic (DDNS) node A/AAAA records.
/// Dynamic IPs need frequent updates.
pub const NODE_DDNS_TTL: u32 = 300;

/// TTL for TLSA identity records.
/// Certificates rarely change.
pub const TLSA_TTL: u32 = 86400;

/// TTL for confirmed blocklist entries.
/// Protection persists in cache for 24 hours.
pub const BLOCKLIST_CONFIRMED_TTL: u32 = 86400;

/// TTL for suspicious (patrol-detected, not yet confirmed) entries.
/// Shorter TTL since these may be cleared as false positives.
pub const BLOCKLIST_SUSPICIOUS_TTL: u32 = 3600;

/// TTL for community-reported entries.
/// Moderate confidence, 12-hour cache.
pub const BLOCKLIST_COMMUNITY_TTL: u32 = 43200;

/// TTL for reputation TXT records.
/// Changes moderately as new intel arrives.
pub const REPUTATION_TTL: u32 = 7200;

/// TTL for signal/version-check records.
/// Near-zero for fast staleness detection.
pub const SIGNAL_TTL: u32 = 30;

/// TTL for geo/ASN block records.
/// Country and ASN blocks are stable data.
pub const GEO_ASN_TTL: u32 = 86400;

/// SOA minimum TTL (negative caching).
/// Quick false-positive recovery: if an IP is clean (NXDOMAIN),
/// resolvers only cache that for 5 minutes.
pub const SOA_MINIMUM_TTL: u32 = 300;

/// SOA refresh interval (Hickory uses i32 for SOA fields).
pub const SOA_REFRESH: i32 = 3600;

/// SOA retry interval.
pub const SOA_RETRY: i32 = 900;

/// SOA expire interval.
pub const SOA_EXPIRE: i32 = 604_800;

/// Select the appropriate TTL based on threat classification.
pub const fn ttl_for_threat_class(class: ThreatClass) -> u32 {
    match class {
        ThreatClass::Confirmed => BLOCKLIST_CONFIRMED_TTL,
        ThreatClass::Suspicious => BLOCKLIST_SUSPICIOUS_TTL,
        ThreatClass::Community => BLOCKLIST_COMMUNITY_TTL,
        ThreatClass::Clean => SOA_MINIMUM_TTL,
    }
}

/// Threat classification for TTL selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatClass {
    /// Confirmed malicious (manual ban, repeated offender).
    Confirmed,
    /// Suspicious (patrol-detected, threshold exceeded).
    Suspicious,
    /// Community-reported (crowdsourced intel).
    Community,
    /// Not listed (used for SOA minimum / negative caching).
    Clean,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_values_are_reasonable() {
        // Signal must be much shorter than blocklist.
        assert!(SIGNAL_TTL < BLOCKLIST_SUSPICIOUS_TTL);
        // Confirmed must be >= suspicious.
        assert!(BLOCKLIST_CONFIRMED_TTL >= BLOCKLIST_SUSPICIOUS_TTL);
        // SOA minimum must be short for false-positive recovery.
        assert!(SOA_MINIMUM_TTL <= 600);
    }

    #[test]
    fn test_ttl_for_threat_class() {
        assert_eq!(ttl_for_threat_class(ThreatClass::Confirmed), 86400);
        assert_eq!(ttl_for_threat_class(ThreatClass::Suspicious), 3600);
        assert_eq!(ttl_for_threat_class(ThreatClass::Community), 43200);
        assert_eq!(ttl_for_threat_class(ThreatClass::Clean), 300);
    }
}
