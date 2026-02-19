//! Zone builder: converts defense state into DNS records.
//!
//! Reads blocked IPs, countries, ASNs from i1-cli's `defend::State`
//! and builds the corresponding DNS zone records for each authority.

use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{Name, RData, Record};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::net::Ipv4Addr;

use crate::authority::{threat_authority, ttl_policy};
use crate::config::ZoneConfig;
use crate::encoding::dnsbl::DnsblCode;
use crate::encoding::signal::SignalData;
use crate::encoding::txt_intel;

/// Defense state data needed to build zones.
///
/// This is a subset of i1-cli's `defend::State`, kept separate to avoid
/// a direct dependency on i1-cli (which would create a circular dep).
#[derive(Debug, Clone, Default)]
pub struct DefenseSnapshot {
    /// Blocked IP addresses and CIDR ranges.
    pub blocked_ips: Vec<String>,
    /// Blocked country codes (inbound).
    pub blocked_countries: Vec<String>,
    /// Blocked country codes (outbound / honeypot mode).
    pub blocked_countries_outbound: Vec<String>,
    /// Blocked AS numbers (e.g., "AS12345").
    pub blocked_asns: Vec<String>,
    /// Whitelisted IPs.
    pub whitelisted_ips: Vec<String>,
}

/// Result of building all zones from a defense snapshot.
pub struct BuiltZones {
    /// DNSBL zone (bl.i1.is) - reversed-IP -> A record.
    pub blocklist: InMemoryAuthority,
    /// Reputation zone (rep.i1.is) - reversed-IP -> TXT record.
    pub reputation: InMemoryAuthority,
    /// Geo zone (geo.i1.is) - country codes -> TXT status.
    pub geo: InMemoryAuthority,
    /// ASN zone (asn.i1.is) - AS numbers -> TXT status.
    pub asn: InMemoryAuthority,
    /// Signal zone (sig.i1.is) - version records.
    pub signal: InMemoryAuthority,
    /// Zone serial used.
    pub serial: u32,
    /// Total entry count across all zones.
    pub entry_count: u32,
}

/// Build all DNS zones from a defense state snapshot.
pub fn build_zones(
    snapshot: &DefenseSnapshot,
    zones: &ZoneConfig,
    serial: u32,
) -> crate::Result<BuiltZones> {
    let mut blocklist = threat_authority::create_zone(&parse_name(&zones.blocklist)?, serial)?;
    let mut reputation = threat_authority::create_zone(&parse_name(&zones.reputation)?, serial)?;
    let mut geo = threat_authority::create_zone(&parse_name(&zones.geo)?, serial)?;
    let mut asn = threat_authority::create_zone(&parse_name(&zones.asn)?, serial)?;
    let mut signal = threat_authority::create_zone(&parse_name(&zones.signal)?, serial)?;

    let mut entry_count: u32 = 0;

    entry_count += populate_ip_records(&mut blocklist, &mut reputation, snapshot, zones, serial)?;
    entry_count += populate_geo_records(&mut geo, snapshot, zones, serial)?;
    entry_count += populate_asn_records(&mut asn, snapshot, zones, serial)?;

    // Build signal record (version check).
    let signal_data = SignalData::new(u64::from(serial), entry_count);
    threat_authority::insert_signal_record(
        &mut signal,
        &zones.signal,
        &signal_data.to_txt(),
        serial,
    )?;

    Ok(BuiltZones {
        blocklist,
        reputation,
        geo,
        asn,
        signal,
        serial,
        entry_count,
    })
}

/// Populate DNSBL and reputation records from blocked IPs.
fn populate_ip_records(
    blocklist: &mut InMemoryAuthority,
    reputation: &mut InMemoryAuthority,
    snapshot: &DefenseSnapshot,
    zones: &ZoneConfig,
    serial: u32,
) -> crate::Result<u32> {
    let mut count = 0;

    for ip_str in &snapshot.blocked_ips {
        // Skip CIDRs (DNSBL is per-IP; CIDRs need expansion).
        if ip_str.contains('/') {
            continue;
        }

        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            threat_authority::insert_dnsbl_record(
                blocklist,
                &ip,
                DnsblCode::Listed,
                &zones.blocklist,
                serial,
            )?;

            let rep_data = txt_intel::ReputationData {
                threat: Some("blocked".into()),
                ..txt_intel::ReputationData::empty()
            };
            if let Ok(txt) = txt_intel::encode(&rep_data) {
                let name = Name::parse(
                    &format!(
                        "{}.{}",
                        crate::encoding::dnsbl::reverse_ipv4(&ip),
                        &zones.reputation
                    ),
                    None,
                )
                .map_err(|e| crate::SrvError::Zone(format!("invalid rep name: {e}")))?;
                threat_authority::insert_txt_record(
                    reputation,
                    &name,
                    &txt,
                    ttl_policy::REPUTATION_TTL,
                    serial,
                );
            }

            count += 1;
        }
    }

    Ok(count)
}

/// Populate geo zone records from blocked countries.
fn populate_geo_records(
    geo: &mut InMemoryAuthority,
    snapshot: &DefenseSnapshot,
    zones: &ZoneConfig,
    serial: u32,
) -> crate::Result<u32> {
    let mut count = 0;

    for country in &snapshot.blocked_countries {
        let name = Name::parse(&format!("{country}.{}", &zones.geo), None)
            .map_err(|e| crate::SrvError::Zone(format!("invalid geo name: {e}")))?;
        geo.upsert_mut(
            Record::from_rdata(
                name,
                ttl_policy::GEO_ASN_TTL,
                RData::TXT(TXT::new(vec![
                    "status=blocked;direction=inbound".to_string(),
                ])),
            ),
            serial,
        );
        count += 1;
    }

    for country in &snapshot.blocked_countries_outbound {
        let name = Name::parse(&format!("{country}.{}", &zones.geo), None)
            .map_err(|e| crate::SrvError::Zone(format!("invalid geo name: {e}")))?;
        let direction = if snapshot.blocked_countries.contains(country) {
            "both"
        } else {
            "outbound"
        };
        geo.upsert_mut(
            Record::from_rdata(
                name,
                ttl_policy::GEO_ASN_TTL,
                RData::TXT(TXT::new(vec![format!(
                    "status=blocked;direction={direction}"
                )])),
            ),
            serial,
        );
        count += 1;
    }

    Ok(count)
}

/// Populate ASN zone records from blocked ASNs.
fn populate_asn_records(
    asn: &mut InMemoryAuthority,
    snapshot: &DefenseSnapshot,
    zones: &ZoneConfig,
    serial: u32,
) -> crate::Result<u32> {
    let mut count = 0;

    for asn_str in &snapshot.blocked_asns {
        let num = asn_str
            .strip_prefix("AS")
            .or_else(|| asn_str.strip_prefix("as"))
            .unwrap_or(asn_str);
        let name = Name::parse(&format!("{num}.{}", &zones.asn), None)
            .map_err(|e| crate::SrvError::Zone(format!("invalid ASN name: {e}")))?;
        asn.upsert_mut(
            Record::from_rdata(
                name,
                ttl_policy::GEO_ASN_TTL,
                RData::TXT(TXT::new(vec![format!("status=blocked;asn={asn_str}")])),
            ),
            serial,
        );
        count += 1;
    }

    Ok(count)
}

/// Helper to parse a zone name string.
fn parse_name(zone: &str) -> crate::Result<Name> {
    Name::parse(zone, None)
        .map_err(|e| crate::SrvError::Zone(format!("invalid zone name '{zone}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZoneConfig;

    #[test]
    fn test_build_empty_zones() {
        let snapshot = DefenseSnapshot::default();
        let zones = ZoneConfig::default();
        let built = build_zones(&snapshot, &zones, 1).unwrap();
        assert_eq!(built.entry_count, 0);
        assert_eq!(built.serial, 1);
    }

    #[test]
    fn test_build_with_blocked_ips() {
        let snapshot = DefenseSnapshot {
            blocked_ips: vec!["1.2.3.4".into(), "10.0.0.1".into()],
            ..Default::default()
        };
        let zones = ZoneConfig::default();
        let built = build_zones(&snapshot, &zones, 100).unwrap();
        assert_eq!(built.entry_count, 2);
    }

    #[test]
    fn test_build_with_countries() {
        let snapshot = DefenseSnapshot {
            blocked_countries: vec!["cn".into(), "ru".into()],
            blocked_countries_outbound: vec!["cn".into(), "kz".into()],
            ..Default::default()
        };
        let zones = ZoneConfig::default();
        let built = build_zones(&snapshot, &zones, 1).unwrap();
        // 2 inbound + 2 outbound = 4 entries.
        assert_eq!(built.entry_count, 4);
    }

    #[test]
    fn test_build_with_asns() {
        let snapshot = DefenseSnapshot {
            blocked_asns: vec!["AS12345".into(), "AS67890".into()],
            ..Default::default()
        };
        let zones = ZoneConfig::default();
        let built = build_zones(&snapshot, &zones, 1).unwrap();
        assert_eq!(built.entry_count, 2);
    }

    #[test]
    fn test_cidrs_are_skipped() {
        let snapshot = DefenseSnapshot {
            blocked_ips: vec!["1.2.3.0/24".into(), "10.0.0.1".into()],
            ..Default::default()
        };
        let zones = ZoneConfig::default();
        let built = build_zones(&snapshot, &zones, 1).unwrap();
        // CIDR skipped, only the single IP counts.
        assert_eq!(built.entry_count, 1);
    }
}
