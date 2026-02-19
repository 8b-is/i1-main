//! Threat authority: wraps Hickory's in-memory authority for threat zones.
//!
//! Manages the DNS records that represent our threat intelligence data.
//! Records are rebuilt periodically from defense state.

use hickory_proto::rr::rdata::{A, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record};
use hickory_server::authority::ZoneType;
use hickory_server::store::in_memory::InMemoryAuthority;
use std::net::Ipv4Addr;

use crate::authority::ttl_policy;
use crate::encoding::dnsbl::DnsblCode;

/// Creates an empty in-memory authority for a zone with a proper SOA record.
///
/// The SOA is required for any valid DNS zone. We set it up with
/// reasonable defaults for a threat intelligence zone.
pub fn create_zone(origin: &Name, serial: u32) -> crate::Result<InMemoryAuthority> {
    let mut authority = InMemoryAuthority::empty(
        origin.clone(),
        ZoneType::Primary,
        false, // no AXFR
    );

    // Every zone needs a SOA record.
    let soa = SOA::new(
        Name::parse("ns1.i1.is.", None)
            .map_err(|e| crate::SrvError::Zone(format!("invalid SOA mname: {e}")))?,
        Name::parse("admin.i1.is.", None)
            .map_err(|e| crate::SrvError::Zone(format!("invalid SOA rname: {e}")))?,
        serial,
        ttl_policy::SOA_REFRESH,
        ttl_policy::SOA_RETRY,
        ttl_policy::SOA_EXPIRE,
        ttl_policy::SOA_MINIMUM_TTL,
    );

    authority.upsert_mut(
        Record::from_rdata(origin.clone(), ttl_policy::NS_TTL, RData::SOA(soa)),
        serial,
    );

    Ok(authority)
}

/// Insert a DNSBL A record into the blocklist zone.
///
/// Maps a reversed IP (e.g., `4.3.2.1`) to a 127.0.0.X response code
/// under the given zone origin.
pub fn insert_dnsbl_record(
    authority: &mut InMemoryAuthority,
    ip: &Ipv4Addr,
    code: DnsblCode,
    zone_origin: &str,
    serial: u32,
) -> crate::Result<()> {
    let reversed = crate::encoding::dnsbl::reverse_ipv4(ip);
    let name = Name::parse(&format!("{reversed}.{zone_origin}"), None)
        .map_err(|e| crate::SrvError::Zone(format!("invalid DNSBL name: {e}")))?;

    let ttl = ttl_policy::ttl_for_threat_class(match code {
        DnsblCode::Suspicious => ttl_policy::ThreatClass::Suspicious,
        DnsblCode::Community => ttl_policy::ThreatClass::Community,
        _ => ttl_policy::ThreatClass::Confirmed,
    });

    authority.upsert_mut(
        Record::from_rdata(name, ttl, RData::A(A::from(code.to_ipv4()))),
        serial,
    );

    Ok(())
}

/// Insert a TXT reputation record into the reputation zone.
pub fn insert_txt_record(
    authority: &mut InMemoryAuthority,
    name: &Name,
    txt_data: &str,
    ttl: u32,
    serial: u32,
) {
    authority.upsert_mut(
        Record::from_rdata(
            name.clone(),
            ttl,
            RData::TXT(TXT::new(vec![txt_data.to_string()])),
        ),
        serial,
    );
}

/// Insert a signal/version record into the signal zone.
pub fn insert_signal_record(
    authority: &mut InMemoryAuthority,
    zone_origin: &str,
    signal_txt: &str,
    serial: u32,
) -> crate::Result<()> {
    let name = Name::parse(&crate::encoding::signal::SignalData::query_name(zone_origin), None)
        .map_err(|e| crate::SrvError::Zone(format!("invalid signal name: {e}")))?;

    authority.upsert_mut(
        Record::from_rdata(
            name,
            ttl_policy::SIGNAL_TTL,
            RData::TXT(TXT::new(vec![signal_txt.to_string()])),
        ),
        serial,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::authority::Authority;

    #[test]
    fn test_create_zone() {
        let origin = Name::parse("bl.i1.is.", None).unwrap();
        let authority = create_zone(&origin, 1).unwrap();
        // Zone exists with correct origin.
        assert_eq!(
            authority.origin().to_string(),
            "bl.i1.is."
        );
    }

    #[test]
    fn test_insert_dnsbl_record() {
        let origin = Name::parse("bl.i1.is.", None).unwrap();
        let mut authority = create_zone(&origin, 1).unwrap();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        insert_dnsbl_record(&mut authority, &ip, DnsblCode::Malicious, "bl.i1.is.", 1).unwrap();
        // Record was inserted (no panic, no error).
    }

    #[test]
    fn test_insert_txt_record() {
        let origin = Name::parse("rep.i1.is.", None).unwrap();
        let mut authority = create_zone(&origin, 1).unwrap();
        let name = Name::parse("4.3.2.1.rep.i1.is.", None).unwrap();
        insert_txt_record(&mut authority, &name, "cc=cn;threat=high", 7200, 1);
        // Record was inserted (no panic).
    }
}
