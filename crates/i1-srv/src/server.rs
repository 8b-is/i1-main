//! DNS server runner: binds UDP+TCP and serves threat intelligence zones.

use hickory_server::authority::{Authority, AuthorityObject, Catalog};
use hickory_server::server::ServerFuture;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

use crate::authority::zone_builder::{self, BuiltZones, DefenseSnapshot};
use crate::config::ServerConfig;

/// TCP connection timeout for DNS queries.
const TCP_TIMEOUT: Duration = Duration::from_secs(30);

/// Build a catalog from built zones.
fn build_catalog(zones: BuiltZones) -> Catalog {
    let mut catalog = Catalog::new();

    // Register each zone in the catalog.
    let bl_origin = Authority::origin(&zones.blocklist).clone();
    let rep_origin = Authority::origin(&zones.reputation).clone();
    let geo_origin = Authority::origin(&zones.geo).clone();
    let asn_origin = Authority::origin(&zones.asn).clone();
    let sig_origin = Authority::origin(&zones.signal).clone();

    catalog.upsert(
        bl_origin,
        vec![Arc::new(zones.blocklist) as Arc<dyn AuthorityObject>],
    );
    catalog.upsert(
        rep_origin,
        vec![Arc::new(zones.reputation) as Arc<dyn AuthorityObject>],
    );
    catalog.upsert(
        geo_origin,
        vec![Arc::new(zones.geo) as Arc<dyn AuthorityObject>],
    );
    catalog.upsert(
        asn_origin,
        vec![Arc::new(zones.asn) as Arc<dyn AuthorityObject>],
    );
    catalog.upsert(
        sig_origin,
        vec![Arc::new(zones.signal) as Arc<dyn AuthorityObject>],
    );

    catalog
}

/// Start the DNS server with the given configuration and defense state.
///
/// This function binds UDP and TCP sockets, builds the DNS zones from
/// the defense snapshot, and runs until shutdown.
pub async fn run(config: &ServerConfig, snapshot: DefenseSnapshot) -> crate::Result<()> {
    // Build zones from defense state.
    let serial = chrono::Utc::now().format("%Y%m%d01").to_string();
    let serial: u32 = serial
        .parse()
        .map_err(|e| crate::SrvError::Zone(format!("serial parse error: {e}")))?;

    let zones = zone_builder::build_zones(&snapshot, &config.zones, serial)?;

    info!(
        serial = serial,
        entries = zones.entry_count,
        "built DNS zones from defense state"
    );

    let catalog = build_catalog(zones);

    // Create server.
    let mut server = ServerFuture::new(catalog);

    // Bind UDP.
    let udp_socket = UdpSocket::bind(config.listen)
        .await
        .map_err(|e| crate::SrvError::Server(format!("UDP bind {}: {e}", config.listen)))?;
    info!(addr = %config.listen, "UDP socket bound");
    server.register_socket(udp_socket);

    // Bind TCP.
    let tcp_listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| crate::SrvError::Server(format!("TCP bind {}: {e}", config.listen)))?;
    info!(addr = %config.listen, "TCP listener bound");
    server.register_listener(tcp_listener, TCP_TIMEOUT);

    info!(
        addr = %config.listen,
        node = %config.node_name,
        "i1-srv DNS threat intel server running"
    );

    // Run until shutdown.
    server
        .block_until_done()
        .await
        .map_err(|e| crate::SrvError::Server(format!("server error: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZoneConfig;

    #[test]
    fn test_build_catalog() {
        let snapshot = DefenseSnapshot {
            blocked_ips: vec!["1.2.3.4".into()],
            blocked_countries: vec!["cn".into()],
            blocked_asns: vec!["AS12345".into()],
            ..Default::default()
        };
        let zones = zone_builder::build_zones(&snapshot, &ZoneConfig::default(), 1).unwrap();
        let catalog = build_catalog(zones);
        // Catalog was built without panicking.
        drop(catalog);
    }
}
