//! Server configuration for i1-srv nodes.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for an i1-srv DNS threat intelligence node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// UDP/TCP listen address (default: 0.0.0.0:5353).
    pub listen: SocketAddr,

    /// Zone origins this node is authoritative for.
    pub zones: ZoneConfig,

    /// Node identity (hostname under srv.i1.is).
    pub node_name: String,

    /// Path to defense state file (default: auto-detect from i1-cli).
    pub state_path: Option<PathBuf>,

    /// How often to reload defense state (seconds).
    #[serde(default = "default_reload_interval")]
    pub reload_interval_secs: u64,

    /// Gossip/sync peers (other i1-srv node addresses).
    #[serde(default)]
    pub peers: Vec<String>,
}

/// Zone origins and their delegation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// DNSBL zone origin (default: bl.i1.is).
    #[serde(default = "default_bl_zone")]
    pub blocklist: String,

    /// Reputation zone origin (default: rep.i1.is).
    #[serde(default = "default_rep_zone")]
    pub reputation: String,

    /// Geo-block zone origin (default: geo.i1.is).
    #[serde(default = "default_geo_zone")]
    pub geo: String,

    /// ASN block zone origin (default: asn.i1.is).
    #[serde(default = "default_asn_zone")]
    pub asn: String,

    /// Signal zone origin (default: sig.i1.is).
    #[serde(default = "default_sig_zone")]
    pub signal: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:5353".parse().expect("valid default addr"),
            zones: ZoneConfig::default(),
            node_name: String::from("node1"),
            state_path: None,
            reload_interval_secs: default_reload_interval(),
            peers: Vec::new(),
        }
    }
}

impl Default for ZoneConfig {
    fn default() -> Self {
        Self {
            blocklist: default_bl_zone(),
            reputation: default_rep_zone(),
            geo: default_geo_zone(),
            asn: default_asn_zone(),
            signal: default_sig_zone(),
        }
    }
}

impl ServerConfig {
    /// Load config from a TOML file, falling back to defaults.
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content).map_err(|e| crate::SrvError::Config(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }
}

// Default value functions for serde.
const fn default_reload_interval() -> u64 {
    60
}

fn default_bl_zone() -> String {
    String::from("bl.i1.is.")
}

fn default_rep_zone() -> String {
    String::from("rep.i1.is.")
}

fn default_geo_zone() -> String {
    String::from("geo.i1.is.")
}

fn default_asn_zone() -> String {
    String::from("asn.i1.is.")
}

fn default_sig_zone() -> String {
    String::from("sig.i1.is.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.listen.port(), 5353);
        assert_eq!(config.zones.blocklist, "bl.i1.is.");
        assert_eq!(config.zones.reputation, "rep.i1.is.");
        assert_eq!(config.reload_interval_secs, 60);
        assert!(config.peers.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = ServerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.listen.port(), config.listen.port());
        assert_eq!(parsed.zones.blocklist, config.zones.blocklist);
    }
}
