//! Data collector: reads defense state and converts to DNS-ready data.
//!
//! Watches the `defend::State` file and rebuilds zone records when it changes.
//! This is the bridge between i1-cli's local state and i1-srv's DNS zones.

use crate::authority::zone_builder::{AuditData, DefenseSnapshot};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Defense state file structure (matches i1-cli's `defend::State` serialization).
///
/// We deserialize this directly from the JSON state file rather than
/// depending on i1-cli (to avoid circular dependencies).
#[derive(Debug, Clone, Default, Deserialize)]
struct StateFile {
    #[serde(default)]
    blocked_countries: Vec<String>,
    #[serde(default)]
    blocked_countries_outbound: Vec<String>,
    #[serde(default)]
    blocked_ips: Vec<String>,
    #[serde(default)]
    blocked_asns: Vec<String>,
    #[serde(default)]
    whitelisted_ips: Vec<String>,
}

/// Find the default defense state file path.
///
/// Uses the same path as i1-cli: `~/.local/share/i1/showdi1/defend_state.json`
/// (or platform equivalent via the `directories` crate path convention).
pub fn default_state_path() -> Option<PathBuf> {
    // Match i1-cli's path: ProjectDirs::from("is", "i1", "showdi1").data_dir()
    dirs::data_dir().map(|d| d.join("showdi1").join("defend_state.json"))
}

/// Load a defense snapshot from the state file.
///
/// Returns a default (empty) snapshot if the file doesn't exist,
/// which is fine for a fresh node with no blocks yet.
pub fn load_snapshot(path: &Path) -> crate::Result<DefenseSnapshot> {
    if !path.exists() {
        return Ok(DefenseSnapshot::default());
    }

    let content = std::fs::read_to_string(path)
        .map_err(|e| crate::SrvError::State(format!("failed to read {}: {e}", path.display())))?;

    let state: StateFile = serde_json::from_str(&content)
        .map_err(|e| crate::SrvError::State(format!("failed to parse state: {e}")))?;

    Ok(DefenseSnapshot {
        blocked_ips: state.blocked_ips,
        blocked_countries: state.blocked_countries,
        blocked_countries_outbound: state.blocked_countries_outbound,
        blocked_asns: state.blocked_asns,
        whitelisted_ips: state.whitelisted_ips,
        audit: None,
    })
}

/// Find the default audit snapshot file path.
///
/// Uses `~/.local/share/i1/audit_snapshot.json`, matching the path
/// written by `i1 audit --publish`.
pub fn default_audit_path() -> Option<PathBuf> {
    dirs::data_dir().map(|d| d.join("i1").join("audit_snapshot.json"))
}

/// Load an audit snapshot from a JSON file published by `i1 audit --publish`.
///
/// Returns `None` if the file doesn't exist (no audit data published yet).
/// This is normal for nodes that haven't run `i1 audit full --publish`.
pub fn load_audit_snapshot(path: &Path) -> crate::Result<Option<AuditData>> {
    if !path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(path).map_err(|e| {
        crate::SrvError::State(format!("failed to read audit snapshot {}: {e}", path.display()))
    })?;

    let snapshot: i1_audit::AuditSnapshot = serde_json::from_str(&content).map_err(|e| {
        warn!(path = %path.display(), error = %e, "failed to parse audit snapshot");
        crate::SrvError::State(format!("failed to parse audit snapshot: {e}"))
    })?;

    Ok(Some(AuditData {
        binaries: snapshot.binaries,
        root_certs: snapshot.root_certs,
        node_id: snapshot.node_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_nonexistent_file() {
        let path = Path::new("/tmp/nonexistent_i1_state_test.json");
        let snapshot = load_snapshot(path).unwrap();
        assert!(snapshot.blocked_ips.is_empty());
        assert!(snapshot.blocked_countries.is_empty());
    }

    #[test]
    fn test_load_valid_state() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"{{
                "blocked_countries": ["cn", "ru"],
                "blocked_countries_outbound": ["cn", "kz", "ro", "ru"],
                "blocked_ips": ["1.2.3.4", "10.0.0.0/24"],
                "blocked_asns": ["AS12345"],
                "whitelisted_ips": ["173.71.155.73"]
            }}"#
        )
        .unwrap();

        let snapshot = load_snapshot(tmpfile.path()).unwrap();
        assert_eq!(snapshot.blocked_countries, vec!["cn", "ru"]);
        assert_eq!(
            snapshot.blocked_countries_outbound,
            vec!["cn", "kz", "ro", "ru"]
        );
        assert_eq!(snapshot.blocked_ips, vec!["1.2.3.4", "10.0.0.0/24"]);
        assert_eq!(snapshot.blocked_asns, vec!["AS12345"]);
        assert_eq!(snapshot.whitelisted_ips, vec!["173.71.155.73"]);
    }

    #[test]
    fn test_load_minimal_state() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(tmpfile, r#"{{"blocked_ips": ["1.1.1.1"]}}"#).unwrap();

        let snapshot = load_snapshot(tmpfile.path()).unwrap();
        assert_eq!(snapshot.blocked_ips, vec!["1.1.1.1"]);
        // Other fields default to empty.
        assert!(snapshot.blocked_countries.is_empty());
        assert!(snapshot.blocked_asns.is_empty());
    }

    #[test]
    fn test_load_audit_snapshot() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        write!(
            tmpfile,
            r#"{{
                "node_id": "test-node",
                "collected_at": "2026-02-19T00:00:00Z",
                "system_uptime_secs": 86400,
                "cpu_count": 4,
                "binaries": [{{
                    "path": "/usr/bin/sshd",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "create_date": "2026-01-01T00:00:00Z",
                    "modify_date": "2026-01-01T00:00:00Z",
                    "identity": {{ "inode": 1, "device_id": 1 }},
                    "size": 1047552,
                    "running": true,
                    "process_names": ["sshd"],
                    "trust_score": null
                }}],
                "processes": [],
                "root_certs": [{{
                    "path": "/etc/ssl/certs/ca.pem",
                    "fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "issuer": "CN=DigiCert, O=DigiCert Inc",
                    "subject": "CN=DigiCert",
                    "serial": "0a1234",
                    "not_before": "2020-01-01T00:00:00Z",
                    "not_after": "2030-01-01T00:00:00Z",
                    "expired": false,
                    "in_consensus": null,
                    "trust_score": null
                }}],
                "summary": {{
                    "total_binaries": 1,
                    "total_processes": 0,
                    "total_root_certs": 1,
                    "running_binaries": 1,
                    "expired_certs": 0,
                    "low_trust_binaries": 0,
                    "unknown_certs": 0
                }}
            }}"#
        )
        .unwrap();

        let audit = load_audit_snapshot(tmpfile.path()).unwrap();
        assert!(audit.is_some());
        let data = audit.unwrap();
        assert_eq!(data.node_id, "test-node");
        assert_eq!(data.binaries.len(), 1);
        assert_eq!(data.root_certs.len(), 1);
        assert_eq!(data.binaries[0].path, "/usr/bin/sshd");
    }

    #[test]
    fn test_load_missing_audit() {
        let path = Path::new("/tmp/nonexistent_i1_audit_test.json");
        let result = load_audit_snapshot(path).unwrap();
        assert!(result.is_none());
    }
}
