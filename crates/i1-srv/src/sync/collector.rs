//! Data collector: reads defense state and converts to DNS-ready data.
//!
//! Watches the `defend::State` file and rebuilds zone records when it changes.
//! This is the bridge between i1-cli's local state and i1-srv's DNS zones.

use crate::authority::zone_builder::DefenseSnapshot;
use serde::Deserialize;
use std::path::{Path, PathBuf};

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
    })
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
}
