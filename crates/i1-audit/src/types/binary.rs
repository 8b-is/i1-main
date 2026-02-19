//! Binary file information types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::trust::TrustScore;

/// Unique file identity on disk (inode + device).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    pub inode: u64,
    pub device_id: u64,
}

/// Complete information about a discovered binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    /// Absolute path on disk
    pub path: String,
    /// SHA-256 hex digest
    pub sha256: String,
    /// File creation time (statx btime, fallback to mtime)
    pub create_date: DateTime<Utc>,
    /// Last modification time
    pub modify_date: DateTime<Utc>,
    /// Inode + device identity
    pub identity: FileIdentity,
    /// File size in bytes
    pub size: u64,
    /// Whether any running process maps to this binary
    pub running: bool,
    /// Names of processes running this binary
    pub process_names: Vec<String>,
    /// Computed trust score (None until scored)
    pub trust_score: Option<TrustScore>,
}
