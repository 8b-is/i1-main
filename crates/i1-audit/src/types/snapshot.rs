//! Audit snapshot -- point-in-time system state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::BinaryInfo;
use super::cert::RootCertInfo;
use super::process::ProcessInfo;

/// Complete audit snapshot of a system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSnapshot {
    /// Unique node identifier (hostname or machine-id)
    pub node_id: String,
    /// When this snapshot was collected
    pub collected_at: DateTime<Utc>,
    /// System uptime in seconds
    pub system_uptime_secs: u64,
    /// Number of CPU cores
    pub cpu_count: u32,
    /// Discovered binaries with hashes
    pub binaries: Vec<BinaryInfo>,
    /// Running processes
    pub processes: Vec<ProcessInfo>,
    /// Root certificates
    pub root_certs: Vec<RootCertInfo>,
    /// Summary statistics
    pub summary: AuditSummary,
}

/// Summary statistics for a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total binaries discovered
    pub total_binaries: usize,
    /// Total running processes
    pub total_processes: usize,
    /// Total root certificates found
    pub total_root_certs: usize,
    /// Binaries matched to running processes
    pub running_binaries: usize,
    /// Expired root certificates
    pub expired_certs: usize,
    /// Binaries with trust score below threshold
    pub low_trust_binaries: usize,
    /// Certs not found in consensus
    pub unknown_certs: usize,
}

impl AuditSummary {
    /// Build summary from snapshot data.
    #[must_use]
    pub fn from_snapshot(
        binaries: &[BinaryInfo],
        processes: &[ProcessInfo],
        certs: &[RootCertInfo],
        trust_threshold: f64,
    ) -> Self {
        Self {
            total_binaries: binaries.len(),
            total_processes: processes.len(),
            total_root_certs: certs.len(),
            running_binaries: binaries.iter().filter(|b| b.running).count(),
            expired_certs: certs.iter().filter(|c| c.expired).count(),
            low_trust_binaries: binaries
                .iter()
                .filter(|b| {
                    b.trust_score
                        .as_ref()
                        .is_some_and(|s| s.total < trust_threshold)
                })
                .count(),
            unknown_certs: certs.iter().filter(|c| c.in_consensus == Some(false)).count(),
        }
    }
}
