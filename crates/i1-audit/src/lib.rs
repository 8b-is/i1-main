//! # i1-audit
//!
//! Zero-trust binary & certificate audit system.
//!
//! Don't trust authority, trust evidence. A binary's reputation is earned
//! through observable behavior across many machines. A root cert's legitimacy
//! is validated by network consensus, not by the fact that it exists in your
//! local trust store.
//!
//! ## Multi-Factor Trust Scoring
//!
//! - **Hash** (SHA-256) -- is this binary known?
//! - **Create date** -- when did it appear on disk?
//! - **Unique ID** (inode + device) -- has the file been replaced?
//! - **Process name** -- does it match expectations?
//! - **Usage metric** -- `(uptime / system_uptime) * (avg_cpu / max_cpu)`
//! - **Consensus** -- how many other nodes report the same hash?
//!
//! ## Data Flow
//!
//! ```text
//! Phase 1: Local Collection (no network)
//!   discover_binaries() + discover_processes() + discover_root_certs()
//!   -> correlate_processes() -> sha256_file() each
//!   -> AuditSnapshot
//!
//! Phase 2: Local Trust Scoring (no network)
//!   score_binary() with age, identity, usage, provenance factors
//!   -> AuditSnapshot with partial scores (consensus=0.0)
//!
//! Phase 3: Network Consensus (requires i1-srv)
//!   query bin.i1.is / ca.i1.is for each hash
//!   -> fill in hash_consensus + network_consensus factors
//!
//! Phase 4: Publish (optional --publish)
//!   AuditSnapshot -> DNS records at bin.i1.is + ca.i1.is
//! ```

pub mod consensus;
pub mod discovery;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod qr;
pub mod scoring;
pub mod types;
pub mod verify;

pub use error::{AuditError, Result};
pub use types::*;

use chrono::Utc;

/// Collect a full audit snapshot of the local system.
///
/// Runs Phases 1 & 2: local discovery + local trust scoring.
/// Network consensus (Phase 3) is not included -- call consensus
/// queries separately.
///
/// # Errors
///
/// Returns `AuditError` if process discovery or binary discovery fails.
pub async fn collect_snapshot(
    bin_paths: &[&str],
    weights: &TrustWeights,
) -> Result<AuditSnapshot> {
    // Phase 1: Discover
    let processes = discovery::discover_processes()?;
    let mut binaries = discovery::discover_binaries(bin_paths).await?;
    let mut root_certs = discovery::discover_root_certs().await?;

    // Correlate binaries with running processes
    discovery::correlate_processes(&mut binaries, &processes);

    // Phase 2: Score
    for bin in &mut binaries {
        bin.trust_score = Some(scoring::score_binary(bin, weights));
    }
    for cert in &mut root_certs {
        cert.trust_score = Some(scoring::score_cert(cert));
    }

    // Build snapshot
    let system_uptime = discovery::get_system_uptime().unwrap_or(0);
    let cpu_count = discovery::get_cpu_count();

    let node_id = get_node_id();
    let summary = AuditSummary::from_snapshot(&binaries, &processes, &root_certs, 0.5);

    Ok(AuditSnapshot {
        node_id,
        collected_at: Utc::now(),
        system_uptime_secs: system_uptime,
        cpu_count,
        binaries,
        processes,
        root_certs,
        summary,
    })
}

/// Get a stable node identifier.
///
/// Tries `/etc/machine-id` first, then hostname.
fn get_node_id() -> String {
    // Try machine-id
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let trimmed = id.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    // Fallback: hostname
    hostname::get().map_or_else(
        |_| "unknown".to_string(),
        |h| h.to_string_lossy().into_owned(),
    )
}
