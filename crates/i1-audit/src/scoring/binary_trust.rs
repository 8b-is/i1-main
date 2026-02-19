//! Multi-factor trust scoring for binaries.

use chrono::Utc;
use std::process::Command;

use crate::types::{BinaryInfo, TrustScore, TrustWeights};

/// Score a binary's trustworthiness using local factors.
///
/// Network consensus factor (`hash_consensus`) is left at 0.0 until
/// Phase 3 (consensus queries) fills it in.
#[must_use]
pub fn score_binary(binary: &BinaryInfo, weights: &TrustWeights) -> TrustScore {
    let age_factor = compute_age_factor(binary);
    let identity_stability = compute_identity_stability(binary);
    let usage_normality = compute_usage_normality(binary);
    let provenance_score = compute_provenance(binary);

    // Consensus is 0.0 until network queries fill it in
    let hash_consensus = 0.0;

    TrustScore::compute(
        hash_consensus,
        age_factor,
        identity_stability,
        usage_normality,
        provenance_score,
        weights,
    )
}

/// Age factor: sigmoid curve.
///
/// - 0 days -> 0.0
/// - 30 days -> ~0.5
/// - 365 days -> ~0.97
///
/// Intuition: a binary that's been around a long time is less likely
/// to be recently planted malware.
#[allow(clippy::cast_precision_loss)]
fn compute_age_factor(binary: &BinaryInfo) -> f64 {
    let age_days = (Utc::now() - binary.create_date).num_days().max(0) as f64;
    // Sigmoid: 1 / (1 + e^(-k*(x - midpoint)))
    // midpoint = 30 days, k = 0.05
    let k = 0.05;
    let midpoint = 30.0;
    1.0 / (1.0 + (-k * (age_days - midpoint)).exp())
}

/// Identity stability: 1.0 if the inode/device look normal.
///
/// For now this is always 1.0 (we'd need historical snapshots to detect
/// inode changes). A replaced binary would get a new inode on most
/// filesystems, which future diff logic will catch.
const fn compute_identity_stability(_binary: &BinaryInfo) -> f64 {
    // TODO: compare with previous snapshot to detect inode changes
    1.0
}

/// Usage normality: how normal is this binary's behavior?
///
/// Running binaries that are in standard paths get a boost.
/// Non-running binaries in system paths are also normal.
fn compute_usage_normality(binary: &BinaryInfo) -> f64 {
    let in_system_path = binary.path.starts_with("/usr/")
        || binary.path.starts_with("/bin")
        || binary.path.starts_with("/sbin");

    if in_system_path {
        // System binaries are expected; running or not is fine
        if binary.running { 1.0 } else { 0.8 }
    } else if binary.running {
        // Running but not in system path -- worth investigating
        0.4
    } else {
        0.5
    }
}

/// Check if the binary is managed by a package manager.
///
/// Checks dpkg, rpm, and pacman.
fn compute_provenance(binary: &BinaryInfo) -> f64 {
    // Try pacman (Arch)
    if is_pacman_owned(&binary.path) {
        return 1.0;
    }
    // Try dpkg (Debian/Ubuntu)
    if is_dpkg_owned(&binary.path) {
        return 1.0;
    }
    // Try rpm (Fedora/RHEL)
    if is_rpm_owned(&binary.path) {
        return 1.0;
    }

    // Not found in any package manager
    0.0
}

/// Check if pacman owns this file.
fn is_pacman_owned(path: &str) -> bool {
    Command::new("pacman")
        .args(["-Qo", path])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Check if dpkg owns this file.
fn is_dpkg_owned(path: &str) -> bool {
    Command::new("dpkg")
        .args(["-S", path])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Check if rpm owns this file.
fn is_rpm_owned(path: &str) -> bool {
    Command::new("rpm")
        .args(["-qf", path])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileIdentity;
    use chrono::Duration;

    fn make_binary(age_days: i64, running: bool, path: &str) -> BinaryInfo {
        BinaryInfo {
            path: path.to_string(),
            sha256: "deadbeef".into(),
            create_date: Utc::now() - Duration::days(age_days),
            modify_date: Utc::now() - Duration::days(age_days),
            identity: FileIdentity {
                inode: 1234,
                device_id: 5678,
            },
            size: 1024,
            running,
            process_names: Vec::new(),
            trust_score: None,
        }
    }

    #[test]
    fn age_factor_sigmoid() {
        let young = make_binary(0, false, "/usr/bin/test");
        let middle = make_binary(30, false, "/usr/bin/test");
        let old = make_binary(365, false, "/usr/bin/test");

        let f_young = compute_age_factor(&young);
        let f_middle = compute_age_factor(&middle);
        let f_old = compute_age_factor(&old);

        assert!(f_young < 0.3, "young binary should have low age factor");
        assert!(
            (f_middle - 0.5).abs() < 0.1,
            "30-day binary should be near 0.5"
        );
        assert!(f_old > 0.9, "old binary should have high age factor");
    }

    #[test]
    fn usage_normality_system_path() {
        let running = make_binary(30, true, "/usr/bin/sshd");
        let not_running = make_binary(30, false, "/usr/bin/sshd");
        let outside = make_binary(30, true, "/tmp/sketchy");

        assert!(compute_usage_normality(&running) > compute_usage_normality(&outside));
        assert!(compute_usage_normality(&not_running) > compute_usage_normality(&outside));
    }
}
