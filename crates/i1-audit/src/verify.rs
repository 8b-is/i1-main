//! Trust digest and TTL verification.
//!
//! A trust digest is a compact SHA-256 of the system's audit state:
//! binary hashes, cert fingerprints, and node identity. Published to
//! `sig.i1.is` with a known TTL.
//!
//! ## How TTL verification works
//!
//! 1. Node publishes: `<node-prefix>.sig.i1.is. 60 TXT "digest=<hash>;ts=<epoch>"`
//! 2. `i1 audit verify` generates a QR code containing a verification URL
//! 3. Phone scans QR over cell network (independent trust path)
//! 4. Phone resolves the DNS name → compares value + TTL
//!
//! If the TTL is wildly different from expected, someone is caching or
//! replaying the record. If the value differs, the record was tampered.
//! The phone's cell network provides a trust path independent of your
//! local network.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::hash::sha256_bytes;
use crate::types::AuditSnapshot;

/// Expected TTL for signal records (seconds).
/// Kept low so stale cache is detectable.
pub const SIGNAL_TTL: u32 = 60;

/// Maximum acceptable TTL drift (seconds).
/// If the observed TTL differs by more than this, flag it.
pub const MAX_TTL_DRIFT: u32 = 10;

/// A verification token: everything needed to check system integrity
/// from an independent network path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyToken {
    /// DNS name to query (e.g., `a3f2b8c91d4e.sig.i1.is.`)
    pub dns_name: String,
    /// Expected TXT record value
    pub expected_value: String,
    /// Expected TTL (seconds)
    pub expected_ttl: u32,
    /// When this token was generated (epoch seconds)
    pub generated_at: i64,
    /// Node ID prefix (first 12 chars of node hash)
    pub node_prefix: String,
    /// Full trust digest hash
    pub digest: String,
}

impl VerifyToken {
    /// Build a verification URL for i1.is.
    ///
    /// When scanned, the phone opens this URL. The server resolves
    /// the DNS from its perspective and shows the comparison.
    #[must_use]
    pub fn verification_url(&self) -> String {
        format!(
            "https://i1.is/verify?n={}&d={}&ttl={}&ts={}",
            self.node_prefix, self.digest, self.expected_ttl, self.generated_at
        )
    }

    /// Build the DNS name for this token's signal record.
    #[must_use]
    pub fn signal_dns_name(node_prefix: &str) -> String {
        format!("{node_prefix}.sig.i1.is.")
    }
}

/// Compute a trust digest from an audit snapshot.
///
/// The digest is SHA-256 of: `node_id || binary_count || binary_hashes || cert_count || cert_fingerprints`
///
/// This creates a compact fingerprint of your system state that can be
/// published to DNS and verified from any network path.
#[must_use]
pub fn compute_trust_digest(snapshot: &AuditSnapshot) -> String {
    let mut material = Vec::new();

    // Node identity
    material.extend_from_slice(snapshot.node_id.as_bytes());
    material.extend_from_slice(b"|");

    // Binary hashes (sorted for determinism)
    let mut bin_hashes: Vec<&str> = snapshot.binaries.iter().map(|b| b.sha256.as_str()).collect();
    bin_hashes.sort_unstable();
    material.extend_from_slice(bin_hashes.len().to_string().as_bytes());
    material.extend_from_slice(b"|");
    for h in &bin_hashes {
        material.extend_from_slice(h.as_bytes());
    }
    material.extend_from_slice(b"|");

    // Cert fingerprints (sorted)
    let mut cert_fps: Vec<&str> = snapshot
        .root_certs
        .iter()
        .map(|c| c.fingerprint.as_str())
        .collect();
    cert_fps.sort_unstable();
    material.extend_from_slice(cert_fps.len().to_string().as_bytes());
    material.extend_from_slice(b"|");
    for fp in &cert_fps {
        material.extend_from_slice(fp.as_bytes());
    }

    sha256_bytes(&material)
}

/// Build the TXT record value for a signal record.
///
/// Format: `digest=<hash>;ts=<epoch>;bins=<count>;certs=<count>`
#[must_use]
pub fn build_signal_txt(snapshot: &AuditSnapshot, digest: &str) -> String {
    format!(
        "digest={};ts={};bins={};certs={}",
        digest,
        Utc::now().timestamp(),
        snapshot.binaries.len(),
        snapshot.root_certs.len()
    )
}

/// Generate a complete verification token from a snapshot.
#[must_use]
pub fn generate_verify_token(snapshot: &AuditSnapshot) -> VerifyToken {
    let digest = compute_trust_digest(snapshot);
    let node_prefix = &digest[..12];
    let dns_name = VerifyToken::signal_dns_name(node_prefix);
    let expected_value = build_signal_txt(snapshot, &digest);
    let now = Utc::now().timestamp();

    VerifyToken {
        dns_name,
        expected_value,
        expected_ttl: SIGNAL_TTL,
        generated_at: now,
        node_prefix: node_prefix.to_string(),
        digest,
    }
}

/// Result of a TTL verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Did the TXT value match?
    pub value_match: bool,
    /// Expected TXT value
    pub expected_value: String,
    /// Observed TXT value (None if NXDOMAIN)
    pub observed_value: Option<String>,
    /// Expected TTL
    pub expected_ttl: u32,
    /// Observed TTL (None if NXDOMAIN)
    pub observed_ttl: Option<u32>,
    /// TTL drift (absolute difference)
    pub ttl_drift: Option<u32>,
    /// Is the TTL drift within acceptable range?
    pub ttl_ok: bool,
    /// Overall verdict
    pub verdict: Verdict,
}

/// Verification verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Everything checks out
    Ok,
    /// Record not found (not yet published, or stripped)
    NotPublished,
    /// Value mismatch -- record was tampered
    Tampered,
    /// TTL drift too high -- possible cache poisoning or replay
    StaleCache,
    /// Both value and TTL are wrong
    Compromised,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "OK"),
            Self::NotPublished => write!(f, "NOT PUBLISHED"),
            Self::Tampered => write!(f, "TAMPERED"),
            Self::StaleCache => write!(f, "STALE CACHE"),
            Self::Compromised => write!(f, "COMPROMISED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuditSnapshot, AuditSummary};

    fn make_snapshot() -> AuditSnapshot {
        AuditSnapshot {
            node_id: "test-node-123".into(),
            collected_at: Utc::now(),
            system_uptime_secs: 86400,
            cpu_count: 4,
            binaries: vec![],
            processes: vec![],
            root_certs: vec![],
            summary: AuditSummary {
                total_binaries: 0,
                total_processes: 0,
                total_root_certs: 0,
                running_binaries: 0,
                expired_certs: 0,
                low_trust_binaries: 0,
                unknown_certs: 0,
            },
        }
    }

    #[test]
    fn digest_is_deterministic() {
        let snap = make_snapshot();
        let d1 = compute_trust_digest(&snap);
        let d2 = compute_trust_digest(&snap);
        assert_eq!(d1, d2);
    }

    #[test]
    fn digest_is_64_hex_chars() {
        let snap = make_snapshot();
        let digest = compute_trust_digest(&snap);
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_token_has_valid_url() {
        let snap = make_snapshot();
        let token = generate_verify_token(&snap);
        let url = token.verification_url();
        assert!(url.starts_with("https://i1.is/verify?"));
        assert!(url.contains(&token.node_prefix));
    }

    #[test]
    fn signal_txt_format() {
        let snap = make_snapshot();
        let digest = compute_trust_digest(&snap);
        let txt = build_signal_txt(&snap, &digest);
        assert!(txt.starts_with("digest="));
        assert!(txt.contains(";ts="));
        assert!(txt.contains(";bins=0"));
        assert!(txt.contains(";certs=0"));
    }
}
