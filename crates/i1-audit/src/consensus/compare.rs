//! Local vs network comparison -- flag anomalies.
//!
//! After consensus queries, compare local state to what the network knows.
//! Unknown binaries or certs that aren't in consensus are flagged.

use crate::types::{BinaryInfo, RootCertInfo};

/// Anomaly detected during comparison.
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// What kind of anomaly
    pub kind: AnomalyKind,
    /// How severe is it
    pub severity: Severity,
    /// Human-readable description
    pub description: String,
}

/// Types of anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Binary hash not found in network consensus
    UnknownBinary,
    /// Binary hash found but with very few nodes
    RareBinary,
    /// Root cert not found in network consensus
    UnknownCert,
    /// Root cert that is expired
    ExpiredCert,
    /// Binary in non-standard location that is running
    SuspiciousLocation,
}

/// Severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Compare local binaries against consensus data.
///
/// Returns anomalies for binaries that the network doesn't know about
/// or that have suspiciously few reports.
#[must_use]
pub fn compare_binaries(binaries: &[BinaryInfo], _min_node_threshold: u32) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    for bin in binaries {
        let score = bin.trust_score.as_ref();

        // Check consensus
        if let Some(s) = score {
            if s.hash_consensus < 0.01 {
                let severity = if bin.running {
                    Severity::High
                } else {
                    Severity::Medium
                };
                anomalies.push(Anomaly {
                    kind: AnomalyKind::UnknownBinary,
                    severity,
                    description: format!(
                        "Binary not in consensus: {} (running={})",
                        bin.path, bin.running
                    ),
                });
            } else if s.hash_consensus < 0.3 {
                anomalies.push(Anomaly {
                    kind: AnomalyKind::RareBinary,
                    severity: Severity::Low,
                    description: format!(
                        "Binary rarely seen in consensus: {} (consensus={:.0}%)",
                        bin.path,
                        s.hash_consensus * 100.0
                    ),
                });
            }
        }

        // Check suspicious location
        let in_system_path = bin.path.starts_with("/usr/")
            || bin.path.starts_with("/bin")
            || bin.path.starts_with("/sbin");
        if !in_system_path && bin.running {
            anomalies.push(Anomaly {
                kind: AnomalyKind::SuspiciousLocation,
                severity: Severity::Medium,
                description: format!("Running binary outside system paths: {}", bin.path),
            });
        }
    }

    anomalies
}

/// Compare local root certs against consensus data.
#[must_use]
pub fn compare_certs(certs: &[RootCertInfo]) -> Vec<Anomaly> {
    let mut anomalies = Vec::new();

    for cert in certs {
        if cert.expired {
            anomalies.push(Anomaly {
                kind: AnomalyKind::ExpiredCert,
                severity: Severity::Medium,
                description: format!(
                    "Expired root cert: {} (expired {})",
                    cert.subject,
                    cert.not_after.format("%Y-%m-%d")
                ),
            });
        }

        if cert.in_consensus == Some(false) {
            anomalies.push(Anomaly {
                kind: AnomalyKind::UnknownCert,
                severity: Severity::Critical,
                description: format!(
                    "Root cert NOT in network consensus: {} (issuer={})",
                    cert.subject, cert.issuer
                ),
            });
        }
    }

    anomalies
}
