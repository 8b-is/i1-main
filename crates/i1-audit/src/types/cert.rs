//! Root certificate information types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SHA-256 fingerprint of a certificate's DER encoding.
pub type CertFingerprint = String;

/// Trust assessment for a root certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTrust {
    /// Overall trust 0.0..1.0
    pub score: f64,
    /// How many network nodes report this cert
    pub network_consensus: f64,
    /// Is the cert expired?
    pub validity_ok: bool,
    /// Known issuer in community database
    pub known_issuer: bool,
}

/// Information about a root certificate found in the local trust store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCertInfo {
    /// Path to the file containing this cert
    pub path: String,
    /// SHA-256 fingerprint of DER bytes (hex)
    pub fingerprint: CertFingerprint,
    /// Issuer distinguished name (human-readable)
    pub issuer: String,
    /// Subject distinguished name (human-readable)
    pub subject: String,
    /// Serial number (hex)
    pub serial: String,
    /// Not valid before
    pub not_before: DateTime<Utc>,
    /// Not valid after
    pub not_after: DateTime<Utc>,
    /// Whether the cert is currently expired
    pub expired: bool,
    /// Network consensus: None until queried, Some(true) if found
    pub in_consensus: Option<bool>,
    /// Trust score (None until scored)
    pub trust_score: Option<CertTrust>,
}
