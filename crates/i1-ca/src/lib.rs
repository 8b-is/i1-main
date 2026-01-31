//! # i1-ca
//!
//! Certificate Authority infrastructure for i1.is.
//!
//! ## Architecture
//!
//! ```text
//! AIR-GAPPED ROOT (offline, secure vault)
//!        │
//!        ├── Intermediate CA #1 "condom" (online, signs proxy certs)
//!        ├── Intermediate CA #2 "backup" (cold standby)
//!        └── Intermediate CA #3 "regional" (future geo distribution)
//! ```
//!
//! ## Security Model
//!
//! - Root CA private key NEVER touches the internet
//! - Root only signs intermediate CAs (rare ceremony)
//! - Intermediates can be revoked without touching root
//! - End-entity certs are short-lived (hours/days)
//!
//! ## Example
//!
//! ```rust,ignore
//! use i1_ca::{RootCa, IntermediateCa, CertificateRequest};
//!
//! // On air-gapped machine: generate root (ONCE)
//! let root = RootCa::generate("i1.is Root CA")?;
//! root.save_to_file("root.key", "root.crt")?;
//!
//! // Sign an intermediate (air-gapped ceremony)
//! let intermediate_csr = IntermediateCa::create_csr("i1.is Condom CA")?;
//! let intermediate_cert = root.sign_intermediate(&intermediate_csr)?;
//!
//! // Online: intermediate signs end-entity certs
//! let proxy_cert = intermediate.sign_end_entity("*.example.com")?;
//! ```

mod error;
mod root;
mod intermediate;
mod end_entity;
mod revocation;

pub use error::CaError;
pub use root::RootCa;
pub use intermediate::IntermediateCa;
pub use end_entity::{EndEntityCert, CertificateRequest};
pub use revocation::{RevocationList, RevocationReason};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Certificate metadata for tracking and auditing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Unique identifier
    pub id: Uuid,
    /// Serial number (hex)
    pub serial: String,
    /// Subject common name
    pub subject: String,
    /// Issuer common name
    pub issuer: String,
    /// Not valid before
    pub not_before: DateTime<Utc>,
    /// Not valid after
    pub not_after: DateTime<Utc>,
    /// Certificate type
    pub cert_type: CertificateType,
    /// Is this certificate revoked?
    pub revoked: bool,
    /// Revocation reason (if revoked)
    pub revocation_reason: Option<RevocationReason>,
}

/// Type of certificate in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateType {
    /// Root CA - air-gapped, signs only intermediates
    Root,
    /// Intermediate CA - online, signs end-entity certs
    Intermediate,
    /// End-entity - actual TLS certs for domains
    EndEntity,
}

/// Key algorithm choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum KeyAlgorithm {
    /// ECDSA with P-256 curve (recommended for speed)
    #[default]
    EcdsaP256,
    /// ECDSA with P-384 curve (higher security)
    EcdsaP384,
    /// RSA 2048-bit (legacy compatibility)
    Rsa2048,
    /// RSA 4096-bit (higher security, slower)
    Rsa4096,
}


/// Validity period presets.
#[derive(Debug, Clone, Copy)]
pub enum ValidityPeriod {
    /// Root CA: 20 years
    Root,
    /// Intermediate CA: 5 years (general purpose)
    Intermediate,
    /// User intermediate: 30 days (per-user monthly rotation)
    UserIntermediate,
    /// Session intermediate: 24 hours (ephemeral)
    SessionIntermediate,
    /// End-entity: configurable days
    EndEntity(u32),
    /// Custom duration in days
    Custom(u32),
}

impl ValidityPeriod {
    /// Get the number of days for this validity period.
    pub fn days(&self) -> u32 {
        match self {
            ValidityPeriod::Root => 20 * 365,           // 20 years
            ValidityPeriod::Intermediate => 5 * 365,    // 5 years
            ValidityPeriod::UserIntermediate => 30,     // 30 days
            ValidityPeriod::SessionIntermediate => 1,   // 24 hours
            ValidityPeriod::EndEntity(d) => *d,
            ValidityPeriod::Custom(d) => *d,
        }
    }
}

/// Intermediate CA purpose - helps track patient zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntermediatePurpose {
    /// General purpose intermediate
    General,
    /// Per-user intermediate (user_id)
    User { user_id: String },
    /// Per-session intermediate (session_id)
    Session { session_id: String },
    /// Regional intermediate
    Region { region: String },
    /// Honeypot operations only
    Honeypot,
    /// Testing/development
    Testing,
}

impl IntermediatePurpose {
    /// Generate a descriptive name for this intermediate.
    pub fn ca_name(&self) -> String {
        match self {
            IntermediatePurpose::General => "i1.is General CA".to_string(),
            IntermediatePurpose::User { user_id } => format!("i1.is User CA [{}]", user_id),
            IntermediatePurpose::Session { session_id } => format!("i1.is Session CA [{}]", &session_id[..8.min(session_id.len())]),
            IntermediatePurpose::Region { region } => format!("i1.is {} CA", region),
            IntermediatePurpose::Honeypot => "i1.is Honeypot CA".to_string(),
            IntermediatePurpose::Testing => "i1.is Testing CA".to_string(),
        }
    }

    /// Get recommended validity for this purpose.
    pub fn validity(&self) -> ValidityPeriod {
        match self {
            IntermediatePurpose::General => ValidityPeriod::Intermediate,
            IntermediatePurpose::User { .. } => ValidityPeriod::UserIntermediate,
            IntermediatePurpose::Session { .. } => ValidityPeriod::SessionIntermediate,
            IntermediatePurpose::Region { .. } => ValidityPeriod::Intermediate,
            IntermediatePurpose::Honeypot => ValidityPeriod::Custom(90), // 90 days
            IntermediatePurpose::Testing => ValidityPeriod::Custom(7),   // 1 week
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validity_periods() {
        assert_eq!(ValidityPeriod::Root.days(), 7300);
        assert_eq!(ValidityPeriod::Intermediate.days(), 1825);
        assert_eq!(ValidityPeriod::EndEntity(1).days(), 1);
    }
}
