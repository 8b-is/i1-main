//! Intermediate Certificate Authority - ONLINE.
//!
//! Intermediates are signed by the root and do the actual work.
//! They can be revoked without compromising the root.

use chrono::{Duration, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::path::Path;
use uuid::Uuid;

use crate::{CaError, CertificateInfo, CertificateType, IntermediatePurpose, KeyAlgorithm};

/// Intermediate Certificate Authority.
///
/// Lives online, signs end-entity certificates.
/// Can be revoked if compromised without touching root.
pub struct IntermediateCa {
    /// Key pair for signing
    key_pair: KeyPair,
    /// The signed certificate
    certificate: Certificate,
    /// Certificate chain (intermediate + root)
    chain_pem: String,
    /// Private key
    key_pem: String,
    /// Metadata
    pub info: CertificateInfo,
    /// Purpose of this intermediate (for patient zero tracking)
    pub purpose: IntermediatePurpose,
}

impl IntermediateCa {
    /// Create a new intermediate CA signed by the root.
    pub fn generate(
        name: &str,
        root: &crate::RootCa,
        _algorithm: KeyAlgorithm,
    ) -> Result<Self, CaError> {
        Self::generate_with_purpose(name, root, IntermediatePurpose::General)
    }

    /// Create a purpose-specific intermediate CA.
    ///
    /// This is key for patient zero tracking - each user/session/region
    /// gets their own intermediate, so when something goes wrong, you
    /// know exactly where to look.
    pub fn generate_with_purpose(
        name: &str,
        root: &crate::RootCa,
        purpose: IntermediatePurpose,
    ) -> Result<Self, CaError> {
        let key_pair = KeyPair::generate()?;
        let key_pem = key_pair.serialize_pem();

        let mut params = CertificateParams::default();

        // Distinguished Name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        dn.push(DnType::OrganizationName, "i1.is");
        dn.push(DnType::CountryName, "IS");
        params.distinguished_name = dn;

        // Intermediate CA - can sign end-entity only (path length = 0)
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Validity based on purpose
        let validity = purpose.validity();
        let now = Utc::now();
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc()
            + time::Duration::days(validity.days() as i64);

        let serial = Uuid::new_v4();
        params.serial_number = Some((serial.as_u128() as u64).into());

        let certificate = params.signed_by(&key_pair, root.certificate(), root.key_pair())?;
        let cert_pem = certificate.pem();
        let chain_pem = format!("{}\n{}", cert_pem, root.certificate_pem());

        let info = CertificateInfo {
            id: Uuid::new_v4(),
            serial: format!("{:016x}", serial.as_u128() as u64),
            subject: name.to_string(),
            issuer: root.info.subject.clone(),
            not_before: now,
            not_after: now + Duration::days(validity.days() as i64),
            cert_type: CertificateType::Intermediate,
            revoked: false,
            revocation_reason: None,
        };

        Ok(Self {
            key_pair,
            certificate,
            chain_pem,
            key_pem,
            info,
            purpose,
        })
    }

    /// Create a per-user intermediate CA.
    ///
    /// Each user gets their own CA. If their session is compromised,
    /// we revoke just their CA - patient zero identified instantly.
    pub fn for_user(user_id: &str, root: &crate::RootCa) -> Result<Self, CaError> {
        let purpose = IntermediatePurpose::User { user_id: user_id.to_string() };
        let name = purpose.ca_name();
        Self::generate_with_purpose(&name, root, purpose)
    }

    /// Create a per-session intermediate CA.
    ///
    /// Ephemeral CA for a single browsing session. Maximum isolation.
    pub fn for_session(session_id: &str, root: &crate::RootCa) -> Result<Self, CaError> {
        let purpose = IntermediatePurpose::Session { session_id: session_id.to_string() };
        let name = purpose.ca_name();
        Self::generate_with_purpose(&name, root, purpose)
    }

    /// Create a regional intermediate CA.
    pub fn for_region(region: &str, root: &crate::RootCa) -> Result<Self, CaError> {
        let purpose = IntermediatePurpose::Region { region: region.to_string() };
        let name = purpose.ca_name();
        Self::generate_with_purpose(&name, root, purpose)
    }

    /// Create a honeypot-only intermediate CA.
    ///
    /// Used exclusively for honeypot operations. If this CA is
    /// compromised, we know someone's attacking our traps.
    pub fn for_honeypot(root: &crate::RootCa) -> Result<Self, CaError> {
        let purpose = IntermediatePurpose::Honeypot;
        let name = purpose.ca_name();
        Self::generate_with_purpose(&name, root, purpose)
    }

    /// Get the full certificate chain PEM (intermediate + root).
    pub fn chain_pem(&self) -> &str {
        &self.chain_pem
    }

    /// Get the private key PEM.
    pub fn private_key_pem(&self) -> &str {
        &self.key_pem
    }

    /// Save to files.
    pub fn save_to_files(
        &self,
        key_path: impl AsRef<Path>,
        chain_path: impl AsRef<Path>,
    ) -> Result<(), CaError> {
        std::fs::write(key_path, &self.key_pem)?;
        std::fs::write(chain_path, &self.chain_pem)?;
        Ok(())
    }

    /// Sign an end-entity certificate for a domain.
    pub fn sign_domain(&self, domain: &str, validity_days: u32) -> Result<(String, String), CaError> {
        // Generate key for end-entity
        let end_key = KeyPair::generate()?;
        let end_key_pem = end_key.serialize_pem();

        let mut params = CertificateParams::new(vec![domain.to_string()])?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after =
            time::OffsetDateTime::now_utc() + time::Duration::days(validity_days as i64);

        let serial = Uuid::new_v4();
        params.serial_number = Some((serial.as_u128() as u64).into());

        // Sign with intermediate
        let cert = params.signed_by(&end_key, &self.certificate, &self.key_pair)?;
        let cert_pem = cert.pem();

        Ok((cert_pem, end_key_pem))
    }

    /// Sign a wildcard certificate.
    pub fn sign_wildcard(&self, base_domain: &str, validity_days: u32) -> Result<(String, String), CaError> {
        let wildcard = format!("*.{}", base_domain);
        self.sign_domain(&wildcard, validity_days)
    }

    /// Get the certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Get the key pair.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RootCa;

    #[test]
    fn test_generate_intermediate() {
        let root = RootCa::generate("Test Root", KeyAlgorithm::EcdsaP256).unwrap();
        let intermediate =
            IntermediateCa::generate("Test Intermediate", &root, KeyAlgorithm::EcdsaP256).unwrap();

        assert!(intermediate.chain_pem().contains("BEGIN CERTIFICATE"));
        assert_eq!(intermediate.info.issuer, "Test Root");
        assert_eq!(intermediate.info.cert_type, CertificateType::Intermediate);
    }

    #[test]
    fn test_sign_domain() {
        let root = RootCa::generate("Root", KeyAlgorithm::EcdsaP256).unwrap();
        let intermediate =
            IntermediateCa::generate("Intermediate", &root, KeyAlgorithm::EcdsaP256).unwrap();

        let (cert_pem, key_pem) = intermediate.sign_domain("example.com", 1).unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn test_patient_zero_tracking() {
        // Simulate: Root CA in vault, user-specific intermediates online
        let root = RootCa::generate("i1.is Root CA", KeyAlgorithm::EcdsaP256).unwrap();

        // Each user gets their own intermediate
        let alice_ca = IntermediateCa::for_user("alice-123", &root).unwrap();
        let bob_ca = IntermediateCa::for_user("bob-456", &root).unwrap();
        let grandma_ca = IntermediateCa::for_user("grandma-789", &root).unwrap();

        // Grandma clicks a scam link, we issue a cert for the fake site
        let (scam_cert, _) = grandma_ca.sign_domain("microsoft-support.scam", 1).unwrap();

        // Later: We detect the scam cert was used maliciously
        // Patient zero = grandma's CA (we know exactly whose session was involved)
        assert!(matches!(
            grandma_ca.purpose,
            IntermediatePurpose::User { ref user_id } if user_id == "grandma-789"
        ));

        // Revoke grandma's CA, Alice and Bob unaffected
        assert!(scam_cert.contains("BEGIN CERTIFICATE"));
        assert_ne!(alice_ca.info.serial, grandma_ca.info.serial);
        assert_ne!(bob_ca.info.serial, grandma_ca.info.serial);
    }

    #[test]
    fn test_session_intermediate() {
        let root = RootCa::generate("Root", KeyAlgorithm::EcdsaP256).unwrap();
        let session = IntermediateCa::for_session("sess-abc123", &root).unwrap();

        // Session CAs are ephemeral - 1 day validity
        assert!(matches!(session.purpose, IntermediatePurpose::Session { .. }));
        assert!(session.info.subject.contains("Session CA"));
    }

    #[test]
    fn test_honeypot_intermediate() {
        let root = RootCa::generate("Root", KeyAlgorithm::EcdsaP256).unwrap();
        let honeypot = IntermediateCa::for_honeypot(&root).unwrap();

        assert!(matches!(honeypot.purpose, IntermediatePurpose::Honeypot));
        assert!(honeypot.info.subject.contains("Honeypot"));
    }
}
