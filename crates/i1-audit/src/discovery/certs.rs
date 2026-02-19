//! Root certificate store discovery and parsing.

use chrono::{DateTime, TimeZone, Utc};
use std::path::Path;
use tracing::{debug, warn};

use crate::error::{AuditError, Result};
use crate::hash::sha256_bytes;
use crate::types::RootCertInfo;

/// Known root CA store locations across Linux distributions.
const CA_STORE_PATHS: &[&str] = &[
    // Arch / Fedora / RHEL bundle
    "/etc/ssl/certs/ca-certificates.crt",
    // Debian / Ubuntu bundle
    "/etc/ssl/certs/ca-bundle.crt",
    // Individual cert directory (Debian/Ubuntu)
    "/etc/ssl/certs",
    // Fedora / RHEL individual certs
    "/etc/pki/tls/certs",
    // SUSE
    "/etc/ssl/ca-bundle.pem",
    // Alpine
    "/etc/ssl/cert.pem",
    // p11-kit trust anchors
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    // Arch p11-kit
    "/etc/ca-certificates/extracted",
];

/// Discover all root certificates in system trust stores.
///
/// # Errors
///
/// Returns `AuditError` if certificate parsing fails for an entire store.
/// Individual cert parse failures are logged and skipped.
pub async fn discover_root_certs() -> Result<Vec<RootCertInfo>> {
    let mut certs = Vec::new();
    let mut seen_fingerprints = std::collections::HashSet::new();

    for store_path in CA_STORE_PATHS {
        let path = Path::new(store_path);
        if !path.exists() {
            debug!(path = store_path, "CA store path not found, skipping");
            continue;
        }

        if path.is_file() {
            match parse_pem_bundle(path).await {
                Ok(found) => {
                    for cert in found {
                        if seen_fingerprints.insert(cert.fingerprint.clone()) {
                            certs.push(cert);
                        }
                    }
                }
                Err(e) => warn!(path = store_path, error = %e, "failed to parse CA bundle"),
            }
        } else if path.is_dir() {
            match parse_cert_directory(path).await {
                Ok(found) => {
                    for cert in found {
                        if seen_fingerprints.insert(cert.fingerprint.clone()) {
                            certs.push(cert);
                        }
                    }
                }
                Err(e) => warn!(path = store_path, error = %e, "failed to scan cert directory"),
            }
        }
    }

    Ok(certs)
}

/// Parse a PEM bundle file containing multiple certificates.
async fn parse_pem_bundle(path: &Path) -> Result<Vec<RootCertInfo>> {
    let path_str = path.display().to_string();
    let content = tokio::fs::read(path)
        .await
        .map_err(|e| AuditError::io(&path_str, e))?;

    let pems = pem::parse_many(&content).map_err(|e| AuditError::PemDecode {
        path: path_str.clone(),
        reason: e.to_string(),
    })?;

    let mut certs = Vec::new();
    for p in &pems {
        if p.tag() != "CERTIFICATE" {
            continue;
        }
        match parse_x509_der(p.contents(), &path_str) {
            Ok(cert) => certs.push(cert),
            Err(e) => debug!(path = %path_str, error = %e, "skipping cert in bundle"),
        }
    }

    Ok(certs)
}

/// Parse all .pem / .crt files in a directory.
async fn parse_cert_directory(dir: &Path) -> Result<Vec<RootCertInfo>> {
    let mut certs = Vec::new();
    let mut entries = tokio::fs::read_dir(dir)
        .await
        .map_err(|e| AuditError::io(dir.display().to_string(), e))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| AuditError::io(dir.display().to_string(), e))?
    {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "pem" | "crt" | "cer") {
            continue;
        }
        match parse_pem_bundle(&path).await {
            Ok(found) => certs.extend(found),
            Err(e) => debug!(path = %path.display(), error = %e, "skipping cert file"),
        }
    }

    Ok(certs)
}

/// Parse a single DER-encoded X.509 certificate.
fn parse_x509_der(der: &[u8], source_path: &str) -> Result<RootCertInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| {
        AuditError::CertParse {
            path: source_path.to_string(),
            reason: e.to_string(),
        }
    })?;

    let fingerprint = sha256_bytes(der);
    let issuer = cert.issuer().to_string();
    let subject = cert.subject().to_string();
    let serial = cert.raw_serial_as_string();

    let not_before = asn1_to_utc(cert.validity().not_before);
    let not_after = asn1_to_utc(cert.validity().not_after);
    let expired = Utc::now() > not_after;

    Ok(RootCertInfo {
        path: source_path.to_string(),
        fingerprint,
        issuer,
        subject,
        serial,
        not_before,
        not_after,
        expired,
        in_consensus: None,
        trust_score: None,
    })
}

/// Convert an ASN.1 `GeneralizedTime` / `UTCTime` to `DateTime<Utc>`.
fn asn1_to_utc(t: x509_parser::time::ASN1Time) -> DateTime<Utc> {
    let epoch = t.timestamp();
    Utc.timestamp_opt(epoch, 0)
        .single()
        .unwrap_or_else(Utc::now)
}
