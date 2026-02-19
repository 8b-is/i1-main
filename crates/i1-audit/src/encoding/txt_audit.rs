//! Hybrid key=value + CBOR encoding for DNS TXT records.
//!
//! Small payloads use plain `k=v;k=v` pairs.
//! When the payload exceeds the 255-byte TXT record limit,
//! overflow fields are CBOR-encoded and base64-appended.

use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::error::{AuditError, Result};
use crate::types::BinaryInfo;
use crate::types::RootCertInfo;

/// Maximum length for a single DNS TXT string.
const TXT_MAX: usize = 255;

/// Encode a binary's audit data as a TXT record value.
///
/// Format: `"hash=<full>;name=<basename>;size=<bytes>;trust=<0-100>;nodes=<count>"`
///
/// If the data overflows 255 bytes, extra fields go into CBOR+base64 overflow.
///
/// # Errors
///
/// Returns `AuditError::Encoding` if CBOR serialization fails.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn encode_binary_txt(binary: &BinaryInfo, node_count: u32) -> Result<String> {
    let basename = binary
        .path
        .rsplit('/')
        .next()
        .unwrap_or(&binary.path);

    let trust_pct = binary
        .trust_score
        .as_ref()
        .map_or(0, |s| (s.total * 100.0) as u32);

    let core = format!(
        "hash={};name={};size={};trust={};nodes={}",
        binary.sha256, basename, binary.size, trust_pct, node_count
    );

    if core.len() <= TXT_MAX {
        return Ok(core);
    }

    // Overflow: put full hash in CBOR
    let short_hash = &binary.sha256[..12];
    let kv = format!(
        "h={};name={};size={};trust={};nodes={}",
        short_hash, basename, binary.size, trust_pct, node_count
    );

    let mut cbor_buf = Vec::new();
    ciborium::into_writer(&binary.sha256, &mut cbor_buf)
        .map_err(|e| AuditError::Encoding(e.to_string()))?;
    let overflow = B64.encode(&cbor_buf);

    Ok(format!("{kv};cbor={overflow}"))
}

/// Encode a root cert's audit data as a TXT record value.
#[must_use]
pub fn encode_cert_txt(cert: &RootCertInfo, node_count: u32) -> String {
    // Extract a short issuer name (CN only)
    let short_issuer = extract_cn(&cert.issuer).unwrap_or(&cert.issuer);

    format!(
        "fp={};issuer={};exp={};nodes={}",
        cert.fingerprint,
        short_issuer,
        cert.not_after.format("%Y-%m-%d"),
        node_count
    )
}

/// Extract the CN= value from a distinguished name string.
fn extract_cn(dn: &str) -> Option<&str> {
    for part in dn.split(',') {
        let trimmed = part.trim();
        if let Some(cn) = trimmed.strip_prefix("CN=") {
            return Some(cn.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileIdentity;
    use chrono::Utc;

    #[test]
    fn encode_binary_basic() {
        let bin = BinaryInfo {
            path: "/usr/bin/sshd".into(),
            sha256: "a".repeat(64),
            create_date: Utc::now(),
            modify_date: Utc::now(),
            identity: FileIdentity {
                inode: 1,
                device_id: 1,
            },
            size: 1_047_552,
            running: true,
            process_names: vec!["sshd".into()],
            trust_score: None,
        };

        let txt = encode_binary_txt(&bin, 142).unwrap();
        assert!(txt.contains("name=sshd"));
        assert!(txt.contains("nodes=142"));
        assert!(txt.contains("size=1047552"));
    }

    #[test]
    fn extract_cn_works() {
        assert_eq!(
            extract_cn("CN=DigiCert Global Root G2, O=DigiCert Inc"),
            Some("DigiCert Global Root G2")
        );
        assert_eq!(extract_cn("O=Nope"), None);
    }
}
