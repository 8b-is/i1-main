//! Hybrid TXT record encoding for IP reputation data.
//!
//! Two encoding modes:
//! - **Simple (k=v)**: Semicolon-separated key=value pairs, human-readable via `dig`.
//!   Example: `"cc=cn;asn=AS1234;org=Evil Corp;ports=22,80;threat=high"`
//!
//! - **CBOR overflow**: When data exceeds ~250 bytes or contains complex structures,
//!   encode as CBOR+Base64 prefixed with `cbor:`.
//!   Example: `"cbor:pWNvcmdk...base64data..."`
//!
//! DNS TXT records can hold up to 255 bytes per string, with multiple strings
//! per record. We use the simple format when possible for debuggability.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Maximum bytes for simple k=v encoding before switching to CBOR.
const SIMPLE_MAX_BYTES: usize = 250;

/// CBOR prefix in TXT records.
const CBOR_PREFIX: &str = "cbor:";

/// Reputation data for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationData {
    /// Country code (ISO 2-letter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<String>,

    /// AS number (e.g., "AS1234").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,

    /// Organization name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,

    /// Open ports (comma-separated in simple format).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<u16>,

    /// Threat level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat: Option<String>,

    /// Attack pattern (e.g., "ssh", "web-scan", "smtp").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,

    /// Number of hits/detections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hits: Option<u32>,

    /// Extra fields for extensibility.
    #[serde(flatten)]
    pub extra: BTreeMap<String, String>,
}

impl ReputationData {
    /// Create an empty reputation record (all fields None/empty).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }
}

/// Encode reputation data into a TXT record string.
///
/// Uses simple k=v format when small enough, CBOR+Base64 for overflow.
pub fn encode(data: &ReputationData) -> crate::Result<String> {
    let simple = encode_simple(data);

    if simple.len() <= SIMPLE_MAX_BYTES {
        Ok(simple)
    } else {
        encode_cbor(data)
    }
}

/// Decode a TXT record string back into reputation data.
pub fn decode(txt: &str) -> crate::Result<ReputationData> {
    txt.strip_prefix(CBOR_PREFIX).map_or_else(
        || Ok(decode_simple(txt)),
        decode_cbor,
    )
}

/// Encode as simple semicolon-separated k=v pairs.
fn encode_simple(data: &ReputationData) -> String {
    let mut parts = Vec::new();

    if let Some(ref cc) = data.cc {
        parts.push(format!("cc={cc}"));
    }
    if let Some(ref asn) = data.asn {
        parts.push(format!("asn={asn}"));
    }
    if let Some(ref org) = data.org {
        parts.push(format!("org={org}"));
    }
    if !data.ports.is_empty() {
        let ports_str: Vec<String> = data.ports.iter().map(ToString::to_string).collect();
        parts.push(format!("ports={}", ports_str.join(",")));
    }
    if let Some(ref threat) = data.threat {
        parts.push(format!("threat={threat}"));
    }
    if let Some(ref pattern) = data.pattern {
        parts.push(format!("pattern={pattern}"));
    }
    if let Some(hits) = data.hits {
        parts.push(format!("hits={hits}"));
    }
    for (k, v) in &data.extra {
        parts.push(format!("{k}={v}"));
    }

    parts.join(";")
}

/// Decode simple k=v format.
fn decode_simple(txt: &str) -> ReputationData {
    let mut data = ReputationData {
        cc: None,
        asn: None,
        org: None,
        ports: Vec::new(),
        threat: None,
        pattern: None,
        hits: None,
        extra: BTreeMap::new(),
    };

    for part in txt.split(';') {
        if let Some((key, value)) = part.split_once('=') {
            match key {
                "cc" => data.cc = Some(value.to_string()),
                "asn" => data.asn = Some(value.to_string()),
                "org" => data.org = Some(value.to_string()),
                "ports" => {
                    data.ports = value.split(',').filter_map(|p| p.parse().ok()).collect();
                }
                "threat" => data.threat = Some(value.to_string()),
                "pattern" => data.pattern = Some(value.to_string()),
                "hits" => data.hits = value.parse().ok(),
                _ => {
                    data.extra.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    data
}

/// Encode as CBOR + Base64.
fn encode_cbor(data: &ReputationData) -> crate::Result<String> {
    use base64::Engine;

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(data, &mut cbor_bytes)
        .map_err(|e| crate::SrvError::Cbor(e.to_string()))?;

    let b64 = base64::engine::general_purpose::STANDARD.encode(&cbor_bytes);
    Ok(format!("{CBOR_PREFIX}{b64}"))
}

/// Decode CBOR + Base64.
fn decode_cbor(b64: &str) -> crate::Result<ReputationData> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| crate::SrvError::Cbor(format!("base64 decode failed: {e}")))?;

    ciborium::from_reader(&bytes[..]).map_err(|e| crate::SrvError::Cbor(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ReputationData {
        ReputationData {
            cc: Some("cn".into()),
            asn: Some("AS1234".into()),
            org: Some("Evil Corp".into()),
            ports: vec![22, 80, 443],
            threat: Some("high".into()),
            pattern: Some("ssh".into()),
            hits: Some(42),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn test_simple_encode_decode() {
        let data = sample_data();
        let encoded = encode_simple(&data);
        assert!(encoded.contains("cc=cn"));
        assert!(encoded.contains("asn=AS1234"));
        assert!(encoded.contains("ports=22,80,443"));
        assert!(encoded.contains("hits=42"));

        let decoded = decode_simple(&encoded);
        assert_eq!(decoded.cc, data.cc);
        assert_eq!(decoded.asn, data.asn);
        assert_eq!(decoded.ports, data.ports);
        assert_eq!(decoded.hits, data.hits);
    }

    #[test]
    fn test_cbor_encode_decode() {
        let data = sample_data();
        let encoded = encode_cbor(&data).unwrap();
        assert!(encoded.starts_with("cbor:"));

        let decoded = decode_cbor(encoded.strip_prefix("cbor:").unwrap()).unwrap();
        assert_eq!(decoded.cc, data.cc);
        assert_eq!(decoded.asn, data.asn);
        assert_eq!(decoded.ports, data.ports);
    }

    #[test]
    fn test_auto_encoding_uses_simple_for_small_data() {
        let data = sample_data();
        let encoded = encode(&data).unwrap();
        // Small data should use simple format (no cbor: prefix).
        assert!(!encoded.starts_with("cbor:"));
    }

    #[test]
    fn test_decode_dispatches_correctly() {
        let simple = "cc=us;threat=low";
        let decoded = decode(simple).unwrap();
        assert_eq!(decoded.cc.as_deref(), Some("us"));
        assert_eq!(decoded.threat.as_deref(), Some("low"));
    }

    #[test]
    fn test_roundtrip_via_cbor() {
        let data = sample_data();
        let encoded = encode_cbor(&data).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.org, data.org);
        assert_eq!(decoded.pattern, data.pattern);
    }
}
