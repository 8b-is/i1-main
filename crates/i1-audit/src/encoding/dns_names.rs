//! DNS name encoding for hash-prefix lookups.
//!
//! Binary hashes are published as DNS TXT records under `bin.i1.is.`
//! and certificate fingerprints under `ca.i1.is.`.
//!
//! DNS label = first 12 hex chars of SHA-256 (48 bits).
//! Full hash is stored inside the TXT record value.

/// Zone suffix for binary hash lookups.
pub const BIN_ZONE: &str = "bin.i1.is.";

/// Zone suffix for certificate fingerprint lookups.
pub const CA_ZONE: &str = "ca.i1.is.";

/// Length of the hash prefix used as DNS label (hex chars).
const HASH_PREFIX_LEN: usize = 12;

/// Build a DNS query name for a binary hash.
///
/// Example: `sha256 = "a3f2b8c91d4e..."` -> `"a3f2b8c91d4e.bin.i1.is."`
#[must_use]
pub fn binary_dns_name(sha256: &str) -> String {
    let prefix = &sha256[..HASH_PREFIX_LEN.min(sha256.len())];
    format!("{prefix}.{BIN_ZONE}")
}

/// Build a DNS query name for a certificate fingerprint.
///
/// Example: `fingerprint = "d4e5f6a7b8c9..."` -> `"d4e5f6a7b8c9.ca.i1.is."`
#[must_use]
pub fn cert_dns_name(fingerprint: &str) -> String {
    let prefix = &fingerprint[..HASH_PREFIX_LEN.min(fingerprint.len())];
    format!("{prefix}.{CA_ZONE}")
}

/// Extract the hash prefix from a DNS name.
#[must_use]
pub fn extract_prefix(dns_name: &str) -> Option<&str> {
    dns_name.split('.').next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_name_format() {
        let name = binary_dns_name("a3f2b8c91d4e567890abcdef");
        assert_eq!(name, "a3f2b8c91d4e.bin.i1.is.");
    }

    #[test]
    fn cert_name_format() {
        let name = cert_dns_name("d4e5f6a7b8c9012345abcdef");
        assert_eq!(name, "d4e5f6a7b8c9.ca.i1.is.");
    }

    #[test]
    fn extract_prefix_works() {
        assert_eq!(
            extract_prefix("a3f2b8c91d4e.bin.i1.is."),
            Some("a3f2b8c91d4e")
        );
    }
}
