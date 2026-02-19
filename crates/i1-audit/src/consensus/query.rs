//! DNS consensus queries against bin.i1.is / ca.i1.is.
//!
//! Phase 3 implementation -- queries the network to see how many
//! other nodes report the same binary hash or cert fingerprint.

use hickory_resolver::TokioResolver;
use tracing::debug;

use crate::encoding::{binary_dns_name, cert_dns_name};
use crate::error::{AuditError, Result};

/// Result of a consensus query for a single hash/fingerprint.
#[derive(Debug, Clone)]
pub struct ConsensusResult {
    /// The hash or fingerprint queried
    pub hash: String,
    /// Whether a TXT record was found
    pub found: bool,
    /// Number of nodes that report this hash (parsed from TXT `nodes=` field)
    pub node_count: u32,
    /// Trust percentage from the network (parsed from TXT `trust=` field)
    pub network_trust: Option<u32>,
}

/// Query the network for a binary hash consensus.
///
/// # Errors
///
/// Returns `AuditError::DnsQuery` if the DNS query fails unexpectedly.
pub async fn query_binary_consensus(
    resolver: &TokioResolver,
    sha256: &str,
) -> Result<ConsensusResult> {
    let name = binary_dns_name(sha256);
    query_txt_record(resolver, &name, sha256).await
}

/// Query the network for a certificate fingerprint consensus.
///
/// # Errors
///
/// Returns `AuditError::DnsQuery` if the DNS query fails unexpectedly.
pub async fn query_cert_consensus(
    resolver: &TokioResolver,
    fingerprint: &str,
) -> Result<ConsensusResult> {
    let name = cert_dns_name(fingerprint);
    query_txt_record(resolver, &name, fingerprint).await
}

/// Generic TXT record query and parse.
async fn query_txt_record(
    resolver: &TokioResolver,
    dns_name: &str,
    hash: &str,
) -> Result<ConsensusResult> {
    debug!(name = dns_name, "querying DNS consensus");

    let lookup = resolver.txt_lookup(dns_name).await;

    match lookup {
        Ok(records) => Ok(records.iter().next().map_or_else(
            || ConsensusResult {
                hash: hash.to_string(),
                found: false,
                node_count: 0,
                network_trust: None,
            },
            |record| {
                let txt = record.to_string();
                let node_count = parse_field(&txt, "nodes").unwrap_or(0);
                let network_trust = parse_field(&txt, "trust");
                ConsensusResult {
                    hash: hash.to_string(),
                    found: true,
                    node_count,
                    network_trust,
                }
            },
        )),
        Err(e) => {
            // NXDOMAIN or SERVFAIL -- hash not in network
            debug!(name = dns_name, error = %e, "no consensus record found");
            Ok(ConsensusResult {
                hash: hash.to_string(),
                found: false,
                node_count: 0,
                network_trust: None,
            })
        }
    }
}

/// Parse a `key=value` field from a semicolon-delimited TXT record.
fn parse_field(txt: &str, key: &str) -> Option<u32> {
    let prefix = format!("{key}=");
    for part in txt.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix(&prefix) {
            return val.parse().ok();
        }
    }
    None
}

/// Create a resolver configured for i1.is lookups.
///
/// Uses system resolver by default. In production, could be configured
/// to use specific nameservers for the i1.is zone.
///
/// # Errors
///
/// Returns `AuditError::DnsQuery` if the system resolver cannot be created.
pub fn create_resolver() -> Result<TokioResolver> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| AuditError::DnsQuery(format!("failed to create resolver: {e}")))?
        .build();
    Ok(resolver)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_from_txt() {
        let txt = "hash=abc;name=sshd;size=1024;trust=87;nodes=142";
        assert_eq!(parse_field(txt, "nodes"), Some(142));
        assert_eq!(parse_field(txt, "trust"), Some(87));
        assert_eq!(parse_field(txt, "size"), Some(1024));
        assert_eq!(parse_field(txt, "missing"), None);
    }
}
