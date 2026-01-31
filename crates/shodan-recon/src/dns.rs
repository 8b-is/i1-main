//! DNS resolution integration.

use crate::error::{ReconError, ReconResult};
use std::net::IpAddr;
use std::time::Duration;

/// DNS lookup result
#[derive(Debug, Clone)]
pub struct DnsLookupResult {
    /// Query that was performed
    pub query: String,
    /// IP addresses found (for A/AAAA lookups)
    pub addresses: Vec<IpAddr>,
    /// Hostnames found (for PTR lookups)
    pub hostnames: Vec<String>,
    /// Response time
    pub response_time: Duration,
}

/// DNS resolver
pub struct DnsResolver {
    _private: (),
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    /// Create a resolver using default configuration
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Resolve hostname to IP addresses using system DNS
    pub async fn lookup(&self, hostname: &str) -> ReconResult<Vec<IpAddr>> {
        use tokio::net::lookup_host;

        let start = std::time::Instant::now();

        // Use port 0 for lookup
        let addr_str = format!("{hostname}:0");
        let addrs = lookup_host(&addr_str)
            .await
            .map_err(|e| ReconError::Dns(e.to_string()))?;

        Ok(addrs.map(|a| a.ip()).collect())
    }

    /// Reverse DNS lookup (IP to hostnames)
    ///
    /// Note: This uses the system resolver and may not work for all IPs.
    pub async fn reverse(&self, ip: IpAddr) -> ReconResult<DnsLookupResult> {
        let start = std::time::Instant::now();

        // Use hickory for reverse lookups
        use hickory_resolver::{config::*, TokioAsyncResolver};

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let response = resolver
            .reverse_lookup(ip)
            .await
            .map_err(|e| ReconError::Dns(e.to_string()))?;

        let hostnames: Vec<String> = response.iter().map(|n| n.to_string()).collect();

        Ok(DnsLookupResult {
            query: ip.to_string(),
            addresses: vec![ip],
            hostnames,
            response_time: start.elapsed(),
        })
    }

    /// Lookup MX records for a domain
    pub async fn lookup_mx(&self, domain: &str) -> ReconResult<Vec<String>> {
        use hickory_resolver::{config::*, TokioAsyncResolver};

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let response = resolver
            .mx_lookup(domain)
            .await
            .map_err(|e| ReconError::Dns(e.to_string()))?;

        Ok(response.iter().map(|mx| mx.exchange().to_string()).collect())
    }

    /// Lookup TXT records for a domain
    pub async fn lookup_txt(&self, domain: &str) -> ReconResult<Vec<String>> {
        use hickory_resolver::{config::*, TokioAsyncResolver};

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let response = resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| ReconError::Dns(e.to_string()))?;

        Ok(response
            .iter()
            .map(|txt| {
                txt.iter()
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect())
    }

    /// Lookup NS records for a domain
    pub async fn lookup_ns(&self, domain: &str) -> ReconResult<Vec<String>> {
        use hickory_resolver::{config::*, TokioAsyncResolver};

        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let response = resolver
            .ns_lookup(domain)
            .await
            .map_err(|e| ReconError::Dns(e.to_string()))?;

        Ok(response.iter().map(|ns| ns.to_string()).collect())
    }
}
