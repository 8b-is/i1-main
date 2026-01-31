//! Host enrichment by combining data from multiple sources.

use i1_core::HostInfo;
use std::net::IpAddr;

/// Combined intelligence from all configured sources
#[derive(Debug, Clone, Default)]
pub struct EnrichedHost {
    /// Data from provider lookup
    pub host_info: Option<HostInfo>,

    /// Port scan results
    #[cfg(feature = "scanner")]
    pub scan: Option<crate::scanner::ScanResult>,

    /// WHOIS information
    #[cfg(feature = "whois")]
    pub whois: Option<crate::whois::WhoisInfo>,
}

/// Builder for host enrichment with multiple data sources
#[derive(Default)]
pub struct HostEnricher {
    #[cfg(feature = "scanner")]
    scanner: Option<crate::scanner::Scanner>,

    #[cfg(feature = "whois")]
    whois_client: Option<crate::whois::WhoisClient>,
}

impl HostEnricher {
    /// Create a new host enricher
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add port scanner
    #[cfg(feature = "scanner")]
    #[must_use]
    pub fn with_scanner(mut self, scanner: crate::scanner::Scanner) -> Self {
        self.scanner = Some(scanner);
        self
    }

    /// Add WHOIS client
    #[cfg(feature = "whois")]
    #[must_use]
    pub fn with_whois(mut self, client: crate::whois::WhoisClient) -> Self {
        self.whois_client = Some(client);
        self
    }

    /// Enrich a single IP address with all configured local sources
    pub async fn enrich(&self, _ip: IpAddr) -> EnrichedHost {
        let result = EnrichedHost::default();

        // Run port scan if configured
        #[cfg(feature = "scanner")]
        if let Some(scanner) = &self.scanner {
            if let Ok(scan) = scanner.scan(ip).await {
                result.scan = Some(scan);
            }
        }

        // WHOIS lookup if configured
        #[cfg(feature = "whois")]
        if let Some(client) = &self.whois_client {
            if let Ok(info) = client.lookup_ip(ip).await {
                result.whois = Some(info);
            }
        }

        result
    }

    /// Enrich multiple IPs concurrently
    pub async fn enrich_many(&self, ips: &[IpAddr]) -> Vec<EnrichedHost> {
        let futures: Vec<_> = ips.iter().map(|ip| self.enrich(*ip)).collect();
        futures_util::future::join_all(futures).await
    }
}
