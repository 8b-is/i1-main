//! Host enrichment by combining data from multiple sources.

use shodan_core::HostInfo;
use std::net::IpAddr;

/// Combined intelligence from all configured sources
#[derive(Debug, Clone, Default)]
pub struct EnrichedHost {
    /// Data from Shodan API
    pub shodan: Option<HostInfo>,

    /// Port scan results
    #[cfg(feature = "scanner")]
    pub scan: Option<crate::scanner::ScanResult>,

    /// WHOIS information
    #[cfg(feature = "whois")]
    pub whois: Option<crate::whois::WhoisInfo>,

    // DNS and trace temporarily disabled
    // #[cfg(feature = "dns")]
    // pub dns: Option<crate::dns::DnsLookupResult>,

    // #[cfg(feature = "trace")]
    // pub trace: Option<crate::trace::TraceResult>,
}

/// Builder for host enrichment with multiple data sources
#[derive(Default)]
pub struct HostEnricher {
    shodan_client: Option<shodan_client::ShodanClient>,

    #[cfg(feature = "scanner")]
    scanner: Option<crate::scanner::Scanner>,

    #[cfg(feature = "whois")]
    whois_client: Option<crate::whois::WhoisClient>,

    // DNS and trace temporarily disabled
    // #[cfg(feature = "dns")]
    // dns_resolver: Option<crate::dns::DnsResolver>,

    // #[cfg(feature = "trace")]
    // tracer: Option<crate::trace::NetworkTracer>,
}

impl HostEnricher {
    /// Create a new host enricher
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add Shodan API client
    #[must_use]
    pub fn with_shodan(mut self, client: shodan_client::ShodanClient) -> Self {
        self.shodan_client = Some(client);
        self
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

    // DNS and trace temporarily disabled
    // /// Add DNS resolver
    // #[cfg(feature = "dns")]
    // #[must_use]
    // pub fn with_dns(mut self, resolver: crate::dns::DnsResolver) -> Self {
    //     self.dns_resolver = Some(resolver);
    //     self
    // }

    // /// Add network tracer
    // #[cfg(feature = "trace")]
    // #[must_use]
    // pub fn with_tracer(mut self, tracer: crate::trace::NetworkTracer) -> Self {
    //     self.tracer = Some(tracer);
    //     self
    // }

    /// Enrich a single IP address with all configured sources
    pub async fn enrich(&self, ip: IpAddr) -> EnrichedHost {
        let mut result = EnrichedHost::default();

        // Fetch from Shodan if configured
        if let Some(client) = &self.shodan_client {
            if let Ok(host) = client.search().host(&ip.to_string()).await {
                result.shodan = Some(host);
            }
        }

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

        // DNS and trace temporarily disabled
        // #[cfg(feature = "dns")]
        // if let Some(resolver) = &self.dns_resolver {
        //     if let Ok(dns) = resolver.reverse(ip).await {
        //         result.dns = Some(dns);
        //     }
        // }

        // #[cfg(feature = "trace")]
        // if let Some(tracer) = &self.tracer {
        //     if let Ok(trace) = tracer.trace(ip).await {
        //         result.trace = Some(trace);
        //     }
        // }

        result
    }

    /// Enrich multiple IPs concurrently
    pub async fn enrich_many(&self, ips: &[IpAddr]) -> Vec<EnrichedHost> {
        let futures: Vec<_> = ips.iter().map(|ip| self.enrich(*ip)).collect();
        futures_util::future::join_all(futures).await
    }
}
