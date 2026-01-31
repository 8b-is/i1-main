//! DNS API endpoints.

use crate::ShodanClient;
use shodan_core::{DnsResolveResult, DnsReverseResult, DomainInfo, Result};

/// DNS API endpoints
pub struct DnsApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> DnsApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Get DNS information for a domain
    ///
    /// Note: Uses 1 query credit per lookup
    #[must_use]
    pub fn domain(&self, domain: impl Into<String>) -> DomainRequestBuilder<'a> {
        DomainRequestBuilder::new(self.client, domain.into())
    }

    /// Resolve hostnames to IP addresses
    pub async fn resolve(&self, hostnames: &[&str]) -> Result<DnsResolveResult> {
        let hostnames_str = hostnames.join(",");
        self.client
            .get_with_query("/dns/resolve", &[("hostnames", &hostnames_str)])
            .await
    }

    /// Reverse DNS lookup - get hostnames for IP addresses
    pub async fn reverse(&self, ips: &[&str]) -> Result<DnsReverseResult> {
        let ips_str = ips.join(",");
        self.client
            .get_with_query("/dns/reverse", &[("ips", &ips_str)])
            .await
    }
}

/// Builder for domain lookup requests
pub struct DomainRequestBuilder<'a> {
    client: &'a ShodanClient,
    domain: String,
    history: bool,
    record_type: Option<String>,
    page: u32,
}

impl<'a> DomainRequestBuilder<'a> {
    fn new(client: &'a ShodanClient, domain: String) -> Self {
        Self {
            client,
            domain,
            history: false,
            record_type: None,
            page: 1,
        }
    }

    /// Include historical DNS data
    #[must_use]
    pub fn history(mut self, include: bool) -> Self {
        self.history = include;
        self
    }

    /// Filter by record type (A, AAAA, MX, NS, TXT, SOA, CNAME)
    #[must_use]
    pub fn record_type(mut self, rtype: impl Into<String>) -> Self {
        self.record_type = Some(rtype.into());
        self
    }

    /// Set the page number for pagination
    #[must_use]
    pub fn page(mut self, page: u32) -> Self {
        self.page = page;
        self
    }

    /// Execute the request
    pub async fn send(self) -> Result<DomainInfo> {
        let mut params = Vec::new();

        if self.history {
            params.push(("history", "true".to_string()));
        }

        if let Some(ref rtype) = self.record_type {
            params.push(("type", rtype.clone()));
        }

        if self.page > 1 {
            params.push(("page", self.page.to_string()));
        }

        let params_ref: Vec<(&str, &str)> = params
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();

        self.client
            .get_with_query(&format!("/dns/domain/{}", self.domain), &params_ref)
            .await
    }
}
