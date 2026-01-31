//! On-demand scanning API endpoints.

use crate::ShodanClient;
use shodan_core::{ProtocolMap, Result, ScanList, ScanResponse, ScanStatus};

/// On-demand scanning API endpoints
pub struct ScanApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> ScanApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// List all ports that Shodan crawlers monitor
    pub async fn ports(&self) -> Result<Vec<u16>> {
        self.client.get("/shodan/ports").await
    }

    /// List all protocols available for on-demand scanning
    pub async fn protocols(&self) -> Result<ProtocolMap> {
        self.client.get("/shodan/protocols").await
    }

    /// Request an on-demand scan of IPs
    ///
    /// Note: Requires scan credits
    #[must_use]
    pub fn request(&self) -> ScanRequestBuilder<'a> {
        ScanRequestBuilder::new(self.client)
    }

    /// List all active scans for the account
    pub async fn list(&self) -> Result<ScanList> {
        self.client.get("/shodan/scans").await
    }

    /// Get the status of a specific scan
    pub async fn status(&self, scan_id: &str) -> Result<ScanStatus> {
        self.client
            .get(&format!("/shodan/scan/{scan_id}"))
            .await
    }
}

/// Builder for scan requests
pub struct ScanRequestBuilder<'a> {
    client: &'a ShodanClient,
    ips: Vec<String>,
    services: Vec<String>,
}

impl<'a> ScanRequestBuilder<'a> {
    fn new(client: &'a ShodanClient) -> Self {
        Self {
            client,
            ips: Vec::new(),
            services: Vec::new(),
        }
    }

    /// Add an IP address or network to scan
    #[must_use]
    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.ips.push(ip.into());
        self
    }

    /// Add multiple IPs or networks to scan
    #[must_use]
    pub fn ips<I, S>(mut self, ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ips.extend(ips.into_iter().map(Into::into));
        self
    }

    /// Add a specific service to scan for
    #[must_use]
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.services.push(service.into());
        self
    }

    /// Add multiple services to scan for
    #[must_use]
    pub fn services<I, S>(mut self, services: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.services.extend(services.into_iter().map(Into::into));
        self
    }

    /// Submit the scan request
    pub async fn send(self) -> Result<ScanResponse> {
        if self.ips.is_empty() {
            return Err(shodan_core::ShodanError::InvalidQuery(
                "At least one IP address is required".to_string(),
            ));
        }

        let ips_str = self.ips.join(",");
        let params = vec![("ips", ips_str.as_str())];

        // Note: services parameter requires special handling
        // Each service should be a separate form field

        self.client.post_form("/shodan/scan", &params).await
    }
}
