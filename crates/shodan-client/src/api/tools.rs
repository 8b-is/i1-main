//! Utility API endpoints.

use crate::ShodanClient;
use shodan_core::{HttpHeaders, MyIpResponse, Result};

/// Utility API endpoints
pub struct ToolsApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> ToolsApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Get the HTTP headers that the client is sending
    pub async fn http_headers(&self) -> Result<HttpHeaders> {
        self.client.get("/tools/httpheaders").await
    }

    /// Get your current public IP address
    pub async fn my_ip(&self) -> Result<MyIpResponse> {
        self.client.get("/tools/myip").await
    }
}
