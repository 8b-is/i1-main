//! Account API endpoints.

use crate::ShodanClient;
use shodan_core::{AccountProfile, ApiInfo, Result};

/// Account API endpoints
pub struct AccountApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> AccountApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Get account profile information
    pub async fn profile(&self) -> Result<AccountProfile> {
        self.client.get("/account/profile").await
    }

    /// Get API plan information including available credits
    pub async fn api_info(&self) -> Result<ApiInfo> {
        self.client.get("/api-info").await
    }
}
