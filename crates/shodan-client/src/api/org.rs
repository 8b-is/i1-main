//! Organization API endpoints (Enterprise).

use crate::ShodanClient;
use shodan_core::{Organization, Result};

/// Organization API endpoints (Enterprise only)
pub struct OrgApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> OrgApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Get information about the organization
    pub async fn info(&self) -> Result<Organization> {
        self.client.get("/org").await
    }

    /// Add a member to the organization
    pub async fn add_member(&self, username: &str, notify: bool) -> Result<()> {
        let mut params = Vec::new();
        if notify {
            params.push(("notify", "true"));
        }

        // Build URL manually since we need PUT with query params
        let path = format!("/org/member/{username}");
        self.client.put(&path).await
    }

    /// Remove a member from the organization
    pub async fn remove_member(&self, username: &str) -> Result<()> {
        self.client
            .delete(&format!("/org/member/{username}"))
            .await
    }
}
