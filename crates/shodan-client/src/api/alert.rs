//! Network alert API endpoints.

use crate::ShodanClient;
use shodan_core::{Alert, AlertFilters, CreateAlertRequest, Result, Trigger, UpdateAlertRequest};

/// Network alert API endpoints
pub struct AlertApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> AlertApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Create a new network alert
    #[must_use]
    pub fn create(&self, name: impl Into<String>) -> CreateAlertBuilder<'a> {
        CreateAlertBuilder::new(self.client, name.into())
    }

    /// Get information about a specific alert
    pub async fn get(&self, alert_id: &str) -> Result<Alert> {
        self.client
            .get(&format!("/shodan/alert/{alert_id}/info"))
            .await
    }

    /// List all alerts for the account
    pub async fn list(&self) -> Result<Vec<Alert>> {
        self.client.get("/shodan/alert/info").await
    }

    /// Delete an alert
    pub async fn delete(&self, alert_id: &str) -> Result<()> {
        self.client
            .delete(&format!("/shodan/alert/{alert_id}"))
            .await
    }

    /// Update an existing alert
    #[must_use]
    pub fn update(&self, alert_id: impl Into<String>) -> UpdateAlertBuilder<'a> {
        UpdateAlertBuilder::new(self.client, alert_id.into())
    }

    /// List available trigger types
    pub async fn triggers(&self) -> Result<Vec<Trigger>> {
        self.client.get("/shodan/alert/triggers").await
    }

    /// Enable a trigger on an alert
    pub async fn enable_trigger(&self, alert_id: &str, trigger: &str) -> Result<()> {
        self.client
            .put(&format!("/shodan/alert/{alert_id}/trigger/{trigger}"))
            .await
    }

    /// Disable a trigger on an alert
    pub async fn disable_trigger(&self, alert_id: &str, trigger: &str) -> Result<()> {
        self.client
            .delete(&format!("/shodan/alert/{alert_id}/trigger/{trigger}"))
            .await
    }

    /// Add a service to the trigger whitelist
    pub async fn whitelist_service(
        &self,
        alert_id: &str,
        trigger: &str,
        service: &str,
    ) -> Result<()> {
        self.client
            .put(&format!(
                "/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}"
            ))
            .await
    }

    /// Remove a service from the trigger whitelist
    pub async fn unwhitelist_service(
        &self,
        alert_id: &str,
        trigger: &str,
        service: &str,
    ) -> Result<()> {
        self.client
            .delete(&format!(
                "/shodan/alert/{alert_id}/trigger/{trigger}/ignore/{service}"
            ))
            .await
    }

    /// Attach a notifier to an alert
    pub async fn attach_notifier(&self, alert_id: &str, notifier_id: &str) -> Result<()> {
        self.client
            .put(&format!("/shodan/alert/{alert_id}/notifier/{notifier_id}"))
            .await
    }

    /// Detach a notifier from an alert
    pub async fn detach_notifier(&self, alert_id: &str, notifier_id: &str) -> Result<()> {
        self.client
            .delete(&format!("/shodan/alert/{alert_id}/notifier/{notifier_id}"))
            .await
    }
}

/// Builder for creating alerts
pub struct CreateAlertBuilder<'a> {
    client: &'a ShodanClient,
    name: String,
    ip_ranges: Vec<String>,
    expires: Option<u32>,
}

impl<'a> CreateAlertBuilder<'a> {
    fn new(client: &'a ShodanClient, name: String) -> Self {
        Self {
            client,
            name,
            ip_ranges: Vec::new(),
            expires: None,
        }
    }

    /// Add an IP or CIDR range to monitor
    #[must_use]
    pub fn ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_ranges.push(ip.into());
        self
    }

    /// Add multiple IPs or CIDR ranges to monitor
    #[must_use]
    pub fn ips<I, S>(mut self, ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ip_ranges.extend(ips.into_iter().map(Into::into));
        self
    }

    /// Set expiration in days (0 = never)
    #[must_use]
    pub fn expires_in_days(mut self, days: u32) -> Self {
        self.expires = Some(days);
        self
    }

    /// Create the alert
    pub async fn send(self) -> Result<Alert> {
        let request = CreateAlertRequest {
            name: self.name,
            filters: AlertFilters::new(self.ip_ranges),
            expires: self.expires,
        };

        self.client.post("/shodan/alert", &request).await
    }
}

/// Builder for updating alerts
pub struct UpdateAlertBuilder<'a> {
    client: &'a ShodanClient,
    alert_id: String,
    ip_ranges: Vec<String>,
}

impl<'a> UpdateAlertBuilder<'a> {
    fn new(client: &'a ShodanClient, alert_id: String) -> Self {
        Self {
            client,
            alert_id,
            ip_ranges: Vec::new(),
        }
    }

    /// Set the IP ranges to monitor
    #[must_use]
    pub fn ips<I, S>(mut self, ips: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ip_ranges = ips.into_iter().map(Into::into).collect();
        self
    }

    /// Update the alert
    pub async fn send(self) -> Result<Alert> {
        let request = UpdateAlertRequest {
            filters: AlertFilters::new(self.ip_ranges),
        };

        self.client
            .post(&format!("/shodan/alert/{}", self.alert_id), &request)
            .await
    }
}
