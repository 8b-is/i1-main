//! Notifier API endpoints.

use crate::ShodanClient;
use shodan_core::{CreateNotifierRequest, Notifier, ProviderMap, Result, UpdateNotifierRequest};
use std::collections::HashMap;

/// Notifier API endpoints
pub struct NotifierApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> NotifierApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// List all notifiers for the account
    pub async fn list(&self) -> Result<Vec<Notifier>> {
        self.client.get("/notifier").await
    }

    /// Get information about a specific notifier
    pub async fn get(&self, notifier_id: &str) -> Result<Notifier> {
        self.client.get(&format!("/notifier/{notifier_id}")).await
    }

    /// List available notification providers
    pub async fn providers(&self) -> Result<ProviderMap> {
        self.client.get("/notifier/provider").await
    }

    /// Create a new notifier
    #[must_use]
    pub fn create(&self, provider: impl Into<String>) -> CreateNotifierBuilder<'a> {
        CreateNotifierBuilder::new(self.client, provider.into())
    }

    /// Delete a notifier
    pub async fn delete(&self, notifier_id: &str) -> Result<()> {
        self.client
            .delete(&format!("/notifier/{notifier_id}"))
            .await
    }

    /// Update a notifier
    #[must_use]
    pub fn update(&self, notifier_id: impl Into<String>) -> UpdateNotifierBuilder<'a> {
        UpdateNotifierBuilder::new(self.client, notifier_id.into())
    }
}

/// Builder for creating notifiers
pub struct CreateNotifierBuilder<'a> {
    client: &'a ShodanClient,
    provider: String,
    description: Option<String>,
    args: HashMap<String, serde_json::Value>,
}

impl<'a> CreateNotifierBuilder<'a> {
    fn new(client: &'a ShodanClient, provider: String) -> Self {
        Self {
            client,
            provider,
            description: None,
            args: HashMap::new(),
        }
    }

    /// Set a description for the notifier
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add a string argument
    #[must_use]
    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args
            .insert(key.into(), serde_json::Value::String(value.into()));
        self
    }

    /// Add a JSON value argument
    #[must_use]
    pub fn arg_json(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.args.insert(key.into(), value);
        self
    }

    /// Create the notifier
    pub async fn send(self) -> Result<Notifier> {
        let request = CreateNotifierRequest {
            provider: self.provider,
            description: self.description,
            args: self.args,
        };

        self.client.post("/notifier", &request).await
    }
}

/// Builder for updating notifiers
pub struct UpdateNotifierBuilder<'a> {
    client: &'a ShodanClient,
    notifier_id: String,
    description: Option<String>,
    args: HashMap<String, serde_json::Value>,
}

impl<'a> UpdateNotifierBuilder<'a> {
    fn new(client: &'a ShodanClient, notifier_id: String) -> Self {
        Self {
            client,
            notifier_id,
            description: None,
            args: HashMap::new(),
        }
    }

    /// Update the description
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Update a string argument
    #[must_use]
    pub fn arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.args
            .insert(key.into(), serde_json::Value::String(value.into()));
        self
    }

    /// Update the notifier
    pub async fn send(self) -> Result<Notifier> {
        let request = UpdateNotifierRequest {
            description: self.description,
            args: self.args,
        };

        self.client
            .post(&format!("/notifier/{}", self.notifier_id), &request)
            .await
    }
}
