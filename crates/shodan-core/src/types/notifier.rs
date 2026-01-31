use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Notification service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notifier {
    /// Unique notifier ID
    pub id: String,

    /// Provider name (e.g., "email", "slack", "webhook")
    pub provider: String,

    /// User-friendly description
    #[serde(default)]
    pub description: Option<String>,

    /// Provider-specific arguments
    #[serde(default)]
    pub args: HashMap<String, serde_json::Value>,
}

impl Notifier {
    /// Get an argument as a string
    #[must_use]
    pub fn get_arg(&self, key: &str) -> Option<&str> {
        self.args.get(key).and_then(|v| v.as_str())
    }
}

/// Notification provider definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifierProvider {
    /// Provider name
    pub name: String,

    /// Provider description
    #[serde(default)]
    pub description: Option<String>,

    /// Required argument names
    #[serde(default)]
    pub required: Vec<String>,

    /// Optional argument names
    #[serde(default)]
    pub optional: Vec<String>,
}

/// Map of available providers
pub type ProviderMap = HashMap<String, NotifierProvider>;

/// Request to create a notifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNotifierRequest {
    /// Provider type
    pub provider: String,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Provider-specific arguments
    #[serde(flatten)]
    pub args: HashMap<String, serde_json::Value>,
}

/// Request to update a notifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateNotifierRequest {
    /// Updated description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated provider-specific arguments
    #[serde(flatten)]
    pub args: HashMap<String, serde_json::Value>,
}

/// Common notifier provider types
pub mod providers {
    /// Email notification
    pub const EMAIL: &str = "email";
    /// Slack webhook
    pub const SLACK: &str = "slack";
    /// Generic webhook
    pub const WEBHOOK: &str = "webhook";
    /// PagerDuty
    pub const PAGERDUTY: &str = "pagerduty";
    /// Telegram
    pub const TELEGRAM: &str = "telegram";
}
