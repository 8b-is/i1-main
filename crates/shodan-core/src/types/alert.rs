use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Network monitoring alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    /// Unique alert ID
    pub id: String,

    /// Alert name
    pub name: String,

    /// IP filters (networks to monitor)
    #[serde(default)]
    pub filters: AlertFilters,

    /// Enabled triggers (trigger name -> enabled)
    #[serde(default)]
    pub triggers: HashMap<String, bool>,

    /// Attached notifier IDs
    #[serde(default)]
    pub notifiers: Vec<String>,

    /// When the alert was created
    #[serde(default)]
    pub created: Option<String>,

    /// When the alert expires (if set)
    #[serde(default)]
    pub expires: Option<i64>,

    /// Whether the alert has expired
    #[serde(default)]
    pub expired: bool,

    /// Number of IPs being monitored
    #[serde(default)]
    pub size: u64,
}

impl Alert {
    /// Returns true if the alert is still active
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.expired
    }

    /// Returns true if this trigger is enabled
    #[must_use]
    pub fn has_trigger(&self, trigger: &str) -> bool {
        self.triggers.get(trigger).copied().unwrap_or(false)
    }
}

/// Alert IP filters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertFilters {
    /// IP addresses or CIDR ranges to monitor
    #[serde(default)]
    pub ip: Vec<String>,
}

impl AlertFilters {
    /// Create new filters with the given IPs
    #[must_use]
    pub fn new(ips: Vec<String>) -> Self {
        Self { ip: ips }
    }

    /// Returns true if no IPs are configured
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ip.is_empty()
    }
}

/// Alert trigger definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trigger {
    /// Trigger name/ID
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,

    /// Trigger rule
    #[serde(default)]
    pub rule: Option<String>,
}

/// Request to create an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAlertRequest {
    /// Alert name
    pub name: String,

    /// IP filters
    pub filters: AlertFilters,

    /// Expiration in days (0 = never)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<u32>,
}

/// Request to update an alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAlertRequest {
    /// Updated IP filters
    pub filters: AlertFilters,
}

/// Whitelisted service for a trigger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    /// IP address
    pub ip: String,

    /// Port number
    pub port: u16,
}

impl WhitelistEntry {
    /// Create from "ip:port" format
    pub fn from_service_str(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() == 2 {
            let port = parts[1].parse().ok()?;
            Some(Self {
                ip: parts[0].to_string(),
                port,
            })
        } else {
            None
        }
    }

    /// Format as "ip:port"
    #[must_use]
    pub fn to_service_str(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}
