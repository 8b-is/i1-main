use serde::{Deserialize, Serialize};

/// Account profile information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProfile {
    /// Username/display name
    #[serde(default)]
    pub display_name: Option<String>,

    /// Account member status
    #[serde(default)]
    pub member: bool,

    /// Available credits
    #[serde(default)]
    pub credits: i32,

    /// When the account was created
    #[serde(default)]
    pub created: Option<String>,
}

/// API plan information from /api-info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInfo {
    /// Available query credits
    #[serde(default)]
    pub query_credits: i32,

    /// Available scan credits
    #[serde(default)]
    pub scan_credits: i32,

    /// Is this a HTTPS-monitored API key
    #[serde(default)]
    pub https: bool,

    /// Is telnet access enabled
    #[serde(default)]
    pub telnet: bool,

    /// Unlocked features
    #[serde(default)]
    pub unlocked: bool,

    /// Plan name
    #[serde(default)]
    pub plan: Option<String>,

    /// Monthly usage limits
    #[serde(default)]
    pub usage_limits: Option<UsageLimits>,
}

impl ApiInfo {
    /// Returns true if there are query credits available
    #[must_use]
    pub fn has_query_credits(&self) -> bool {
        self.query_credits > 0
    }

    /// Returns true if there are scan credits available
    #[must_use]
    pub fn has_scan_credits(&self) -> bool {
        self.scan_credits > 0
    }
}

/// Monthly API usage limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLimits {
    /// Query credit limit
    #[serde(default)]
    pub query_credits: Option<i32>,

    /// Scan credit limit
    #[serde(default)]
    pub scan_credits: Option<i32>,

    /// Monitored IPs limit
    #[serde(default)]
    pub monitored_ips: Option<i32>,
}

/// Organization information (Enterprise)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    /// Organization ID
    #[serde(default)]
    pub id: Option<String>,

    /// Organization name
    #[serde(default)]
    pub name: Option<String>,

    /// When the organization was created
    #[serde(default)]
    pub created: Option<String>,

    /// Admin usernames
    #[serde(default)]
    pub admins: Vec<String>,

    /// Member usernames
    #[serde(default)]
    pub members: Vec<String>,

    /// Pending member invites
    #[serde(default)]
    pub pending: Vec<String>,

    /// Organization upgrade status
    #[serde(default)]
    pub upgrade: Option<bool>,

    /// Available domains (for filtering)
    #[serde(default)]
    pub domains: Vec<String>,

    /// Organization logo URL
    #[serde(default)]
    pub logo: Option<String>,
}

impl Organization {
    /// Returns true if the user is an admin
    #[must_use]
    pub fn is_admin(&self, username: &str) -> bool {
        self.admins.iter().any(|a| a == username)
    }

    /// Returns true if the user is a member (including admins)
    #[must_use]
    pub fn is_member(&self, username: &str) -> bool {
        self.members.iter().any(|m| m == username) || self.is_admin(username)
    }

    /// Total number of members (including admins)
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len() + self.admins.len()
    }
}

/// Bulk dataset information (Enterprise)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dataset {
    /// Dataset name/identifier
    pub name: String,

    /// Dataset scope (type of data)
    #[serde(default)]
    pub scope: Option<String>,

    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,
}

/// File within a bulk dataset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetFile {
    /// File name
    pub name: String,

    /// File size in bytes
    #[serde(default)]
    pub size: u64,

    /// Timestamp
    #[serde(default)]
    pub timestamp: Option<String>,

    /// Download URL
    #[serde(default)]
    pub url: Option<String>,
}

/// HTTP headers from /tools/httpheaders
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaders(pub std::collections::HashMap<String, String>);

impl HttpHeaders {
    /// Get a header value
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Iterate over headers
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

/// Response from /tools/myip
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MyIpResponse(pub String);

impl MyIpResponse {
    /// Get the IP address as a string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Try to parse as an IP address
    #[must_use]
    pub fn parse(&self) -> Option<std::net::IpAddr> {
        self.0.parse().ok()
    }
}

impl std::fmt::Display for MyIpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
