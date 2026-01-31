use super::{GeoLocation, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Search results from /shodan/host/search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// Matching banners/services
    pub matches: Vec<SearchMatch>,

    /// Total number of results
    pub total: u64,

    /// Facet aggregations if requested
    #[serde(default)]
    pub facets: HashMap<String, Vec<FacetValue>>,
}

impl SearchResults {
    /// Returns true if there are no results
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Returns the number of matches in this page
    #[must_use]
    pub fn len(&self) -> usize {
        self.matches.len()
    }
}

/// Individual match in search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatch {
    /// IP address (parsed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,

    /// IP address as string
    pub ip_str: String,

    /// Port number
    pub port: u16,

    /// Transport protocol
    #[serde(default)]
    pub transport: Transport,

    /// Hostnames associated with this IP
    #[serde(default)]
    pub hostnames: Vec<String>,

    /// Domains associated with this IP
    #[serde(default)]
    pub domains: Vec<String>,

    /// Organization that owns the IP
    #[serde(default)]
    pub org: Option<String>,

    /// Autonomous System Number
    #[serde(default)]
    pub asn: Option<String>,

    /// Internet Service Provider
    #[serde(default)]
    pub isp: Option<String>,

    /// Operating system
    #[serde(default)]
    pub os: Option<String>,

    /// Product name
    #[serde(default)]
    pub product: Option<String>,

    /// Product version
    #[serde(default)]
    pub version: Option<String>,

    /// CPE identifiers
    #[serde(default)]
    pub cpe: Vec<String>,

    /// Raw banner data
    #[serde(default)]
    pub data: Option<String>,

    /// Geographic location
    #[serde(flatten)]
    pub location: GeoLocation,

    /// Timestamp
    #[serde(default)]
    pub timestamp: Option<String>,

    /// HTTP data if available
    #[serde(default)]
    pub http: Option<super::host::HttpData>,

    /// SSL data if available
    #[serde(default)]
    pub ssl: Option<super::host::SslData>,

    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// Vulnerabilities
    #[serde(default)]
    pub vulns: HashMap<String, super::host::VulnInfo>,
}

impl SearchMatch {
    /// Returns the IP address, parsing from string if needed
    #[must_use]
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.ip.or_else(|| self.ip_str.parse().ok())
    }

    /// Returns true if this service has known vulnerabilities
    #[must_use]
    pub fn is_vulnerable(&self) -> bool {
        !self.vulns.is_empty()
    }
}

/// Facet aggregation value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FacetValue {
    /// The value being aggregated
    pub value: serde_json::Value,

    /// Count of matches with this value
    pub count: u64,
}

impl FacetValue {
    /// Try to get the value as a string
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        self.value.as_str()
    }

    /// Try to get the value as an integer
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        self.value.as_i64()
    }
}

/// Host count result from /shodan/host/count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCount {
    /// Total number of matching results
    pub total: u64,

    /// Facet aggregations if requested
    #[serde(default)]
    pub facets: HashMap<String, Vec<FacetValue>>,
}

/// Parsed query tokens from /shodan/host/search/tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTokens {
    /// Parsed filter attributes
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,

    /// Parsing errors
    #[serde(default)]
    pub errors: Vec<String>,

    /// Original query string
    #[serde(default)]
    pub string: String,

    /// Extracted filters
    #[serde(default)]
    pub filters: Vec<String>,
}

impl QueryTokens {
    /// Returns true if there were any parsing errors
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

/// Saved search query from the directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuery {
    /// Query title
    #[serde(default)]
    pub title: Option<String>,

    /// Query description
    #[serde(default)]
    pub description: Option<String>,

    /// The actual search query
    #[serde(default)]
    pub query: Option<String>,

    /// Number of votes
    #[serde(default)]
    pub votes: i32,

    /// Associated tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// Timestamp when created
    #[serde(default)]
    pub timestamp: Option<String>,
}

/// Directory search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryDirectory {
    /// Matching queries
    #[serde(default)]
    pub matches: Vec<SavedQuery>,

    /// Total number of results
    #[serde(default)]
    pub total: u64,
}

/// Popular tag information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTag {
    /// Tag name
    #[serde(default)]
    pub value: Option<String>,

    /// Number of queries using this tag
    #[serde(default)]
    pub count: u64,
}

/// Popular tags response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PopularTags {
    /// List of popular tags
    #[serde(default)]
    pub matches: Vec<QueryTag>,
}
