use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Geographic location information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Two-letter country code (ISO 3166-1 alpha-2)
    #[serde(default)]
    pub country_code: Option<String>,

    /// Full country name
    #[serde(default)]
    pub country_name: Option<String>,

    /// City name
    #[serde(default)]
    pub city: Option<String>,

    /// Region/state code
    #[serde(default)]
    pub region_code: Option<String>,

    /// Postal/ZIP code
    #[serde(default)]
    pub postal_code: Option<String>,

    /// Latitude coordinate
    #[serde(default)]
    pub latitude: Option<f64>,

    /// Longitude coordinate
    #[serde(default)]
    pub longitude: Option<f64>,

    /// Area code (for US locations)
    #[serde(default)]
    pub area_code: Option<i32>,

    /// DMA code (for US locations)
    #[serde(default)]
    pub dma_code: Option<i32>,
}

impl GeoLocation {
    /// Returns true if the location has coordinates
    #[must_use]
    pub const fn has_coordinates(&self) -> bool {
        self.latitude.is_some() && self.longitude.is_some()
    }

    /// Returns the coordinates as a tuple if available
    #[must_use]
    pub fn coordinates(&self) -> Option<(f64, f64)> {
        match (self.latitude, self.longitude) {
            (Some(lat), Some(lon)) => Some((lat, lon)),
            _ => None,
        }
    }
}

/// Transport protocol for a service
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

impl Default for Transport {
    fn default() -> Self {
        Self::Tcp
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

/// Network or IP range specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NetworkSpec {
    /// Single IP address
    Ip(IpAddr),
    /// CIDR notation (e.g., "192.168.1.0/24")
    Cidr(String),
}

impl std::fmt::Display for NetworkSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Cidr(cidr) => write!(f, "{cidr}"),
        }
    }
}

impl From<IpAddr> for NetworkSpec {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl From<String> for NetworkSpec {
    fn from(s: String) -> Self {
        Self::Cidr(s)
    }
}

impl From<&str> for NetworkSpec {
    fn from(s: &str) -> Self {
        Self::Cidr(s.to_string())
    }
}
