use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Domain information from Shodan DNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    /// The domain queried
    #[serde(default)]
    pub domain: Option<String>,

    /// Associated tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// DNS records by type
    #[serde(default)]
    pub data: Vec<DnsRecord>,

    /// Subdomains discovered
    #[serde(default)]
    pub subdomains: Vec<String>,

    /// More pages available
    #[serde(default)]
    pub more: bool,
}

impl DomainInfo {
    /// Get all records of a specific type
    #[must_use]
    pub fn records_by_type(&self, record_type: &str) -> Vec<&DnsRecord> {
        self.data
            .iter()
            .filter(|r| r.record_type.as_deref() == Some(record_type))
            .collect()
    }

    /// Get all A records
    #[must_use]
    pub fn a_records(&self) -> Vec<&DnsRecord> {
        self.records_by_type("A")
    }

    /// Get all AAAA records
    #[must_use]
    pub fn aaaa_records(&self) -> Vec<&DnsRecord> {
        self.records_by_type("AAAA")
    }

    /// Get all MX records
    #[must_use]
    pub fn mx_records(&self) -> Vec<&DnsRecord> {
        self.records_by_type("MX")
    }

    /// Get all TXT records
    #[must_use]
    pub fn txt_records(&self) -> Vec<&DnsRecord> {
        self.records_by_type("TXT")
    }
}

/// Individual DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Record type (A, AAAA, MX, TXT, NS, SOA, CNAME)
    #[serde(default, rename = "type")]
    pub record_type: Option<String>,

    /// Record value
    #[serde(default)]
    pub value: Option<String>,

    /// Subdomain (for this specific record)
    #[serde(default)]
    pub subdomain: Option<String>,

    /// Last seen timestamp
    #[serde(default)]
    pub last_seen: Option<String>,

    /// Priority (for MX records)
    #[serde(default)]
    pub priority: Option<u16>,

    /// Additional ports (for some records)
    #[serde(default)]
    pub ports: Vec<u16>,
}

impl DnsRecord {
    /// Try to parse the value as an IP address
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        self.value.as_ref()?.parse().ok()
    }

    /// Returns true if this is an A or AAAA record
    #[must_use]
    pub fn is_address_record(&self) -> bool {
        matches!(
            self.record_type.as_deref(),
            Some("A") | Some("AAAA")
        )
    }
}

/// DNS resolution result (hostname -> IP)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolveResult(pub HashMap<String, String>);

impl DnsResolveResult {
    /// Get the IP for a hostname
    #[must_use]
    pub fn get(&self, hostname: &str) -> Option<&str> {
        self.0.get(hostname).map(String::as_str)
    }

    /// Iterate over hostname-IP pairs
    pub fn iter(&self) -> impl Iterator<Item = (&String, &String)> {
        self.0.iter()
    }
}

impl IntoIterator for DnsResolveResult {
    type Item = (String, String);
    type IntoIter = std::collections::hash_map::IntoIter<String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// Reverse DNS result (IP -> hostnames)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsReverseResult(pub HashMap<String, Vec<String>>);

impl DnsReverseResult {
    /// Get hostnames for an IP
    #[must_use]
    pub fn get(&self, ip: &str) -> Option<&[String]> {
        self.0.get(ip).map(Vec::as_slice)
    }

    /// Iterate over IP-hostnames pairs
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<String>)> {
        self.0.iter()
    }
}

impl IntoIterator for DnsReverseResult {
    type Item = (String, Vec<String>);
    type IntoIter = std::collections::hash_map::IntoIter<String, Vec<String>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
