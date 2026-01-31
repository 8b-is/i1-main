//! WHOIS lookup integration using whois-rs.

use crate::error::{ReconError, ReconResult};
use std::net::IpAddr;

/// WHOIS lookup result
#[derive(Debug, Clone)]
pub struct WhoisInfo {
    /// Raw WHOIS response
    pub raw: String,
    /// Registrar name
    pub registrar: Option<String>,
    /// Registrant information
    pub registrant: Option<RegistrantInfo>,
    /// Domain creation date
    pub creation_date: Option<String>,
    /// Domain expiration date
    pub expiration_date: Option<String>,
    /// Name servers
    pub name_servers: Vec<String>,
    /// Domain status codes
    pub status: Vec<String>,
}

/// Registrant information from WHOIS
#[derive(Debug, Clone)]
pub struct RegistrantInfo {
    /// Registrant name
    pub name: Option<String>,
    /// Organization name
    pub organization: Option<String>,
    /// Contact email
    pub email: Option<String>,
    /// Country
    pub country: Option<String>,
}

/// WHOIS client
pub struct WhoisClient {
    whois: whois_rs::WhoIs,
}

impl WhoisClient {
    /// Create a new WHOIS client
    pub fn new() -> ReconResult<Self> {
        // Load from embedded server list
        let whois = whois_rs::WhoIs::from_string(include_str!("whois_servers.json"))
            .map_err(|e| ReconError::Whois(e.to_string()))?;
        Ok(Self { whois })
    }

    /// Lookup WHOIS information for a domain
    pub async fn lookup_domain(&self, domain: &str) -> ReconResult<WhoisInfo> {
        let options = whois_rs::WhoIsLookupOptions::from_string(domain)
            .map_err(|e| ReconError::Whois(e.to_string()))?;
        let raw = self
            .whois
            .lookup(options)
            .map_err(|e| ReconError::Whois(e.to_string()))?;

        Ok(parse_whois_response(&raw))
    }

    /// Lookup WHOIS information for an IP address
    pub async fn lookup_ip(&self, ip: IpAddr) -> ReconResult<WhoisInfo> {
        let options = whois_rs::WhoIsLookupOptions::from_string(&ip.to_string())
            .map_err(|e| ReconError::Whois(e.to_string()))?;
        let raw = self
            .whois
            .lookup(options)
            .map_err(|e| ReconError::Whois(e.to_string()))?;

        Ok(parse_whois_response(&raw))
    }
}

/// Parse raw WHOIS response into structured data
fn parse_whois_response(raw: &str) -> WhoisInfo {
    let mut info = WhoisInfo {
        raw: raw.to_string(),
        registrar: None,
        registrant: None,
        creation_date: None,
        expiration_date: None,
        name_servers: Vec::new(),
        status: Vec::new(),
    };

    // Simple line-based parsing
    for line in raw.lines() {
        let line = line.trim();
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();

            match key.as_str() {
                "registrar" => info.registrar = Some(value),
                "creation date" | "created" => info.creation_date = Some(value),
                "expiration date" | "expires" | "registry expiry date" => {
                    info.expiration_date = Some(value);
                }
                "name server" | "nserver" => {
                    if !value.is_empty() {
                        info.name_servers.push(value);
                    }
                }
                "status" | "domain status" => {
                    if !value.is_empty() {
                        info.status.push(value);
                    }
                }
                _ => {}
            }
        }
    }

    info
}
