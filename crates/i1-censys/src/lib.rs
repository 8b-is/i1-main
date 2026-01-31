//! # i1-censys
//!
//! Censys provider implementation for i1 threat intelligence.
//!
//! This crate provides access to the [Censys](https://censys.io) Search 2.0 API,
//! implementing the i1 provider traits.
//!
//! # Example
//!
//! ```rust,ignore
//! use i1_censys::CensysProvider;
//! use i1_providers::{Provider, HostLookup};
//!
//! let provider = CensysProvider::new("api-id", "api-secret");
//! let host = provider.lookup_host("8.8.8.8").await?;
//! println!("Organization: {:?}", host.org);
//! ```

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use governor::{Quota, RateLimiter};
use i1_core::{GeoLocation, HostInfo, I1Error, Result, Service};
use i1_providers::{
    AuthConfig, HealthStatus, HostLookup, Provider, ProviderHealth, RateLimitConfig,
    SearchProvider, SearchResults,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use tracing::{debug, instrument};

const DEFAULT_BASE_URL: &str = "https://search.censys.io/api/v2";

/// Censys provider for i1
pub struct CensysProvider {
    inner: Arc<CensysInner>,
}

struct CensysInner {
    http: Client,
    api_id: String,
    api_secret: String,
    base_url: String,
    rate_limiter: RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
    >,
}

impl CensysProvider {
    /// Create a new Censys provider with API credentials
    pub fn new(api_id: impl Into<String>, api_secret: impl Into<String>) -> Self {
        Self::with_config(api_id, api_secret, RateLimitConfig::censys())
    }

    /// Create with custom rate limit config
    pub fn with_config(
        api_id: impl Into<String>,
        api_secret: impl Into<String>,
        rate_limit: RateLimitConfig,
    ) -> Self {
        let quota = Quota::per_second(
            NonZeroU32::new((rate_limit.requests_per_second.max(0.1) * 10.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        )
        .allow_burst(NonZeroU32::new(rate_limit.burst_size).unwrap_or(NonZeroU32::MIN));

        Self {
            inner: Arc::new(CensysInner {
                http: Client::new(),
                api_id: api_id.into(),
                api_secret: api_secret.into(),
                base_url: DEFAULT_BASE_URL.to_string(),
                rate_limiter: RateLimiter::direct(quota),
            }),
        }
    }

    /// Get authentication config for this provider
    pub fn auth_config(&self) -> AuthConfig {
        AuthConfig::censys(&self.inner.api_id, &self.inner.api_secret)
    }

    /// Make a GET request to the Censys API
    #[instrument(skip(self), fields(provider = "censys"))]
    async fn get<T: serde::de::DeserializeOwned>(&self, endpoint: &str) -> Result<T> {
        // Wait for rate limiter
        self.inner.rate_limiter.until_ready().await;

        let url = format!("{}{}", self.inner.base_url, endpoint);
        debug!(url = %url, "Censys API request");

        let response = self
            .inner
            .http
            .get(&url)
            .basic_auth(&self.inner.api_id, Some(&self.inner.api_secret))
            .send()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let message = response.text().await.unwrap_or_default();

            return match code {
                401 | 403 => Err(I1Error::Unauthorized),
                429 => Err(I1Error::RateLimited { retry_after: None }),
                404 => Err(I1Error::NotFound {
                    resource: endpoint.to_string(),
                }),
                _ => Err(I1Error::provider("censys", code, message)),
            };
        }

        response
            .json()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))
    }

    /// Make a POST request to the Censys API
    #[instrument(skip(self, body), fields(provider = "censys"))]
    async fn post<T: serde::de::DeserializeOwned, B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> Result<T> {
        self.inner.rate_limiter.until_ready().await;

        let url = format!("{}{}", self.inner.base_url, endpoint);
        debug!(url = %url, "Censys API POST request");

        let response = self
            .inner
            .http
            .post(&url)
            .basic_auth(&self.inner.api_id, Some(&self.inner.api_secret))
            .json(body)
            .send()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))?;

        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            let message = response.text().await.unwrap_or_default();

            return match code {
                401 | 403 => Err(I1Error::Unauthorized),
                429 => Err(I1Error::RateLimited { retry_after: None }),
                _ => Err(I1Error::provider("censys", code, message)),
            };
        }

        response
            .json()
            .await
            .map_err(|e| I1Error::Http(e.to_string()))
    }

    /// Convert Censys host response to i1 `HostInfo`
    fn convert_host(host: CensysHost) -> HostInfo {
        let services: Vec<Service> = host
            .services
            .into_iter()
            .map(|s| Service {
                port: s.port,
                transport: i1_core::Transport::from_str(&s.transport_protocol),
                product: s
                    .software
                    .as_ref()
                    .and_then(|sw| sw.first().map(|s| s.product.clone()))
                    .flatten(),
                version: s
                    .software
                    .as_ref()
                    .and_then(|sw| sw.first().map(|s| s.version.clone()))
                    .flatten(),
                cpe: vec![],
                data: s.banner,
                timestamp: None,
                shodan_module: None,
                http: None,
                ssl: None,
                ssh: None,
                vulns: std::collections::HashMap::new(),
                tags: vec![],
                devicetype: None,
                info: None,
                os: None,
            })
            .collect();

        let ports: Vec<u16> = services.iter().map(|s| s.port).collect();

        HostInfo {
            ip: host.ip.parse().ok(),
            ip_str: host.ip,
            hostnames: host.dns.map(|d| d.names).unwrap_or_default(),
            domains: vec![],
            org: host.autonomous_system.as_ref().map(|a| a.name.clone()),
            asn: host
                .autonomous_system
                .as_ref()
                .map(|a| format!("AS{}", a.asn)),
            isp: None,
            os: host.operating_system.and_then(|o| o.product),
            ports,
            vulns: vec![],
            tags: host.labels.unwrap_or_default(),
            location: GeoLocation {
                country_code: host.location.as_ref().and_then(|l| l.country_code.clone()),
                country_name: host.location.as_ref().and_then(|l| l.country.clone()),
                city: host.location.as_ref().and_then(|l| l.city.clone()),
                latitude: host
                    .location
                    .as_ref()
                    .and_then(|l| l.coordinates.as_ref().map(|c| c.latitude)),
                longitude: host
                    .location
                    .as_ref()
                    .and_then(|l| l.coordinates.as_ref().map(|c| c.longitude)),
                ..Default::default()
            },
            data: services,
            last_update: host.last_updated_at,
        }
    }
}

impl Clone for CensysProvider {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[async_trait]
impl Provider for CensysProvider {
    fn name(&self) -> &'static str {
        "censys"
    }

    fn display_name(&self) -> &'static str {
        "Censys"
    }

    fn base_url(&self) -> &str {
        &self.inner.base_url
    }

    fn is_configured(&self) -> bool {
        !self.inner.api_id.is_empty() && !self.inner.api_secret.is_empty()
    }

    async fn health_check(&self) -> Result<ProviderHealth> {
        let start = Instant::now();

        match self.get::<serde_json::Value>("/account").await {
            Ok(info) => {
                let quota = info
                    .get("quota")
                    .and_then(|q| q.get("remaining"))
                    .and_then(serde_json::Value::as_i64);

                Ok(ProviderHealth {
                    provider: "censys".to_string(),
                    status: HealthStatus::Healthy,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    credits_remaining: quota,
                    message: None,
                })
            }
            Err(I1Error::Unauthorized) => Ok(ProviderHealth {
                provider: "censys".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some("Invalid API credentials".to_string()),
            }),
            Err(e) => Ok(ProviderHealth {
                provider: "censys".to_string(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(start.elapsed().as_millis() as u64),
                credits_remaining: None,
                message: Some(e.to_string()),
            }),
        }
    }
}

#[async_trait]
impl HostLookup for CensysProvider {
    #[instrument(skip(self), fields(provider = "censys"))]
    async fn lookup_host(&self, ip: &str) -> Result<HostInfo> {
        let response: CensysHostResponse = self.get(&format!("/hosts/{ip}")).await?;
        Ok(Self::convert_host(response.result))
    }
}

#[async_trait]
impl SearchProvider for CensysProvider {
    #[instrument(skip(self), fields(provider = "censys"))]
    async fn search(&self, query: &str, page: Option<u32>) -> Result<SearchResults> {
        #[derive(Serialize)]
        struct SearchRequest<'a> {
            q: &'a str,
            per_page: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            cursor: Option<String>,
        }

        let request = SearchRequest {
            q: query,
            per_page: 25,
            cursor: None, // TODO: implement cursor-based pagination
        };

        let response: CensysSearchResponse = self.post("/hosts/search", &request).await?;

        let results: Vec<HostInfo> = response
            .result
            .hits
            .into_iter()
            .map(Self::convert_host)
            .collect();

        Ok(SearchResults {
            provider: "censys".to_string(),
            total: response.result.total as u64,
            page: page.unwrap_or(1),
            results,
            facets: None,
        })
    }

    #[instrument(skip(self), fields(provider = "censys"))]
    async fn count(&self, query: &str) -> Result<u64> {
        #[derive(Serialize)]
        struct AggregateRequest<'a> {
            q: &'a str,
            field: &'a str,
            num_buckets: u32,
        }

        let request = AggregateRequest {
            q: query,
            field: "services.port",
            num_buckets: 1,
        };

        let response: CensysAggregateResponse = self.post("/hosts/aggregate", &request).await?;
        Ok(response.result.total as u64)
    }
}

// Censys-specific response types
#[derive(Debug, Deserialize)]
struct CensysHostResponse {
    result: CensysHost,
}

#[derive(Debug, Deserialize)]
struct CensysHost {
    ip: String,
    #[serde(default)]
    services: Vec<CensysService>,
    #[serde(default)]
    location: Option<CensysLocation>,
    #[serde(default)]
    autonomous_system: Option<CensysAS>,
    #[serde(default)]
    dns: Option<CensysDns>,
    #[serde(default)]
    operating_system: Option<CensysOS>,
    #[serde(default)]
    labels: Option<Vec<String>>,
    #[serde(default)]
    last_updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // API response fields - may not all be used yet
struct CensysService {
    port: u16,
    #[serde(default)]
    transport_protocol: String,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    software: Option<Vec<CensysSoftware>>,
}

#[derive(Debug, Deserialize)]
struct CensysSoftware {
    product: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysLocation {
    country: Option<String>,
    country_code: Option<String>,
    city: Option<String>,
    coordinates: Option<CensysCoordinates>,
}

#[derive(Debug, Deserialize)]
struct CensysCoordinates {
    latitude: f64,
    longitude: f64,
}

#[derive(Debug, Deserialize)]
struct CensysAS {
    asn: u32,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CensysDns {
    #[serde(default)]
    names: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct CensysOS {
    product: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysSearchResponse {
    result: CensysSearchResult,
}

#[derive(Debug, Deserialize)]
struct CensysSearchResult {
    #[serde(default)]
    hits: Vec<CensysHost>,
    total: usize,
}

#[derive(Debug, Deserialize)]
struct CensysAggregateResponse {
    result: CensysAggregateResult,
}

#[derive(Debug, Deserialize)]
struct CensysAggregateResult {
    total: usize,
}
