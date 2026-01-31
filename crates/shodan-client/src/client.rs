//! Main Shodan API client implementation.

use crate::api::*;
use crate::config::RetryConfig;
use reqwest::Client as HttpClient;
use serde::de::DeserializeOwned;
use shodan_core::{Result, ShodanError};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

/// The Shodan API base URL
const DEFAULT_BASE_URL: &str = "https://api.shodan.io";

/// Default request timeout
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Main Shodan API client
#[derive(Clone)]
pub struct ShodanClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    http: HttpClient,
    api_key: String,
    base_url: String,
    #[allow(dead_code)] // Will be used for retry logic
    retry_config: RetryConfig,
}

impl ShodanClient {
    /// Create a new client with the given API key using default settings
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        ShodanClientBuilder::new(api_key).build()
    }

    /// Create a builder for custom configuration
    #[must_use]
    pub fn builder(api_key: impl Into<String>) -> ShodanClientBuilder {
        ShodanClientBuilder::new(api_key)
    }

    /// Access search-related endpoints
    #[must_use]
    pub fn search(&self) -> SearchApi<'_> {
        SearchApi::new(self)
    }

    /// Access on-demand scanning endpoints
    #[must_use]
    pub fn scan(&self) -> ScanApi<'_> {
        ScanApi::new(self)
    }

    /// Access network alert endpoints
    #[must_use]
    pub fn alerts(&self) -> AlertApi<'_> {
        AlertApi::new(self)
    }

    /// Access notifier endpoints
    #[must_use]
    pub fn notifiers(&self) -> NotifierApi<'_> {
        NotifierApi::new(self)
    }

    /// Access DNS endpoints
    #[must_use]
    pub fn dns(&self) -> DnsApi<'_> {
        DnsApi::new(self)
    }

    /// Access directory/query endpoints
    #[must_use]
    pub fn directory(&self) -> DirectoryApi<'_> {
        DirectoryApi::new(self)
    }

    /// Access bulk data endpoints (enterprise)
    #[must_use]
    pub fn bulk(&self) -> BulkApi<'_> {
        BulkApi::new(self)
    }

    /// Access organization endpoints (enterprise)
    #[must_use]
    pub fn org(&self) -> OrgApi<'_> {
        OrgApi::new(self)
    }

    /// Access account endpoints
    #[must_use]
    pub fn account(&self) -> AccountApi<'_> {
        AccountApi::new(self)
    }

    /// Access utility endpoints
    #[must_use]
    pub fn tools(&self) -> ToolsApi<'_> {
        ToolsApi::new(self)
    }

    /// Perform a GET request
    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.get_with_query(path, &[]).await
    }

    /// Perform a GET request with query parameters
    pub(crate) async fn get_with_query<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let url = self.build_url(path, params)?;
        debug!(url = %url, "GET request");

        let response = self
            .inner
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Perform a POST request with JSON body
    pub(crate) async fn post<T: DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let url = self.build_url(path, &[])?;
        debug!(url = %url, "POST request");

        let response = self
            .inner
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Perform a POST request with form data
    pub(crate) async fn post_form<T: DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, &str)],
    ) -> Result<T> {
        let url = self.build_url(path, &[])?;
        debug!(url = %url, "POST form request");

        let response = self
            .inner
            .http
            .post(&url)
            .form(params)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        self.handle_response(response).await
    }

    /// Perform a PUT request
    pub(crate) async fn put(&self, path: &str) -> Result<()> {
        let url = self.build_url(path, &[])?;
        debug!(url = %url, "PUT request");

        let response = self
            .inner
            .http
            .put(&url)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        self.handle_empty_response(response).await
    }

    /// Perform a DELETE request
    pub(crate) async fn delete(&self, path: &str) -> Result<()> {
        let url = self.build_url(path, &[])?;
        debug!(url = %url, "DELETE request");

        let response = self
            .inner
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|e| ShodanError::Http(e.to_string()))?;

        self.handle_empty_response(response).await
    }

    /// Build a URL with query parameters (including API key)
    fn build_url(&self, path: &str, params: &[(&str, &str)]) -> Result<String> {
        let mut url = format!("{}{}", self.inner.base_url, path);

        // Add API key and other params
        url.push_str("?key=");
        url.push_str(&self.inner.api_key);

        for (key, value) in params {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(&urlencoding::encode(value));
        }

        Ok(url)
    }

    /// Handle an API response that returns JSON
    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        if status.is_success() {
            let body = response.text().await.map_err(|e| ShodanError::Http(e.to_string()))?;
            serde_json::from_str(&body).map_err(ShodanError::Json)
        } else {
            self.handle_error(status.as_u16(), response).await
        }
    }

    /// Handle an API response that returns no body
    async fn handle_empty_response(&self, response: reqwest::Response) -> Result<()> {
        let status = response.status();

        if status.is_success() {
            Ok(())
        } else {
            self.handle_error(status.as_u16(), response).await
        }
    }

    /// Convert an error response to a ShodanError
    async fn handle_error<T>(&self, status: u16, response: reqwest::Response) -> Result<T> {
        let body = response.text().await.unwrap_or_default();

        // Try to parse error message from JSON
        let message = serde_json::from_str::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
            .unwrap_or(body);

        match status {
            401 => Err(ShodanError::Unauthorized),
            402 => Err(ShodanError::InsufficientCredits {
                required: 0,
                available: 0,
            }),
            404 => Err(ShodanError::NotFound { resource: message }),
            429 => {
                warn!("Rate limited by Shodan API");
                Err(ShodanError::RateLimited { retry_after: None })
            }
            _ => Err(ShodanError::Api {
                code: status,
                message,
            }),
        }
    }
}

/// Builder for configuring a [`ShodanClient`]
pub struct ShodanClientBuilder {
    api_key: String,
    base_url: String,
    timeout: Duration,
    user_agent: String,
    retry_config: RetryConfig,
}

impl ShodanClientBuilder {
    /// Create a new builder with the given API key
    #[must_use]
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            base_url: DEFAULT_BASE_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            user_agent: format!("shodan-rust/{}", env!("CARGO_PKG_VERSION")),
            retry_config: RetryConfig::default(),
        }
    }

    /// Set the base URL (useful for testing)
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Set the request timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the User-Agent header
    #[must_use]
    pub fn user_agent(mut self, agent: impl Into<String>) -> Self {
        self.user_agent = agent.into();
        self
    }

    /// Set retry configuration
    #[must_use]
    pub fn retry(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Build the client
    #[must_use]
    pub fn build(self) -> ShodanClient {
        let http = HttpClient::builder()
            .timeout(self.timeout)
            .user_agent(&self.user_agent)
            .gzip(true)
            .build()
            .expect("Failed to build HTTP client");

        ShodanClient {
            inner: Arc::new(ClientInner {
                http,
                api_key: self.api_key,
                base_url: self.base_url,
                retry_config: self.retry_config,
            }),
        }
    }
}

// URL encoding helper
mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}
