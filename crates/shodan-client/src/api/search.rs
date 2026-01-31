//! Search API endpoints.

use crate::ShodanClient;
use shodan_core::{HostCount, HostInfo, QueryTokens, Result, SearchResults};

/// Search API endpoints
pub struct SearchApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> SearchApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// Get all information about a host
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let host = client.search().host("8.8.8.8").await?;
    /// println!("Ports: {:?}", host.ports);
    /// ```
    pub async fn host(&self, ip: &str) -> Result<HostInfo> {
        self.client.get(&format!("/shodan/host/{ip}")).await
    }

    /// Get host information with options
    #[must_use]
    pub fn host_with_options(&self, ip: impl Into<String>) -> HostRequestBuilder<'a> {
        HostRequestBuilder::new(self.client, ip.into())
    }

    /// Search Shodan with a query string
    #[must_use]
    pub fn query(&self, query: impl Into<String>) -> SearchRequestBuilder<'a> {
        SearchRequestBuilder::new(self.client, query.into())
    }

    /// Get count of results without consuming query credits
    #[must_use]
    pub fn count(&self, query: impl Into<String>) -> CountRequestBuilder<'a> {
        CountRequestBuilder::new(self.client, query.into())
    }

    /// List all available search facets
    pub async fn facets(&self) -> Result<Vec<String>> {
        self.client.get("/shodan/host/search/facets").await
    }

    /// List all available search filters
    pub async fn filters(&self) -> Result<Vec<String>> {
        self.client.get("/shodan/host/search/filters").await
    }

    /// Parse a search query into tokens
    pub async fn tokens(&self, query: &str) -> Result<QueryTokens> {
        self.client
            .get_with_query("/shodan/host/search/tokens", &[("query", query)])
            .await
    }
}

/// Builder for host requests with options
pub struct HostRequestBuilder<'a> {
    client: &'a ShodanClient,
    ip: String,
    history: bool,
    minify: bool,
}

impl<'a> HostRequestBuilder<'a> {
    fn new(client: &'a ShodanClient, ip: String) -> Self {
        Self {
            client,
            ip,
            history: false,
            minify: false,
        }
    }

    /// Include historical banners
    #[must_use]
    pub fn history(mut self, include: bool) -> Self {
        self.history = include;
        self
    }

    /// Return only basic host information
    #[must_use]
    pub fn minify(mut self, minify: bool) -> Self {
        self.minify = minify;
        self
    }

    /// Execute the request
    pub async fn send(self) -> Result<HostInfo> {
        let mut params = Vec::new();
        if self.history {
            params.push(("history", "true"));
        }
        if self.minify {
            params.push(("minify", "true"));
        }

        self.client
            .get_with_query(&format!("/shodan/host/{}", self.ip), &params)
            .await
    }
}

/// Builder for search requests
pub struct SearchRequestBuilder<'a> {
    client: &'a ShodanClient,
    query: String,
    facets: Vec<String>,
    page: u32,
    minify: bool,
}

impl<'a> SearchRequestBuilder<'a> {
    fn new(client: &'a ShodanClient, query: String) -> Self {
        Self {
            client,
            query,
            facets: Vec::new(),
            page: 1,
            minify: false,
        }
    }

    /// Add a facet to aggregate results
    #[must_use]
    pub fn facet(mut self, facet: impl Into<String>) -> Self {
        self.facets.push(facet.into());
        self
    }

    /// Add multiple facets
    #[must_use]
    pub fn facets<I, S>(mut self, facets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.facets.extend(facets.into_iter().map(Into::into));
        self
    }

    /// Set the page number (1-indexed)
    #[must_use]
    pub fn page(mut self, page: u32) -> Self {
        self.page = page;
        self
    }

    /// Return minimal results
    #[must_use]
    pub fn minify(mut self, minify: bool) -> Self {
        self.minify = minify;
        self
    }

    /// Execute the search
    pub async fn send(self) -> Result<SearchResults> {
        let mut params = vec![("query", self.query.as_str())];

        let page_str = self.page.to_string();
        if self.page > 1 {
            params.push(("page", &page_str));
        }

        let facets_str = self.facets.join(",");
        if !self.facets.is_empty() {
            params.push(("facets", &facets_str));
        }

        if self.minify {
            params.push(("minify", "true"));
        }

        self.client
            .get_with_query("/shodan/host/search", &params)
            .await
    }
}

/// Builder for count requests
pub struct CountRequestBuilder<'a> {
    client: &'a ShodanClient,
    query: String,
    facets: Vec<String>,
}

impl<'a> CountRequestBuilder<'a> {
    fn new(client: &'a ShodanClient, query: String) -> Self {
        Self {
            client,
            query,
            facets: Vec::new(),
        }
    }

    /// Add a facet to aggregate results
    #[must_use]
    pub fn facet(mut self, facet: impl Into<String>) -> Self {
        self.facets.push(facet.into());
        self
    }

    /// Add multiple facets
    #[must_use]
    pub fn facets<I, S>(mut self, facets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.facets.extend(facets.into_iter().map(Into::into));
        self
    }

    /// Execute the count request
    pub async fn send(self) -> Result<HostCount> {
        let mut params = vec![("query", self.query.as_str())];

        let facets_str = self.facets.join(",");
        if !self.facets.is_empty() {
            params.push(("facets", &facets_str));
        }

        self.client
            .get_with_query("/shodan/host/count", &params)
            .await
    }
}
