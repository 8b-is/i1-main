//! Directory API endpoints (saved queries).

use crate::ShodanClient;
use shodan_core::{PopularTags, QueryDirectory, Result};

/// Directory API endpoints for saved queries
pub struct DirectoryApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> DirectoryApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// List publicly saved search queries
    #[must_use]
    pub fn list(&self) -> QueryListBuilder<'a> {
        QueryListBuilder::new(self.client)
    }

    /// Search saved queries by keyword
    #[must_use]
    pub fn search(&self, query: impl Into<String>) -> QuerySearchBuilder<'a> {
        QuerySearchBuilder::new(self.client, query.into())
    }

    /// Get popular tags from saved queries
    pub async fn tags(&self, size: Option<u32>) -> Result<PopularTags> {
        let mut params = Vec::new();

        let size_str;
        if let Some(s) = size {
            size_str = s.to_string();
            params.push(("size", size_str.as_str()));
        }

        self.client
            .get_with_query("/shodan/query/tags", &params)
            .await
    }
}

/// Builder for listing saved queries
pub struct QueryListBuilder<'a> {
    client: &'a ShodanClient,
    page: u32,
    sort: Option<String>,
    order: Option<String>,
}

impl<'a> QueryListBuilder<'a> {
    fn new(client: &'a ShodanClient) -> Self {
        Self {
            client,
            page: 1,
            sort: None,
            order: None,
        }
    }

    /// Set the page number
    #[must_use]
    pub fn page(mut self, page: u32) -> Self {
        self.page = page;
        self
    }

    /// Sort by field (votes, timestamp)
    #[must_use]
    pub fn sort(mut self, field: impl Into<String>) -> Self {
        self.sort = Some(field.into());
        self
    }

    /// Sort order (asc, desc)
    #[must_use]
    pub fn order(mut self, order: impl Into<String>) -> Self {
        self.order = Some(order.into());
        self
    }

    /// Execute the request
    pub async fn send(self) -> Result<QueryDirectory> {
        let mut params = Vec::new();

        let page_str = self.page.to_string();
        if self.page > 1 {
            params.push(("page", page_str.as_str()));
        }

        let sort_str;
        if let Some(ref s) = self.sort {
            sort_str = s.clone();
            params.push(("sort", sort_str.as_str()));
        }

        let order_str;
        if let Some(ref o) = self.order {
            order_str = o.clone();
            params.push(("order", order_str.as_str()));
        }

        self.client.get_with_query("/shodan/query", &params).await
    }
}

/// Builder for searching saved queries
pub struct QuerySearchBuilder<'a> {
    client: &'a ShodanClient,
    query: String,
    page: u32,
}

impl<'a> QuerySearchBuilder<'a> {
    fn new(client: &'a ShodanClient, query: String) -> Self {
        Self {
            client,
            query,
            page: 1,
        }
    }

    /// Set the page number
    #[must_use]
    pub fn page(mut self, page: u32) -> Self {
        self.page = page;
        self
    }

    /// Execute the search
    pub async fn send(self) -> Result<QueryDirectory> {
        let mut params = vec![("query", self.query.as_str())];

        let page_str = self.page.to_string();
        if self.page > 1 {
            params.push(("page", &page_str));
        }

        self.client
            .get_with_query("/shodan/query/search", &params)
            .await
    }
}
