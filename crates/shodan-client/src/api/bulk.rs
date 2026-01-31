//! Bulk data API endpoints (Enterprise).

use crate::ShodanClient;
use shodan_core::{Dataset, DatasetFile, Result};

/// Bulk data API endpoints (Enterprise only)
pub struct BulkApi<'a> {
    client: &'a ShodanClient,
}

impl<'a> BulkApi<'a> {
    pub(crate) fn new(client: &'a ShodanClient) -> Self {
        Self { client }
    }

    /// List all available datasets
    pub async fn datasets(&self) -> Result<Vec<Dataset>> {
        self.client.get("/shodan/data").await
    }

    /// List files in a specific dataset
    pub async fn files(&self, dataset: &str) -> Result<Vec<DatasetFile>> {
        self.client
            .get(&format!("/shodan/data/{dataset}"))
            .await
    }
}
