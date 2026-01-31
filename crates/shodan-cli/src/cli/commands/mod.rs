//! Command implementations.

pub mod account;
pub mod alert;
pub mod config;
pub mod count;
pub mod defend;
pub mod dns;
pub mod host;
pub mod myip;
pub mod scan;
pub mod search;
pub mod shell;

use crate::output::OutputFormat;

/// Shared context for all commands.
#[derive(Debug, Clone)]
pub struct Context {
    /// Shodan API key
    pub api_key: Option<String>,

    /// Output format
    pub output_format: OutputFormat,

    /// Whether to show educational explanations
    pub explain: bool,

    /// Verbose output
    pub verbose: bool,

    /// Disable colors
    pub no_color: bool,
}

impl Context {
    /// Get the API key, returning an error if not set.
    pub fn require_api_key(&self) -> anyhow::Result<&str> {
        self.api_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "API key required.\n\n\
                 Set it with one of:\n  \
                 1. --api-key <KEY>\n  \
                 2. SHODAN_API_KEY environment variable\n  \
                 3. showdi1 config set api_key <KEY>\n\n\
                 Get your key at: https://account.shodan.io"
            )
        })
    }

    /// Create a Shodan client with the configured API key.
    pub fn client(&self) -> anyhow::Result<shodan::ShodanClient> {
        let key = self.require_api_key()?;
        Ok(shodan::ShodanClient::new(key))
    }
}
