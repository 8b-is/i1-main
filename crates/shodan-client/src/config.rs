//! Client configuration types.

use std::time::Duration;

/// Retry configuration for failed requests
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,

    /// Initial backoff duration
    pub initial_backoff: Duration,

    /// Maximum backoff duration
    pub max_backoff: Duration,

    /// Whether to retry on rate limit errors
    pub retry_on_rate_limit: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            retry_on_rate_limit: true,
        }
    }
}

impl RetryConfig {
    /// Create a new retry configuration
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            retry_on_rate_limit: true,
        }
    }

    /// Set maximum retries
    #[must_use]
    pub const fn max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set initial backoff duration
    #[must_use]
    pub const fn initial_backoff(mut self, duration: Duration) -> Self {
        self.initial_backoff = duration;
        self
    }

    /// Set maximum backoff duration
    #[must_use]
    pub const fn max_backoff(mut self, duration: Duration) -> Self {
        self.max_backoff = duration;
        self
    }

    /// Calculate backoff for a given attempt
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let backoff = self.initial_backoff.as_millis() as u64 * 2u64.pow(attempt);
        let max = self.max_backoff.as_millis() as u64;
        Duration::from_millis(backoff.min(max))
    }
}
