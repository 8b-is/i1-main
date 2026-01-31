use thiserror::Error;

/// Result type alias for Shodan operations
pub type Result<T> = std::result::Result<T, ShodanError>;

/// Errors that can occur when using the Shodan API
#[derive(Error, Debug)]
pub enum ShodanError {
    /// Authentication failed - invalid or missing API key
    #[error("authentication failed: invalid API key")]
    Unauthorized,

    /// Rate limit exceeded
    #[error("rate limit exceeded, retry after {retry_after:?} seconds")]
    RateLimited {
        /// Seconds to wait before retrying
        retry_after: Option<u64>,
    },

    /// Insufficient query or scan credits
    #[error("insufficient credits: {required} required, {available} available")]
    InsufficientCredits {
        /// Credits required for the operation
        required: u32,
        /// Credits currently available
        available: u32,
    },

    /// Resource not found
    #[error("resource not found: {resource}")]
    NotFound {
        /// Description of the resource that wasn't found
        resource: String,
    },

    /// API returned an error response
    #[error("API error ({code}): {message}")]
    Api {
        /// HTTP status code
        code: u16,
        /// Error message from the API
        message: String,
    },

    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    Http(String),

    /// Request timed out
    #[error("request timed out after {0} seconds")]
    Timeout(u64),

    /// Connection failed
    #[error("connection failed: {0}")]
    Connection(String),

    /// JSON parsing/serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid IP address format
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Invalid query syntax
    #[error("invalid query syntax: {0}")]
    InvalidQuery(String),

    /// Invalid URL
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// Port scan failed
    #[error("port scan failed: {0}")]
    Scan(String),

    /// WHOIS lookup failed
    #[error("WHOIS lookup failed: {0}")]
    Whois(String),

    /// DNS resolution failed
    #[error("DNS resolution failed: {0}")]
    Dns(String),

    /// Traceroute failed
    #[error("traceroute failed: {0}")]
    Trace(String),

    /// Generic internal error
    #[error("internal error: {0}")]
    Internal(String),
}

impl ShodanError {
    /// Returns true if the error is retryable
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Timeout(_) | Self::Connection(_)
        )
    }

    /// Returns true if the error is due to authentication
    #[must_use]
    pub const fn is_auth_error(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    /// Returns the HTTP status code if this is an API error
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized => Some(401),
            Self::RateLimited { .. } => Some(429),
            Self::NotFound { .. } => Some(404),
            Self::Api { code, .. } => Some(*code),
            _ => None,
        }
    }
}
