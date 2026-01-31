use thiserror::Error;

/// Result type alias for reconnaissance operations
pub type ReconResult<T> = std::result::Result<T, ReconError>;

/// Errors from reconnaissance tools
#[derive(Error, Debug)]
pub enum ReconError {
    /// Port scan error
    #[error("scan error: {0}")]
    Scan(String),

    /// WHOIS lookup error
    #[error("WHOIS error: {0}")]
    Whois(String),

    /// DNS resolution error
    #[error("DNS error: {0}")]
    Dns(String),

    /// Traceroute error
    #[error("trace error: {0}")]
    Trace(String),

    /// Network I/O error
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),

    /// Invalid IP address
    #[error("invalid IP address: {0}")]
    InvalidIp(String),

    /// Timeout
    #[error("operation timed out")]
    Timeout,

    /// Permission denied (requires root/admin)
    #[error("permission denied: {0}")]
    PermissionDenied(String),
}

impl From<ReconError> for shodan_core::ShodanError {
    fn from(err: ReconError) -> Self {
        match err {
            ReconError::Scan(msg) => Self::Scan(msg),
            ReconError::Whois(msg) => Self::Whois(msg),
            ReconError::Dns(msg) => Self::Dns(msg),
            ReconError::Trace(msg) => Self::Trace(msg),
            ReconError::Network(e) => Self::Connection(e.to_string()),
            ReconError::InvalidIp(ip) => Self::InvalidIp(ip),
            ReconError::Timeout => Self::Timeout(0),
            ReconError::PermissionDenied(msg) => Self::Internal(msg),
        }
    }
}
