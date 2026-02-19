//! Error types for the i1-srv DNS threat intelligence server.

use thiserror::Error;

/// Errors that can occur in i1-srv operations.
#[derive(Error, Debug)]
pub enum SrvError {
    /// DNS server failed to bind or start.
    #[error("dns server error: {0}")]
    Server(String),

    /// Failed to build or update a DNS zone.
    #[error("zone error: {0}")]
    Zone(String),

    /// Record encoding failed (DNSBL, TXT, CBOR).
    #[error("encoding error: {0}")]
    Encoding(String),

    /// CBOR serialization/deserialization failed.
    #[error("cbor error: {0}")]
    Cbor(String),

    /// Configuration is invalid or missing required fields.
    #[error("config error: {0}")]
    Config(String),

    /// State file read/write failed.
    #[error("state error: {0}")]
    State(String),

    /// Node identity or certificate error.
    #[error("identity error: {0}")]
    Identity(String),

    /// DANE/TLSA trust verification failed.
    #[error("trust verification failed: {0}")]
    Trust(String),

    /// Gossip/sync protocol error.
    #[error("sync error: {0}")]
    Sync(String),

    /// DNS query to another server failed.
    #[error("dns query failed: {0}")]
    DnsQuery(String),

    /// TTL manipulation detected.
    #[error("ttl manipulation detected: expected {expected}s, observed {observed}s from {resolver}")]
    TtlManipulation {
        expected: u32,
        observed: u32,
        resolver: String,
    },

    /// IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
