//! i1-srv: Distributed DNS threat intelligence server.
//!
//! Serves threat data as DNS records, creating a decentralized control plane
//! where cached DNS responses provide protection even when servers go dark.
//!
//! # Architecture
//!
//! Each i1-srv node is a DNS authority for delegated zones under i1.is:
//! - `bl.i1.is` - DNSBL blocklist (reversed-IP -> 127.0.0.X return codes)
//! - `rep.i1.is` - IP reputation metadata (TXT records)
//! - `geo.i1.is` - Country-level blocks
//! - `asn.i1.is` - ASN-level blocks
//! - `sig.i1.is` - Signal records (near-zero TTL version checks)
//!
//! # Encoding
//!
//! Threat data is encoded into DNS records using two strategies:
//! - **Simple**: Semicolon-separated `k=v` pairs in TXT records (human-readable via `dig`)
//! - **Complex**: CBOR+Base64 in TXT records, prefixed with `cbor:` for overflow data

pub mod authority;
pub mod config;
pub mod encoding;
pub mod error;
pub mod node;
pub mod server;
pub mod sync;
pub mod trust;

// Re-exports for convenience.
pub use config::ServerConfig;
pub use error::SrvError;

/// Result type for i1-srv operations.
pub type Result<T> = std::result::Result<T, SrvError>;
