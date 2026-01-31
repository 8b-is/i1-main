//! Modern Rust client for the Shodan.io API with integrated network reconnaissance tools.
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use shodan::ShodanClient;
//!
//! #[tokio::main]
//! async fn main() -> shodan::Result<()> {
//!     let client = ShodanClient::new("your-api-key");
//!
//!     // Get host information
//!     let host = client.search().host("8.8.8.8").await?;
//!     println!("Organization: {:?}", host.org);
//!     println!("Open ports: {:?}", host.ports);
//!
//!     // Search with query
//!     let results = client.search()
//!         .query("apache country:US")
//!         .facets(["port", "org"])
//!         .send()
//!         .await?;
//!
//!     println!("Total: {} results", results.total);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Features
//!
//! - `default` - Uses rustls for TLS
//! - `rustls` - Use rustls for TLS (recommended)
//! - `native-tls` - Use system native TLS
//! - `recon` - Enable network reconnaissance tools
//! - `scanner` - Enable port scanning (requires `recon`)
//! - `whois` - Enable WHOIS lookups (requires `recon`)
//! - `dns` - Enable DNS resolution (requires `recon`)
//! - `trace` - Enable traceroute (requires `recon`)
//! - `full-recon` - Enable all reconnaissance tools

#![doc(html_root_url = "https://docs.rs/shodan/2.0.0")]

// Re-export core types
pub use shodan_core::*;

// Re-export client
pub use shodan_client::{ShodanClient, ShodanClientBuilder};

// Re-export recon if enabled
#[cfg(feature = "recon")]
pub use shodan_recon as recon;

// Re-export runtime for convenience
pub use tokio;
pub use serde;
pub use serde_json;
