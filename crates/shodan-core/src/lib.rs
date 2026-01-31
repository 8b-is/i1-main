//! Core types and traits for the Shodan API client.
//!
//! This crate provides the foundational types used across the Shodan library:
//!
//! - **Types**: Strongly-typed representations of all Shodan API responses
//! - **Errors**: Comprehensive error handling with [`ShodanError`]
//!
//! # Example
//!
//! ```rust,ignore
//! use shodan_core::{HostInfo, ShodanError, Result};
//!
//! fn process_host(host: HostInfo) -> Result<()> {
//!     println!("IP: {}", host.ip_str);
//!     println!("Ports: {:?}", host.ports);
//!     Ok(())
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/shodan-core/2.0.0")]

mod error;
pub mod types;

pub use error::{Result, ShodanError};
pub use types::*;
