//! Network reconnaissance tools integration for Shodan.
//!
//! This crate provides optional integrations with network security tools.

#![doc(html_root_url = "https://docs.rs/shodan-recon/2.0.0")]

mod error;

#[cfg(feature = "scanner")]
pub mod scanner;

#[cfg(feature = "whois")]
pub mod whois;

// Temporarily disabled due to API changes
// #[cfg(feature = "dns")]
// pub mod dns;

// #[cfg(feature = "trace")]
// pub mod trace;

pub mod enrichment;

pub use error::{ReconError, ReconResult};
