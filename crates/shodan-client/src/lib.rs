//! HTTP client for the Shodan API.
//!
//! This crate provides the main [`ShodanClient`] for interacting with the Shodan API.

#![doc(html_root_url = "https://docs.rs/shodan-client/2.0.0")]

mod client;
mod config;
pub mod api;

pub use client::{ShodanClient, ShodanClientBuilder};
pub use config::*;
pub use shodan_core::{Result, ShodanError};
