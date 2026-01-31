//! # shodan-cli
//!
//! Educational command-line interface for Shodan.io with integrated defensive tools.
//!
//! ## Features
//!
//! - **Shodan API access**: Search, host lookup, DNS, scanning, alerts
//! - **Educational mode**: `--explain` flag explains what commands do
//! - **Defend module**: Geo-blocking, IP banning, nftables rule generation
//! - **Interactive shell**: REPL with tab completion
//! - **Multiple output formats**: Pretty tables, JSON, CSV, YAML

pub mod cli;
pub mod config;
pub mod defend;
pub mod education;
pub mod interactive;
pub mod output;

pub use cli::run;
