//! showdi1 - Educational Shodan CLI
//!
//! A command-line interface for Shodan.io that teaches as it works.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    shodan_cli::run().await
}
