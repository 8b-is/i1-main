//! Basic example demonstrating Shodan API usage.
//!
//! Run with: cargo run --example basic_search
//!
//! Set the SHODAN_API_KEY environment variable before running.

use shodan::{ShodanClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Get API key from environment
    let api_key = std::env::var("SHODAN_API_KEY")
        .expect("SHODAN_API_KEY environment variable is required");

    // Create client
    let client = ShodanClient::new(&api_key);

    // Get API info (credits, plan, etc.)
    println!("=== API Info ===");
    let info = client.account().api_info().await?;
    println!("Plan: {:?}", info.plan);
    println!("Query credits: {}", info.query_credits);
    println!("Scan credits: {}", info.scan_credits);
    println!();

    // Get your public IP
    println!("=== My IP ===");
    let my_ip = client.tools().my_ip().await?;
    println!("Your IP: {}", my_ip);
    println!();

    // Look up a well-known host (Google DNS)
    println!("=== Host Info: 8.8.8.8 ===");
    let host = client.search().host("8.8.8.8").await?;
    println!("IP: {}", host.ip_str);
    println!("Organization: {:?}", host.org);
    println!("ASN: {:?}", host.asn);
    println!("Ports: {:?}", host.ports);
    println!("Hostnames: {:?}", host.hostnames);
    println!();

    // Search with count (doesn't use query credits)
    println!("=== Search Count ===");
    let count = client.search()
        .count("port:22")
        .facet("country")
        .send()
        .await?;
    println!("Total SSH servers: {}", count.total);
    if let Some(countries) = count.facets.get("country") {
        println!("Top countries:");
        for facet in countries.iter().take(5) {
            println!("  {:?}: {}", facet.value, facet.count);
        }
    }
    println!();

    // List available search filters
    println!("=== Available Filters ===");
    let filters = client.search().filters().await?;
    println!("Filters: {} available", filters.len());
    for filter in filters.iter().take(10) {
        println!("  - {}", filter);
    }
    if filters.len() > 10 {
        println!("  ... and {} more", filters.len() - 10);
    }

    Ok(())
}
