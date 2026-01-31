//! Example demonstrating port scanning with the recon module.
//!
//! Run with: cargo run --example port_scan --features scanner
//!
//! Note: This example performs active network scanning.
//! Only use on networks you have permission to scan.

#[cfg(feature = "scanner")]
use shodan::recon::scanner::{Scanner, PortSpec, ScanConfig};

#[tokio::main]
async fn main() {
    #[cfg(feature = "scanner")]
    {
        use std::net::IpAddr;
        use std::time::Duration;

        // Parse target from command line or use default
        let target: IpAddr = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| "127.0.0.1".parse().unwrap());

        println!("=== Port Scanner Example ===");
        println!("Target: {}", target);
        println!();

        // Create scanner with custom config
        let scanner = Scanner::new()
            .ports(PortSpec::List(vec![22, 80, 443, 8080, 8443]))
            .timeout(Duration::from_secs(2));

        println!("Scanning ports: 22, 80, 443, 8080, 8443...");

        match scanner.scan(target).await {
            Ok(result) => {
                println!("\nScan completed in {:?}", result.scan_time);
                println!("Open ports:");
                for port in &result.open_ports {
                    println!("  {} - {:?}", port.port, port.state);
                }
                if result.open_ports.is_empty() {
                    println!("  (none found)");
                }
            }
            Err(e) => {
                eprintln!("Scan failed: {}", e);
            }
        }
    }

    #[cfg(not(feature = "scanner"))]
    {
        println!("Scanner feature not enabled.");
        println!("Run with: cargo run --example port_scan --features scanner");
    }
}
