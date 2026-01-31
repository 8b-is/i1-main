# shodan-rust

[![Crates.io](https://img.shields.io/crates/v/shodan.svg)](https://crates.io/crates/shodan)
[![Documentation](https://docs.rs/shodan/badge.svg)](https://docs.rs/shodan)

Modern, async Rust client for the [Shodan.io](https://shodan.io) API with integrated network reconnaissance tools.

## Features

- **Complete API Coverage**: All 40+ Shodan API endpoints
- **Async/Await**: Built on tokio for high-performance async I/O
- **Strongly Typed**: Full type definitions for all API responses
- **Builder Pattern**: Ergonomic fluent API for complex queries
- **Network Recon** (optional): Port scanning, WHOIS lookups

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
shodan = "2.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

For network reconnaissance features:

```toml
[dependencies]
shodan = { version = "2.0", features = ["full-recon"] }
```

## Quick Start

```rust
use shodan::ShodanClient;

#[tokio::main]
async fn main() -> shodan::Result<()> {
    let client = ShodanClient::new("your-api-key");

    // Get host information
    let host = client.search().host("8.8.8.8").await?;
    println!("Organization: {:?}", host.org);
    println!("Open ports: {:?}", host.ports);

    // Search with facets
    let results = client.search()
        .query("apache country:US")
        .facets(["port", "org"])
        .send()
        .await?;

    println!("Total: {} results", results.total);

    Ok(())
}
```

## API Coverage

### Search Methods
- `client.search().host(ip)` - Host information
- `client.search().query(q).send()` - Search Shodan
- `client.search().count(q).send()` - Count results (no credits)
- `client.search().facets()` - Available facets
- `client.search().filters()` - Available filters

### Network Alerts
- `client.alerts().create(name).ip("1.2.3.4").send()` - Create alert
- `client.alerts().list()` - List all alerts
- `client.alerts().enable_trigger(id, trigger)` - Enable trigger

### DNS
- `client.dns().domain("example.com").send()` - Domain info
- `client.dns().resolve(&["host1", "host2"])` - Resolve hostnames
- `client.dns().reverse(&["1.2.3.4"])` - Reverse DNS

### On-Demand Scanning
- `client.scan().ports()` - List crawled ports
- `client.scan().request().ip("1.2.3.4").send()` - Request scan

### Account
- `client.account().api_info()` - API credits and plan
- `client.account().profile()` - Account profile

### Utility
- `client.tools().my_ip()` - Your public IP
- `client.tools().http_headers()` - HTTP headers

## Network Recon (Optional Features)

Enable with `--features full-recon`:

```rust
use shodan::recon::{Scanner, PortSpec};

let scanner = Scanner::new()
    .ports(PortSpec::Top100);

let result = scanner.scan("192.168.1.1".parse()?).await?;
for port in result.open_ports {
    println!("Port {} is open", port.port);
}
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | Core API client with rustls TLS |
| `rustls` | Use rustls for TLS (default) |
| `native-tls` | Use system native TLS |
| `recon` | Enable network recon module |
| `scanner` | Port scanning |
| `whois` | WHOIS lookups |
| `full-recon` | All recon features |

## License

MIT OR Apache-2.0
