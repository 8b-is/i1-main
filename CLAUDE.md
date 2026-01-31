# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Modern async Rust client for the Shodan.io API with integrated network reconnaissance tools. This is a complete rewrite of the original 2016-era library.

## Build Commands

```bash
# Build all crates
cargo build --workspace

# Build with recon features
cargo build --workspace --features full-recon

# Run tests
cargo test --all

# Run a single test
cargo test -p shodan-client test_name -- --nocapture

# Lint (strict - must pass before commits)
cargo clippy -- -D warnings

# Format
cargo fmt

# Run examples (requires SHODAN_API_KEY env var)
cargo run --example basic_search
cargo run --example port_scan --features scanner

# Run the CLI
cargo run -p shodan-cli -- --help
./target/debug/showdi1 --help
```

## Architecture

Cargo workspace with five crates:

```
crates/
├── shodan-core/     # Core types, error handling (zero external deps)
├── shodan-client/   # HTTP client, API endpoints (reqwest + tokio)
├── shodan-recon/    # Network tools (scanner, whois) - optional
├── shodan/          # Facade crate, re-exports all public API
└── shodan-cli/      # Educational CLI (binary: showdi1)
```

### Key Files

- `crates/shodan-core/src/types/*.rs` - All API response types
- `crates/shodan-core/src/error.rs` - Error types
- `crates/shodan-client/src/client.rs` - Main `ShodanClient` implementation
- `crates/shodan-client/src/api/*.rs` - API endpoint modules

### API Design Pattern

Builder pattern with fluent API:

```rust
// Simple call
let host = client.search().host("8.8.8.8").await?;

// With options
let host = client.search()
    .host_with_options("8.8.8.8")
    .history(true)
    .send()
    .await?;

// Search with builder
let results = client.search()
    .query("apache")
    .facets(["port", "org"])
    .page(1)
    .send()
    .await?;
```

## Feature Flags

- `default` - Uses rustls TLS
- `rustls` / `native-tls` - TLS backend choice
- `recon` - Enable shodan-recon crate
- `scanner` - Port scanning (TCP connect)
- `whois` - WHOIS lookups
- `full-recon` - All recon features

## API Coverage

40+ endpoints organized by module:

| Module | Endpoints |
|--------|-----------|
| `search()` | host, query, count, facets, filters, tokens |
| `scan()` | ports, protocols, request, list, status |
| `alerts()` | create, list, get, delete, triggers, notifiers |
| `notifiers()` | list, get, create, delete, providers |
| `dns()` | domain, resolve, reverse |
| `directory()` | list, search, tags |
| `bulk()` | datasets, files (enterprise) |
| `org()` | info, add_member, remove_member (enterprise) |
| `account()` | profile, api_info |
| `tools()` | my_ip, http_headers |

## Testing

```bash
# Unit tests with mocks
cargo test --all

# With specific features
cargo test --all --features full-recon

# Live API tests (requires SHODAN_API_KEY env var)
SHODAN_API_KEY=xxx cargo test --features live-tests
```

## CLI (showdi1)

Educational command-line interface with defensive tools.

```bash
# Shodan API commands
showdi1 host 8.8.8.8              # Look up host
showdi1 search "apache port:80"   # Search database
showdi1 count "nginx"             # Count without credits
showdi1 dns domain example.com    # DNS lookup
showdi1 account                   # Check credits

# Defensive tools (geo-blocking)
showdi1 defend status             # Show blocking status
showdi1 defend geoblock add cn ru # Block countries
showdi1 defend ban 1.2.3.4        # Ban IP
showdi1 defend export             # Generate nftables rules

# Educational mode
showdi1 host 8.8.8.8 --explain    # Explains what command does
showdi1 defend geoblock codes     # Country code reference
```

Key files:
- `crates/shodan-cli/src/cli/args.rs` - Clap command definitions
- `crates/shodan-cli/src/cli/commands/*.rs` - Command implementations
- `crates/shodan-cli/src/defend/mod.rs` - Firewall rule generation
- `crates/shodan-cli/src/education/mod.rs` - Educational explanations

## Notes

- License: MIT OR Apache-2.0
- Min Rust: 1.75+ (async trait stabilization)
- DNS and trace features temporarily disabled (upstream API changes)
- Workspace uses strict clippy lints: `pedantic`, `nursery`, `cargo` enabled (some common patterns allowed via workspace lints)
- Tests use `wiremock` for HTTP mocking (no live API calls in unit tests)
