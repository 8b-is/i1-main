//! Command-line argument definitions using clap.

use clap::{Parser, Subcommand, Args};
use crate::output::OutputFormat;

/// Educational command-line interface for Shodan.io
///
/// Find exposed services, lookup hosts, and defend your network.
/// Use --explain on any command to learn what it does.
///
/// Get your API key at: https://account.shodan.io
#[derive(Parser, Debug)]
#[command(name = "showdi1")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    /// Shodan API key (or set SHODAN_API_KEY env var)
    #[arg(short = 'k', long, env = "SHODAN_API_KEY", global = true)]
    pub api_key: Option<String>,

    /// Output format
    #[arg(short, long, global = true, value_enum)]
    pub output: Option<OutputFormat>,

    /// Explain what this command does (educational mode)
    #[arg(long, global = true)]
    pub explain: bool,

    /// Increase verbosity
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Look up information about a specific IP address
    Host(HostArgs),

    /// Search Shodan's database
    Search(SearchArgs),

    /// Count results without using query credits
    Count(CountArgs),

    /// DNS lookups and domain information
    Dns(DnsArgs),

    /// On-demand scanning operations
    Scan(ScanArgs),

    /// Network monitoring alerts
    Alert(AlertArgs),

    /// Account and API key information
    Account(AccountArgs),

    /// Show your public IP address
    Myip,

    /// Defensive tools: geo-blocking, IP bans, firewall rules
    Defend(DefendArgs),

    /// Start interactive shell mode
    Shell,

    /// Manage CLI configuration
    Config(ConfigArgs),
}

// ============================================================================
// Host command
// ============================================================================

#[derive(Args, Debug)]
pub struct HostArgs {
    /// IP address to look up
    pub ip: String,

    /// Include historical data
    #[arg(long)]
    pub history: bool,

    /// Return minimal information
    #[arg(long)]
    pub minify: bool,
}

// ============================================================================
// Search command
// ============================================================================

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Shodan query (e.g., "apache country:US port:80")
    pub query: String,

    /// Add facets to aggregate results (e.g., port, country, org)
    #[arg(short, long)]
    pub facets: Vec<String>,

    /// Page number (1-indexed)
    #[arg(short, long, default_value = "1")]
    pub page: u32,

    /// Return minimal results
    #[arg(long)]
    pub minify: bool,
}

// ============================================================================
// Count command
// ============================================================================

#[derive(Args, Debug)]
pub struct CountArgs {
    /// Shodan query to count
    pub query: String,

    /// Add facets to aggregate results
    #[arg(short, long)]
    pub facets: Vec<String>,
}

// ============================================================================
// DNS command
// ============================================================================

#[derive(Args, Debug)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub command: DnsCommands,
}

#[derive(Subcommand, Debug)]
pub enum DnsCommands {
    /// Get domain information including subdomains and DNS records
    Domain {
        /// Domain name to look up
        domain: String,

        /// Include historical DNS records
        #[arg(long)]
        history: bool,

        /// Filter by record type (A, AAAA, MX, NS, TXT, SOA, CNAME)
        #[arg(short = 't', long)]
        record_type: Option<String>,
    },

    /// Resolve hostnames to IP addresses
    Resolve {
        /// Hostnames to resolve (comma-separated or multiple args)
        hostnames: Vec<String>,
    },

    /// Reverse DNS lookup
    Reverse {
        /// IP addresses (comma-separated or multiple args)
        ips: Vec<String>,
    },
}

// ============================================================================
// Scan command
// ============================================================================

#[derive(Args, Debug)]
pub struct ScanArgs {
    #[command(subcommand)]
    pub command: ScanCommands,
}

#[derive(Subcommand, Debug)]
pub enum ScanCommands {
    /// List ports that Shodan crawlers monitor
    Ports,

    /// List available scan protocols
    Protocols,

    /// Request an on-demand scan (uses scan credits)
    Request {
        /// IP address or CIDR range to scan
        target: String,

        /// Specific service to scan for
        #[arg(short, long)]
        service: Option<String>,
    },

    /// List your active scans
    List,

    /// Get status of a specific scan
    Status {
        /// Scan ID to check
        scan_id: String,
    },
}

// ============================================================================
// Alert command
// ============================================================================

#[derive(Args, Debug)]
pub struct AlertArgs {
    #[command(subcommand)]
    pub command: AlertCommands,
}

#[derive(Subcommand, Debug)]
pub enum AlertCommands {
    /// List all your alerts
    List,

    /// Create a new network alert
    Create {
        /// Alert name
        name: String,

        /// IP addresses or CIDR ranges to monitor
        #[arg(short, long, required = true)]
        ips: Vec<String>,

        /// Days until expiration (0 = never)
        #[arg(long, default_value = "0")]
        expires: u32,
    },

    /// Get details of a specific alert
    Get {
        /// Alert ID
        id: String,
    },

    /// Delete an alert
    Delete {
        /// Alert ID
        id: String,
    },

    /// List available trigger types
    Triggers,
}

// ============================================================================
// Account command
// ============================================================================

#[derive(Args, Debug)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: Option<AccountCommands>,
}

#[derive(Subcommand, Debug)]
pub enum AccountCommands {
    /// Show account profile
    Profile,

    /// Show API usage and credits
    Credits,
}

// ============================================================================
// Defend command
// ============================================================================

#[derive(Args, Debug)]
pub struct DefendArgs {
    #[command(subcommand)]
    pub command: DefendCommands,
}

#[derive(Subcommand, Debug)]
pub enum DefendCommands {
    /// Show current blocking status
    Status {
        /// Quick one-line status
        #[arg(long)]
        quick: bool,
    },

    /// Manage country-level geo-blocking
    Geoblock(GeoblockArgs),

    /// Ban specific IPs or networks
    Ban {
        /// IP address, CIDR range, or --as for AS number
        target: String,

        /// Ban by AS number (e.g., AS12345)
        #[arg(long = "as")]
        as_number: bool,

        /// Preview without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Remove a ban
    Unban {
        /// IP address, CIDR range, or AS number to unban
        target: String,
    },

    /// Manage whitelisted IPs (never blocked)
    Whitelist(WhitelistArgs),

    /// Export firewall rules
    Export {
        /// Output format: nftables, iptables, pf
        #[arg(long, default_value = "nftables")]
        format: String,
    },

    /// Import IPs to block from file or stdin
    Import {
        /// Read from stdin
        #[arg(long)]
        stdin: bool,

        /// File to import from
        file: Option<String>,
    },

    /// Undo the last change
    Undo,

    /// Disable all blocking (emergency)
    Disable,
}

#[derive(Args, Debug)]
pub struct GeoblockArgs {
    #[command(subcommand)]
    pub command: GeoblockCommands,
}

#[derive(Subcommand, Debug)]
pub enum GeoblockCommands {
    /// List currently blocked countries
    List,

    /// Block countries by code (e.g., cn ru ro)
    Add {
        /// Country codes to block
        countries: Vec<String>,

        /// Preview without applying
        #[arg(long)]
        dry_run: bool,
    },

    /// Unblock a country
    Remove {
        /// Country code to unblock
        country: String,
    },

    /// Update IP ranges from ipdeny.com
    Update,

    /// Show country code reference
    Codes,
}

#[derive(Args, Debug)]
pub struct WhitelistArgs {
    #[command(subcommand)]
    pub command: WhitelistCommands,
}

#[derive(Subcommand, Debug)]
pub enum WhitelistCommands {
    /// Show whitelisted IPs
    Show,

    /// Add IP to whitelist
    Add {
        /// IP address or CIDR range
        ip: String,
    },

    /// Remove IP from whitelist
    Remove {
        /// IP address or CIDR range
        ip: String,
    },
}

// ============================================================================
// Config command
// ============================================================================

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set a configuration value
    Set {
        /// Key to set (e.g., api_key, output_format)
        key: String,

        /// Value to set
        value: String,
    },

    /// Show config file path
    Path,
}
