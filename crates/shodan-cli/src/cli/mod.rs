//! CLI argument parsing and command dispatch.

pub mod args;
pub mod commands;

use anyhow::Result;
use args::{Cli, Commands};
use clap::Parser;

use crate::config::Config;
use crate::output::OutputFormat;

/// Run the CLI application.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let config = Config::load()?;

    // Determine output format
    let output_format = cli.output.unwrap_or(OutputFormat::Pretty);

    // Get API key from CLI, env, or config
    let api_key = cli
        .api_key
        .or_else(|| std::env::var("SHODAN_API_KEY").ok())
        .or_else(|| config.api_key.clone());

    // Create context for commands
    let ctx = commands::Context {
        api_key,
        output_format,
        explain: cli.explain,
        verbose: cli.verbose,
        no_color: cli.no_color,
    };

    // Dispatch to appropriate command
    match cli.command {
        Commands::Host(args) => commands::host::execute(ctx, args).await,
        Commands::Search(args) => commands::search::execute(ctx, args).await,
        Commands::Count(args) => commands::count::execute(ctx, args).await,
        Commands::Dns(args) => commands::dns::execute(ctx, args).await,
        Commands::Scan(args) => commands::scan::execute(ctx, args).await,
        Commands::Alert(args) => commands::alert::execute(ctx, args).await,
        Commands::Account(args) => commands::account::execute(ctx, args).await,
        Commands::Myip => commands::myip::execute(ctx).await,
        Commands::Defend(args) => commands::defend::execute(ctx, args).await,
        Commands::Shell => commands::shell::execute(ctx).await,
        Commands::Config(args) => commands::config::execute(ctx, args).await,
    }
}
