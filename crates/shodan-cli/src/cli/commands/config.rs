//! `showdi1 config` - CLI configuration management.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{ConfigArgs, ConfigCommands};
use crate::config::Config;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: ConfigArgs) -> Result<()> {
    match args.command {
        ConfigCommands::Show => show_config(ctx).await,
        ConfigCommands::Set { key, value } => set_config(ctx, &key, &value).await,
        ConfigCommands::Path => show_path(ctx).await,
    }
}

async fn show_config(ctx: Context) -> Result<()> {
    let config = Config::load()?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&config)?);
        }
        _ => {
            println!("{}", "Current Configuration:".bold());
            println!();

            // API Key (masked)
            let api_display = config.api_key.as_ref().map(|k| {
                if k.len() > 8 {
                    format!("{}...{}", &k[..4], &k[k.len()-4..])
                } else {
                    "****".to_string()
                }
            }).unwrap_or_else(|| "(not set)".dimmed().to_string());
            println!("  {} {}", "api_key:".bold(), api_display);

            // Output format
            println!("  {} {:?}", "output_format:".bold(),
                config.output_format.unwrap_or(OutputFormat::Pretty));

            // Other settings
            println!("  {} {}", "show_tips:".bold(), config.show_tips);
            println!("  {} {}", "explain_by_default:".bold(), config.explain_by_default);
        }
    }

    Ok(())
}

async fn set_config(_ctx: Context, key: &str, value: &str) -> Result<()> {
    let mut config = Config::load()?;

    match key {
        "api_key" => {
            config.api_key = Some(value.to_string());
            println!("{} API key set.", "Success:".green().bold());
        }
        "output_format" | "output" => {
            config.output_format = Some(value.parse()?);
            println!("{} Output format set to {}.", "Success:".green().bold(), value.cyan());
        }
        "show_tips" => {
            config.show_tips = value.parse()?;
            println!("{} show_tips set to {}.", "Success:".green().bold(), value);
        }
        "explain_by_default" | "explain" => {
            config.explain_by_default = value.parse()?;
            println!("{} explain_by_default set to {}.", "Success:".green().bold(), value);
        }
        _ => {
            anyhow::bail!(
                "Unknown config key: {}\n\n\
                 Available keys:\n  \
                 api_key          - Your Shodan API key\n  \
                 output_format    - Default output format (pretty/json/csv/yaml)\n  \
                 show_tips        - Show helpful tips (true/false)\n  \
                 explain_by_default - Always explain commands (true/false)",
                key
            );
        }
    }

    config.save()?;

    Ok(())
}

async fn show_path(_ctx: Context) -> Result<()> {
    let path = Config::path()?;
    println!("{}", path.display());
    Ok(())
}
