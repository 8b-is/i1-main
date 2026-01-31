//! `showdi1 account` - Account and API information.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{AccountArgs, AccountCommands};
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: AccountArgs) -> Result<()> {
    // Default to showing credits if no subcommand
    match args.command.unwrap_or(AccountCommands::Credits) {
        AccountCommands::Profile => show_profile(ctx).await,
        AccountCommands::Credits => show_credits(ctx).await,
    }
}

async fn show_profile(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::account_profile().print();
    }

    let client = ctx.client()?;
    let profile = client.account().profile().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&profile)?);
        }
        _ => {
            println!("{}: {}", "Display Name".bold(), profile.display_name.as_deref().unwrap_or("N/A"));
            println!("{}: {}", "Member".bold(), if profile.member { "Yes" } else { "No" });
            println!("{}: {}", "Credits".bold(), profile.credits);
            if let Some(created) = &profile.created {
                println!("{}: {}", "Created".bold(), created);
            }
        }
    }

    Ok(())
}

async fn show_credits(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::account_credits().print();
    }

    let client = ctx.client()?;
    let info = client.account().api_info().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&info)?);
        }
        OutputFormat::Csv => {
            println!("plan,query_credits,scan_credits");
            println!("{},{},{}",
                info.plan.as_deref().unwrap_or("unknown"),
                info.query_credits,
                info.scan_credits
            );
        }
        OutputFormat::Pretty => {
            println!("{}", "API Credits".bold().underline());
            println!();

            let query_color = if info.query_credits > 50 {
                "green"
            } else if info.query_credits > 10 {
                "yellow"
            } else {
                "red"
            };

            println!("  {} {}",
                "Query Credits:".bold(),
                format!("{}", info.query_credits).color(query_color)
            );
            println!("  {} {}",
                "Scan Credits:".bold(),
                info.scan_credits
            );
            println!("  {} {}",
                "Plan:".bold(),
                info.plan.as_deref().unwrap_or("Free")
            );

            if info.query_credits <= 10 {
                println!();
                println!("{}", "Tip: Use 'count' instead of 'search' to preview without using credits".yellow());
            }
        }
    }

    Ok(())
}
