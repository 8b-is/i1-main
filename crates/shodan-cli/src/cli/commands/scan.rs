//! `showdi1 scan` - On-demand scanning operations.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{ScanArgs, ScanCommands};
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: ScanArgs) -> Result<()> {
    match args.command {
        ScanCommands::Ports => list_ports(ctx).await,
        ScanCommands::Protocols => list_protocols(ctx).await,
        ScanCommands::Request { target, service } => request_scan(ctx, &target, service.as_deref()).await,
        ScanCommands::List => list_scans(ctx).await,
        ScanCommands::Status { scan_id } => scan_status(ctx, &scan_id).await,
    }
}

async fn list_ports(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::scan_ports().print();
    }

    let client = ctx.client()?;
    let ports = client.scan().ports().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&ports)?);
        }
        _ => {
            println!("{}", "Ports monitored by Shodan crawlers:".bold());
            println!();

            // Group ports by range
            let mut sorted = ports.clone();
            sorted.sort();

            for chunk in sorted.chunks(10) {
                let line: String = chunk.iter()
                    .map(|p| format!("{:>5}", p))
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("  {}", line);
            }

            println!();
            println!("{}", format!("Total: {} ports", ports.len()).dimmed());
        }
    }

    Ok(())
}

async fn list_protocols(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::scan_protocols().print();
    }

    let client = ctx.client()?;
    let protocols = client.scan().protocols().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&protocols)?);
        }
        _ => {
            println!("{}", "Available scan protocols:".bold());
            println!();

            for (name, description) in &protocols {
                println!("  {:20} {}", name.cyan(), description.dimmed());
            }
        }
    }

    Ok(())
}

async fn request_scan(ctx: Context, target: &str, service: Option<&str>) -> Result<()> {
    if ctx.explain {
        Explain::scan_request(target).print();
    }

    let client = ctx.client()?;

    // Check credits first
    let info = client.account().api_info().await?;
    if info.scan_credits <= 0 {
        anyhow::bail!(
            "No scan credits available.\n\
             Current: {} scan credits\n\n\
             Upgrade your plan at: https://account.shodan.io",
            info.scan_credits
        );
    }

    println!("{} This will use 1 scan credit.", "Warning:".yellow().bold());
    println!("You have {} scan credits remaining.", info.scan_credits);

    let mut builder = client.scan().request().ip(target);

    if let Some(svc) = service {
        builder = builder.service(svc);
    }

    let result = builder.send().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        _ => {
            println!();
            println!("{}", "Scan submitted!".green().bold());
            println!("  {} {}", "Scan ID:".bold(), result.id);
            println!("  {} {}", "IPs:".bold(), result.count);
            println!("  {} {}", "Credits Used:".bold(), result.credits_left);
            println!();
            println!("Check status with: {} scan status {}", "showdi1".cyan(), result.id);
        }
    }

    Ok(())
}

async fn list_scans(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::scan_list().print();
    }

    let client = ctx.client()?;
    let scans = client.scan().list().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&scans)?);
        }
        _ => {
            println!("{}", "Your Scans:".bold());
            println!();

            if scans.matches.is_empty() {
                println!("  No active scans.");
            } else {
                for scan in &scans.matches {
                    let status_str = scan.status.to_string();
                    let status_color = match scan.status {
                        shodan_core::ScanState::Done => "green",
                        shodan_core::ScanState::Processing => "yellow",
                        shodan_core::ScanState::Queue => "cyan",
                        _ => "white",
                    };

                    println!("  {} {:12} {}",
                        scan.id.cyan(),
                        status_str.color(status_color),
                        scan.created.as_deref().unwrap_or("").dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}

async fn scan_status(ctx: Context, scan_id: &str) -> Result<()> {
    if ctx.explain {
        Explain::scan_status().print();
    }

    let client = ctx.client()?;
    let status = client.scan().status(scan_id).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        _ => {
            println!("{} {}", "Scan ID:".bold(), scan_id.cyan());
            println!("{} {}", "Status:".bold(),
                match status.status {
                    shodan_core::ScanState::Done => "Done".green().to_string(),
                    shodan_core::ScanState::Processing => "Processing".yellow().to_string(),
                    shodan_core::ScanState::Queue => "In Queue".cyan().to_string(),
                    shodan_core::ScanState::Submitting => "Submitting".cyan().to_string(),
                }
            );

            if let Some(created) = &status.created {
                println!("{} {}", "Created:".bold(), created);
            }
        }
    }

    Ok(())
}
