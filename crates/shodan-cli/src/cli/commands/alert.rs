//! `showdi1 alert` - Network monitoring alerts.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{AlertArgs, AlertCommands};
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: AlertArgs) -> Result<()> {
    match args.command {
        AlertCommands::List => list_alerts(ctx).await,
        AlertCommands::Create { name, ips, expires } => create_alert(ctx, &name, &ips, expires).await,
        AlertCommands::Get { id } => get_alert(ctx, &id).await,
        AlertCommands::Delete { id } => delete_alert(ctx, &id).await,
        AlertCommands::Triggers => list_triggers(ctx).await,
    }
}

async fn list_alerts(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::alert_list().print();
    }

    let client = ctx.client()?;
    let alerts = client.alerts().list().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&alerts)?);
        }
        _ => {
            println!("{}", "Your Alerts:".bold());
            println!();

            if alerts.is_empty() {
                println!("  No alerts configured.");
                println!();
                println!("  Create one with: {} alert create <NAME> --ips <IP>", "showdi1".cyan());
            } else {
                for alert in &alerts {
                    println!("  {} {}", alert.id.cyan(), alert.name);
                    if !alert.filters.ip.is_empty() {
                        println!("    IPs: {}", alert.filters.ip.join(", "));
                    }
                    if let Some(exp) = &alert.expires {
                        println!("    Expires: {}", exp);
                    }
                    println!();
                }
            }
        }
    }

    Ok(())
}

async fn create_alert(ctx: Context, name: &str, ips: &[String], expires: u32) -> Result<()> {
    if ctx.explain {
        Explain::alert_create().print();
    }

    let client = ctx.client()?;

    let mut builder = client.alerts().create(name);

    for ip in ips {
        builder = builder.ip(ip);
    }

    if expires > 0 {
        builder = builder.expires_in_days(expires);
    }

    let alert = builder.send().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&alert)?);
        }
        _ => {
            println!("{}", "Alert created!".green().bold());
            println!();
            println!("  {} {}", "ID:".bold(), alert.id.cyan());
            println!("  {} {}", "Name:".bold(), alert.name);
            println!("  {} {}", "IPs:".bold(), alert.filters.ip.join(", "));

            if expires > 0 {
                println!("  {} {} days", "Expires in:".bold(), expires);
            } else {
                println!("  {} Never", "Expires:".bold());
            }

            println!();
            println!("View details: {} alert get {}", "showdi1".cyan(), alert.id);
        }
    }

    Ok(())
}

async fn get_alert(ctx: Context, id: &str) -> Result<()> {
    if ctx.explain {
        Explain::alert_get().print();
    }

    let client = ctx.client()?;
    let alert = client.alerts().get(id).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&alert)?);
        }
        _ => {
            println!("{} {}", "Alert:".bold(), alert.name.cyan());
            println!();
            println!("  {} {}", "ID:".bold(), alert.id);
            println!("  {} {}", "Created:".bold(), alert.created.as_deref().unwrap_or("?"));

            if let Some(exp) = &alert.expires {
                println!("  {} {}", "Expires:".bold(), exp);
            }

            println!();
            println!("{}", "Monitored IPs:".bold().underline());
            for ip in &alert.filters.ip {
                println!("  {}", ip);
            }

            if !alert.triggers.is_empty() {
                println!();
                println!("{}", "Triggers:".bold().underline());
                for (name, enabled) in &alert.triggers {
                    let status = if *enabled { "enabled".green() } else { "disabled".dimmed() };
                    println!("  {} [{}]", name, status);
                }
            }
        }
    }

    Ok(())
}

async fn delete_alert(ctx: Context, id: &str) -> Result<()> {
    if ctx.explain {
        Explain::alert_delete().print();
    }

    let client = ctx.client()?;
    client.alerts().delete(id).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "deleted": id }));
        }
        _ => {
            println!("{} Alert {} deleted.", "Success:".green().bold(), id.cyan());
        }
    }

    Ok(())
}

async fn list_triggers(ctx: Context) -> Result<()> {
    if ctx.explain {
        Explain::alert_triggers().print();
    }

    let client = ctx.client()?;
    let triggers = client.alerts().triggers().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&triggers)?);
        }
        _ => {
            println!("{}", "Available Alert Triggers:".bold());
            println!();

            for trigger in &triggers {
                println!("  {}", trigger.name.cyan().bold());
                if let Some(desc) = &trigger.description {
                    println!("    {}", desc);
                }
                if let Some(rule) = &trigger.rule {
                    println!("    Rule: {}", rule.dimmed());
                }
                println!();
            }
        }
    }

    Ok(())
}
