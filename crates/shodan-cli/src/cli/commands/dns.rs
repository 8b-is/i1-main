//! `showdi1 dns` - DNS lookups and domain information.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{DnsArgs, DnsCommands};
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: DnsArgs) -> Result<()> {
    match args.command {
        DnsCommands::Domain { domain, history, record_type } => {
            domain_lookup(ctx, &domain, history, record_type.as_deref()).await
        }
        DnsCommands::Resolve { hostnames } => {
            resolve_hostnames(ctx, &hostnames).await
        }
        DnsCommands::Reverse { ips } => {
            reverse_lookup(ctx, &ips).await
        }
    }
}

async fn domain_lookup(
    ctx: Context,
    domain: &str,
    history: bool,
    record_type: Option<&str>,
) -> Result<()> {
    if ctx.explain {
        Explain::dns_domain(domain).print();
    }

    let client = ctx.client()?;

    let mut builder = client.dns().domain(domain);

    if history {
        builder = builder.history(true);
    }

    if let Some(rt) = record_type {
        builder = builder.record_type(rt);
    }

    let info = builder.send().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&info)?);
        }
        _ => {
            println!("{} {}", "Domain:".bold(), info.domain.as_deref().unwrap_or(domain).cyan());
            println!();

            if !info.subdomains.is_empty() {
                println!("{}", "Subdomains:".bold().underline());
                for sub in info.subdomains.iter().take(20) {
                    println!("  {}.{}", sub.green(), domain);
                }
                if info.subdomains.len() > 20 {
                    println!("  {} more...", info.subdomains.len() - 20);
                }
                println!();
            }

            if !info.data.is_empty() {
                println!("{}", "DNS Records:".bold().underline());
                for record in &info.data {
                    println!("  {:6} {:40} {}",
                        record.record_type.as_deref().unwrap_or("?").yellow(),
                        record.subdomain.as_deref().unwrap_or("@"),
                        record.value.as_deref().unwrap_or("")
                    );
                }
            }
        }
    }

    Ok(())
}

async fn resolve_hostnames(ctx: Context, hostnames: &[String]) -> Result<()> {
    if ctx.explain {
        Explain::dns_resolve().print();
    }

    let client = ctx.client()?;

    // Flatten comma-separated values
    let hosts: Vec<&str> = hostnames
        .iter()
        .flat_map(|h| h.split(','))
        .map(|s| s.trim())
        .collect();

    let results = client.dns().resolve(&hosts).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results.0)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&results.0)?);
        }
        OutputFormat::Csv => {
            println!("hostname,ip");
            for (host, ip) in &results.0 {
                println!("{},{}", host, ip);
            }
        }
        OutputFormat::Pretty => {
            println!("{}", "Resolved Hostnames:".bold().underline());
            for (host, ip) in &results.0 {
                println!("  {} -> {}", host, ip.to_string().cyan());
            }
        }
    }

    Ok(())
}

async fn reverse_lookup(ctx: Context, ips: &[String]) -> Result<()> {
    if ctx.explain {
        Explain::dns_reverse().print();
    }

    let client = ctx.client()?;

    // Flatten comma-separated values
    let ip_list: Vec<&str> = ips
        .iter()
        .flat_map(|i| i.split(','))
        .map(|s| s.trim())
        .collect();

    let results = client.dns().reverse(&ip_list).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results.0)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&results.0)?);
        }
        OutputFormat::Csv => {
            println!("ip,hostnames");
            for (ip, hosts) in &results.0 {
                println!("{},\"{}\"", ip, hosts.join(";"));
            }
        }
        OutputFormat::Pretty => {
            println!("{}", "Reverse DNS:".bold().underline());
            for (ip, hosts) in &results.0 {
                println!("  {} -> {}", ip.to_string().cyan(), hosts.join(", "));
            }
        }
    }

    Ok(())
}
