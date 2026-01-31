//! `showdi1 host` - Look up information about an IP address.

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled, settings::Style};

use super::Context;
use crate::cli::args::HostArgs;
use crate::education::Explain;
use crate::output::OutputFormat;

#[derive(Tabled)]
struct PortRow {
    #[tabled(rename = "Port")]
    port: u16,
    #[tabled(rename = "Protocol")]
    transport: String,
    #[tabled(rename = "Service")]
    product: String,
    #[tabled(rename = "Version")]
    version: String,
}

pub async fn execute(ctx: Context, args: HostArgs) -> Result<()> {
    if ctx.explain {
        Explain::host(&args.ip).print();
    }

    let client = ctx.client()?;

    // Build the request
    let host = if args.history || args.minify {
        client.search()
            .host_with_options(&args.ip)
            .history(args.history)
            .minify(args.minify)
            .send()
            .await?
    } else {
        client.search().host(&args.ip).await?
    };

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&host)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&host)?);
        }
        OutputFormat::Csv => {
            // Simple CSV with basic info
            println!("ip,org,asn,country,ports");
            let ports: Vec<String> = host.ports.iter().map(|p| p.to_string()).collect();
            println!("{},{},{},{},\"{}\"",
                host.ip_str,
                host.org.as_deref().unwrap_or(""),
                host.asn.as_deref().unwrap_or(""),
                host.location.country_code.as_deref().unwrap_or(""),
                ports.join(";")
            );
        }
        OutputFormat::Pretty => {
            print_host_pretty(&host, &ctx);
        }
    }

    Ok(())
}

fn print_host_pretty(host: &shodan_core::types::HostInfo, _ctx: &Context) {
    // Header
    println!("{} {}", "Host:".bold(), host.ip_str.cyan().bold());
    println!();

    // Basic info
    if let Some(org) = &host.org {
        println!("  {} {}", "Organization:".bold(), org);
    }
    if let Some(asn) = &host.asn {
        println!("  {} {}", "ASN:".bold(), asn);
    }
    if let Some(isp) = &host.isp {
        println!("  {} {}", "ISP:".bold(), isp);
    }
    if let Some(os) = &host.os {
        println!("  {} {}", "OS:".bold(), os);
    }

    // Location
    if let Some(country) = &host.location.country_name {
        let city = host.location.city.as_deref().unwrap_or("");
        let region = host.location.region_code.as_deref().unwrap_or("");
        let location = [city, region, country.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {} {}", "Location:".bold(), location);
    }

    // Hostnames
    if !host.hostnames.is_empty() {
        println!("  {} {}", "Hostnames:".bold(), host.hostnames.join(", "));
    }

    // Ports table
    if !host.ports.is_empty() {
        println!();
        println!("{}", "Open Ports:".bold().underline());

        let mut rows: Vec<PortRow> = Vec::new();

        if !host.data.is_empty() {
            for svc in &host.data {
                rows.push(PortRow {
                    port: svc.port,
                    transport: svc.transport.to_string(),
                    product: svc.product.clone().unwrap_or_default(),
                    version: svc.version.clone().unwrap_or_default(),
                });
            }
        } else {
            // Just list ports without details
            for port in &host.ports {
                rows.push(PortRow {
                    port: *port,
                    transport: "tcp".to_string(),
                    product: String::new(),
                    version: String::new(),
                });
            }
        }

        let table = Table::new(&rows)
            .with(Style::rounded())
            .to_string();
        println!("{}", table);
    }

    // Vulnerabilities
    if !host.vulns.is_empty() {
        println!();
        println!("{}", "Vulnerabilities:".bold().red());
        for vuln in &host.vulns {
            println!("  {} {}", "-".red(), vuln);
        }
        println!();
        println!("{}", format!("Learn more: https://cheet.is/security/cve/{}", host.vulns[0]).dimmed());
    } else {
        println!();
        println!("{} {}", "Vulnerabilities:".bold(), "None detected".green());
    }

    // Last update
    if let Some(update) = &host.last_update {
        println!();
        println!("{}", format!("Last updated: {}", update).dimmed());
    }
}
