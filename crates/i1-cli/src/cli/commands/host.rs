//! `i1 host` - Look up information about an IP address.

use anyhow::Result;
use colored::Colorize;
use tabled::{settings::Style, Table, Tabled};

use super::Context;
use crate::cli::args::HostArgs;
use crate::output::OutputFormat;
use i1::HostInfo;

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
    let provider = ctx.host_provider()?;

    let host = provider.lookup_host(&args.ip).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&host)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&host)?);
        }
        OutputFormat::Csv => {
            println!("ip,org,asn,country,ports");
            let ports: Vec<String> = host
                .ports
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            println!(
                "{},{},{},{},\"{}\"",
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

fn print_host_pretty(host: &HostInfo, ctx: &Context) {
    // Header
    if ctx.no_color {
        println!("Host: {}", host.ip_str);
    } else {
        println!("{} {}", "Host:".bold(), host.ip_str.cyan().bold());
    }
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

        if host.data.is_empty() {
            for port in &host.ports {
                rows.push(PortRow {
                    port: *port,
                    transport: "tcp".to_string(),
                    product: String::new(),
                    version: String::new(),
                });
            }
        } else {
            for svc in &host.data {
                rows.push(PortRow {
                    port: svc.port,
                    transport: svc.transport.to_string(),
                    product: svc.product.clone().unwrap_or_default(),
                    version: svc.version.clone().unwrap_or_default(),
                });
            }
        }

        let table = Table::new(&rows).with(Style::rounded()).to_string();
        println!("{table}");
    }

    // Vulnerabilities
    if host.vulns.is_empty() {
        println!();
        if ctx.no_color {
            println!("Vulnerabilities: None detected");
        } else {
            println!("{} {}", "Vulnerabilities:".bold(), "None detected".green());
        }
    } else {
        println!();
        if ctx.no_color {
            println!("Vulnerabilities:");
        } else {
            println!("{}", "Vulnerabilities:".bold().red());
        }
        for vuln in &host.vulns {
            println!("  - {vuln}");
        }
    }

    // Last update
    if let Some(update) = &host.last_update {
        println!();
        println!("{}", format!("Last updated: {update}").dimmed());
    }
}
