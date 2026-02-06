//! `i1 search` - Search threat intelligence database.

use anyhow::Result;
use colored::Colorize;
use tabled::{settings::Style, Table, Tabled};

use super::Context;
use crate::cli::args::SearchArgs;
use crate::output::OutputFormat;

#[derive(Tabled)]
struct SearchRow {
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "Ports")]
    ports: String,
    #[tabled(rename = "Org")]
    org: String,
    #[tabled(rename = "Country")]
    country: String,
}

pub async fn execute(ctx: Context, args: SearchArgs) -> Result<()> {
    let provider = ctx.search_provider()?;

    let results = provider.search(&args.query, Some(args.page)).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&results)?);
        }
        OutputFormat::Csv => {
            println!("ip,ports,org,country");
            for host in &results.results {
                let ports: Vec<String> = host
                    .ports
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                println!(
                    "{},\"{}\",{},{}",
                    host.ip_str,
                    ports.join(";"),
                    host.org.as_deref().unwrap_or(""),
                    host.location.country_code.as_deref().unwrap_or("")
                );
            }
        }
        OutputFormat::Pretty => {
            if ctx.no_color {
                println!("Total Results: {}", results.total);
            } else {
                println!(
                    "{} {}",
                    "Total Results:".bold(),
                    results.total.to_string().cyan()
                );
            }
            println!("{} {}", "Query:".bold(), args.query.dimmed());
            println!();

            if results.results.is_empty() {
                println!("No results found.");
            } else {
                println!("{}", "Results:".bold().underline());

                let rows: Vec<SearchRow> = results
                    .results
                    .iter()
                    .take(25)
                    .map(|host| {
                        let ports: Vec<String> = host
                            .ports
                            .iter()
                            .map(std::string::ToString::to_string)
                            .collect();
                        SearchRow {
                            ip: host.ip_str.clone(),
                            ports: ports.join(", "),
                            org: host
                                .org
                                .clone()
                                .unwrap_or_default()
                                .chars()
                                .take(30)
                                .collect(),
                            country: host.location.country_code.clone().unwrap_or_default(),
                        }
                    })
                    .collect();

                let table = Table::new(&rows).with(Style::rounded()).to_string();
                println!("{table}");

                if results.results.len() > 25 {
                    println!();
                    println!(
                        "{}",
                        format!("... and {} more results", results.results.len() - 25).dimmed()
                    );
                }
            }

            println!();
            if args.page == 1 && results.total > 100 {
                println!(
                    "{}",
                    format!(
                        "Tip: Use --page 2 to see more results (page 1 of {})",
                        (results.total / 100) + 1
                    )
                    .dimmed()
                );
            }
        }
    }

    Ok(())
}
