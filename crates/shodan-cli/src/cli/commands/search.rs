//! `showdi1 search` - Search Shodan's database.

use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled, settings::Style};

use super::Context;
use crate::cli::args::SearchArgs;
use crate::education::Explain;
use crate::output::OutputFormat;

#[derive(Tabled)]
struct SearchRow {
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "Port")]
    port: u16,
    #[tabled(rename = "Org")]
    org: String,
    #[tabled(rename = "Product")]
    product: String,
}

pub async fn execute(ctx: Context, args: SearchArgs) -> Result<()> {
    if ctx.explain {
        Explain::search(&args.query).print();
    }

    let client = ctx.client()?;

    // Build the search request
    let mut builder = client.search().query(&args.query);

    for facet in &args.facets {
        builder = builder.facet(facet);
    }

    builder = builder.page(args.page);

    if args.minify {
        builder = builder.minify(true);
    }

    let results = builder.send().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&results)?);
        }
        OutputFormat::Csv => {
            println!("ip,port,org,product,country");
            for m in &results.matches {
                println!("{},{},{},{},{}",
                    m.ip_str,
                    m.port,
                    m.org.as_deref().unwrap_or(""),
                    m.product.as_deref().unwrap_or(""),
                    m.location.country_code.as_deref().unwrap_or("")
                );
            }
        }
        OutputFormat::Pretty => {
            print_search_pretty(&results, &args, &ctx);
        }
    }

    Ok(())
}

fn print_search_pretty(
    results: &shodan_core::types::SearchResults,
    args: &SearchArgs,
    _ctx: &Context,
) {
    // Header
    println!("{} {}", "Total Results:".bold(), results.total.to_string().cyan());
    println!("{} {}", "Query:".bold(), args.query.dimmed());
    println!();

    // Facets if present
    if !results.facets.is_empty() {
        for (name, values) in &results.facets {
            println!("{} {}:", "Facet:".bold(), name.yellow());
            for fv in values.iter().take(5) {
                println!("  {:>8}  {}", fv.count.to_string().cyan(), fv.value);
            }
            println!();
        }
    }

    // Results table
    if !results.matches.is_empty() {
        println!("{}", "Results:".bold().underline());

        let rows: Vec<SearchRow> = results.matches.iter().take(25).map(|m| {
            SearchRow {
                ip: m.ip_str.clone(),
                port: m.port,
                org: m.org.clone()
                    .unwrap_or_default()
                    .chars()
                    .take(30)
                    .collect(),
                product: m.product.clone()
                    .unwrap_or_default()
                    .chars()
                    .take(20)
                    .collect(),
            }
        }).collect();

        let table = Table::new(&rows)
            .with(Style::rounded())
            .to_string();
        println!("{}", table);

        if results.matches.len() > 25 {
            println!();
            println!("{}", format!("... and {} more results", results.matches.len() - 25).dimmed());
        }
    }

    // Tips
    println!();
    if args.facets.is_empty() {
        println!("{}", "Tip: Add --facets port,country to see distribution".dimmed());
    }
    if args.page == 1 && results.total > 100 {
        println!("{}", format!("Tip: Use --page 2 to see more results (page 1 of {})",
            (results.total / 100) + 1).dimmed());
    }
}
