//! `showdi1 count` - Count results without using credits.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::CountArgs;
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: CountArgs) -> Result<()> {
    if ctx.explain {
        Explain::count(&args.query).print();
    }

    let client = ctx.client()?;

    // Build the count request
    let mut builder = client.search().count(&args.query);

    for facet in &args.facets {
        builder = builder.facet(facet);
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
            println!("total");
            println!("{}", results.total);
        }
        OutputFormat::Pretty => {
            println!("{} {}", "Total:".bold(), results.total.to_string().cyan().bold());
            println!("{} {}", "Query:".bold(), args.query.dimmed());

            // Facets if present
            if !results.facets.is_empty() {
                println!();
                for (name, values) in &results.facets {
                    println!("{} {}:", "Facet:".bold(), name.yellow());
                    for fv in values.iter().take(10) {
                        let pct = (fv.count as f64 / results.total as f64 * 100.0) as u32;
                        let bar = "█".repeat((pct / 5) as usize);
                        println!("  {:>8}  {:>3}% {} {}",
                            fv.count.to_string().cyan(),
                            pct,
                            bar.green(),
                            fv.value
                        );
                    }
                    println!();
                }
            }

            println!();
            println!("{}", "This query did not use any credits!".green());
            println!("{}", "Use 'search' to see actual results.".dimmed());
        }
    }

    Ok(())
}
