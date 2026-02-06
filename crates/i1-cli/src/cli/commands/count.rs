//! `i1 count` - Count results without using credits.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::CountArgs;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: CountArgs) -> Result<()> {
    let provider = ctx.search_provider()?;

    let count = provider.count(&args.query).await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{{\"count\":{},\"query\":\"{}\"}}", count, args.query);
        }
        OutputFormat::Yaml => {
            println!("count: {}\nquery: {}", count, args.query);
        }
        OutputFormat::Csv => {
            println!("total");
            println!("{count}");
        }
        OutputFormat::Pretty => {
            if ctx.no_color {
                println!("Total: {count}");
            } else {
                println!("{} {}", "Total:".bold(), count.to_string().cyan().bold());
            }
            println!("{} {}", "Query:".bold(), args.query.dimmed());
            println!();
            if ctx.no_color {
                println!("This query did not use any credits!");
            } else {
                println!("{}", "This query did not use any credits!".green());
            }
            println!("{}", "Use 'search' to see actual results.".dimmed());
        }
    }

    Ok(())
}
