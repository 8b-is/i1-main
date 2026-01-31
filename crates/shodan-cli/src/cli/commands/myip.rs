//! `showdi1 myip` - Show your public IP address.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context) -> Result<()> {
    // Show explanation if requested
    if ctx.explain {
        Explain::myip().print();
    }

    let client = ctx.client()?;
    let ip = client.tools().my_ip().await?;

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::json!({ "ip": ip.as_str() }));
        }
        OutputFormat::Csv => {
            println!("ip");
            println!("{}", ip.as_str());
        }
        OutputFormat::Yaml => {
            println!("ip: {}", ip.as_str());
        }
        OutputFormat::Pretty => {
            if ctx.no_color {
                println!("Your IP: {}", ip.as_str());
            } else {
                println!("Your IP: {}", ip.as_str().cyan().bold());
            }
        }
    }

    Ok(())
}
