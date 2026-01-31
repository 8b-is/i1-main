//! `showdi1 defend` - Defensive tools: geo-blocking, IP bans, firewall rules.

use anyhow::Result;
use colored::Colorize;

use super::Context;
use crate::cli::args::{DefendArgs, DefendCommands, GeoblockArgs, GeoblockCommands, WhitelistArgs, WhitelistCommands};
use crate::defend;
use crate::education::Explain;
use crate::output::OutputFormat;

pub async fn execute(ctx: Context, args: DefendArgs) -> Result<()> {
    match args.command {
        DefendCommands::Status { quick } => status(ctx, quick).await,
        DefendCommands::Geoblock(gb) => geoblock(ctx, gb).await,
        DefendCommands::Ban { target, as_number, dry_run } => ban(ctx, &target, as_number, dry_run).await,
        DefendCommands::Unban { target } => unban(ctx, &target).await,
        DefendCommands::Whitelist(wl) => whitelist(ctx, wl).await,
        DefendCommands::Export { format } => export(ctx, &format).await,
        DefendCommands::Import { stdin, file } => import(ctx, stdin, file.as_deref()).await,
        DefendCommands::Undo => undo(ctx).await,
        DefendCommands::Disable => disable(ctx).await,
    }
}

async fn status(ctx: Context, quick: bool) -> Result<()> {
    if ctx.explain {
        Explain::defend_status().print();
    }

    let state = defend::State::load()?;

    if quick {
        let countries: Vec<&str> = state.blocked_countries.iter().map(|s| s.as_str()).collect();
        println!("Blocking {} countries, {} IPs, {} ASNs | Whitelist: {} IPs",
            countries.len(),
            state.blocked_ips.len(),
            state.blocked_asns.len(),
            state.whitelisted_ips.len()
        );
        return Ok(());
    }

    match ctx.output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&state)?);
        }
        _ => {
            println!("{}", "Defense Status".bold().underline());
            println!();

            // Countries
            if state.blocked_countries.is_empty() {
                println!("{} None", "Blocked Countries:".bold());
            } else {
                println!("{}", "Blocked Countries:".bold());
                for code in &state.blocked_countries {
                    let name = defend::country_name(code);
                    println!("  {} - {}", code.to_uppercase().red(), name);
                }
            }
            println!();

            // IPs
            println!("{} {}", "Blocked IPs/Ranges:".bold(), state.blocked_ips.len());
            for ip in state.blocked_ips.iter().take(10) {
                println!("  {}", ip.red());
            }
            if state.blocked_ips.len() > 10 {
                println!("  ... and {} more", state.blocked_ips.len() - 10);
            }
            println!();

            // ASNs
            println!("{} {}", "Blocked ASNs:".bold(), state.blocked_asns.len());
            for asn in state.blocked_asns.iter().take(5) {
                println!("  {}", asn.red());
            }
            println!();

            // Whitelist
            println!("{} {}", "Whitelisted IPs:".bold(), state.whitelisted_ips.len());
            for ip in &state.whitelisted_ips {
                println!("  {}", ip.green());
            }
            println!();

            // Tip
            println!("{}", "Use 'defend export' to generate firewall rules.".dimmed());
        }
    }

    Ok(())
}

async fn geoblock(ctx: Context, args: GeoblockArgs) -> Result<()> {
    match args.command {
        GeoblockCommands::List => {
            let state = defend::State::load()?;
            if state.blocked_countries.is_empty() {
                println!("No countries currently blocked.");
                println!();
                println!("Block countries with: {} defend geoblock add cn ru", "showdi1".cyan());
            } else {
                println!("{}", "Blocked Countries:".bold());
                for code in &state.blocked_countries {
                    let name = defend::country_name(code);
                    println!("  {} - {}", code.to_uppercase().red(), name);
                }
            }
            Ok(())
        }
        GeoblockCommands::Add { countries, dry_run } => {
            if ctx.explain {
                Explain::geoblock_add(&countries).print();
            }

            let mut state = defend::State::load()?;
            let mut added = Vec::new();

            for code in &countries {
                let normalized = code.to_lowercase();
                if !state.blocked_countries.contains(&normalized) {
                    state.blocked_countries.push(normalized.clone());
                    added.push(normalized);
                }
            }

            if added.is_empty() {
                println!("All specified countries are already blocked.");
                return Ok(());
            }

            if dry_run {
                println!("{}", "[DRY RUN]".yellow().bold());
                println!("Would block: {}", added.join(", ").red());
                println!();
                println!("Run without --dry-run to apply.");
            } else {
                state.save()?;
                println!("{} Now blocking: {}", "Success:".green().bold(), added.join(", ").red());
                println!();
                println!("Generate rules with: {} defend export", "showdi1".cyan());
            }

            Ok(())
        }
        GeoblockCommands::Remove { country } => {
            let mut state = defend::State::load()?;
            let normalized = country.to_lowercase();

            if let Some(pos) = state.blocked_countries.iter().position(|c| c == &normalized) {
                state.blocked_countries.remove(pos);
                state.save()?;
                println!("{} Removed {} from blocked countries.", "Success:".green().bold(), country.to_uppercase().cyan());
            } else {
                println!("Country {} is not currently blocked.", country.to_uppercase());
            }

            Ok(())
        }
        GeoblockCommands::Update => {
            println!("Updating IP ranges from ipdeny.com...");
            println!();
            println!("{}", "This feature will download fresh IP ranges for blocked countries.".dimmed());
            println!("{}", "Coming soon!".yellow());
            Ok(())
        }
        GeoblockCommands::Codes => {
            println!("{}", "Country Codes Reference".bold().underline());
            println!();
            println!("{}", "Common attack sources:".bold());
            println!("  {} - China         {} - Russia        {} - Romania",
                "cn".red(), "ru".red(), "ro".red());
            println!("  {} - Poland        {} - Kazakhstan    {} - Ukraine",
                "pl".red(), "kz".red(), "ua".red());
            println!("  {} - Vietnam       {} - Brazil        {} - India",
                "vn".red(), "br".red(), "in".red());
            println!("  {} - South Korea   {} - Thailand      {} - Indonesia",
                "kr".yellow(), "th".yellow(), "id".yellow());
            println!();
            println!("Full list: {}", "https://www.ipdeny.com/ipblocks/".cyan().underline());
            println!();
            println!("Learn more: {}", "https://cheet.is/security/geoblock/countries".dimmed());
            Ok(())
        }
    }
}

async fn ban(ctx: Context, target: &str, as_number: bool, dry_run: bool) -> Result<()> {
    if ctx.explain {
        Explain::defend_ban(target, as_number).print();
    }

    let mut state = defend::State::load()?;

    if as_number {
        // Ban AS number
        let asn = target.trim_start_matches("AS").trim_start_matches("as");
        if dry_run {
            println!("{} Would block AS{}", "[DRY RUN]".yellow().bold(), asn);
        } else {
            state.blocked_asns.push(format!("AS{}", asn));
            state.save()?;
            println!("{} Blocked AS{}", "Success:".green().bold(), asn.red());
        }
    } else {
        // Ban IP or CIDR
        if dry_run {
            println!("{} Would block {}", "[DRY RUN]".yellow().bold(), target);
        } else {
            state.blocked_ips.push(target.to_string());
            state.save()?;
            println!("{} Blocked {}", "Success:".green().bold(), target.red());
        }
    }

    println!();
    println!("Generate rules with: {} defend export", "showdi1".cyan());

    Ok(())
}

async fn unban(_ctx: Context, target: &str) -> Result<()> {
    let mut state = defend::State::load()?;

    // Check if it's an ASN
    if target.to_uppercase().starts_with("AS") {
        if let Some(pos) = state.blocked_asns.iter().position(|a| a.eq_ignore_ascii_case(target)) {
            state.blocked_asns.remove(pos);
            state.save()?;
            println!("{} Unblocked {}", "Success:".green().bold(), target.cyan());
            return Ok(());
        }
    }

    // Check IPs
    if let Some(pos) = state.blocked_ips.iter().position(|i| i == target) {
        state.blocked_ips.remove(pos);
        state.save()?;
        println!("{} Unblocked {}", "Success:".green().bold(), target.cyan());
        return Ok(());
    }

    println!("{} {} is not currently blocked.", "Note:".yellow(), target);
    Ok(())
}

async fn whitelist(_ctx: Context, args: WhitelistArgs) -> Result<()> {
    match args.command {
        WhitelistCommands::Show => {
            let state = defend::State::load()?;
            if state.whitelisted_ips.is_empty() {
                println!("No IPs whitelisted.");
            } else {
                println!("{}", "Whitelisted IPs:".bold());
                for ip in &state.whitelisted_ips {
                    println!("  {}", ip.green());
                }
            }
            Ok(())
        }
        WhitelistCommands::Add { ip } => {
            let mut state = defend::State::load()?;
            if !state.whitelisted_ips.contains(&ip) {
                state.whitelisted_ips.push(ip.clone());
                state.save()?;
                println!("{} Added {} to whitelist.", "Success:".green().bold(), ip.green());
            } else {
                println!("{} is already whitelisted.", ip);
            }
            Ok(())
        }
        WhitelistCommands::Remove { ip } => {
            let mut state = defend::State::load()?;
            if let Some(pos) = state.whitelisted_ips.iter().position(|i| i == &ip) {
                state.whitelisted_ips.remove(pos);
                state.save()?;
                println!("{} Removed {} from whitelist.", "Success:".green().bold(), ip);
            } else {
                println!("{} is not in the whitelist.", ip);
            }
            Ok(())
        }
    }
}

async fn export(ctx: Context, format: &str) -> Result<()> {
    if ctx.explain {
        Explain::defend_export(format).print();
    }

    let state = defend::State::load()?;

    match format.to_lowercase().as_str() {
        "nftables" | "nft" => {
            let rules = defend::generate_nftables(&state)?;
            println!("{}", rules);
        }
        "iptables" | "ipt" => {
            let rules = defend::generate_iptables(&state)?;
            println!("{}", rules);
        }
        "pf" => {
            let rules = defend::generate_pf(&state)?;
            println!("{}", rules);
        }
        _ => {
            anyhow::bail!(
                "Unknown format: {}\n\n\
                 Supported formats:\n  \
                 nftables  - Linux nftables (recommended)\n  \
                 iptables  - Legacy iptables\n  \
                 pf        - BSD/macOS pf",
                format
            );
        }
    }

    Ok(())
}

async fn import(_ctx: Context, stdin: bool, file: Option<&str>) -> Result<()> {
    println!("{}", "Import feature coming soon!".yellow());
    println!();
    println!("This will allow importing IPs from:");
    if stdin {
        println!("  - Standard input (pipe from other commands)");
    }
    if let Some(f) = file {
        println!("  - File: {}", f);
    }
    Ok(())
}

async fn undo(_ctx: Context) -> Result<()> {
    println!("{}", "Undo feature coming soon!".yellow());
    println!();
    println!("This will revert the last change to defense settings.");
    Ok(())
}

async fn disable(_ctx: Context) -> Result<()> {
    println!("{}", "EMERGENCY DISABLE".red().bold());
    println!();
    println!("This would remove all blocking rules immediately.");
    println!();
    println!("On Linux, run:");
    println!("  {}", "nft delete table inet geoblock".cyan());
    println!();
    println!("This is a safety feature - not applying automatically.");
    Ok(())
}
