//! Audit command implementation — system integrity checks.

use anyhow::Result;
use colored::Colorize;

use crate::cli::args::{AuditArgs, AuditCommands};
use crate::output::OutputFormat;

use super::Context;

/// Execute the audit command.
pub async fn execute(ctx: Context, args: AuditArgs) -> Result<()> {
    match args.command {
        AuditCommands::Binaries {
            publish: _,
            below,
            paths,
        } => audit_binaries(&ctx, below, paths.as_deref()).await,
        AuditCommands::Processes => audit_processes(&ctx).await,
        AuditCommands::Certs { validate: _ } => audit_certs(&ctx).await,
        AuditCommands::Full { publish: _ } => audit_full(&ctx).await,
        AuditCommands::Verify { output, url_only } => {
            audit_verify(&ctx, &output, url_only).await
        }
    }
}

/// Audit system binaries: discover, hash, score.
async fn audit_binaries(
    ctx: &Context,
    below: Option<f64>,
    extra_paths: Option<&[String]>,
) -> Result<()> {
    use i1_audit::discovery::{
        correlate_processes, discover_binaries, discover_processes, DEFAULT_BIN_PATHS,
    };
    use i1_audit::scoring::{offline_weights, score_binary};

    println!(
        "{}",
        "  Auditing system binaries...".bright_cyan()
    );
    println!();

    // Build path list
    let mut paths: Vec<&str> = DEFAULT_BIN_PATHS.to_vec();
    if let Some(extra) = extra_paths {
        for p in extra {
            paths.push(p.as_str());
        }
    }

    let processes = discover_processes().unwrap_or_default();
    let mut binaries = discover_binaries(&paths).await?;
    correlate_processes(&mut binaries, &processes);

    let weights = offline_weights();
    for bin in &mut binaries {
        bin.trust_score = Some(score_binary(bin, &weights));
    }

    // Sort by trust score ascending (lowest trust first)
    binaries.sort_by(|a, b| {
        let sa = a.trust_score.as_ref().map_or(0.0, |s| s.total);
        let sb = b.trust_score.as_ref().map_or(0.0, |s| s.total);
        sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Filter if --below is set
    if let Some(threshold) = below {
        binaries.retain(|b| {
            b.trust_score
                .as_ref()
                .is_some_and(|s| s.total < threshold)
        });
    }

    if matches!(ctx.output_format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&binaries)?);
        return Ok(());
    }

    // Pretty output
    let total = binaries.len();
    let running = binaries.iter().filter(|b| b.running).count();

    println!(
        "  {} binaries discovered ({} running)",
        total.to_string().bright_white(),
        running.to_string().bright_green()
    );
    println!();

    for bin in &binaries {
        let trust = bin.trust_score.as_ref().map_or(0.0, |s| s.total);
        let trust_pct = (trust * 100.0) as u32;
        let trust_color = match trust_pct {
            0..=30 => format!("{trust_pct:>3}%").bright_red(),
            31..=60 => format!("{trust_pct:>3}%").bright_yellow(),
            _ => format!("{trust_pct:>3}%").bright_green(),
        };

        let running_indicator = if bin.running {
            " RUNNING".bright_green()
        } else {
            "".normal()
        };

        let basename = bin.path.rsplit('/').next().unwrap_or(&bin.path);
        println!(
            "  {} {} {} {}{}",
            trust_color,
            &bin.sha256[..12].dimmed(),
            basename.bright_white(),
            format_size(bin.size).dimmed(),
            running_indicator
        );
    }

    println!();
    Ok(())
}

/// Audit running processes.
async fn audit_processes(ctx: &Context) -> Result<()> {
    use i1_audit::discovery::discover_processes;

    println!("{}", "  Auditing running processes...".bright_cyan());
    println!();

    let processes = discover_processes()?;

    if matches!(ctx.output_format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&processes)?);
        return Ok(());
    }

    println!(
        "  {} processes discovered",
        processes.len().to_string().bright_white()
    );
    println!();

    // Show top processes by usage metric
    let mut sorted = processes;
    sorted.sort_by(|a, b| {
        b.usage
            .value
            .partial_cmp(&a.usage.value)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    println!(
        "  {}  {}  {}  {}",
        "PID".dimmed(),
        "USAGE".dimmed(),
        "NAME".dimmed(),
        "EXE".dimmed()
    );

    for proc in sorted.iter().take(30) {
        let usage_pct = (proc.usage.value * 100.0) as u32;
        let usage_str = format!("{usage_pct:>5}%");
        let usage_color = match usage_pct {
            0..=10 => usage_str.normal(),
            11..=50 => usage_str.bright_yellow(),
            _ => usage_str.bright_red(),
        };

        println!(
            "  {:>7}  {}  {}  {}",
            proc.pid.to_string().dimmed(),
            usage_color,
            proc.name.bright_white(),
            proc.exe_path.as_deref().unwrap_or("?").dimmed()
        );
    }

    if sorted.len() > 30 {
        println!(
            "  ... and {} more",
            (sorted.len() - 30).to_string().dimmed()
        );
    }

    println!();
    Ok(())
}

/// Audit root certificate store.
async fn audit_certs(ctx: &Context) -> Result<()> {
    use i1_audit::discovery::discover_root_certs;
    use i1_audit::scoring::score_cert;

    println!("{}", "  Auditing root certificates...".bright_cyan());
    println!();

    let mut certs = discover_root_certs().await?;

    for cert in &mut certs {
        cert.trust_score = Some(score_cert(cert));
    }

    if matches!(ctx.output_format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&certs)?);
        return Ok(());
    }

    let total = certs.len();
    let expired = certs.iter().filter(|c| c.expired).count();

    println!(
        "  {} root certs ({} expired)",
        total.to_string().bright_white(),
        if expired > 0 {
            expired.to_string().bright_red()
        } else {
            expired.to_string().bright_green()
        }
    );
    println!();

    // Sort: expired first, then by expiry date
    certs.sort_by(|a, b| {
        b.expired
            .cmp(&a.expired)
            .then_with(|| a.not_after.cmp(&b.not_after))
    });

    for cert in &certs {
        let status = if cert.expired {
            "EXPIRED".bright_red()
        } else {
            "  VALID".bright_green()
        };

        let fp_short = &cert.fingerprint[..12];

        // Extract just CN from subject
        let subject_short = extract_cn(&cert.subject).unwrap_or(&cert.subject);
        let subject_display = if subject_short.len() > 50 {
            format!("{}...", &subject_short[..47])
        } else {
            subject_short.to_string()
        };

        println!(
            "  {} {} {} (expires {})",
            status,
            fp_short.dimmed(),
            subject_display.bright_white(),
            cert.not_after.format("%Y-%m-%d").to_string().dimmed()
        );
    }

    println!();
    Ok(())
}

/// Full audit: binaries + processes + certs.
async fn audit_full(ctx: &Context) -> Result<()> {
    use i1_audit::discovery::DEFAULT_BIN_PATHS;
    use i1_audit::scoring::offline_weights;

    if matches!(ctx.output_format, OutputFormat::Json) {
        let paths: Vec<&str> = DEFAULT_BIN_PATHS.to_vec();
        let weights = offline_weights();
        let snapshot = i1_audit::collect_snapshot(&paths, &weights).await?;
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
        return Ok(());
    }

    println!(
        "{}",
        "  i1 audit — Zero-Trust System Integrity Check".bright_cyan().bold()
    );
    println!();

    audit_binaries(ctx, None, None).await?;
    audit_processes(ctx).await?;
    audit_certs(ctx).await?;

    Ok(())
}

/// Generate a verification QR code for independent TTL checking.
async fn audit_verify(ctx: &Context, output_path: &str, url_only: bool) -> Result<()> {
    use i1_audit::discovery::DEFAULT_BIN_PATHS;
    use i1_audit::scoring::offline_weights;
    use i1_audit::verify::generate_verify_token;
    use std::path::Path;

    println!(
        "{}",
        "  Generating trust verification token...".bright_cyan()
    );
    println!();

    // Collect a snapshot to compute the trust digest
    let paths: Vec<&str> = DEFAULT_BIN_PATHS.to_vec();
    let weights = offline_weights();
    let snapshot = i1_audit::collect_snapshot(&paths, &weights).await?;

    let token = generate_verify_token(&snapshot);

    if matches!(ctx.output_format, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&token)?);
        return Ok(());
    }

    // Print verification details
    println!(
        "  {}  {}",
        "Node prefix:".dimmed(),
        token.node_prefix.bright_white()
    );
    println!(
        "  {}  {}",
        "Trust digest:".dimmed(),
        token.digest.bright_white()
    );
    println!(
        "  {}  {}",
        "DNS record:".dimmed(),
        token.dns_name.bright_yellow()
    );
    println!(
        "  {}  {} seconds",
        "Expected TTL:".dimmed(),
        token.expected_ttl.to_string().bright_white()
    );
    println!(
        "  {}  {}",
        "Binaries:".dimmed(),
        snapshot.binaries.len().to_string().bright_white()
    );
    println!(
        "  {}  {}",
        "Root certs:".dimmed(),
        snapshot.root_certs.len().to_string().bright_white()
    );
    println!();

    let url = token.verification_url();
    println!(
        "  {}  {}",
        "Verify URL:".dimmed(),
        url.bright_cyan().underline()
    );

    if url_only {
        return Ok(());
    }

    // Render QR in terminal
    println!();
    let qr_text = i1_audit::qr::render_qr_terminal(&token);
    println!("{qr_text}");
    println!();

    // Save PNG
    let path = Path::new(output_path);
    i1_audit::qr::generate_qr_png(&token, path)?;
    println!(
        "  {} {}",
        "QR code saved:".bright_green(),
        output_path.bright_white()
    );
    println!();
    println!(
        "  {}",
        "Scan with your phone (on cell network) to verify DNS integrity.".dimmed()
    );
    println!(
        "  {}",
        "If your local DNS is poisoned, the phone will see different results.".dimmed()
    );
    println!();

    Ok(())
}

/// Format file size for display.
fn format_size(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1}M", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{bytes}B")
    }
}

/// Extract CN= from a distinguished name.
fn extract_cn(dn: &str) -> Option<&str> {
    for part in dn.split(',') {
        let trimmed = part.trim();
        if let Some(cn) = trimmed.strip_prefix("CN=") {
            return Some(cn.trim());
        }
    }
    None
}
