//! Process discovery via `/proc` filesystem.

use procfs::prelude::*;
use tracing::debug;

use crate::error::{AuditError, Result};
use crate::types::{ProcessInfo, UsageMetric};

/// Discover all running processes from `/proc`.
///
/// Uses the `procfs` crate for safe, structured access.
///
/// # Errors
///
/// Returns `AuditError::Procfs` if `/proc` cannot be read.
pub fn discover_processes() -> Result<Vec<ProcessInfo>> {
    let system_uptime = get_system_uptime()?;
    let cpu_count = get_cpu_count();
    let boot_time = get_boot_time()?;

    let mut processes = Vec::new();

    let all_procs =
        procfs::process::all_processes().map_err(|e| AuditError::Procfs(e.to_string()))?;

    for entry in all_procs {
        let proc = match entry {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "skipping inaccessible process");
                continue;
            }
        };

        match collect_process_info(&proc, system_uptime, cpu_count, boot_time) {
            Ok(info) => processes.push(info),
            Err(e) => {
                debug!(error = %e, "skipping process");
            }
        }
    }

    Ok(processes)
}

/// Collect info for a single process.
#[allow(clippy::cast_precision_loss)]
fn collect_process_info(
    proc: &procfs::process::Process,
    system_uptime: u64,
    cpu_count: u32,
    boot_time_secs: u64,
) -> Result<ProcessInfo> {
    let stat = proc.stat().map_err(|e| AuditError::Procfs(e.to_string()))?;

    let name = stat.comm.clone();
    let pid = stat.pid;
    let uid = proc
        .status()
        .map(|s| s.ruid)
        .unwrap_or(u32::MAX);

    // Exe path (may fail for kernel threads or permission issues)
    let exe_path = proc.exe().ok().map(|p| p.display().to_string());

    // Command line
    let cmdline = proc.cmdline().unwrap_or_default();

    // Compute usage metric
    let ticks_per_sec = procfs::ticks_per_second();
    let start_time_secs = boot_time_secs + (stat.starttime / ticks_per_sec);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let program_uptime_secs = now_secs.saturating_sub(start_time_secs);

    // CPU time (user + system) in seconds
    let total_cpu_secs =
        (stat.utime + stat.stime) as f64 / ticks_per_sec as f64;
    let avg_cpu = if program_uptime_secs > 0 {
        total_cpu_secs / program_uptime_secs as f64
    } else {
        0.0
    };

    let usage = UsageMetric::compute(
        program_uptime_secs,
        system_uptime,
        avg_cpu,
        f64::from(cpu_count),
    );

    Ok(ProcessInfo {
        pid,
        name,
        exe_path,
        cmdline,
        uid,
        usage,
    })
}

/// Get system uptime in seconds.
///
/// # Errors
///
/// Returns `AuditError::Procfs` if `/proc/uptime` cannot be read.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn get_system_uptime() -> Result<u64> {
    let uptime =
        procfs::Uptime::current().map_err(|e| AuditError::Procfs(e.to_string()))?;
    Ok(uptime.uptime as u64)
}

/// Get number of CPU cores.
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn get_cpu_count() -> u32 {
    procfs::CpuInfo::current()
        .map(|c: procfs::CpuInfo| c.num_cores() as u32)
        .unwrap_or(1)
}

/// Get system boot time in seconds since epoch.
fn get_boot_time() -> Result<u64> {
    let boot_time =
        procfs::boot_time_secs().map_err(|e| AuditError::Procfs(e.to_string()))?;
    Ok(boot_time)
}
