//! Binary discovery -- walk standard paths and collect metadata.

use chrono::{DateTime, TimeZone, Utc};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use tracing::{debug, warn};
use walkdir::WalkDir;

use crate::error::{AuditError, Result};
use crate::hash::sha256_file;
use crate::types::{BinaryInfo, FileIdentity};

/// Default paths to scan for binaries.
pub const DEFAULT_BIN_PATHS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
];

/// Discover all executable binaries in the given paths.
///
/// Walks each directory, skipping symlinks-to-nowhere and unreadable files.
/// Returns `BinaryInfo` with hashes but without process correlation (that's
/// done by `correlate_processes`).
///
/// # Errors
///
/// Returns `AuditError` if directory walking fails catastrophically.
pub async fn discover_binaries(paths: &[&str]) -> Result<Vec<BinaryInfo>> {
    let mut binaries = Vec::new();

    for base_path in paths {
        let base = Path::new(base_path);
        if !base.exists() {
            debug!(path = base_path, "skipping non-existent bin path");
            continue;
        }

        let entries: Vec<_> = WalkDir::new(base)
            .max_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        for entry in entries {
            let path = entry.path();
            match collect_binary_info(path).await {
                Ok(info) => binaries.push(info),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "skipping binary");
                }
            }
        }
    }

    Ok(binaries)
}

/// Collect metadata + hash for a single binary.
async fn collect_binary_info(path: &Path) -> Result<BinaryInfo> {
    let path_str = path.display().to_string();
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| AuditError::io(&path_str, e))?;

    // Check executable bit
    let mode = meta.mode();
    if mode & 0o111 == 0 {
        return Err(AuditError::Hash {
            path: path_str,
            reason: "not executable".into(),
        });
    }

    let sha256 = sha256_file(path).await?;

    // File timestamps
    let mtime = meta.mtime();
    let modify_date = timestamp_to_utc(mtime);

    // Try creation time (btime via statx), fall back to mtime
    let create_date = meta.created().map_or(modify_date, |created| {
        let dur = created
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        #[allow(clippy::cast_possible_wrap)]
        Utc.timestamp_opt(dur.as_secs() as i64, dur.subsec_nanos())
            .single()
            .unwrap_or(modify_date)
    });

    let identity = FileIdentity {
        inode: meta.ino(),
        device_id: meta.dev(),
    };

    Ok(BinaryInfo {
        path: path_str,
        sha256,
        create_date,
        modify_date,
        identity,
        size: meta.len(),
        running: false,
        process_names: Vec::new(),
        trust_score: None,
    })
}

/// Convert a Unix timestamp (seconds) to `DateTime<Utc>`.
fn timestamp_to_utc(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .unwrap_or_else(Utc::now)
}

/// Correlate discovered binaries with running processes.
///
/// For each process, check if its exe path matches a discovered binary.
/// Marks matching binaries as `running = true` and adds the process name.
pub fn correlate_processes(
    binaries: &mut [BinaryInfo],
    processes: &[crate::types::ProcessInfo],
) {
    for proc in processes {
        let Some(exe) = &proc.exe_path else {
            continue;
        };
        for bin in binaries.iter_mut() {
            if bin.path == *exe {
                bin.running = true;
                if !bin.process_names.contains(&proc.name) {
                    bin.process_names.push(proc.name.clone());
                }
            }
        }
    }
}
