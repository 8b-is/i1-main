//! Process information types.

use serde::{Deserialize, Serialize};

/// Information about a running process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: i32,
    /// Process name (comm)
    pub name: String,
    /// Path to the executable binary
    pub exe_path: Option<String>,
    /// Command line arguments
    pub cmdline: Vec<String>,
    /// User ID running the process
    pub uid: u32,
    /// Usage metric for this process
    pub usage: UsageMetric,
}

/// Resource usage metric for a process.
///
/// `value = (program_uptime / system_uptime) * (avg_cpu / max_cpu_capability)`
///
/// A high value means the process has been running long and consuming
/// significant CPU -- worth paying attention to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageMetric {
    /// How long this process has been alive (seconds)
    pub program_uptime_secs: u64,
    /// System uptime (seconds)
    pub system_uptime_secs: u64,
    /// Average CPU usage 0.0..1.0
    pub avg_cpu: f64,
    /// Number of CPU cores
    pub max_cpu_capability: f64,
    /// Computed value: `(uptime_ratio) * (cpu_ratio)`
    pub value: f64,
}

impl UsageMetric {
    /// Compute the usage metric from raw values.
    #[allow(clippy::cast_precision_loss)]
    pub fn compute(
        program_uptime_secs: u64,
        system_uptime_secs: u64,
        avg_cpu: f64,
        max_cpu_capability: f64,
    ) -> Self {
        let uptime_ratio = if system_uptime_secs > 0 {
            program_uptime_secs as f64 / system_uptime_secs as f64
        } else {
            0.0
        };
        let cpu_ratio = if max_cpu_capability > 0.0 {
            avg_cpu / max_cpu_capability
        } else {
            0.0
        };
        let value = uptime_ratio * cpu_ratio;

        Self {
            program_uptime_secs,
            system_uptime_secs,
            avg_cpu,
            max_cpu_capability,
            value,
        }
    }
}
