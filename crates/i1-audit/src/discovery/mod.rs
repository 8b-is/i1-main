//! System discovery — binaries, processes, and root certificates.

pub mod binaries;
pub mod certs;
pub mod processes;

pub use binaries::{correlate_processes, discover_binaries, DEFAULT_BIN_PATHS};
pub use certs::discover_root_certs;
pub use processes::{discover_processes, get_cpu_count, get_system_uptime};
