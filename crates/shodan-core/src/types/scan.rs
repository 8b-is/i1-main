use serde::{Deserialize, Serialize};

/// On-demand scan request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    /// IP addresses or networks to scan (comma-separated)
    pub ips: String,

    /// Specific services to scan for
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
}

/// Response from creating a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    /// Unique scan ID
    pub id: String,

    /// Number of IPs being scanned
    #[serde(default)]
    pub count: u32,

    /// Credits consumed
    #[serde(default)]
    pub credits_left: i32,
}

/// Scan status information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatus {
    /// Unique scan ID
    pub id: String,

    /// Number of IPs
    #[serde(default)]
    pub count: u32,

    /// Timestamp when scan was created
    #[serde(default)]
    pub created: Option<String>,

    /// Current status
    pub status: ScanState,

    /// Status message
    #[serde(default)]
    pub status_check: Option<String>,
}

/// Possible scan states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ScanState {
    /// Scan is being submitted
    Submitting,
    /// Scan is in the queue
    Queue,
    /// Scan is being processed
    Processing,
    /// Scan is complete
    Done,
}

impl ScanState {
    /// Returns true if the scan is finished
    #[must_use]
    pub const fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    /// Returns true if the scan is still running
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Submitting | Self::Queue | Self::Processing)
    }
}

impl std::fmt::Display for ScanState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submitting => write!(f, "SUBMITTING"),
            Self::Queue => write!(f, "QUEUE"),
            Self::Processing => write!(f, "PROCESSING"),
            Self::Done => write!(f, "DONE"),
        }
    }
}

/// List of active scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanList {
    /// Active scans
    #[serde(default)]
    pub matches: Vec<ScanStatus>,

    /// Total number of scans
    #[serde(default)]
    pub total: u64,
}

/// Port that Shodan crawlers monitor
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrawledPort(pub u16);

impl From<u16> for CrawledPort {
    fn from(port: u16) -> Self {
        Self(port)
    }
}

impl From<CrawledPort> for u16 {
    fn from(port: CrawledPort) -> Self {
        port.0
    }
}

/// Protocol information for on-demand scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protocol {
    /// Protocol name
    pub name: String,

    /// Protocol description
    #[serde(default)]
    pub description: Option<String>,
}

/// Map of available protocols
pub type ProtocolMap = std::collections::HashMap<String, String>;
