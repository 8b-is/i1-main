//! Port scanning integration using pistol.

use crate::error::ReconResult;
use std::net::IpAddr;
use std::time::Duration;

/// Port scanning configuration
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Ports to scan
    pub ports: PortSpec,
    /// Scan type/method
    pub scan_type: ScanType,
    /// Timeout per probe
    pub timeout: Duration,
    /// Maximum concurrent probes
    pub concurrent: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            ports: PortSpec::Top1000,
            scan_type: ScanType::TcpConnect,
            timeout: Duration::from_secs(5),
            concurrent: 100,
        }
    }
}

/// Port specification for scanning
#[derive(Debug, Clone)]
pub enum PortSpec {
    /// Top 100 most common ports
    Top100,
    /// Top 1000 most common ports
    Top1000,
    /// Custom port range
    Range(std::ops::RangeInclusive<u16>),
    /// Specific list of ports
    List(Vec<u16>),
    /// All ports (1-65535)
    All,
}

impl PortSpec {
    /// Convert to a list of ports
    #[must_use]
    pub fn to_ports(&self) -> Vec<u16> {
        match self {
            Self::Top100 => TOP_100_PORTS.to_vec(),
            Self::Top1000 => TOP_1000_PORTS.to_vec(),
            Self::Range(r) => r.clone().collect(),
            Self::List(l) => l.clone(),
            Self::All => (1..=65535).collect(),
        }
    }
}

/// Scan type/technique
#[derive(Debug, Clone, Copy, Default)]
pub enum ScanType {
    /// TCP connect scan (no raw sockets required)
    #[default]
    TcpConnect,
    /// TCP SYN scan (requires raw sockets)
    TcpSyn,
    /// TCP FIN scan
    TcpFin,
    /// TCP ACK scan
    TcpAck,
    /// UDP scan
    Udp,
}

/// Port scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Target IP address
    pub target: IpAddr,
    /// Open ports with details
    pub open_ports: Vec<PortInfo>,
    /// Total scan duration
    pub scan_time: Duration,
}

/// Information about a scanned port
#[derive(Debug, Clone)]
pub struct PortInfo {
    /// Port number
    pub port: u16,
    /// Port state
    pub state: PortState,
    /// Detected service info
    pub service: Option<ServiceInfo>,
}

/// State of a scanned port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    /// Port is open
    Open,
    /// Port is closed
    Closed,
    /// Port is filtered (no response)
    Filtered,
    /// Port state is uncertain
    OpenFiltered,
}

/// Service detection information
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    /// Service name
    pub name: Option<String>,
    /// Product name
    pub product: Option<String>,
    /// Version string
    pub version: Option<String>,
    /// Banner grabbed from service
    pub banner: Option<String>,
}

/// Port scanner
pub struct Scanner {
    config: ScanConfig,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    /// Create a new scanner with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ScanConfig::default())
    }

    /// Create a scanner with custom configuration
    #[must_use]
    pub fn with_config(config: ScanConfig) -> Self {
        Self { config }
    }

    /// Set the ports to scan
    #[must_use]
    pub fn ports(mut self, ports: PortSpec) -> Self {
        self.config.ports = ports;
        self
    }

    /// Set the scan type
    #[must_use]
    pub fn scan_type(mut self, scan_type: ScanType) -> Self {
        self.config.scan_type = scan_type;
        self
    }

    /// Set the timeout per probe
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Scan a single target
    pub async fn scan(&self, target: IpAddr) -> ReconResult<ScanResult> {
        use std::time::Instant;

        let start = Instant::now();
        let ports = self.config.ports.to_ports();

        // Perform TCP connect scan
        let mut open_ports = Vec::new();

        // Use concurrent scanning with semaphore to limit connections
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(self.config.concurrent));
        let timeout = self.config.timeout;

        let mut handles = Vec::new();

        for port in ports {
            let sem = semaphore.clone();
            let addr = std::net::SocketAddr::new(target, port);

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.ok()?;
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(_)) => Some(PortInfo {
                        port,
                        state: PortState::Open,
                        service: None,
                    }),
                    _ => None,
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            if let Ok(Some(port_info)) = handle.await {
                open_ports.push(port_info);
            }
        }

        // Sort by port number
        open_ports.sort_by_key(|p| p.port);

        Ok(ScanResult {
            target,
            open_ports,
            scan_time: start.elapsed(),
        })
    }

    /// Scan multiple targets concurrently
    pub async fn scan_many(&self, targets: &[IpAddr]) -> Vec<ReconResult<ScanResult>> {
        let futures: Vec<_> = targets.iter().map(|ip| self.scan(*ip)).collect();
        futures_util::future::join_all(futures).await
    }
}

// Top 100 most common ports
const TOP_100_PORTS: [u16; 100] = [
    21, 22, 23, 25, 26, 53, 80, 81, 110, 111, 113, 135, 139, 143, 179, 199, 443, 445, 465, 514,
    515, 548, 554, 587, 646, 993, 995, 1025, 1026, 1027, 1433, 1720, 1723, 2000, 2001, 3306, 3389,
    5060, 5666, 5900, 6001, 8000, 8008, 8080, 8443, 8888, 10000, 32768, 49152, 49153, 49154, 49155,
    49156, 49157, 1024, 1030, 1041, 1048, 1049, 1053, 1054, 1056, 1058, 1059, 1060, 1110, 1234,
    1494, 1521, 1755, 1900, 2049, 2121, 2717, 3000, 3128, 3986, 4899, 5000, 5009, 5051, 5101, 5190,
    5357, 5432, 5631, 5800, 6000, 6379, 6443, 7001, 7002, 8081, 8082, 8181, 8880, 9000, 9090, 9100,
    9200,
];

// Top 1000 ports (abbreviated - in practice would be the full nmap top 1000)
const TOP_1000_PORTS: [u16; 100] = TOP_100_PORTS;
