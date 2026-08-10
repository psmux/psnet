use std::collections::HashMap;
use std::net::IpAddr;

use chrono::NaiveTime;
use serde::{Serialize, Deserialize};

// ─── DNS cache ───────────────────────────────────────────────────────────────

pub type DnsCache = HashMap<IpAddr, Option<String>>;

// ─── Protocol ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConnProto {
    Tcp,
    Udp,
}

impl ConnProto {
    pub fn label(&self) -> &str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

// ─── TCP State ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    pub fn from_raw(v: u32) -> Self {
        match v {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            _ => Self::Unknown(v),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::Established => Color::Green,
            Self::Listen => Color::Cyan,
            Self::SynSent | Self::SynReceived => Color::Yellow,
            Self::TimeWait | Self::FinWait1 | Self::FinWait2 => Color::Magenta,
            Self::CloseWait | Self::Closing | Self::LastAck => Color::LightRed,
            Self::Closed | Self::DeleteTcb => Color::DarkGray,
            Self::Unknown(_) => Color::Gray,
        }
    }
}

// ─── Connection ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Connection {
    pub proto: ConnProto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    /// DNS-resolved hostname for remote address (if available).
    pub dns_hostname: Option<String>,
    /// Owning service/module resolved via GetOwnerModuleFrom*Entry.
    /// Only populated for service-hosting processes (svchost.exe), where the
    /// exe name alone does not identify what is actually using the socket.
    pub module_name: Option<String>,
}

/// Unique key for identifying a connection across ticks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub proto: ConnProto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
}

impl Connection {
    pub fn key(&self) -> ConnKey {
        ConnKey {
            proto: self.proto.clone(),
            local_addr: self.local_addr,
            local_port: self.local_port,
            remote_addr: self.remote_addr,
            remote_port: self.remote_port,
        }
    }

    /// Heuristic: is this an outbound connection?
    pub fn is_outbound(&self) -> bool {
        if let Some(rp) = self.remote_port {
            // Well-known remote ports suggest we initiated the connection
            matches!(rp, 80 | 443 | 22 | 21 | 25 | 53 | 110 | 143 | 993 | 995
                | 587 | 465 | 8080 | 8443 | 3306 | 5432 | 6379 | 27017)
                || (self.local_port > 1024 && rp <= 1024)
                || (self.local_port > 49152)
        } else {
            false
        }
    }
}

// ─── Speed history ───────────────────────────────────────────────────────────

pub struct SpeedHistory {
    pub download: std::collections::VecDeque<f64>,
    pub upload: std::collections::VecDeque<f64>,
    pub max_points: usize,
}

impl SpeedHistory {
    pub fn new(max_points: usize) -> Self {
        Self {
            download: std::collections::VecDeque::with_capacity(max_points),
            upload: std::collections::VecDeque::with_capacity(max_points),
            max_points,
        }
    }

    pub fn push(&mut self, down: f64, up: f64) {
        self.download.push_back(down);
        self.upload.push_back(up);
        if self.download.len() > self.max_points {
            self.download.pop_front();
        }
        if self.upload.len() > self.max_points {
            self.upload.pop_front();
        }
    }
}

// ─── Traffic event (for live capture tab) ────────────────────────────────────

#[derive(Clone, Debug)]
pub enum TrafficEventKind {
    NewConnection,
    ConnectionClosed,
    StateChange,
    DataActivity,
}

#[derive(Clone, Debug)]
pub struct TrafficEntry {
    pub event: TrafficEventKind,
}

// ─── Bottom pane tab ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BottomTab {
    Dashboard,
    Connections,
    Servers,
    Packets,
    Topology,
    Alerts,
    Firewall,
    Devices,
    Networks,
}

impl BottomTab {
    pub fn next(&self) -> Self {
        match self {
            Self::Dashboard => Self::Connections,
            Self::Connections => Self::Servers,
            Self::Servers => Self::Packets,
            Self::Packets => Self::Topology,
            Self::Topology => Self::Alerts,
            Self::Alerts => Self::Firewall,
            Self::Firewall => Self::Devices,
            Self::Devices => Self::Networks,
            Self::Networks => Self::Dashboard,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Self::Dashboard => Self::Networks,
            Self::Connections => Self::Dashboard,
            Self::Servers => Self::Connections,
            Self::Packets => Self::Servers,
            Self::Topology => Self::Packets,
            Self::Alerts => Self::Topology,
            Self::Firewall => Self::Alerts,
            Self::Devices => Self::Firewall,
            Self::Networks => Self::Devices,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Connections => "Connections",
            Self::Servers => "Servers",
            Self::Packets => "Packets",
            Self::Topology => "Topology",
            Self::Alerts => "Alerts",
            Self::Firewall => "Firewall",
            Self::Devices => "Devices",
            Self::Networks => "Networks",
        }
    }

}

/// Time range for the dashboard traffic graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DashboardTimeRange {
    Minutes5,
    Minutes15,
    Hour1,
    Hours24,
}

impl DashboardTimeRange {
    pub fn label(&self) -> &str {
        match self {
            Self::Minutes5 => "5m",
            Self::Minutes15 => "15m",
            Self::Hour1 => "1h",
            Self::Hours24 => "24h",
        }
    }
    pub fn samples(&self) -> usize {
        match self {
            Self::Minutes5 => 300,
            Self::Minutes15 => 900,
            Self::Hour1 => 3600,
            Self::Hours24 => 86400,
        }
    }
}

/// Extended traffic history for dashboard graph (stores per-second samples).
pub struct TrafficHistory {
    pub samples: std::collections::VecDeque<(f64, f64)>,
    pub max_samples: usize,
}

impl TrafficHistory {
    pub fn new(max: usize) -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(max.min(8192)),
            max_samples: max,
        }
    }
    pub fn push(&mut self, down_bps: f64, up_bps: f64) {
        self.samples.push_back((down_bps, up_bps));
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }
}

// ─── Process name cache ──────────────────────────────────────────────────────

pub type PidCache = HashMap<u32, String>;

/// Cache of resolved owner modules keyed by (pid, local_port, proto).
/// `None` records a failed lookup so it is not retried every tick. Entries
/// whose socket disappears are pruned each refresh, so the cache never
/// outgrows the live connection table.
pub type ModuleCache = HashMap<(u32, u16, ConnProto), Option<String>>;

// ─── Packet snippet (for live wire preview) ──────────────────────────────────

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PacketSnippet {
    pub timestamp: NaiveTime,
    pub direction: PacketDirection,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ConnProto,
    /// Printable ASCII snippet from the payload
    pub snippet: String,
    /// Total payload size in bytes
    pub payload_size: usize,
    // Wireshark-style fields:
    pub ttl: u8,
    pub ip_total_len: u16,
    pub ip_id: u16,
    /// TCP flags byte: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
    pub tcp_flags: u8,
    pub tcp_seq: u32,
    pub tcp_ack_num: u32,
    pub tcp_window: u16,
    /// First 256 bytes of actual payload for hex dump
    pub raw_payload: Vec<u8>,
}

impl PacketSnippet {
    pub fn tcp_flags_str(&self) -> String {
        if self.protocol != ConnProto::Tcp {
            return String::new();
        }
        let mut flags = Vec::new();
        if self.tcp_flags & 0x02 != 0 { flags.push("SYN"); }
        if self.tcp_flags & 0x10 != 0 { flags.push("ACK"); }
        if self.tcp_flags & 0x01 != 0 { flags.push("FIN"); }
        if self.tcp_flags & 0x04 != 0 { flags.push("RST"); }
        if self.tcp_flags & 0x08 != 0 { flags.push("PSH"); }
        if self.tcp_flags & 0x20 != 0 { flags.push("URG"); }
        if flags.is_empty() {
            String::new()
        } else {
            format!("[{}]", flags.join(","))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

// ─── Alert types (GlassWire-style) ──────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn label(&self) -> &str {
        match self {
            Self::Info => "INFO",
            Self::Warning => "WARN",
            Self::Critical => "CRIT",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::Info => Color::Rgb(80, 180, 255),
            Self::Warning => Color::Rgb(255, 200, 60),
            Self::Critical => Color::Rgb(255, 80, 80),
        }
    }
}

#[derive(Clone, Debug)]
pub enum AlertKind {
    /// First time an application connects to the network
    NewAppFirstConnection { process_name: String, remote: String },
    /// DNS server configuration changed
    DnsServerChanged { old_servers: Vec<IpAddr>, new_servers: Vec<IpAddr> },
    /// Suspicious host contacted (known bad IP)
    SuspiciousHost { process_name: String, ip: IpAddr, reason: String },
    /// RDP connection detected
    RdpConnection { remote_addr: IpAddr, inbound: bool },
    /// Bandwidth spike detected
    BandwidthSpike { direction: String, speed_bps: f64, threshold_bps: f64 },
    /// New device appeared on LAN
    NewDevice { ip: IpAddr, mac: String, hostname: Option<String> },
    /// Device left the LAN
    DeviceLeft { ip: IpAddr, mac: String },
    /// ARP spoofing: multiple IPs claiming same MAC, or IP changed MAC
    ArpAnomaly { ip: IpAddr, expected_mac: String, actual_mac: String },
    /// Bandwidth overage: data plan limit exceeded
    BandwidthOverage { used_bytes: u64, limit_bytes: u64 },
    /// Application info changed (binary modified)
    AppChanged { process_name: String, detail: String },
    /// Traffic anomaly: app traffic significantly above baseline
    TrafficAnomaly { process_name: String, current_bytes: u64, baseline_bytes: u64 },
    /// Hosts file was modified
    HostsFileChanged { detail: String },
    /// Proxy settings changed
    ProxyChanged { detail: String },
    /// Evil twin WiFi detected
    EvilTwinDetected { detail: String },
    /// Internet connectivity lost
    InternetLost { detail: String },
    /// Internet connectivity restored
    InternetRestored,
}

impl AlertKind {
    pub fn label(&self) -> &str {
        match self {
            Self::NewAppFirstConnection { .. } => "New App",
            Self::DnsServerChanged { .. } => "DNS Changed",
            Self::SuspiciousHost { .. } => "Suspicious Host",
            Self::RdpConnection { .. } => "RDP Detected",
            Self::BandwidthSpike { .. } => "Bandwidth Spike",
            Self::NewDevice { .. } => "New Device",
            Self::DeviceLeft { .. } => "Device Left",
            Self::ArpAnomaly { .. } => "ARP Anomaly",
            Self::BandwidthOverage { .. } => "Data Overage",
            Self::AppChanged { .. } => "App Changed",
            Self::TrafficAnomaly { .. } => "Anomaly",
            Self::HostsFileChanged { .. } => "Hosts Changed",
            Self::ProxyChanged { .. } => "Proxy Changed",
            Self::EvilTwinDetected { .. } => "Evil Twin",
            Self::InternetLost { .. } => "No Internet",
            Self::InternetRestored => "Internet OK",
        }
    }

    pub fn severity(&self) -> AlertSeverity {
        match self {
            Self::NewAppFirstConnection { .. } => AlertSeverity::Info,
            Self::DnsServerChanged { .. } => AlertSeverity::Warning,
            Self::SuspiciousHost { .. } => AlertSeverity::Critical,
            Self::RdpConnection { .. } => AlertSeverity::Warning,
            Self::BandwidthSpike { .. } => AlertSeverity::Info,
            Self::NewDevice { .. } => AlertSeverity::Info,
            Self::DeviceLeft { .. } => AlertSeverity::Info,
            Self::ArpAnomaly { .. } => AlertSeverity::Critical,
            Self::BandwidthOverage { .. } => AlertSeverity::Warning,
            Self::AppChanged { .. } => AlertSeverity::Warning,
            Self::TrafficAnomaly { .. } => AlertSeverity::Warning,
            Self::HostsFileChanged { .. } => AlertSeverity::Critical,
            Self::ProxyChanged { .. } => AlertSeverity::Warning,
            Self::EvilTwinDetected { .. } => AlertSeverity::Critical,
            Self::InternetLost { .. } => AlertSeverity::Critical,
            Self::InternetRestored => AlertSeverity::Info,
        }
    }

    pub fn description(&self) -> String {
        match self {
            Self::NewAppFirstConnection { process_name, remote } => {
                format!("{} connected to {} for the first time", process_name, remote)
            }
            Self::DnsServerChanged { old_servers, new_servers } => {
                format!("DNS servers changed: {:?} → {:?}", old_servers, new_servers)
            }
            Self::SuspiciousHost { process_name, ip, reason } => {
                format!("{} connected to suspicious host {} ({})", process_name, ip, reason)
            }
            Self::RdpConnection { remote_addr, inbound } => {
                let dir = if *inbound { "Inbound" } else { "Outbound" };
                format!("{} RDP connection from {}", dir, remote_addr)
            }
            Self::BandwidthSpike { direction, speed_bps, .. } => {
                format!("{} spike: {}/s", direction, crate::utils::format_bytes(*speed_bps as u64))
            }
            Self::NewDevice { ip, mac, hostname } => {
                let name = hostname.as_deref().unwrap_or("unknown");
                format!("New device: {} ({}) - {}", ip, mac, name)
            }
            Self::DeviceLeft { ip, mac } => {
                format!("Device left: {} ({})", ip, mac)
            }
            Self::ArpAnomaly { ip, expected_mac, actual_mac } => {
                format!("ARP anomaly: {} changed MAC {} → {}", ip, expected_mac, actual_mac)
            }
            Self::BandwidthOverage { used_bytes, limit_bytes } => {
                format!("Data plan exceeded: {} / {} used",
                    crate::utils::format_bytes(*used_bytes),
                    crate::utils::format_bytes(*limit_bytes))
            }
            Self::AppChanged { process_name, detail } => {
                format!("{}: {}", process_name, detail)
            }
            Self::TrafficAnomaly { process_name, current_bytes, baseline_bytes } => {
                format!("{}: traffic {}x above baseline ({} vs {})",
                    process_name,
                    if *baseline_bytes > 0 { current_bytes / baseline_bytes } else { 0 },
                    crate::utils::format_bytes(*current_bytes),
                    crate::utils::format_bytes(*baseline_bytes))
            }
            Self::HostsFileChanged { detail } => {
                format!("Hosts file modified: {}", detail)
            }
            Self::ProxyChanged { detail } => {
                format!("Proxy settings changed: {}", detail)
            }
            Self::EvilTwinDetected { detail } => {
                format!("Evil twin WiFi detected: {}", detail)
            }
            Self::InternetLost { detail } => {
                format!("Internet connectivity lost: {}", detail)
            }
            Self::InternetRestored => {
                "Internet connectivity restored".to_string()
            }
        }
    }

    /// Alert category for grouped display in the UI.
    pub fn category(&self) -> AlertCategory {
        match self {
            // Security & Threats
            Self::SuspiciousHost { .. }
            | Self::ArpAnomaly { .. }
            | Self::EvilTwinDetected { .. }
            | Self::RdpConnection { .. } => AlertCategory::Security,

            // Network Access (apps connecting)
            Self::NewAppFirstConnection { .. }
            | Self::AppChanged { .. }
            => AlertCategory::NetworkAccess,

            // System Changes
            Self::DnsServerChanged { .. }
            | Self::HostsFileChanged { .. }
            | Self::ProxyChanged { .. } => AlertCategory::SystemChanges,

            // Device Activity
            Self::NewDevice { .. }
            | Self::DeviceLeft { .. } => AlertCategory::DeviceActivity,

            // Bandwidth & Usage
            Self::BandwidthSpike { .. }
            | Self::BandwidthOverage { .. }
            | Self::TrafficAnomaly { .. } => AlertCategory::Bandwidth,

            // Connectivity
            Self::InternetLost { .. }
            | Self::InternetRestored => AlertCategory::Connectivity,
        }
    }
}

/// Categories for grouping alerts in the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertCategory {
    Security,
    NetworkAccess,
    SystemChanges,
    DeviceActivity,
    Bandwidth,
    Connectivity,
}

impl AlertCategory {
    /// Display label for section headers.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Security => "\u{1f6e1} Security & Threats",
            Self::NetworkAccess => "\u{1f310} Network Access",
            Self::SystemChanges => "\u{2699} System Changes",
            Self::DeviceActivity => "\u{1f4f1} Device Activity",
            Self::Bandwidth => "\u{1f4ca} Bandwidth & Usage",
            Self::Connectivity => "\u{1f50c} Connectivity",
        }
    }

    /// Color for section headers.
    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::Security => Color::Rgb(255, 80, 80),
            Self::NetworkAccess => Color::Rgb(100, 200, 255),
            Self::SystemChanges => Color::Rgb(255, 200, 60),
            Self::DeviceActivity => Color::Rgb(80, 220, 160),
            Self::Bandwidth => Color::Rgb(180, 140, 255),
            Self::Connectivity => Color::Rgb(255, 160, 60),
        }
    }

    /// All categories in display order.
    pub fn all() -> &'static [AlertCategory] {
        &[
            AlertCategory::Security,
            AlertCategory::NetworkAccess,
            AlertCategory::SystemChanges,
            AlertCategory::DeviceActivity,
            AlertCategory::Bandwidth,
            AlertCategory::Connectivity,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct Alert {
    pub timestamp: NaiveTime,
    pub kind: AlertKind,
    pub read: bool,
}

// ─── Per-app bandwidth tracking ─────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct AppBandwidth {
    pub process_name: String,
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub active_connections: usize,
    pub last_seen: NaiveTime,
    /// Recent speed samples for mini-sparkline
    pub recent_down: std::collections::VecDeque<f64>,
    pub recent_up: std::collections::VecDeque<f64>,
}

impl AppBandwidth {
    pub fn new(name: String) -> Self {
        Self {
            process_name: name,
            download_bytes: 0,
            upload_bytes: 0,
            active_connections: 0,
            last_seen: chrono::Local::now().time(),
            recent_down: std::collections::VecDeque::from(vec![0.0; 20]),
            recent_up: std::collections::VecDeque::from(vec![0.0; 20]),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.download_bytes + self.upload_bytes
    }

    /// Smoothed recent download speed (average of last 3 samples).
    /// Prevents flickering between "idle" and real values on alternating ticks.
    pub fn smooth_down(&self) -> f64 {
        let n = self.recent_down.len();
        if n == 0 { return 0.0; }
        let take = n.min(3);
        let sum: f64 = self.recent_down.iter().rev().take(take).sum();
        sum / take as f64
    }

    /// Smoothed recent upload speed (average of last 3 samples).
    pub fn smooth_up(&self) -> f64 {
        let n = self.recent_up.len();
        if n == 0 { return 0.0; }
        let take = n.min(3);
        let sum: f64 = self.recent_up.iter().rev().take(take).sum();
        sum / take as f64
    }
}

// ─── Network category (for Networks tab) ─────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkCategory {
    Vpn,
    Docker,
    Wsl,
    HyperV,
    Virtual,
    Secondary,
    Bluetooth,
    MeshVpn,
    Hotspot,
    Tunnel,
}

/// A non-primary network (VPN, Docker, WSL, secondary adapter, etc.).
#[derive(Clone, Debug)]
pub struct RemoteNetwork {
    /// Human-readable name (e.g., "WireGuard Tunnel", "Docker: bridge").
    pub name: String,
    /// Network category.
    pub category: NetworkCategory,
    /// Internal adapter name.
    pub adapter_name: String,
    /// Our IP on this network.
    pub local_ip: std::net::Ipv4Addr,
    /// Subnet mask.
    pub subnet_mask: std::net::Ipv4Addr,
    /// CIDR notation (e.g., "10.0.0.0/24").
    pub subnet_cidr: String,
    /// Gateway address (if configured).
    pub gateway: Option<std::net::Ipv4Addr>,
    /// Devices discovered on this network.
    pub devices: Vec<LanDevice>,
}

// ─── LAN device (scanner) ───────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LanDevice {
    pub ip: IpAddr,
    pub mac: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: NaiveTime,
    pub last_seen: NaiveTime,
    pub is_online: bool,
    /// User-assigned custom label for this device.
    pub custom_name: Option<String>,
    /// Aggregated discovery details from all resolution methods.
    pub discovery_info: String,
    /// Open ports discovered via TCP connect scan.
    pub open_ports: String,
    /// Bytes sent from this PC to this device (cumulative).
    pub bytes_sent: u64,
    /// Bytes received by this PC from this device (cumulative).
    pub bytes_received: u64,
    /// Current tick accumulators (reset each tick).
    pub tick_sent: u64,
    pub tick_received: u64,
    /// Smoothed speed (bytes/s) from last few ticks.
    pub speed_sent: f64,
    pub speed_received: f64,
}

// ─── Firewall rule ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct FirewallRule {
    pub name: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallMode {
    Normal,
    AskToConnect,
    Lockdown,
}


impl FirewallMode {
    pub fn label(&self) -> &str {
        match self {
            Self::Normal => "Normal",
            Self::AskToConnect => "Ask to Connect",
            Self::Lockdown => "Lockdown",
        }
    }
}

/// Action for an app managed by PSNET firewall rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAppAction {
    /// Explicit allow rule (override any other blocks).
    Allow,
    /// Block (connection refused / dropped).
    Deny,
    /// Silent drop (identical to Deny on Windows Firewall, tracked separately).
    Drop,
}

/// Combined firewall + bandwidth detail for the popup overlay.
#[derive(Clone, Debug)]
pub struct FirewallAppDetail {
    pub app_name: String,
    pub app_path: Option<String>,
    pub is_blocked: bool,
    pub current_action: Option<FirewallAppAction>,
    pub conn_count: usize,
    // Bandwidth data
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub current_down_speed: f64,
    pub current_up_speed: f64,
    pub peak_down_speed: f64,
    pub peak_up_speed: f64,
    pub last_seen: String,
    // Action selector state
    pub selected_action: usize, // 0=Allow, 1=Deny, 2=Drop, 3=Back
}

// ─── Data plan / usage persistence ──────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataPlan {
    pub limit_bytes: u64,
    pub reset_day: u8,       // Day of month to reset (1-28)
    pub alert_pct: u8,       // Alert when usage hits this % (e.g., 80)
}

impl Default for DataPlan {
    fn default() -> Self {
        Self {
            limit_bytes: 0, // 0 = no limit
            reset_day: 1,
            alert_pct: 80,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageRecord {
    pub date: String, // YYYY-MM-DD
    pub download_bytes: u64,
    pub upload_bytes: u64,
    pub per_app: HashMap<String, (u64, u64)>, // process_name -> (down, up)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageStore {
    pub data_plan: DataPlan,
    pub daily_records: Vec<UsageRecord>,
}

impl Default for UsageStore {
    fn default() -> Self {
        Self {
            data_plan: DataPlan::default(),
            daily_records: Vec::new(),
        }
    }
}

// ─── Threat intelligence ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ThreatInfo {
    pub ip: IpAddr,
    pub reason: String,
}

// ─── Detail popup ─────────────────────────────────────────────────────────────

/// What is currently being shown in the detail popup overlay.
#[derive(Clone, Debug)]
pub enum DetailKind {
    Connection(Connection),
    Alert(Alert),
    Device(LanDevice),
    FirewallApp(FirewallAppDetail),
    Server {
        kind_label: String,
        kind_icon: String,
        category: String,
        port: u16,
        proto: String,
        bind_addr: String,
        pid: u32,
        process_name: String,
        exe_path: String,
        cmdline: String,
        product_name: String,
        company_name: String,
        version: String,
        http_title: String,
        banner: String,
        response_headers: Vec<(String, String)>,
        active_connections: u32,
        first_seen: String,
        is_responsive: bool,
        tls_detected: bool,
        category_color: (u8, u8, u8),
        detected_techs: Vec<(String, String, String)>, // (name, category, version)
    },
}
