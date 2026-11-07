//! Alert engine — GlassWire-style security & network alerts.
//!
//! Monitors for: new app connections, DNS config changes, suspicious hosts,
//! RDP connections, bandwidth spikes, ARP anomalies, data plan overages,
//! anomaly detection, idle summary, system monitor events.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::Local;

use crate::types::*;

/// Configuration for alert thresholds.
pub struct AlertConfig {
    /// Bandwidth spike threshold (bytes/sec) — alert if exceeded
    pub spike_threshold_down: f64,
    pub spike_threshold_up: f64,
    /// Enable individual alert categories
    pub enable_new_app: bool,
    pub enable_dns_change: bool,
    pub enable_suspicious: bool,
    pub enable_rdp: bool,
    pub enable_spike: bool,
    pub enable_device: bool,
    pub enable_arp: bool,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            spike_threshold_down: 50_000_000.0, // 50 MB/s
            spike_threshold_up: 10_000_000.0,    // 10 MB/s
            enable_new_app: true,
            enable_dns_change: true,
            enable_suspicious: true,
            enable_rdp: true,
            enable_spike: true,
            enable_device: true,
            enable_arp: true,
        }
    }
}

/// Anomaly detector — tracks per-app traffic baselines.
pub struct AnomalyDetector {
    /// Per-app average bytes/tick (rolling average over ~60 samples).
    baselines: HashMap<String, VecDeque<f64>>,
    /// Multiplier: alert if current > baseline * multiplier.
    pub threshold_multiplier: f64,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            threshold_multiplier: 5.0,
        }
    }

    /// Feed current per-app bandwidth and detect anomalies.
    /// Returns list of (process_name, current_bps, avg_bps) for anomalous apps.
    pub fn check(&mut self, app_bandwidth: &HashMap<String, AppBandwidth>) -> Vec<(String, f64, f64)> {
        let mut anomalies = Vec::new();

        for (name, bw) in app_bandwidth {
            let current = (bw.download_bytes + bw.upload_bytes) as f64;
            let history = self.baselines.entry(name.clone()).or_insert_with(|| {
                VecDeque::from(vec![0.0; 60])
            });

            let avg: f64 = history.iter().sum::<f64>() / history.len().max(1) as f64;

            // Only flag if baseline is established (avg > 0) and current is anomalous
            if avg > 1000.0 && current > avg * self.threshold_multiplier {
                anomalies.push((name.clone(), current, avg));
            }

            history.push_back(current);
            if history.len() > 60 {
                history.pop_front();
            }
        }

        anomalies
    }
}

/// Tracks activity while user is idle for "While You Were Away" summary.
pub struct IdleTracker {
    /// Time of last user input.
    pub last_input: Instant,
    /// Idle threshold (seconds) before we consider the user "away".
    pub idle_threshold_secs: u64,
    /// Whether we're currently in idle mode.
    pub is_idle: bool,
    /// Events collected while idle.
    pub idle_events: Vec<String>,
    /// New connections observed while idle.
    pub idle_new_connections: usize,
    /// Bytes transferred while idle.
    pub idle_bytes_down: u64,
    pub idle_bytes_up: u64,
    /// Summary ready to display (set when user returns).
    pub pending_summary: Option<IdleSummary>,
}

#[derive(Clone, Debug)]
pub struct IdleSummary {
    pub duration_secs: u64,
    pub new_connections: usize,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub events: Vec<String>,
}

impl IdleTracker {
    pub fn new() -> Self {
        Self {
            last_input: Instant::now(),
            idle_threshold_secs: 120, // 2 minutes
            is_idle: false,
            idle_events: Vec::new(),
            idle_new_connections: 0,
            idle_bytes_down: 0,
            idle_bytes_up: 0,
            pending_summary: None,
        }
    }

    /// Call on every user keypress.
    pub fn on_input(&mut self) {
        if self.is_idle {
            // User returned — generate summary
            let duration = self.last_input.elapsed().as_secs();
            if !self.idle_events.is_empty() || self.idle_new_connections > 0 {
                self.pending_summary = Some(IdleSummary {
                    duration_secs: duration,
                    new_connections: self.idle_new_connections,
                    bytes_down: self.idle_bytes_down,
                    bytes_up: self.idle_bytes_up,
                    events: self.idle_events.drain(..).collect(),
                });
            }
            self.is_idle = false;
            self.idle_new_connections = 0;
            self.idle_bytes_down = 0;
            self.idle_bytes_up = 0;
        }
        self.last_input = Instant::now();
    }

    /// Call each tick to check idle status and accumulate data.
    pub fn tick(&mut self, new_conns: usize, bytes_down: u64, bytes_up: u64) {
        let elapsed = self.last_input.elapsed().as_secs();
        if elapsed >= self.idle_threshold_secs {
            self.is_idle = true;
            self.idle_new_connections += new_conns;
            self.idle_bytes_down += bytes_down;
            self.idle_bytes_up += bytes_up;
        }
    }

    /// Record a notable event during idle.
    pub fn record_event(&mut self, event: String) {
        if self.is_idle && self.idle_events.len() < 50 {
            self.idle_events.push(event);
        }
    }

}

/// The alert engine — tracks state and generates alerts.
pub struct AlertEngine {
    /// Alerts log (newest at end).
    pub alerts: Vec<Alert>,
    pub max_alerts: usize,
    /// Set of known app names that have connected before.
    known_apps: HashSet<String>,
    /// Previous DNS server list for change detection.
    prev_dns_servers: Vec<IpAddr>,
    /// Known device MACs for ARP anomaly detection.
    known_device_macs: HashMap<IpAddr, String>,
    /// Config
    pub config: AlertConfig,
    /// Unread count
    pub unread_count: usize,
    /// Alert snooze: if set, no new alerts until this instant.
    pub snoozed_until: Option<Instant>,
    /// Anomaly detector
    pub anomaly_detector: AnomalyDetector,
    /// Idle tracker (While You Were Away)
    pub idle_tracker: IdleTracker,
    /// "Since your last visit" summary (shown once on startup)
    pub last_visit_summary: Option<LastVisitSummary>,
    /// Path for alert persistence
    alerts_path: PathBuf,
    /// Path for known-state persistence
    known_state_path: PathBuf,
    /// Addresses the user trusts: alerts about them are not raised (#11).
    pub trusted: crate::network::trusted::TrustedIps,
    /// Deferred load result from background thread
    deferred_state: Option<Arc<Mutex<Option<(HashSet<String>, HashMap<IpAddr, String>, Vec<IpAddr>, Option<LastVisitSummary>)>>>>,
}

impl AlertEngine {
    pub fn new(max_alerts: usize) -> Self {
        let (alerts_path, known_state_path) = Self::default_paths();

        // Start loading known state in background thread
        let deferred = Arc::new(Mutex::new(None));
        {
            let deferred_clone = Arc::clone(&deferred);
            let path = known_state_path.clone();
            std::thread::spawn(move || {
                let result = Self::load_known_state(&path);
                if let Ok(mut d) = deferred_clone.lock() {
                    *d = Some(result);
                }
            });
        }

        Self {
            alerts: Vec::with_capacity(max_alerts),
            max_alerts,
            known_apps: HashSet::new(),
            prev_dns_servers: Vec::new(),
            known_device_macs: HashMap::new(),
            config: AlertConfig::default(),
            unread_count: 0,
            snoozed_until: None,
            anomaly_detector: AnomalyDetector::new(),
            idle_tracker: IdleTracker::new(),
            last_visit_summary: None,
            trusted: crate::network::trusted::TrustedIps::load(
                known_state_path.with_file_name("trusted_ips.txt"),
            ),
            alerts_path,
            known_state_path,
            deferred_state: Some(deferred),
        }
    }

    /// Poll for deferred init completion. Returns true if state was loaded.
    pub fn poll_deferred_init(&mut self) -> bool {
        let deferred = match self.deferred_state.take() {
            Some(d) => d,
            None => return false,
        };
        if let Ok(mut d) = deferred.lock() {
            if let Some((apps, macs, dns, summary)) = d.take() {
                self.known_apps = apps;
                self.known_device_macs = macs;
                self.prev_dns_servers = dns;
                self.last_visit_summary = summary;
                return true;
            }
        }
        // Not ready yet — put it back
        self.deferred_state = Some(deferred);
        false
    }

    fn default_paths() -> (PathBuf, PathBuf) {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            (dir.join("alerts.json"), dir.join("known_state.json"))
        } else {
            (PathBuf::from("psnet_alerts.json"), PathBuf::from("psnet_state.json"))
        }
    }

    fn load_known_state(path: &PathBuf) -> (
        HashSet<String>,
        HashMap<IpAddr, String>,
        Vec<IpAddr>,
        Option<LastVisitSummary>,
    ) {
        let data = match std::fs::read_to_string(path) {
            Ok(d) => d,
            Err(_) => return (HashSet::new(), HashMap::new(), Vec::new(), None),
        };
        let state: KnownState = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(_) => return (HashSet::new(), HashMap::new(), Vec::new(), None),
        };

        let known_apps: HashSet<String> = state.known_apps.into_iter().collect();

        let known_macs: HashMap<IpAddr, String> = state.known_macs.into_iter()
            .filter_map(|(ip_str, mac)| {
                ip_str.parse::<IpAddr>().ok().map(|ip| (ip, mac))
            })
            .collect();

        let dns_servers: Vec<IpAddr> = state.dns_servers.iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();

        let summary = state.last_session_end.map(|end| LastVisitSummary {
            last_session_end: end,
            alert_count: state.last_session_alert_count,
            bytes_down: state.last_session_bytes_down,
            bytes_up: state.last_session_bytes_up,
            connections: state.last_session_connections,
            device_count: state.last_session_device_count,
        });

        (known_apps, known_macs, dns_servers, summary)
    }

    /// Check connections for new app first-connection alerts.
    pub fn check_new_apps(&mut self, connections: &[Connection], dns_cache: &DnsCache) {
        if !self.config.enable_new_app {
            return;
        }
        for conn in connections {
            // "[Kernel]" and "[Closed]" are placeholders, not apps
            if conn.process_name.is_empty()
                || conn.process_name.starts_with("PID:")
                || conn.process_name.starts_with('[')
            {
                continue;
            }
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            let key = conn.process_name.to_lowercase();
            if self.known_apps.insert(key) {
                let remote = conn.remote_addr
                    .map(|ip| {
                        dns_cache.get(&ip)
                            .and_then(|d| d.clone())
                            .unwrap_or_else(|| ip.to_string())
                    })
                    .unwrap_or_else(|| "*".to_string());

                self.push_alert(AlertKind::NewAppFirstConnection {
                    process_name: conn.process_name.clone(),
                    remote,
                });
            }
        }
    }

    /// Check for RDP connections (port 3389).
    pub fn check_rdp(&mut self, connections: &[Connection]) {
        if !self.config.enable_rdp {
            return;
        }
        for conn in connections {
            if !matches!(conn.state.as_ref(), Some(TcpState::Established)) {
                continue;
            }
            let is_rdp_inbound = conn.local_port == 3389;
            let is_rdp_outbound = conn.remote_port == Some(3389);

            if is_rdp_inbound {
                if let Some(remote) = conn.remote_addr {
                    self.push_alert(AlertKind::RdpConnection {
                        remote_addr: remote,
                        inbound: true,
                    });
                }
            } else if is_rdp_outbound {
                if let Some(remote) = conn.remote_addr {
                    self.push_alert(AlertKind::RdpConnection {
                        remote_addr: remote,
                        inbound: false,
                    });
                }
            }
        }
    }

    /// Check for bandwidth spikes.
    pub fn check_bandwidth_spike(&mut self, down_bps: f64, up_bps: f64) {
        if !self.config.enable_spike {
            return;
        }
        if down_bps > self.config.spike_threshold_down {
            self.push_alert(AlertKind::BandwidthSpike {
                direction: "Download".to_string(),
                speed_bps: down_bps,
                threshold_bps: self.config.spike_threshold_down,
            });
        }
        if up_bps > self.config.spike_threshold_up {
            self.push_alert(AlertKind::BandwidthSpike {
                direction: "Upload".to_string(),
                speed_bps: up_bps,
                threshold_bps: self.config.spike_threshold_up,
            });
        }
    }

    /// Check for suspicious host connections.
    pub fn check_suspicious(
        &mut self,
        connections: &[Connection],
        threats: &[ThreatInfo],
    ) {
        if !self.config.enable_suspicious {
            return;
        }
        let threat_ips: HashMap<IpAddr, &ThreatInfo> = threats.iter()
            .map(|t| (t.ip, t))
            .collect();

        for conn in connections {
            if let Some(remote) = conn.remote_addr {
                if let Some(threat) = threat_ips.get(&remote) {
                    self.push_alert(AlertKind::SuspiciousHost {
                        process_name: conn.process_name.clone(),
                        ip: remote,
                        reason: threat.reason.clone(),
                    });
                }
            }
        }
    }

    /// Check DNS server configuration changes.
    pub fn check_dns_servers(&mut self, current_servers: &[IpAddr]) {
        if !self.config.enable_dns_change {
            return;
        }
        if self.prev_dns_servers.is_empty() {
            self.prev_dns_servers = current_servers.to_vec();
            return;
        }
        if self.prev_dns_servers != current_servers {
            self.push_alert(AlertKind::DnsServerChanged {
                old_servers: self.prev_dns_servers.clone(),
                new_servers: current_servers.to_vec(),
            });
            self.prev_dns_servers = current_servers.to_vec();
        }
    }

    /// Check for ARP anomalies from device scan results.
    pub fn check_arp_anomalies(&mut self, devices: &[LanDevice]) {
        if !self.config.enable_arp {
            return;
        }
        for device in devices {
            // Skip devices with empty MAC (discovered by ICMP/TCP/LLMNR — no MAC yet)
            if device.mac.is_empty() {
                continue;
            }
            if let Some(expected_mac) = self.known_device_macs.get(&device.ip) {
                // Only alert if BOTH old and new MACs are non-empty (real MAC change)
                if !expected_mac.is_empty() && *expected_mac != device.mac {
                    self.push_alert(AlertKind::ArpAnomaly {
                        ip: device.ip,
                        expected_mac: expected_mac.clone(),
                        actual_mac: device.mac.clone(),
                    });
                }
                // Always update to the latest known MAC
                self.known_device_macs.insert(device.ip, device.mac.clone());
            } else {
                self.known_device_macs.insert(device.ip, device.mac.clone());
            }
        }
    }

    /// Check for new/departed devices.
    pub fn check_device_changes(
        &mut self,
        current_devices: &[LanDevice],
        prev_devices: &[LanDevice],
    ) {
        if !self.config.enable_device {
            return;
        }
        // Skip devices with empty MACs — streaming discovery finds IPs first,
        // MACs arrive later. Comparing empty MACs causes false churn alerts.
        let prev_macs: HashSet<&str> = prev_devices.iter()
            .filter(|d| !d.mac.is_empty())
            .map(|d| d.mac.as_str())
            .collect();
        let curr_macs: HashSet<&str> = current_devices.iter()
            .filter(|d| !d.mac.is_empty())
            .map(|d| d.mac.as_str())
            .collect();

        // New devices (only if they have a real MAC)
        for device in current_devices {
            if device.mac.is_empty() { continue; }
            if !prev_macs.contains(device.mac.as_str()) {
                self.push_alert(AlertKind::NewDevice {
                    ip: device.ip,
                    mac: device.mac.clone(),
                    hostname: device.hostname.clone(),
                });
            }
        }

        // Departed devices (only if they had a real MAC)
        for device in prev_devices {
            if device.mac.is_empty() { continue; }
            if !curr_macs.contains(device.mac.as_str()) {
                self.push_alert(AlertKind::DeviceLeft {
                    ip: device.ip,
                    mac: device.mac.clone(),
                });
            }
        }
    }

    /// Check data plan overage.
    pub fn check_data_plan(&mut self, used_bytes: u64, limit_bytes: u64, alert_pct: u8) {
        if limit_bytes == 0 {
            return;
        }
        let pct = (used_bytes as f64 / limit_bytes as f64 * 100.0) as u8;
        if pct >= alert_pct {
            self.push_alert(AlertKind::BandwidthOverage {
                used_bytes,
                limit_bytes,
            });
        }
    }

    fn push_alert(&mut self, kind: AlertKind) {
        // The user trusts this address: say nothing about it.
        if let Some(ip) = kind.subject_ip() {
            if self.trusted.contains(ip) {
                return;
            }
        }

        // Check snooze
        if let Some(until) = self.snoozed_until {
            if Instant::now() < until {
                return; // Snoozed
            } else {
                self.snoozed_until = None;
            }
        }

        // Dedup: don't push identical alert within last 30 seconds
        let desc = kind.description();
        if let Some(last) = self.alerts.last() {
            if last.kind.description() == desc {
                return; // Skip duplicate
            }
        }

        // Record in idle tracker if active
        self.idle_tracker.record_event(format!("[{}] {}", kind.label(), desc));

        self.alerts.push(Alert {
            timestamp: Local::now().time(),
            kind,
            read: false,
        });
        self.unread_count += 1;

        if self.alerts.len() > self.max_alerts {
            self.alerts.drain(0..self.alerts.len() - self.max_alerts);
        }
    }

    /// Trust or stop trusting `ip`. Trusting also removes the alerts already
    /// raised about it. Returns true when the address is trusted afterwards.
    pub fn toggle_trusted(&mut self, ip: IpAddr) -> bool {
        let trusted = self.trusted.toggle(ip);
        if trusted {
            let list = &self.trusted;
            self.alerts.retain(|a| a.kind.subject_ip().map_or(true, |s| !list.contains(s)));
            self.unread_count = self.alerts.iter().filter(|a| !a.read).count();
        }
        trusted
    }

    /// Mark all alerts as read.
    pub fn mark_all_read(&mut self) {
        for alert in &mut self.alerts {
            alert.read = true;
        }
        self.unread_count = 0;
    }

    /// Get the count of unread alerts.
    pub fn unread(&self) -> usize {
        self.unread_count
    }

    // ─── Snooze ──────────────────────────────────────────────────────

    /// Snooze all alerts for N seconds.
    pub fn snooze(&mut self, seconds: u64) {
        self.snoozed_until = Some(Instant::now() + std::time::Duration::from_secs(seconds));
    }

    /// Check if alerts are currently snoozed.
    pub fn is_snoozed(&self) -> bool {
        self.snoozed_until
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Cancel snooze.
    pub fn unsnooze(&mut self) {
        self.snoozed_until = None;
    }

    // ─── Anomaly detection ───────────────────────────────────────────

    /// Check for traffic anomalies across all tracked apps.
    pub fn check_anomalies(&mut self, app_bandwidth: &HashMap<String, AppBandwidth>) {
        let anomalies = self.anomaly_detector.check(app_bandwidth);
        for (name, current, avg) in anomalies {
            self.push_alert(AlertKind::TrafficAnomaly {
                process_name: name,
                current_bytes: current as u64,
                baseline_bytes: avg as u64,
            });
        }
    }

    // ─── System monitor events ───────────────────────────────────────

    /// Ingest events from the system monitor (hosts file, proxy, WiFi, app hash).
    pub fn check_system_events(&mut self, events: &[crate::network::system_monitor::SystemEvent]) {
        use crate::network::system_monitor::SystemEvent;
        for event in events {
            match event {
                SystemEvent::HostsFileChanged(detail) => {
                    self.push_alert(AlertKind::HostsFileChanged {
                        detail: detail.clone(),
                    });
                }
                SystemEvent::ProxyChanged(detail) => {
                    self.push_alert(AlertKind::ProxyChanged {
                        detail: detail.clone(),
                    });
                }
                SystemEvent::EvilTwinDetected(detail) => {
                    self.push_alert(AlertKind::EvilTwinDetected {
                        detail: detail.clone(),
                    });
                }
                SystemEvent::AppBinaryChanged { app, detail } => {
                    self.push_alert(AlertKind::AppChanged {
                        process_name: app.clone(),
                        detail: detail.clone(),
                    });
                }
                SystemEvent::InternetLost(detail) => {
                    self.push_alert(AlertKind::InternetLost { detail: detail.clone() });
                }
                SystemEvent::InternetRestored => {
                    self.push_alert(AlertKind::InternetRestored);
                }
            }
        }
    }

    // ─── Persistence ─────────────────────────────────────────────────

    /// Save current alerts to disk (JSON).
    pub fn save_alerts(&self) {
        // Only save last 200 alerts to keep file small
        let to_save: Vec<_> = self.alerts.iter()
            .rev()
            .take(200)
            .map(|a| SavedAlert {
                timestamp: a.timestamp.format("%H:%M:%S").to_string(),
                kind: a.kind.label().to_string(),
                description: a.kind.description(),
                severity: a.kind.severity().label().to_string(),
                read: a.read,
            })
            .collect();

        if let Ok(json) = serde_json::to_string_pretty(&to_save) {
            let _ = std::fs::write(&self.alerts_path, json);
        }
    }

    /// Save known state (apps, MACs, DNS, session stats) to disk for next startup.
    pub fn save_known_state(&self, total_down: u64, total_up: u64, conn_count: usize, device_count: usize) {
        // Cap persisted data to prevent unbounded growth
        let known_apps: Vec<String> = self.known_apps.iter().take(500).cloned().collect();
        let known_macs: Vec<(String, String)> = self.known_device_macs.iter()
            .take(500)
            .map(|(ip, mac)| (ip.to_string(), mac.clone()))
            .collect();
        let state = KnownState {
            known_apps,
            known_macs,
            dns_servers: self.prev_dns_servers.iter().map(|ip| ip.to_string()).collect(),
            last_session_end: Some(Local::now().format("%Y-%m-%d %H:%M:%S").to_string()),
            last_session_alert_count: self.alerts.len(),
            last_session_bytes_down: total_down,
            last_session_bytes_up: total_up,
            last_session_connections: conn_count,
            last_session_device_count: device_count,
        };

        if let Ok(json) = serde_json::to_string_pretty(&state) {
            let _ = std::fs::write(&self.known_state_path, json);
        }
    }
}

// ─── DNS server detection ────────────────────────────────────────────────────

/// Read current DNS server addresses from the system.
pub fn get_dns_servers() -> Vec<IpAddr> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ip", "show", "dns"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        // Look for lines containing IP addresses
        if let Some(ip_str) = extract_ip_from_line(trimmed) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }
    servers
}

/// Serializable alert for disk persistence.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SavedAlert {
    pub timestamp: String,
    pub kind: String,
    pub description: String,
    pub severity: String,
    pub read: bool,
}

/// Persistent known-state saved between sessions.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct KnownState {
    /// Apps that have been seen connecting before.
    pub known_apps: Vec<String>,
    /// Known MAC addresses per IP (for ARP anomaly detection).
    pub known_macs: Vec<(String, String)>, // (ip_str, mac)
    /// Previous DNS server addresses.
    pub dns_servers: Vec<String>,
    /// Last session end time (ISO 8601).
    pub last_session_end: Option<String>,
    /// Total alerts in last session.
    pub last_session_alert_count: usize,
    /// Total bytes down in last session.
    pub last_session_bytes_down: u64,
    /// Total bytes up in last session.
    pub last_session_bytes_up: u64,
    /// Total connections seen in last session.
    pub last_session_connections: usize,
    /// Total unique devices seen in last session.
    pub last_session_device_count: usize,
}

/// Summary of what happened since the user's last visit.
#[derive(Clone, Debug)]
pub struct LastVisitSummary {
    pub last_session_end: String,
    pub alert_count: usize,
    pub bytes_down: u64,
    pub bytes_up: u64,
    pub connections: usize,
    pub device_count: usize,
}

fn extract_ip_from_line(line: &str) -> Option<&str> {
    // Lines like "Statically Configured DNS Servers:    8.8.8.8"
    // or just "                                         8.8.4.4"
    for word in line.split_whitespace().rev() {
        if word.contains('.') || word.contains(':') {
            // Check if it looks like an IP
            if word.parse::<IpAddr>().is_ok() {
                return Some(word);
            }
        }
    }
    None
}
