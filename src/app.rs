use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::process::Command;

use crossterm::event::{KeyCode, MouseEventKind};
use ratatui::layout::Rect;
use sysinfo::Networks;

use crate::network::alerts::AlertEngine;
use crate::network::bandwidth::BandwidthTracker;
use crate::network::capture::TrafficTracker;
use crate::network::connections::fetch_connections;
use crate::network::dns;
use crate::network::firewall::FirewallManager;
use crate::network::geoip::GeoIpResolver;
use crate::network::networks::NetworksScanner;
use crate::network::protocols::ProtocolTracker;
use crate::network::scanner::NetworkScanner;
use crate::network::servers::ServersScanner;
use crate::network::sniffer::PacketSniffer;
use crate::network::speed::get_network_bytes;
use crate::network::system_monitor::SystemMonitor;
use crate::network::threats::ThreatDetector;
use crate::network::usage::UsageTracker;
use crate::types::*;

/// Application state — owns all data, updated each tick.
pub struct App {
    // Speed monitoring
    pub speed_history: SpeedHistory,
    pub current_down_speed: f64,
    pub current_up_speed: f64,
    pub peak_down: f64,
    pub peak_up: f64,
    pub total_down: u64,
    pub total_up: u64,
    pub interface_name: String,
    prev_bytes_recv: u64,
    prev_bytes_sent: u64,
    prev_time: Instant,
    prev_traffic_log_len: usize,

    // Connections tab
    pub connections: Vec<Connection>,
    pub conn_scroll: usize,
    pub sort_column: usize,
    pub sort_ascending: bool,
    pub show_listen: bool,
    pub filter_text: String,

    // Traffic tab
    pub traffic_tracker: TrafficTracker,

    // UI state
    pub bottom_tab: BottomTab,
    pub session_start: Instant,
    /// Hide localhost connections in Connections tab.
    pub hide_localhost_conn: bool,
    /// Selected row in Devices tab.
    pub device_scroll: usize,
    /// Dashboard time range selector.
    pub dashboard_time_range: DashboardTimeRange,
    /// Extended traffic history for dashboard graph.
    pub traffic_history: TrafficHistory,
    /// Connection count history for dashboard sparkline.
    pub connection_count_history: std::collections::VecDeque<u64>,

    // Packet sniffer (wire preview)
    pub sniffer: PacketSniffer,

    // ─── GlassWire-style modules ─────────────────────────────────────
    /// Per-app bandwidth tracking
    pub bandwidth_tracker: BandwidthTracker,
    /// Alert engine (security + network alerts)
    pub alert_engine: AlertEngine,
    /// LAN device scanner
    pub network_scanner: NetworkScanner,
    /// Windows Firewall manager
    pub firewall_manager: FirewallManager,
    /// Threat intelligence detector
    pub threat_detector: ThreatDetector,
    /// Data plan + usage persistence
    pub usage_tracker: UsageTracker,
    /// GeoIP country resolver
    pub geoip: GeoIpResolver,
    /// System monitor (hosts file, proxy, WiFi, app hash)
    pub system_monitor: SystemMonitor,
    /// Non-primary networks scanner (VPN, Docker, WSL, secondary adapters)
    pub networks_scanner: NetworksScanner,
    /// Local servers/listeners scanner (Wappalyzer for PC)
    pub servers_scanner: ServersScanner,

    // Detail popup overlay
    pub detail_popup: Option<DetailKind>,

    /// Tick counter — incremented each update, used for live pulse indicator.
    pub tick_count: u64,

    /// Protocol activity tracker for tag cloud widget.
    pub protocol_tracker: ProtocolTracker,

    // Packets tab state
    pub packets_scroll: usize,
    pub packets_filter: String,
    pub packets_paused: bool,
    pub packets_detail_open: bool,

    // Topology tab state
    pub topology_scroll: usize,

    // Sort state for Devices tab
    pub device_sort_column: usize,
    pub device_sort_ascending: bool,
    // Networks tab state
    pub networks_scroll: usize,
    pub networks_sort_column: usize,
    pub networks_sort_ascending: bool,
    pub bluetooth_expanded: bool,
    // Sort state for Alerts tab
    pub alert_sort_column: Option<usize>,
    pub alert_sort_ascending: bool,
    /// Alerts: which pane (by AlertCategory index among active cats) is focused
    pub alert_focused_pane: usize,
    /// Alerts: per-category scroll offset (keyed by category ordinal)
    pub alert_pane_scrolls: [usize; 6],
    /// Alerts: cached pane rects from last draw (for mouse hit-testing)
    pub alert_pane_rects: Vec<(AlertCategory, ratatui::layout::Rect)>,

    /// Whether incognito mode is active (no disk writes).
    pub incognito: bool,
    /// Hide offline devices in the Devices tab.
    pub hide_offline_devices: bool,
    /// Device rename state — Some(device_index) when renaming.
    pub renaming_device: Option<usize>,
    /// Text buffer for device rename.
    pub device_rename_text: String,

    // World map: recently-closed connections shown as fading dots.
    // (remote_addr, country_code, tick_when_closed)
    pub map_fading_dots: Vec<(IpAddr, &'static str, u64)>,
    /// Previous tick's set of mapped remote IPs (for detecting closures).
    map_prev_remote_ips: HashSet<IpAddr>,
    /// Dashboard map fullscreen toggle.
    pub map_fullscreen: bool,

    /// System-configured DNS servers (detected from ipconfig /all).
    pub dns_servers: Vec<IpAddr>,

    /// Last rendered frame size, used for mouse click coordinate mapping.
    pub last_frame_size: Rect,

    /// Transient status message shown briefly (text, when).
    pub status_message: Option<(String, Instant)>,

    // Internal
    pid_cache: PidCache,
    pub dns_cache: DnsCache,
    dns_tick: u32,

    // Background task results — avoid blocking UI thread
    bg_dns_servers: Arc<Mutex<Option<Vec<IpAddr>>>>,
    bg_dns_ipconfig: Arc<Mutex<Option<Vec<(IpAddr, String)>>>>,

    /// Subsystems disabled via PSNET_DISABLE (comma separated), for leak
    /// bisection and low-footprint operation.
    disabled: std::collections::HashSet<String>,
}

impl App {
    pub fn new(networks: &Networks) -> Self {
        let (recv, sent, iface) = get_network_bytes(networks);
        let disabled: std::collections::HashSet<String> = std::env::var("PSNET_DISABLE")
            .map(|v| v.split(',').map(|s| s.trim().to_lowercase()).collect())
            .unwrap_or_default();
        Self {
            speed_history: SpeedHistory::new(60),
            current_down_speed: 0.0,
            current_up_speed: 0.0,
            peak_down: 0.0,
            peak_up: 0.0,
            total_down: 0,
            total_up: 0,
            interface_name: iface,
            prev_bytes_recv: recv,
            prev_bytes_sent: sent,
            prev_time: Instant::now(),
            prev_traffic_log_len: 0,

            connections: Vec::new(),
            conn_scroll: 0,
            sort_column: 5, // Default sort by State
            sort_ascending: true, // ESTABLISHED first (rank 0)
            show_listen: true,
            filter_text: String::new(),

            traffic_tracker: TrafficTracker::new(5000),

            bottom_tab: BottomTab::Dashboard,
            session_start: Instant::now(),
            hide_localhost_conn: true,
            device_scroll: 0,
            dashboard_time_range: DashboardTimeRange::Minutes5,
            traffic_history: TrafficHistory::new(86400),
            connection_count_history: std::collections::VecDeque::with_capacity(300),

            sniffer: {
                let mut s = PacketSniffer::new(5000);
                if !disabled.contains("sniffer") {
                    s.start();
                }
                s
            },

            // GlassWire-style modules
            bandwidth_tracker: BandwidthTracker::new(),
            alert_engine: AlertEngine::new(1000),
            network_scanner: NetworkScanner::new(),
            networks_scanner: NetworksScanner::new(None), // primary_ip set after first scan
            servers_scanner: ServersScanner::new(),
            firewall_manager: FirewallManager::new(),
            threat_detector: ThreatDetector::new(),
            usage_tracker: UsageTracker::new(),
            geoip: GeoIpResolver::new(),
            system_monitor: SystemMonitor::new(),

            detail_popup: None,
            tick_count: 0,

            protocol_tracker: ProtocolTracker::new(),

            packets_scroll: 0,
            packets_filter: String::new(),
            packets_paused: false,
            packets_detail_open: false,

            topology_scroll: 0,

            device_sort_column: 0,
            device_sort_ascending: false,
            networks_scroll: 0,
            networks_sort_column: 0,
            networks_sort_ascending: false,
            bluetooth_expanded: false,
            alert_sort_column: None,
            alert_sort_ascending: false,
            alert_focused_pane: 0,
            alert_pane_scrolls: [0; 6],
            alert_pane_rects: Vec::new(),

            incognito: false,
            hide_offline_devices: true,
            renaming_device: None,
            device_rename_text: String::new(),

            map_fading_dots: Vec::new(),
            map_prev_remote_ips: HashSet::new(),
            map_fullscreen: false,

            dns_servers: Vec::new(),
            last_frame_size: Rect::default(),

            pid_cache: PidCache::new(),
            dns_cache: DnsCache::new(),
            dns_tick: 0,

            bg_dns_servers: Arc::new(Mutex::new(None)),
            bg_dns_ipconfig: Arc::new(Mutex::new(None)),
            disabled,
            status_message: None,
        }
    }

    /// Fast poll: drain streaming scanner buffers between full ticks.
    /// Called every 200ms for maximum responsiveness. Returns true if data changed.
    pub fn fast_poll(&mut self) -> bool {
        let mut changed = false;

        // Poll devices scanner streaming buffer (always — results arrive from bg thread)
        if let Some(prev_devices) = self.network_scanner.poll_results() {
            self.alert_engine.check_arp_anomalies(&self.network_scanner.devices);
            self.alert_engine.check_device_changes(&self.network_scanner.devices, &prev_devices);
            changed = true;
        }

        // Poll networks scanner streaming buffer — only when on Networks tab
        if self.bottom_tab == BottomTab::Networks {
            if self.networks_scanner.primary_ip.is_none() {
                self.networks_scanner.primary_ip = self.network_scanner.local_ip;
            }
            if self.networks_scanner.poll_results() {
                changed = true;
            }
        }

        changed
    }

    /// Poll deferred initialization results (background file loads).
    /// Returns true if any state was loaded.
    pub fn poll_deferred_init(&mut self) -> bool {
        self.alert_engine.poll_deferred_init()
    }

    /// Refresh network speed and connections. Called each tick.
    pub fn update(&mut self, networks: &mut Networks) {
        // Auto-clear status message after 3 seconds
        if let Some((_, when)) = &self.status_message {
            if when.elapsed().as_secs() >= 3 {
                self.status_message = None;
            }
        }

        networks.refresh();
        let (recv, sent, iface) = get_network_bytes(networks);
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_time).as_secs_f64();

        let tick_delta_down = recv.saturating_sub(self.prev_bytes_recv);
        let tick_delta_up = sent.saturating_sub(self.prev_bytes_sent);

        if elapsed > 0.0 {
            let dr = tick_delta_down as f64;
            let ds = tick_delta_up as f64;
            self.current_down_speed = dr / elapsed;
            self.current_up_speed = ds / elapsed;

            self.total_down += tick_delta_down;
            self.total_up += tick_delta_up;

            if self.current_down_speed > self.peak_down {
                self.peak_down = self.current_down_speed;
            }
            if self.current_up_speed > self.peak_up {
                self.peak_up = self.current_up_speed;
            }

            self.speed_history.push(self.current_down_speed, self.current_up_speed);

            // Dashboard traffic history (per-second)
            self.traffic_history.push(self.current_down_speed, self.current_up_speed);
            // Connection count sparkline
            let active_conns = self.connections.iter()
                .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
                .count() as u64;
            self.connection_count_history.push_back(active_conns);
            if self.connection_count_history.len() > 300 {
                self.connection_count_history.pop_front();
            }
        }

        self.prev_bytes_recv = recv;
        self.prev_bytes_sent = sent;
        self.prev_time = now;
        self.interface_name = iface;

        // Fetch connections
        self.connections = fetch_connections(&mut self.pid_cache);

        // Resolve DNS for remote addresses
        if !self.disabled.contains("dns") {
            self.resolve_dns();
        }

        self.sort_connections();

        // ─── World map: track closed connections for fading dots ─────
        {
            let mut current_ips = HashSet::new();
            for conn in &self.connections {
                if let Some(ip) = conn.remote_addr {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        current_ips.insert(ip);
                    }
                }
            }
            // IPs that were on the map last tick but are gone now → fading
            for ip in &self.map_prev_remote_ips {
                if !current_ips.contains(ip) {
                    if let Some(info) = self.geoip.lookup(*ip) {
                        self.map_fading_dots.push((*ip, info.code, self.tick_count));
                    }
                }
            }
            // Expire old fading dots (>10 ticks)
            self.map_fading_dots.retain(|&(_, _, t)| self.tick_count.saturating_sub(t) < 10);
            self.map_prev_remote_ips = current_ips;
        }

        // Update traffic tracker
        self.traffic_tracker.update(&self.connections, &self.dns_cache);

        // Feed sniffer packets into traffic log as DATA events
        let new_packets = self.sniffer.drain_new();
        if !new_packets.is_empty() {
            self.traffic_tracker.ingest_packets(&new_packets, &self.connections, &self.dns_cache);
            // Per-app bandwidth tracking from sniffer data
            self.bandwidth_tracker.ingest_packets(&new_packets, &self.connections);

            // Feed protocol tracker from new packets
            for pkt in &new_packets {
                let is_udp = pkt.protocol == ConnProto::Udp;
                self.protocol_tracker.record(pkt.src_port, pkt.dst_port, is_udp, self.tick_count);
            }

            // Extract DHCP hostnames from captured packets (option 12)
            for pkt in &new_packets {
                if pkt.protocol == ConnProto::Udp
                    && (pkt.src_port == 67 || pkt.src_port == 68
                        || pkt.dst_port == 67 || pkt.dst_port == 68)
                    && !pkt.raw_payload.is_empty()
                {
                    if let Some((_mac, hostname)) = crate::network::hostnames::parse_dhcp_hostname(&pkt.raw_payload) {
                        // Try to get client IP from DHCP packet fields, fall back to source IP
                        let client_ip = crate::network::hostnames::dhcp_client_ip(&pkt.raw_payload)
                            .or_else(|| match pkt.src_ip {
                                IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_broadcast() => Some(v4),
                                _ => None,
                            });
                        if let Some(ip) = client_ip {
                            if let Ok(mut cache) = self.network_scanner.dhcp_hostnames.lock() {
                                cache.insert(ip, hostname);
                            }
                        }
                    }
                }
            }

            // Per-device bandwidth: correlate packets with LAN device IPs
            // Build IP→index HashMap for O(1) lookups instead of O(n) per packet
            let device_ip_index: HashMap<IpAddr, usize> = self.network_scanner.devices
                .iter()
                .enumerate()
                .map(|(i, d)| (d.ip, i))
                .collect();

            let local_net: Option<(u32, u32)> = match (self.network_scanner.local_ip, self.network_scanner.subnet_mask) {
                (Some(ip), Some(mask)) => Some((u32::from(ip) & u32::from(mask), u32::from(mask))),
                _ => None,
            };
            let gateway_idx: Option<usize> = self.network_scanner.gateway
                .and_then(|gw| device_ip_index.get(&IpAddr::V4(gw)).copied());

            for pkt in &new_packets {
                let bytes = pkt.payload_size as u64;
                let is_inbound = pkt.direction == PacketDirection::Inbound;
                let remote_ip = if is_inbound { pkt.src_ip } else { pkt.dst_ip };

                // O(1) lookup: direct match to LAN device, or attribute to gateway
                let dev_idx = if let Some(&idx) = device_ip_index.get(&remote_ip) {
                    Some(idx)
                } else if let Some(ref net) = local_net {
                    let is_lan = match remote_ip {
                        IpAddr::V4(v4) => (u32::from(v4) & net.1) == net.0,
                        _ => false,
                    };
                    if !is_lan { gateway_idx } else { None }
                } else {
                    None
                };

                if let Some(idx) = dev_idx {
                    let dev = &mut self.network_scanner.devices[idx];
                    if is_inbound {
                        dev.bytes_received += bytes;
                        dev.tick_received += bytes;
                    } else {
                        dev.bytes_sent += bytes;
                        dev.tick_sent += bytes;
                    }
                }
            }
        }

        // Flush per-tick device speed: exponential moving average (0.3 new + 0.7 old)
        for dev in &mut self.network_scanner.devices {
            dev.speed_sent = dev.speed_sent * 0.7 + dev.tick_sent as f64 * 0.3;
            dev.speed_received = dev.speed_received * 0.7 + dev.tick_received as f64 * 0.3;
            dev.tick_sent = 0;
            dev.tick_received = 0;
        }

        // ─── GlassWire-style module updates ──────────────────────────

        // Estimate per-app bandwidth from connections when sniffer has no data
        self.bandwidth_tracker.estimate_from_connections(
            &self.connections,
            self.current_down_speed,
            self.current_up_speed,
        );

        // Finish bandwidth tick (update connection counts, push speed samples)
        self.bandwidth_tracker.finish_tick(&self.connections);

        // Alert engine checks
        self.alert_engine.check_new_apps(&self.connections, &self.dns_cache);
        self.alert_engine.check_rdp(&self.connections);
        self.alert_engine.check_bandwidth_spike(self.current_down_speed, self.current_up_speed);

        // Anomaly detection on per-app bandwidth
        self.alert_engine.check_anomalies(&self.bandwidth_tracker.apps);

        // Threat detection — every 3 ticks (threats don't change that fast)
        if self.tick_count % 3 == 0 {
            let threats = self.threat_detector.scan(&self.connections);
            if !threats.is_empty() {
                self.alert_engine.check_suspicious(&self.connections, &threats);
            }
        }

        // DNS server change detection — background thread every 10 ticks
        // (netsh blocks for 100-500ms, must not run on UI thread)
        if let Ok(mut r) = self.bg_dns_servers.lock() {
            if let Some(servers) = r.take() {
                self.alert_engine.check_dns_servers(&servers);
            }
        }
        if self.dns_tick % 10 == 0 {
            let result = Arc::clone(&self.bg_dns_servers);
            std::thread::spawn(move || {
                let servers = crate::network::alerts::get_dns_servers();
                if let Ok(mut r) = result.lock() {
                    *r = Some(servers);
                }
            });
        }

        // Network scanner tick — full-speed when on Devices tab, slow otherwise
        // (still needed for alert engine: new device, device left, ARP anomaly)
        let on_devices_tab = self.bottom_tab == BottomTab::Devices;
        if (on_devices_tab || self.tick_count % 30 == 0) && !self.disabled.contains("netscan") {
            self.network_scanner.tick();
        }

        // Servers scanner tick — always tick to collect results, scans internally throttled
        if !self.disabled.contains("servers") {
            self.servers_scanner.tick();
        }

        // Networks scanner tick — only when on Networks tab
        if self.bottom_tab == BottomTab::Networks {
            if self.networks_scanner.primary_ip.is_none() {
                self.networks_scanner.primary_ip = self.network_scanner.local_ip;
            }
            self.networks_scanner.tick();
        }

        // System monitor tick (hosts file, proxy, WiFi, app hash changes)
        if !self.disabled.contains("sysmon") {
            let sys_events = self.system_monitor.tick();
            if !sys_events.is_empty() {
                self.alert_engine.check_system_events(&sys_events);
            }
        }

        // Firewall manager tick (periodic rule refresh)
        if !self.disabled.contains("firewall") {
            self.firewall_manager.tick();
        }

        // Ask-to-connect mode: check new processes
        if self.firewall_manager.mode == FirewallMode::AskToConnect {
            for conn in &self.connections {
                if !conn.process_name.is_empty() && !conn.process_name.starts_with("PID:") {
                    self.firewall_manager.check_pending(&conn.process_name);
                }
            }
        }

        // Usage tracking — every 5 ticks (reduces HashMap allocation overhead)
        if self.tick_count % 5 == 0 {
            let per_app: std::collections::HashMap<String, (u64, u64)> = self.bandwidth_tracker.apps.iter()
                .map(|(k, v)| (k.clone(), (v.download_bytes, v.upload_bytes)))
                .collect();
            self.usage_tracker.update(self.total_down, self.total_up, &per_app);
        }

        // Data plan overage alert
        let (used, limit, _pct) = self.usage_tracker.plan_status();
        let alert_pct = self.usage_tracker.data_plan().alert_pct;
        self.alert_engine.check_data_plan(used, limit, alert_pct);

        // Idle tracker tick (While You Were Away)
        let current_log_len = self.traffic_tracker.log.len();
        let new_conn_count = if current_log_len > self.prev_traffic_log_len {
            self.traffic_tracker.log[self.prev_traffic_log_len..]
                .iter()
                .filter(|e| matches!(e.event, TrafficEventKind::NewConnection))
                .count()
        } else {
            0
        };
        self.prev_traffic_log_len = current_log_len;
        self.alert_engine.idle_tracker.tick(new_conn_count, tick_delta_down, tick_delta_up);

        self.dump_debug_stats();

        self.tick_count = self.tick_count.wrapping_add(1);
    }

    /// Opt-in leak diagnostics: PSNET_DEBUG_STATS=<file> appends collection
    /// sizes every 20 ticks so unbounded growth can be pinpointed in the field.
    fn dump_debug_stats(&mut self) {
        if self.tick_count % 20 != 0 {
            return;
        }
        let Ok(path) = std::env::var("PSNET_DEBUG_STATS") else { return };
        let (sniff_len, sniff_bytes) = self.sniffer.snippets.lock()
            .map(|l| (l.len(), l.iter().map(|p| p.raw_payload.len() + p.snippet.len()).sum::<usize>()))
            .unwrap_or((0, 0));
        let per_app_today = self.usage_tracker.store.daily_records.last()
            .map(|r| r.per_app.len()).unwrap_or(0);
        let line = format!(
            "tick={} conns={} dns={} tlog={} sniff={} sniff_b={} apps={} alerts={} devices={} servers={} hist={} usage_days={} usage_apps={} fading={} pidc={}\n",
            self.tick_count,
            self.connections.len(),
            self.dns_cache.len(),
            self.traffic_tracker.log.len(),
            sniff_len,
            sniff_bytes,
            self.bandwidth_tracker.apps.len(),
            self.alert_engine.alerts.len(),
            self.network_scanner.devices.len(),
            self.servers_scanner.servers.len(),
            self.traffic_history.samples.len(),
            self.usage_tracker.store.daily_records.len(),
            per_app_today,
            self.map_fading_dots.len(),
            self.pid_cache.len(),
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = f.write_all(line.as_bytes());
        }
    }

    // ─── DNS resolution ───────────────────────────────────────────────

    /// Read DNS cache from OS and apply hostnames to connections.
    fn resolve_dns(&mut self) {
        // Read from OS DNS cache every 2 ticks (API call is fast but not free)
        if self.dns_tick % 2 == 0 {
            let os_cache = dns::read_dns_cache_api();
            for (ip, hostname) in &os_cache {
                self.dns_cache.entry(*ip).or_insert_with(|| Some(hostname.clone()));
            }
        }

        // Poll background ipconfig result
        if let Ok(mut r) = self.bg_dns_ipconfig.lock() {
            if let Some(entries) = r.take() {
                for (ip, hostname) in entries {
                    self.dns_cache.entry(ip).or_insert_with(|| Some(hostname));
                }
            }
        }

        // Spawn ipconfig parsing on background thread every 10 ticks (avoids 100-500ms block)
        if self.dns_tick % 10 == 0 {
            let result = Arc::clone(&self.bg_dns_ipconfig);
            let dns_srv = Arc::clone(&self.bg_dns_servers);
            std::thread::spawn(move || {
                let cache = dns::read_dns_cache_ipconfig();
                let entries: Vec<_> = cache.into_iter().collect();
                if let Ok(mut r) = result.lock() {
                    *r = Some(entries);
                }
                // Also detect system DNS servers
                let servers = dns::get_system_dns_servers();
                if let Ok(mut s) = dns_srv.lock() {
                    *s = Some(servers);
                }
            });
        }

        // Poll DNS server detection results
        if let Ok(mut s) = self.bg_dns_servers.lock() {
            if let Some(servers) = s.take() {
                self.dns_servers = servers;
            }
        }
        self.dns_tick = self.dns_tick.wrapping_add(1);

        // Cap DNS cache to prevent unbounded growth in long sessions
        if self.dns_cache.len() > 10_000 {
            // Keep most recent entries by clearing and re-populating on next tick
            self.dns_cache.clear();
        }

        // Apply cached DNS names to connections
        for conn in &mut self.connections {
            if let Some(remote_ip) = conn.remote_addr {
                if remote_ip.is_unspecified() {
                    continue;
                }
                if remote_ip.is_loopback() {
                    conn.dns_hostname = Some("localhost".to_string());
                    continue;
                }
                if let Some(cached) = self.dns_cache.get(&remote_ip) {
                    conn.dns_hostname = cached.clone();
                }
            }
        }
    }

    // ─── Sorting ─────────────────────────────────────────────────────────

    pub fn sort_connections(&mut self) {
        let col = self.sort_column;
        let asc = self.sort_ascending;
        self.connections.sort_by(|a, b| {
            let ord = match col {
                0 => a.proto.label().cmp(b.proto.label()),
                // Compare IpAddr directly (numeric order) — no .to_string() allocation
                1 => a.local_addr.cmp(&b.local_addr),
                2 => a.local_port.cmp(&b.local_port),
                // Compare Option<IpAddr> directly — None < Some(_)
                3 => a.remote_addr.cmp(&b.remote_addr),
                4 => a.remote_port.unwrap_or(0).cmp(&b.remote_port.unwrap_or(0)),
                5 => {
                    fn state_rank(s: Option<&TcpState>) -> u8 {
                        match s {
                            Some(TcpState::Established) => 0,
                            Some(TcpState::SynSent) => 1,
                            Some(TcpState::SynReceived) => 2,
                            Some(TcpState::CloseWait) => 3,
                            Some(TcpState::FinWait1) => 4,
                            Some(TcpState::FinWait2) => 5,
                            Some(TcpState::Closing) => 6,
                            Some(TcpState::LastAck) => 7,
                            Some(TcpState::TimeWait) => 8,
                            Some(TcpState::Listen) => 9,
                            Some(TcpState::Closed) => 10,
                            Some(TcpState::DeleteTcb) => 11,
                            Some(TcpState::Unknown(_)) => 12,
                            None => 13,
                        }
                    }
                    state_rank(a.state.as_ref()).cmp(&state_rank(b.state.as_ref()))
                }
                // Case-insensitive byte-by-byte comparison — no .to_lowercase() allocation
                6 => a.process_name.bytes().map(|b| b.to_ascii_lowercase())
                    .cmp(b.process_name.bytes().map(|b| b.to_ascii_lowercase())),
                _ => std::cmp::Ordering::Equal,
            };
            if asc { ord } else { ord.reverse() }
        });
    }

    pub fn toggle_sort(&mut self, col: usize) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
        self.sort_connections();
    }

    // ─── Filtering ───────────────────────────────────────────────────────

    /// Returns (app_name, is_blocked, conn_count) sorted for the Firewall app list.
    /// Blocked apps first, then by connection count descending, then alphabetically.
    pub fn firewall_app_list_filtered(&self) -> Vec<(String, bool, usize)> {
        use std::collections::HashMap;
        // Count connections per process name (preserving original casing)
        let mut map: HashMap<String, (String, usize)> = HashMap::new();
        for conn in &self.connections {
            if conn.process_name.is_empty() || conn.process_name.starts_with("PID:") {
                continue;
            }
            let key = conn.process_name.to_lowercase();
            let entry = map.entry(key).or_insert((conn.process_name.clone(), 0));
            entry.1 += 1;
        }
        // Include apps with any PSNET action (blocked, allowed, dropped) even if not connecting
        for (key, _) in &self.firewall_manager.app_actions {
            map.entry(key.clone()).or_insert((key.clone(), 0));
        }
        // Include apps with bandwidth data (had traffic earlier but may have no current connections)
        for (key, bw) in &self.bandwidth_tracker.apps {
            map.entry(key.clone()).or_insert((bw.process_name.clone(), 0));
        }
        // Apply filter
        let ft = self.firewall_manager.filter_text.to_lowercase();
        let mut list: Vec<(String, bool, usize)> = map.into_values()
            .filter(|(name, _)| ft.is_empty() || name.to_lowercase().contains(&ft))
            .map(|(name, count)| {
                let blocked = self.firewall_manager.is_psnet_blocked(&name);
                (name, blocked, count)
            })
            .collect();
        // Sort by bandwidth column if set, otherwise default sort
        let sort_col = self.bandwidth_tracker.sort_column;
        let sort_asc = self.bandwidth_tracker.sort_ascending;
        let bw_apps = &self.bandwidth_tracker.apps;
        list.sort_by(|a, b| {
            let ord = match sort_col {
                0 => { // Total bytes
                    let ta = bw_apps.get(&a.0.to_lowercase()).map(|b| b.total_bytes()).unwrap_or(0);
                    let tb = bw_apps.get(&b.0.to_lowercase()).map(|b| b.total_bytes()).unwrap_or(0);
                    tb.cmp(&ta)
                }
                1 => { // Download
                    let da = bw_apps.get(&a.0.to_lowercase()).map(|b| b.download_bytes).unwrap_or(0);
                    let db = bw_apps.get(&b.0.to_lowercase()).map(|b| b.download_bytes).unwrap_or(0);
                    db.cmp(&da)
                }
                2 => { // Upload
                    let ua = bw_apps.get(&a.0.to_lowercase()).map(|b| b.upload_bytes).unwrap_or(0);
                    let ub = bw_apps.get(&b.0.to_lowercase()).map(|b| b.upload_bytes).unwrap_or(0);
                    ub.cmp(&ua)
                }
                3 => { // Connections
                    b.2.cmp(&a.2)
                }
                4 => { // Name
                    a.0.to_lowercase().cmp(&b.0.to_lowercase())
                }
                _ => {
                    b.1.cmp(&a.1)
                        .then(b.2.cmp(&a.2))
                        .then(a.0.cmp(&b.0))
                }
            };
            if sort_asc { ord.reverse() } else { ord }
        });
        list
    }

    pub fn filtered_connections(&self) -> Vec<&Connection> {
        // Pre-compute lowercase filter once (not per-connection)
        let ft = if self.filter_text.is_empty() { None } else { Some(self.filter_text.to_lowercase()) };
        let hide_local = self.hide_localhost_conn;
        let show_listen = self.show_listen;

        self.connections.iter().filter(|c| {
            if hide_local {
                if c.local_addr.is_loopback()
                    && c.remote_addr.map(|a| a.is_loopback()).unwrap_or(false)
                {
                    return false;
                }
            }
            if !show_listen {
                if matches!(c.state.as_ref(), Some(TcpState::Listen)) {
                    return false;
                }
            }
            if let Some(ft) = &ft {
                // Use a reusable buffer to avoid per-field String allocations
                let mut buf = String::with_capacity(64);
                use std::fmt::Write;

                if c.process_name.to_lowercase().contains(ft.as_str()) { return true; }

                buf.clear(); write!(buf, "{}", c.local_addr).unwrap();
                if buf.contains(ft.as_str()) { return true; }

                buf.clear(); write!(buf, "{}", c.local_port).unwrap();
                if buf.contains(ft.as_str()) { return true; }

                if let Some(a) = c.remote_addr {
                    buf.clear(); write!(buf, "{}", a).unwrap();
                    if buf.contains(ft.as_str()) { return true; }
                }
                if let Some(p) = c.remote_port {
                    buf.clear(); write!(buf, "{}", p).unwrap();
                    if buf.contains(ft.as_str()) { return true; }
                }
                if let Some(s) = c.state.as_ref() {
                    if s.label().to_lowercase().contains(ft.as_str()) { return true; }
                }
                if c.proto.label().to_lowercase().contains(ft.as_str()) { return true; }
                if let Some(n) = c.dns_hostname.as_ref() {
                    if n.to_lowercase().contains(ft.as_str()) { return true; }
                }
                return false;
            }
            true
        }).collect()
    }

    // ─── Input handling ──────────────────────────────────────────────────

    /// Handle a key press. Returns true if the app should quit.
    pub fn handle_key(&mut self, code: KeyCode) -> bool {
        // Notify idle tracker of user input
        self.alert_engine.idle_tracker.on_input();

        // If detail popup is open, handle navigation for FirewallApp or dismiss
        if self.detail_popup.is_some() {
            if let Some(DetailKind::FirewallApp(ref mut detail)) = self.detail_popup {
                match code {
                    KeyCode::Up => { detail.selected_action = detail.selected_action.saturating_sub(1); }
                    KeyCode::Down => { if detail.selected_action < 3 { detail.selected_action += 1; } }
                    KeyCode::Enter => {
                        if detail.selected_action < 3 {
                            let name = detail.app_name.clone();
                            let path = detail.app_path.clone();
                            let action = match detail.selected_action {
                                0 => FirewallAppAction::Allow,
                                1 => FirewallAppAction::Deny,
                                _ => FirewallAppAction::Drop,
                            };
                            self.detail_popup = None;
                            self.firewall_manager.apply_action(&name, path.as_deref(), action);
                        } else {
                            self.detail_popup = None;
                        }
                    }
                    KeyCode::Esc | KeyCode::Char('q') => { self.detail_popup = None; }
                    _ => {}
                }
            } else {
                // Server detail popup: o/y/p shortcuts for exe path
                let server_exe_path = if let Some(DetailKind::Server { ref exe_path, .. }) = self.detail_popup {
                    if !exe_path.is_empty() { Some(exe_path.clone()) } else { None }
                } else {
                    None
                };

                match code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        self.detail_popup = None;
                    }
                    KeyCode::Char('o') | KeyCode::Char('O') if server_exe_path.is_some() => {
                        let path = server_exe_path.unwrap();
                        let _ = Command::new("explorer.exe")
                            .arg(format!("/select,{}", path))
                            .spawn();
                        self.status_message = Some((format!("Opened folder: {}", path), Instant::now()));
                    }
                    KeyCode::Char('y') | KeyCode::Char('Y') if server_exe_path.is_some() => {
                        let path = server_exe_path.unwrap();
                        if copy_to_clipboard(&path) {
                            self.status_message = Some((format!("Copied: {}", path), Instant::now()));
                        }
                    }
                    KeyCode::Char('p') | KeyCode::Char('P') if server_exe_path.is_some() => {
                        let path = server_exe_path.unwrap();
                        let folder = std::path::Path::new(&path)
                            .parent()
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or(path.clone());
                        if copy_to_clipboard(&folder) {
                            self.status_message = Some((format!("Copied folder: {}", folder), Instant::now()));
                        }
                    }
                    _ => {}
                }
            }
            return false;
        }

        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if !self.incognito {
                    self.alert_engine.save_alerts();
                    self.alert_engine.save_known_state(
                        self.total_down,
                        self.total_up,
                        self.connections.len(),
                        self.network_scanner.devices.len(),
                    );
                    self.usage_tracker.save();
                }
                return true;
            }
            KeyCode::Tab => {
                self.bottom_tab = self.bottom_tab.next();
            }
            KeyCode::BackTab => {
                self.bottom_tab = self.bottom_tab.prev();
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.incognito = !self.incognito;
            }
            KeyCode::Enter => {
                self.open_detail_popup();
            }
            KeyCode::Up => self.scroll_up(1),
            KeyCode::Down => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(20),
            KeyCode::PageDown => self.scroll_down(20),
            KeyCode::Home => self.scroll_home(),
            KeyCode::End => self.scroll_end(),
            _ => {
                match self.bottom_tab {
                    BottomTab::Dashboard => self.handle_dashboard_key(code),
                    BottomTab::Connections => self.handle_connections_key(code),
                    BottomTab::Servers => self.handle_servers_key(code),
                    BottomTab::Packets => self.handle_packets_key(code),
                    BottomTab::Topology => self.handle_topology_key(code),
                    BottomTab::Alerts => self.handle_alerts_key(code),
                    BottomTab::Firewall => self.handle_firewall_key(code),
                    BottomTab::Devices => self.handle_devices_key(code),
                    BottomTab::Networks => self.handle_networks_key(code),
                }
            }
        }
        false
    }

    /// Open the detail popup for the currently selected item in the active tab.
    fn open_detail_popup(&mut self) {
        self.detail_popup = match self.bottom_tab {
            BottomTab::Connections => {
                let filtered = self.filtered_connections();
                let total = filtered.len();
                if total == 0 { return; }
                let selected = self.conn_scroll.min(total - 1);
                filtered.get(selected).map(|c| DetailKind::Connection((*c).clone()))
            }
            BottomTab::Servers => {
                let visible = self.servers_scanner.filtered_servers();
                if visible.is_empty() { return; }
                let selected = self.servers_scanner.scroll_offset.min(visible.len() - 1);
                if let Some(s) = visible.get(selected) {
                    let active = self.connections.iter()
                        .filter(|c| c.local_port == s.port && !matches!(c.state.as_ref(), Some(TcpState::Listen)))
                        .count() as u32;
                    let has_tls = s.details.contains("TLS: yes");
                    Some(DetailKind::Server {
                        kind_label: s.display_name(),
                        kind_icon: s.server_kind.icon().to_string(),
                        category: s.server_kind.category().label().to_string(),
                        port: s.port,
                        proto: s.proto.label().to_string(),
                        bind_addr: s.bind_addr.to_string(),
                        pid: s.pid,
                        process_name: s.process_name.clone(),
                        exe_path: s.exe_path.clone(),
                        cmdline: s.cmdline.clone(),
                        product_name: s.product_name.clone(),
                        company_name: s.company_name.clone(),
                        version: s.version.clone().unwrap_or_default(),
                        http_title: s.http_title.clone().unwrap_or_default(),
                        banner: s.banner.clone().unwrap_or_default(),
                        response_headers: s.response_headers.clone(),
                        active_connections: active,
                        first_seen: s.first_seen.format("%H:%M:%S").to_string(),
                        is_responsive: s.is_responsive,
                        tls_detected: has_tls,
                        category_color: s.server_kind.category().color(),
                        detected_techs: s.detected_techs.iter().map(|t| (t.name.clone(), t.category.clone(), t.version.clone())).collect(),
                    })
                } else {
                    None
                }
            }
            BottomTab::Alerts => {
                // Open detail for selected alert in focused pane
                if let Some((cat, count)) = self.focused_alert_cat() {
                    if count == 0 { return; }
                    let ord = Self::alert_cat_ordinal(cat);
                    let selected = self.alert_pane_scrolls[ord].min(count - 1);
                    let mut cat_alerts: Vec<&crate::types::Alert> = self.alert_engine.alerts.iter()
                        .filter(|a| a.kind.category() == cat)
                        .collect();
                    cat_alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    cat_alerts.get(selected).map(|a| DetailKind::Alert((*a).clone()))
                } else {
                    None
                }
            }
            BottomTab::Devices => {
                let devices: Vec<&crate::types::LanDevice> = self.network_scanner.devices.iter()
                    .filter(|d| !self.hide_offline_devices || d.is_online)
                    .collect();
                let total = devices.len();
                if total == 0 { return; }
                let selected = self.device_scroll.min(total - 1);
                devices.get(selected).map(|d| DetailKind::Device((*d).clone()))
            }
            BottomTab::Networks => {
                let display_rows = crate::ui::networks::build_display_rows(self);
                let total = display_rows.len();
                if total == 0 { return; }
                let selected = self.networks_scroll.min(total - 1);
                match &display_rows[selected] {
                    crate::ui::networks::NetworksRow::BluetoothHeader { .. } => {
                        // Toggle expand on Enter
                        self.bluetooth_expanded = !self.bluetooth_expanded;
                        None
                    }
                    crate::ui::networks::NetworksRow::Device { device, .. } => {
                        Some(DetailKind::Device((*device).clone()))
                    }
                }
            }
            BottomTab::Firewall => {
                // Enter opens combined detail popup with action buttons
                let apps = self.firewall_app_list_filtered();
                if apps.is_empty() { return; }
                let selected = self.firewall_manager.scroll_offset.min(apps.len() - 1);
                if let Some((name, _, conn_count)) = apps.get(selected) {
                    let name = name.clone();
                    let path = self.connections.iter()
                        .find(|c| c.process_name.to_lowercase() == name.to_lowercase())
                        .and_then(|c| crate::network::connections::get_process_full_path(c.pid));
                    let current_action = self.firewall_manager.get_app_action(&name);
                    let is_blocked = self.firewall_manager.is_psnet_blocked(&name);
                    let preselect = match current_action {
                        Some(FirewallAppAction::Allow) => 0,
                        Some(FirewallAppAction::Deny) => 1,
                        Some(FirewallAppAction::Drop) => 2,
                        None => 0,
                    };

                    // Look up bandwidth data
                    let key = name.to_lowercase();
                    let (dl, ul, cd, cu, pd, pu, ls) = if let Some(bw) = self.bandwidth_tracker.apps.get(&key) {
                        (
                            bw.download_bytes,
                            bw.upload_bytes,
                            bw.smooth_down(),
                            bw.smooth_up(),
                            bw.recent_down.iter().copied().fold(0.0_f64, f64::max),
                            bw.recent_up.iter().copied().fold(0.0_f64, f64::max),
                            bw.last_seen.format("%H:%M:%S").to_string(),
                        )
                    } else {
                        (0, 0, 0.0, 0.0, 0.0, 0.0, "-".to_string())
                    };

                    self.detail_popup = Some(DetailKind::FirewallApp(FirewallAppDetail {
                        app_name: name,
                        app_path: path,
                        is_blocked,
                        current_action: current_action.cloned(),
                        conn_count: *conn_count,
                        download_bytes: dl,
                        upload_bytes: ul,
                        current_down_speed: cd,
                        current_up_speed: cu,
                        peak_down_speed: pd,
                        peak_up_speed: pu,
                        last_seen: ls,
                        selected_action: preselect,
                    }));
                }
                return;
            }
            BottomTab::Packets => {
                // Enter toggles the detail pane instead of opening a popup
                self.packets_detail_open = !self.packets_detail_open;
                return;
            }
            BottomTab::Topology => None,
            BottomTab::Dashboard => None,
        };
    }

    fn handle_connections_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.show_listen = !self.show_listen;
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.hide_localhost_conn = !self.hide_localhost_conn;
            }
            // Sort keys mapped to displayed column order:
            // 1=Process, 2=Remote Host, 3=Service, 4=State, 5=Local
            KeyCode::Char('1') => self.toggle_sort(6),
            KeyCode::Char('2') => self.toggle_sort(3),
            KeyCode::Char('3') => self.toggle_sort(4),
            KeyCode::Char('4') => self.toggle_sort(5),
            KeyCode::Char('5') => self.toggle_sort(2),
            // Block selected connection's process via firewall
            KeyCode::Char('b') | KeyCode::Char('B') => {
                let filtered = self.filtered_connections();
                if let Some(conn) = filtered.get(self.conn_scroll) {
                    if !conn.process_name.is_empty() && !conn.process_name.starts_with("PID:") {
                        let pid = conn.pid;
                        // Use the full executable path so Windows Firewall actually matches the rule.
                        // Falling back to the exe name if the path can't be resolved.
                        let path = crate::network::connections::get_process_full_path(pid)
                            .unwrap_or_else(|| conn.process_name.clone());
                        self.firewall_manager.block_app(&path);
                    }
                }
            }
            KeyCode::Backspace => { self.filter_text.pop(); }
            KeyCode::Esc => { self.filter_text.clear(); }
            KeyCode::Char(c) => {
                if c == 'f' || c == 'F' {
                    // 'f' starts filter mode
                } else {
                    self.filter_text.push(c);
                }
            }
            _ => {}
        }
    }


    /// Get the exe_path of the currently selected server (if any).
    fn selected_server_exe_path(&self) -> Option<String> {
        let visible = self.servers_scanner.filtered_servers();
        if visible.is_empty() { return None; }
        let idx = self.servers_scanner.scroll_offset.min(visible.len() - 1);
        let path = &visible[idx].exe_path;
        if path.is_empty() { None } else { Some(path.clone()) }
    }

    fn handle_servers_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.servers_scanner.start_scan();
            }
            // Open containing folder in Explorer
            KeyCode::Char('o') | KeyCode::Char('O') => {
                if let Some(path) = self.selected_server_exe_path() {
                    let _ = Command::new("explorer.exe")
                        .arg(format!("/select,{}", path))
                        .spawn();
                    self.status_message = Some((format!("Opened folder: {}", path), Instant::now()));
                } else {
                    self.status_message = Some(("No executable path available".into(), Instant::now()));
                }
            }
            // Copy full executable path to clipboard
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(path) = self.selected_server_exe_path() {
                    let copied = copy_to_clipboard(&path);
                    if copied {
                        self.status_message = Some((format!("Copied: {}", path), Instant::now()));
                    } else {
                        self.status_message = Some(("Failed to copy to clipboard".into(), Instant::now()));
                    }
                } else {
                    self.status_message = Some(("No executable path available".into(), Instant::now()));
                }
            }
            // Copy containing folder path to clipboard
            KeyCode::Char('p') | KeyCode::Char('P') => {
                if let Some(path) = self.selected_server_exe_path() {
                    let folder = std::path::Path::new(&path)
                        .parent()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or(path.clone());
                    let copied = copy_to_clipboard(&folder);
                    if copied {
                        self.status_message = Some((format!("Copied folder: {}", folder), Instant::now()));
                    } else {
                        self.status_message = Some(("Failed to copy to clipboard".into(), Instant::now()));
                    }
                } else {
                    self.status_message = Some(("No executable path available".into(), Instant::now()));
                }
            }
            KeyCode::Char('1') => {
                self.servers_scanner.sort_column = 0;
                self.servers_scanner.sort_ascending = !self.servers_scanner.sort_ascending;
            }
            KeyCode::Char('2') => {
                self.servers_scanner.sort_column = 1;
                self.servers_scanner.sort_ascending = !self.servers_scanner.sort_ascending;
            }
            KeyCode::Char('3') => {
                self.servers_scanner.sort_column = 3;
                self.servers_scanner.sort_ascending = !self.servers_scanner.sort_ascending;
            }
            KeyCode::Backspace => { self.servers_scanner.filter_text.pop(); }
            KeyCode::Esc => { self.servers_scanner.filter_text.clear(); }
            KeyCode::Char(c) if !c.is_ascii_digit() => {
                self.servers_scanner.filter_text.push(c);
            }
            _ => {}
        }
    }

    fn handle_alerts_key(&mut self, code: KeyCode) {
        // Dismiss banners on any key press
        if self.alert_engine.last_visit_summary.is_some() {
            self.alert_engine.last_visit_summary = None;
            return;
        }
        if self.alert_engine.idle_tracker.pending_summary.is_some() {
            self.alert_engine.idle_tracker.pending_summary = None;
            return;
        }

        let active_cats = crate::ui::alerts::active_categories(&self.alert_engine.alerts);
        let num_panes = active_cats.len();

        match code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.alert_engine.mark_all_read();
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.alert_engine.alerts.clear();
                self.alert_engine.unread_count = 0;
                self.alert_pane_scrolls = [0; 6];
            }
            KeyCode::Char('z') | KeyCode::Char('Z') => {
                if self.alert_engine.is_snoozed() {
                    self.alert_engine.unsnooze();
                } else {
                    self.alert_engine.snooze(300);
                }
            }
            // Navigate between panes
            KeyCode::Left => {
                if num_panes > 0 {
                    if self.alert_focused_pane == 0 {
                        self.alert_focused_pane = num_panes - 1;
                    } else {
                        self.alert_focused_pane -= 1;
                    }
                }
            }
            KeyCode::Right => {
                if num_panes > 0 {
                    self.alert_focused_pane = (self.alert_focused_pane + 1) % num_panes;
                }
            }
            _ => {}
        }
    }

    /// Get the AlertCategory ordinal for scroll array indexing.
    fn alert_cat_ordinal(cat: AlertCategory) -> usize {
        match cat {
            AlertCategory::Security => 0,
            AlertCategory::NetworkAccess => 1,
            AlertCategory::SystemChanges => 2,
            AlertCategory::DeviceActivity => 3,
            AlertCategory::Bandwidth => 4,
            AlertCategory::Connectivity => 5,
        }
    }

    /// Scroll the alert pane under the mouse cursor.
    fn alert_scroll_pane_at(&mut self, col: u16, row: u16, up: bool, n: usize) {
        let mut found = false;
        for (i, (cat, rect)) in self.alert_pane_rects.iter().enumerate() {
            if col >= rect.x && col < rect.x + rect.width
                && row >= rect.y && row < rect.y + rect.height
            {
                self.alert_focused_pane = i;
                let ord = Self::alert_cat_ordinal(*cat);
                let count = self.alert_engine.alerts.iter()
                    .filter(|a| a.kind.category() == *cat)
                    .count();
                if up {
                    self.alert_pane_scrolls[ord] = self.alert_pane_scrolls[ord].saturating_sub(n);
                } else {
                    self.alert_pane_scrolls[ord] = (self.alert_pane_scrolls[ord] + n).min(count.saturating_sub(1));
                }
                found = true;
                break;
            }
        }
        if !found {
            if up { self.scroll_up(n); } else { self.scroll_down(n); }
        }
    }

    /// Get the focused alert category and its alert count.
    fn focused_alert_cat(&self) -> Option<(AlertCategory, usize)> {
        let active_cats = crate::ui::alerts::active_categories(&self.alert_engine.alerts);
        let focused = self.alert_focused_pane.min(active_cats.len().saturating_sub(1));
        active_cats.get(focused).map(|&cat| {
            let count = self.alert_engine.alerts.iter()
                .filter(|a| a.kind.category() == cat)
                .count();
            (cat, count)
        })
    }

    fn handle_firewall_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.firewall_manager.refresh_rules();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.firewall_manager.toggle_ask_to_connect();
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.firewall_manager.toggle_default_policy();
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.firewall_manager.reset_all_psnet_rules();
            }
            // Sort keys (merged from Usage tab)
            KeyCode::Char('1') => {
                self.bandwidth_tracker.sort_column = 0;
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('2') => {
                self.bandwidth_tracker.sort_column = 1;
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('3') => {
                self.bandwidth_tracker.sort_column = 2;
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('4') => {
                self.bandwidth_tracker.sort_column = 4;
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            // Export CSV
            KeyCode::Char('e') | KeyCode::Char('E') => {
                if let Some(data_dir) = dirs::data_dir() {
                    let path = data_dir.join("psnet").join("usage_export.csv");
                    let _ = self.usage_tracker.export_csv(&path.to_string_lossy());
                }
            }
            KeyCode::Backspace => { self.firewall_manager.filter_text.pop(); }
            KeyCode::Esc => { self.firewall_manager.filter_text.clear(); }
            KeyCode::Char(c) => {
                self.firewall_manager.filter_text.push(c);
            }
            _ => {}
        }
    }

    fn handle_devices_key(&mut self, code: KeyCode) {
        // Rename mode intercepts all input
        if let Some(idx) = self.renaming_device {
            match code {
                KeyCode::Enter => {
                    let text = self.device_rename_text.trim().to_string();
                    let mac = self.network_scanner.devices.get(idx).map(|d| d.mac.clone());
                    if let Some(mac) = mac {
                        self.network_scanner.set_label(&mac, text);
                    }
                    self.renaming_device = None;
                    self.device_rename_text.clear();
                }
                KeyCode::Esc => {
                    self.renaming_device = None;
                    self.device_rename_text.clear();
                }
                KeyCode::Backspace => { self.device_rename_text.pop(); }
                KeyCode::Char(c) => { self.device_rename_text.push(c); }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.network_scanner.start_scan();
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                self.hide_offline_devices = !self.hide_offline_devices;
                self.device_scroll = 0;
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                // Map filtered index back to real device index
                let filtered: Vec<usize> = self.network_scanner.devices.iter()
                    .enumerate()
                    .filter(|(_, d)| !self.hide_offline_devices || d.is_online)
                    .map(|(i, _)| i)
                    .collect();
                let total = filtered.len();
                if total > 0 {
                    let sel = self.device_scroll.min(total - 1);
                    let real_idx = filtered[sel];
                    let current = self.network_scanner.devices.get(real_idx)
                        .map(|d| {
                            d.custom_name.as_deref()
                                .or(d.hostname.as_deref())
                                .unwrap_or("")
                                .to_string()
                        })
                        .unwrap_or_default();
                    self.device_rename_text = current;
                    self.renaming_device = Some(real_idx);
                }
            }
            _ => {}
        }
    }

    /// Virtual row count for Networks tab (accounts for BT header + collapse).
    fn networks_display_row_count(&self) -> usize {
        let mut non_bt = 0usize;
        let mut bt = 0usize;
        for net in &self.networks_scanner.networks {
            if net.category == NetworkCategory::Bluetooth {
                bt += net.devices.len();
            } else {
                non_bt += net.devices.len();
            }
        }
        non_bt + if bt > 0 { 1 } else { 0 } + if self.bluetooth_expanded { bt } else { 0 }
    }

    fn handle_networks_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.networks_scanner.start_scan();
            }
            KeyCode::Char('b') | KeyCode::Char('B') => {
                self.bluetooth_expanded = !self.bluetooth_expanded;
            }
            _ => {}
        }
    }

    fn handle_packets_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char(' ') => {
                self.packets_paused = !self.packets_paused;
            }
            KeyCode::Char('d') | KeyCode::Char('D') => {
                self.packets_detail_open = !self.packets_detail_open;
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if let Ok(mut lock) = self.sniffer.snippets.lock() {
                    lock.clear();
                }
            }
            KeyCode::Backspace => { self.packets_filter.pop(); }
            KeyCode::Esc => {
                if !self.packets_filter.is_empty() {
                    self.packets_filter.clear();
                } else {
                    self.packets_detail_open = false;
                }
            }
            KeyCode::Char(c) => {
                self.packets_filter.push(c);
            }
            _ => {}
        }
    }

    fn handle_topology_key(&mut self, _code: KeyCode) {
        // Topology tab currently only uses scroll (handled by scroll_up/scroll_down)
    }

    fn handle_dashboard_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('1') => self.dashboard_time_range = DashboardTimeRange::Minutes5,
            KeyCode::Char('2') => self.dashboard_time_range = DashboardTimeRange::Minutes15,
            KeyCode::Char('3') => self.dashboard_time_range = DashboardTimeRange::Hour1,
            KeyCode::Char('4') => self.dashboard_time_range = DashboardTimeRange::Hours24,
            KeyCode::Char('m') | KeyCode::Char('M') => self.map_fullscreen = !self.map_fullscreen,
            _ => {}
        }
    }

    fn scroll_up(&mut self, n: usize) {
        match self.bottom_tab {
            BottomTab::Connections => {
                self.conn_scroll = self.conn_scroll.saturating_sub(n);
            }
            BottomTab::Servers => {
                self.servers_scanner.scroll_offset = self.servers_scanner.scroll_offset.saturating_sub(n);
            }
            BottomTab::Alerts => {
                if let Some((cat, _count)) = self.focused_alert_cat() {
                    let ord = Self::alert_cat_ordinal(cat);
                    self.alert_pane_scrolls[ord] = self.alert_pane_scrolls[ord].saturating_sub(n);
                }
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = self.firewall_manager.scroll_offset.saturating_sub(n);
            }
            BottomTab::Devices => {
                self.device_scroll = self.device_scroll.saturating_sub(n);
            }
            BottomTab::Networks => {
                self.networks_scroll = self.networks_scroll.saturating_sub(n);
            }
            BottomTab::Packets => {
                self.packets_scroll = self.packets_scroll.saturating_sub(n);
            }
            BottomTab::Topology => {
                self.topology_scroll = self.topology_scroll.saturating_sub(n);
            }
            _ => {}
        }
    }

    fn scroll_down(&mut self, n: usize) {
        match self.bottom_tab {
            BottomTab::Connections => {
                self.conn_scroll += n;
            }
            BottomTab::Servers => {
                self.servers_scanner.scroll_offset += n;
            }
            BottomTab::Alerts => {
                if let Some((cat, count)) = self.focused_alert_cat() {
                    let ord = Self::alert_cat_ordinal(cat);
                    self.alert_pane_scrolls[ord] = (self.alert_pane_scrolls[ord] + n).min(count.saturating_sub(1));
                }
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset += n;
            }
            BottomTab::Devices => {
                self.device_scroll += n;
            }
            BottomTab::Networks => {
                self.networks_scroll += n;
            }
            BottomTab::Packets => {
                self.packets_scroll += n;
            }
            BottomTab::Topology => {
                self.topology_scroll += n;
            }
            _ => {}
        }
    }

    fn scroll_home(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = 0,
            BottomTab::Servers => {
                self.servers_scanner.scroll_offset = 0;
            }
            BottomTab::Alerts => {
                if let Some((cat, _)) = self.focused_alert_cat() {
                    self.alert_pane_scrolls[Self::alert_cat_ordinal(cat)] = 0;
                }
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = 0;
            }
            BottomTab::Devices => {
                self.device_scroll = 0;
            }
            BottomTab::Networks => {
                self.networks_scroll = 0;
            }
            BottomTab::Packets => {
                self.packets_scroll = 0;
            }
            BottomTab::Topology => {
                self.topology_scroll = 0;
            }
            _ => {}
        }
    }

    fn scroll_end(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = self.connections.len(),
            BottomTab::Servers => {
                self.servers_scanner.scroll_offset = self.servers_scanner.filtered_servers().len().saturating_sub(1);
            }
            BottomTab::Alerts => {
                if let Some((cat, count)) = self.focused_alert_cat() {
                    self.alert_pane_scrolls[Self::alert_cat_ordinal(cat)] = count.saturating_sub(1);
                }
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = self.firewall_app_list_filtered().len();
            }
            BottomTab::Devices => {
                self.device_scroll = self.network_scanner.devices.len();
            }
            BottomTab::Networks => {
                self.networks_scroll = self.networks_display_row_count().saturating_sub(1);
            }
            BottomTab::Packets => {
                let total = self.sniffer.recent(2000).len();
                self.packets_scroll = total.saturating_sub(1);
            }
            BottomTab::Topology => {
                // scroll to last remote host
                self.topology_scroll = self.connections.len();
            }
            _ => {}
        }
    }

    /// Handle mouse events. Returns true if the app should quit (always false).
    pub fn handle_mouse(&mut self, kind: MouseEventKind, col: u16, row: u16) -> bool {
        match kind {
            // ── Mouse wheel: scroll 3 lines at a time ──────────────────
            MouseEventKind::ScrollUp => {
                // For Alerts tab, focus the pane under the cursor
                if self.bottom_tab == BottomTab::Alerts {
                    self.alert_scroll_pane_at(col, row, true, 3);
                } else {
                    self.scroll_up(3);
                }
            }
            MouseEventKind::ScrollDown => {
                if self.bottom_tab == BottomTab::Alerts {
                    self.alert_scroll_pane_at(col, row, false, 3);
                } else {
                    self.scroll_down(3);
                }
            }

            // ── Left click ─────────────────────────────────────────────
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                let _frame_h = self.last_frame_size.height;

                // Tab bar is at y == 14 (after title:3 + speed:11)
                if row == 14 {
                    // Close any open popups when switching tabs
                    self.detail_popup = None;

                    // Tab labels rendered as " {n} {label} " with " │ " separators (3 chars).
                    let tab_labels: &[(&str, BottomTab)] = &[
                        ("1 Dashboard",   BottomTab::Dashboard),
                        ("2 Connections", BottomTab::Connections),
                        ("3 Servers",     BottomTab::Servers),
                        ("4 Packets",     BottomTab::Packets),
                        ("5 Topology",    BottomTab::Topology),
                        ("6 Alerts",      BottomTab::Alerts),
                        ("7 Firewall",    BottomTab::Firewall),
                        ("8 Devices",     BottomTab::Devices),
                        ("9 Networks",    BottomTab::Networks),
                    ];

                    let x = col as usize;
                    let mut cursor = 0_usize;
                    for (label, tab) in tab_labels {
                        // Each rendered span is " {label} " = 1 + label.len() + 1
                        let span_len = 1 + label.len() + 1;
                        if x >= cursor && x < cursor + span_len {
                            self.bottom_tab = *tab;
                            break;
                        }
                        // Move past span + " │ " separator (3 chars)
                        cursor += span_len + 3;
                    }
                }
                // Header row click — sort by column
                // Most tabs: header at y=16 (border at 15, header at 16)
                // Firewall: border(15) + status(3) + data_plan(4) + table_border(1) = header at y=24
                else if self.is_header_row(row) {
                    let frame_w = self.last_frame_size.width.saturating_sub(2); // subtract borders
                    let x = col.saturating_sub(1); // adjust for left border
                    self.handle_header_click(x, frame_w);
                }
                // Content area click: data rows start one row after the header
                else if row >= 17 {
                    let content_end = _frame_h.saturating_sub(8);
                    if row < content_end {
                        // Adjust for firewall's extra sub-sections
                        let data_start = if self.bottom_tab == BottomTab::Firewall { 25 } else { 17 };
                        if row < data_start { /* click in sub-section, ignore */ }
                        else {
                            let clicked_row = (row - data_start) as usize;
                            match self.bottom_tab {
                                BottomTab::Connections => {
                                    let max = self.filtered_connections().len().saturating_sub(1);
                                    self.conn_scroll = clicked_row.min(max);
                                }
                                BottomTab::Firewall => {
                                    let max = self.firewall_app_list_filtered().len().saturating_sub(1);
                                    self.firewall_manager.scroll_offset = clicked_row.min(max);
                                }
                                BottomTab::Devices => {
                                    let max = self.network_scanner.devices.len().saturating_sub(1);
                                    self.device_scroll = clicked_row.min(max);
                                }
                                BottomTab::Networks => {
                                    let max = self.networks_display_row_count().saturating_sub(1);
                                    let row = clicked_row.min(max);
                                    self.networks_scroll = row;
                                    // If clicked on BT header, toggle expand
                                    let display_rows = crate::ui::networks::build_display_rows(self);
                                    if let Some(crate::ui::networks::NetworksRow::BluetoothHeader { .. }) = display_rows.get(row) {
                                        self.bluetooth_expanded = !self.bluetooth_expanded;
                                    }
                                }
                                BottomTab::Packets => {
                                    self.packets_scroll = clicked_row;
                                }
                                BottomTab::Alerts => {
                                    // Mouse click: find which pane was clicked
                                    for (i, (cat, rect)) in self.alert_pane_rects.iter().enumerate() {
                                        if col >= rect.x && col < rect.x + rect.width
                                            && row >= rect.y && row < rect.y + rect.height
                                        {
                                            self.alert_focused_pane = i;
                                            // Clicked row within pane (adjust for border)
                                            let pane_row = (row - rect.y).saturating_sub(1) as usize;
                                            let ord = Self::alert_cat_ordinal(*cat);
                                            let count = self.alert_engine.alerts.iter()
                                                .filter(|a| a.kind.category() == *cat)
                                                .count();
                                            // Adjust for viewport scroll
                                            let scroll = self.alert_pane_scrolls[ord];
                                            let visible = (rect.height.saturating_sub(2)) as usize;
                                            let viewport_start = if count <= visible { 0 }
                                                else {
                                                    let half = visible / 2;
                                                    if scroll <= half { 0 }
                                                    else if scroll >= count.saturating_sub(half) { count.saturating_sub(visible) }
                                                    else { scroll.saturating_sub(half) }
                                                };
                                            let clicked_idx = viewport_start + pane_row;
                                            self.alert_pane_scrolls[ord] = clicked_idx.min(count.saturating_sub(1));
                                            break;
                                        }
                                    }
                                }
                                BottomTab::Servers => {
                                    self.servers_scanner.scroll_offset = clicked_row;
                                }
                                BottomTab::Topology => {
                                    self.topology_scroll = clicked_row;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }

            // All other mouse events (right click, drag, move, etc.) — ignore
            _ => {}
        }
        false
    }

    /// Check if the given screen row is the header row for the current tab's table.
    fn is_header_row(&self, row: u16) -> bool {
        let header_y = match self.bottom_tab {
            // Most tabs: outer block border at y=15, header at y=16
            BottomTab::Connections | BottomTab::Devices | BottomTab::Networks
            | BottomTab::Packets | BottomTab::Servers | BottomTab::Alerts => 16,
            // Firewall: border(15) + inner(16) + status(3=16,17,18) + data_plan(4=19,20,21,22)
            //           + table_block_border(23) + header(24)
            BottomTab::Firewall => 24,
            _ => return false,
        };
        row == header_y
    }

    /// Handle a click on the header row — determine which column and toggle sort.
    fn handle_header_click(&mut self, x: u16, frame_w: u16) {
        match self.bottom_tab {
            BottomTab::Connections => {
                // Columns: Process(20), Remote Host(Min22), Geo(7), Service(14), State(14), Local(7)
                let col = column_from_x(x, &[20, 0, 7, 14, 14, 7], frame_w);
                // Map display column to sort column index used by toggle_sort:
                // 0→Process(6), 1→RemoteHost(3), 2→Geo(skip), 3→Service(4), 4→State(5), 5→Local(2)
                if let Some(sort_col) = match col {
                    Some(0) => Some(6), // Process
                    Some(1) => Some(3), // Remote Host
                    Some(3) => Some(4), // Service
                    Some(4) => Some(5), // State
                    Some(5) => Some(2), // Local port
                    _ => None,          // Geo not sortable
                } {
                    self.toggle_sort(sort_col);
                }
            }
            BottomTab::Firewall => {
                // Columns: Status(8), App(Min16), Conns(6), Down(10), Up(10), Total(10), Speed(22)
                let col = column_from_x(x, &[8, 0, 6, 10, 10, 10, 22], frame_w);
                if let Some(col) = col {
                    // Map to bandwidth_tracker sort_column
                    // 0=Status (skip), 1=App(name=4), 2=Conns(3), 3=Down(1), 4=Up(2), 5=Total(0), 6=Speed(skip)
                    if let Some(sort_col) = match col {
                        1 => Some(4), // Application name
                        2 => Some(3), // Connections
                        3 => Some(1), // Download
                        4 => Some(2), // Upload
                        5 => Some(0), // Total
                        _ => None,
                    } {
                        if self.bandwidth_tracker.sort_column == sort_col {
                            self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
                        } else {
                            self.bandwidth_tracker.sort_column = sort_col;
                            self.bandwidth_tracker.sort_ascending = false;
                        }
                    }
                }
            }
            BottomTab::Devices => {
                // Columns: Status(10), IP(22), Hostname(14), MAC(18), Vendor(20), Ports(22), First(9), Last(9), Recv(18), Sent(18), Details(Min)
                let col = column_from_x(x, &[10, 22, 14, 18, 20, 22, 9, 9, 18, 18, 0], frame_w);
                if let Some(col) = col {
                    if self.device_sort_column == col {
                        self.device_sort_ascending = !self.device_sort_ascending;
                    } else {
                        self.device_sort_column = col;
                        self.device_sort_ascending = false;
                    }
                }
            }
            BottomTab::Networks => {
                // Columns: Network(24), Type(10), Status(10), IP(18), Hostname(Min14), MAC(18), Vendor(20), Ports(22)
                let col = column_from_x(x, &[24, 10, 10, 18, 0, 18, 20, 22], frame_w);
                if let Some(col) = col {
                    if self.networks_sort_column == col {
                        self.networks_sort_ascending = !self.networks_sort_ascending;
                    } else {
                        self.networks_sort_column = col;
                        self.networks_sort_ascending = false;
                    }
                }
            }
            BottomTab::Servers => {
                // Columns: Kind(15), Port(7), Proto(6), Process(16), Bind(12), Version(10), Conns(6), Status(6), Details(Min)
                let col = column_from_x(x, &[15, 7, 6, 16, 12, 10, 6, 6, 0], frame_w);
                if let Some(col) = col {
                    if self.servers_scanner.sort_column == col {
                        self.servers_scanner.sort_ascending = !self.servers_scanner.sort_ascending;
                    } else {
                        self.servers_scanner.sort_column = col;
                        self.servers_scanner.sort_ascending = true;
                    }
                }
            }
            BottomTab::Alerts => {
                // Columns: marker(1), Time(9), Severity(6), Type(16), Description(Min30)
                let col = column_from_x(x, &[1, 9, 6, 16, 0], frame_w);
                if let Some(col) = col {
                    if col == 0 { return; } // skip marker column
                    if self.alert_sort_column == Some(col) {
                        self.alert_sort_ascending = !self.alert_sort_ascending;
                    } else {
                        self.alert_sort_column = Some(col);
                        self.alert_sort_ascending = false;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Copy text to Windows clipboard via clip.exe.
fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    match Command::new("clip.exe")
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(mut child) => {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(text.as_bytes());
            }
            child.wait().is_ok()
        }
        Err(_) => false,
    }
}

/// Determine which column index a click at x falls into.
/// `widths` has 0 for Min-constraint columns (they split the remainder).
fn column_from_x(x: u16, widths: &[u16], total_width: u16) -> Option<usize> {
    let fixed_total: u16 = widths.iter().sum();
    let min_count = widths.iter().filter(|&&w| w == 0).count() as u16;
    let remaining = total_width.saturating_sub(fixed_total);
    let min_each = if min_count > 0 { remaining / min_count } else { 0 };

    let mut cursor: u16 = 0;
    for (i, &w) in widths.iter().enumerate() {
        let actual_w = if w == 0 { min_each } else { w };
        if x >= cursor && x < cursor + actual_w {
            return Some(i);
        }
        cursor += actual_w;
    }
    None
}
