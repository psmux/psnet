//! LAN device scanner using the OS neighbour table.
//!
//! Backed by iphlpapi (GetAdaptersInfo/GetIpNetTable) on Windows and by
//! getifaddrs(3) plus /proc/net/{arp,route} on Linux.
//!
//! Scans the local subnet to discover devices, their MAC addresses,
//! and tracks online/offline status over time. Runs scans on a background
//! thread to avoid blocking the UI tick. Uses a streaming pending buffer
//! so results appear in the UI as soon as each device is discovered.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use chrono::Local;

use crate::types::LanDevice;

/// Scan phases for UI display.
pub const SCAN_PHASE_IDLE: u8 = 0;
pub const SCAN_PHASE_ARP: u8 = 1;
pub const SCAN_PHASE_DNS: u8 = 2;

// ─── Win32 FFI ───────────────────────────────────────────────────────────────

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersInfo(
        pAdapterInfo: *mut u8,
        pOutBufLen: *mut u32,
    ) -> u32;

    fn GetIpNetTable(
        pIpNetTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
    ) -> u32;
}

#[cfg(windows)]
const ERROR_SUCCESS: u32 = 0;
#[cfg(windows)]
const ERROR_BUFFER_OVERFLOW: u32 = 111;

// ─── Adapter info parsing (simplified) ──────────────────────────────────────

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct IP_ADAPTER_INFO {
    Next: *mut IP_ADAPTER_INFO,
    ComboIndex: u32,
    AdapterName: [u8; 260],
    Description: [u8; 132],
    AddressLength: u32,
    Address: [u8; 8],
    Index: u32,
    Type: u32,
    DhcpEnabled: u32,
    CurrentIpAddress: *mut IP_ADDR_STRING,
    IpAddressList: IP_ADDR_STRING,
    GatewayList: IP_ADDR_STRING,
    DhcpServer: IP_ADDR_STRING,
    HaveWins: i32,
    PrimaryWinsServer: IP_ADDR_STRING,
    SecondaryWinsServer: IP_ADDR_STRING,
    LeaseObtained: i64,
    LeaseExpires: i64,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct IP_ADDR_STRING {
    Next: *mut IP_ADDR_STRING,
    IpAddress: [u8; 16],
    IpMask: [u8; 16],
    Context: u32,
}

/// Get the local IPv4 address and subnet mask of the primary adapter.
///
/// Picks the first usable adapter, preferring one that owns a default route,
/// so a router with several bridged interfaces still scans the WAN-facing one
/// consistently with the Windows behaviour.
#[cfg(not(windows))]
fn get_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    use crate::network::linux;

    let default = linux::default_route();
    let mut best: Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> = None;

    for ifa in linux::ifaddrs() {
        let (ip, mask) = match (ifa.addr, ifa.netmask) {
            (IpAddr::V4(ip), Some(IpAddr::V4(mask))) => (ip, mask),
            _ => continue,
        };
        if ip.is_loopback() || ip.is_unspecified() || mask == Ipv4Addr::UNSPECIFIED {
            continue;
        }

        let gw = default
            .as_ref()
            .filter(|(_, iface)| *iface == ifa.name)
            .map(|(gw, _)| *gw)
            .unwrap_or(Ipv4Addr::UNSPECIFIED);

        if best.is_none() || !gw.is_unspecified() {
            best = Some((ip, mask, gw));
        }
    }

    best
}

/// Get the local IPv4 address and subnet mask of the primary adapter.
#[cfg(windows)]
fn get_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> {
    unsafe {
        let mut size: u32 = 0;
        let ret = GetAdaptersInfo(std::ptr::null_mut(), &mut size);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetAdaptersInfo(buf.as_mut_ptr(), &mut size);
        if ret != ERROR_SUCCESS {
            return None;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_INFO;
        let mut best: Option<(Ipv4Addr, Ipv4Addr, Ipv4Addr)> = None;

        while !adapter.is_null() {
            let ip_str = cstr_from_bytes(&(*adapter).IpAddressList.IpAddress);
            let mask_str = cstr_from_bytes(&(*adapter).IpAddressList.IpMask);
            let gw_str = cstr_from_bytes(&(*adapter).GatewayList.IpAddress);

            if let (Ok(ip), Ok(mask)) = (ip_str.parse::<Ipv4Addr>(), mask_str.parse::<Ipv4Addr>()) {
                if !ip.is_loopback() && !ip.is_unspecified() && mask != Ipv4Addr::UNSPECIFIED {
                    let gw = gw_str.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED);
                    if best.is_none() || !gw.is_unspecified() {
                        best = Some((ip, mask, gw));
                    }
                }
            }

            adapter = (*adapter).Next;
        }

        best
    }
}

#[cfg(windows)]
fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

/// Generate all IPs in a subnet given IP and mask.
fn subnet_ips(ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<Ipv4Addr> {
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;
    let host_count = broadcast - network;

    // Limit scan to /24 or smaller to avoid huge scans
    if host_count > 254 {
        // Fall back to /24 around the host IP
        let base = ip_u32 & 0xFFFFFF00;
        return (1..255)
            .map(|i| Ipv4Addr::from(base + i))
            .filter(|&a| a != ip)
            .collect();
    }

    (network + 1..broadcast)
        .map(Ipv4Addr::from)
        .filter(|&a| a != ip)
        .collect()
}

// ─── ARP cache instant read (GetIpNetTable — zero network traffic) ──────────

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct MIB_IPNETROW {
    dwIndex: u32,
    dwPhysAddrLen: u32,
    bPhysAddr: [u8; 8],
    dwAddr: u32,
    dwType: u32,
}

/// Read the OS ARP cache instantly (no network traffic).
/// Returns Vec of (ip, mac) for all reachable entries in the local subnet.
///
/// /proc/net/arp already excludes incomplete entries via the flags column
/// (see `linux::arp_table`), which is the equivalent of skipping the
/// invalid/other entry types in the Windows MIB table.
#[cfg(not(windows))]
fn arp_cache_read(local_ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<(Ipv4Addr, String)> {
    use crate::network::linux;

    let ip_u32 = u32::from(local_ip);
    let mask_u32 = u32::from(mask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;

    let mut results = Vec::new();
    for entry in linux::arp_table() {
        // Only include IPs in our subnet (not network/broadcast, not self)
        let ip_val = u32::from(entry.ip);
        if ip_val <= network || ip_val >= broadcast || entry.ip == local_ip {
            continue;
        }
        // Match the Windows formatting so MAC strings compare and display
        // identically across platforms.
        let mac = entry.mac.to_uppercase();
        if mac != "FF:FF:FF:FF:FF:FF" {
            results.push((entry.ip, mac));
        }
    }

    results
}

/// Read the OS ARP cache instantly (no network traffic).
/// Returns Vec of (ip, mac) for all reachable entries in the local subnet.
#[cfg(windows)]
fn arp_cache_read(local_ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<(Ipv4Addr, String)> {
    let mut results = Vec::new();
    let ip_u32 = u32::from(local_ip);
    let mask_u32 = u32::from(mask);
    let network = ip_u32 & mask_u32;
    let broadcast = network | !mask_u32;

    unsafe {
        let mut size: u32 = 0;
        let ret = GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return results;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetIpNetTable(buf.as_mut_ptr(), &mut size, 0);
        if ret != ERROR_SUCCESS {
            return results;
        }

        let num_entries = *(buf.as_ptr() as *const u32);
        let rows_ptr = buf.as_ptr().add(4) as *const MIB_IPNETROW;

        for i in 0..num_entries as usize {
            let row = &*rows_ptr.add(i);
            // 3=dynamic, 4=static; skip invalid(2) and other(1)
            if row.dwType < 3 {
                continue;
            }
            let raw = u32::from_be(row.dwAddr);
            let ip = Ipv4Addr::from(raw);
            // Only include IPs in our subnet (not loopback, not self)
            let ip_val = u32::from(ip);
            if ip_val <= network || ip_val >= broadcast || ip == local_ip {
                continue;
            }
            if row.dwPhysAddrLen >= 6 {
                let mac = format!(
                    "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    row.bPhysAddr[0], row.bPhysAddr[1], row.bPhysAddr[2],
                    row.bPhysAddr[3], row.bPhysAddr[4], row.bPhysAddr[5]
                );
                // Skip broadcast MAC (FF:FF:FF:FF:FF:FF)
                if mac != "FF:FF:FF:FF:FF:FF" {
                    results.push((ip, mac));
                }
            }
        }
    }

    results
}

// ─── Streaming device update ────────────────────────────────────────────────

/// A single device update pushed from the background scan thread.
struct DeviceUpdate {
    ip: Ipv4Addr,
    mac: String,
    hostname: Option<String>,
    discovery_info: String,
    open_ports: String,
}

// ─── Scanner state ───────────────────────────────────────────────────────────

pub struct NetworkScanner {
    /// Known devices keyed by IP (authoritative list).
    pub devices: Vec<LanDevice>,
    /// Streaming pending buffer — background threads push updates here.
    pending: Arc<Mutex<Vec<DeviceUpdate>>>,
    /// Whether a scan is in progress.
    scanning: Arc<AtomicBool>,
    /// Track previous scanning state to detect scan completion.
    was_scanning: bool,
    /// IPs seen during the current scan (for offline marking).
    scan_seen_ips: HashSet<IpAddr>,
    /// Scan progress: (probed, total) shared with background thread.
    scan_progress: Arc<(AtomicUsize, AtomicUsize)>,
    /// Current scan phase (0=idle, 1=ARP, 2=DNS).
    scan_phase: Arc<AtomicU8>,
    /// Last scan timestamp.
    pub last_scan: Option<Instant>,
    /// Local subnet info.
    pub local_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    /// Scan interval tracking.
    scan_tick: u32,
    /// User-assigned labels: MAC → display name.
    pub custom_labels: HashMap<String, String>,
    /// Persistence path for labels.
    labels_path: PathBuf,
    /// DHCP hostname cache: IP → hostname (fed from sniffer DHCP packets).
    pub dhcp_hostnames: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
}

impl NetworkScanner {
    pub fn new() -> Self {
        let (local_ip, subnet_mask, gateway) = get_local_subnet()
            .map(|(ip, mask, gw)| (Some(ip), Some(mask), Some(gw)))
            .unwrap_or((None, None, None));

        let labels_path = Self::labels_path();
        let custom_labels = Self::load_labels(&labels_path);

        // Instant seed: read OS ARP cache (zero network traffic, sub-millisecond)
        let now = Local::now().time();
        let mut devices = Vec::new();
        if let (Some(ip), Some(mask)) = (local_ip, subnet_mask) {
            let cached = arp_cache_read(ip, mask);
            for (cached_ip, mac) in cached {
                devices.push(LanDevice {
                    ip: IpAddr::V4(cached_ip),
                    mac: mac.clone(),
                    hostname: None,
                    vendor: mac_vendor(&mac),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: custom_labels.get(&mac).cloned(),
                    discovery_info: String::new(),
                    open_ports: String::new(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }

        Self {
            devices,
            pending: Arc::new(Mutex::new(Vec::new())),
            scanning: Arc::new(AtomicBool::new(false)),
            was_scanning: false,
            scan_seen_ips: HashSet::new(),
            scan_progress: Arc::new((AtomicUsize::new(0), AtomicUsize::new(0))),
            scan_phase: Arc::new(AtomicU8::new(SCAN_PHASE_IDLE)),
            last_scan: None,
            local_ip,
            gateway,
            subnet_mask,
            scan_tick: 0,
            custom_labels,
            labels_path,
            dhcp_hostnames: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Trigger a full multi-method network scan. Non-blocking.
    ///
    /// **Phase 1 — 10 parallel discovery methods** (all stream results live):
    ///   1. ARP Scan (SendARP)              — Layer 2, gets MACs
    ///   2. ARP Cache (GetIpNetTable)        — Instant, zero traffic
    ///   3. ICMP Ping (IcmpSendEcho)         — Layer 3, crosses VPN tunnels
    ///   4. TCP Connect Probe               — Layer 4, finds services
    ///   5. NetBIOS NBSTAT (UDP 137)         — Windows/Samba hostnames
    ///   6. mDNS (UDP 5353)                 — Apple, IoT, Linux
    ///   7. SSDP/UPnP (UDP 1900)            — Routers, TVs, smart home
    ///   8. DNS PTR Reverse Lookup           — Standard reverse DNS
    ///   9. LLMNR (UDP 5355)                — Link-local names
    ///  10. NetBIOS Broadcast (UDP 137)      — Subnet-wide name query
    ///
    /// **Phase 2 — Hostname enrichment** via 12+ parallel resolution methods.
    pub fn start_scan(&self) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return;
        }

        let (ip, mask) = match (self.local_ip, self.subnet_mask) {
            (Some(ip), Some(mask)) => (ip, mask),
            _ => {
                self.scanning.store(false, Ordering::SeqCst);
                return;
            }
        };

        let pending = Arc::clone(&self.pending);
        let scanning = Arc::clone(&self.scanning);
        let progress = Arc::clone(&self.scan_progress);
        let phase = Arc::clone(&self.scan_phase);
        let gateway = self.gateway;
        let dhcp_hostnames = Arc::clone(&self.dhcp_hostnames);

        // Snapshot known hostnames to skip redundant resolution
        let known_hostnames: HashMap<Ipv4Addr, String> = self.devices.iter()
            .filter_map(|d| {
                if let (IpAddr::V4(v4), Some(ref h)) = (d.ip, &d.hostname) {
                    Some((v4, h.clone()))
                } else {
                    None
                }
            })
            .collect();

        thread::spawn(move || {
            use super::networks::probes;

            let targets = subnet_ips(ip, mask);
            let total_targets = targets.len();
            progress.0.store(0, Ordering::Relaxed);
            progress.1.store(total_targets, Ordering::Relaxed);
            phase.store(SCAN_PHASE_ARP, Ordering::Relaxed);

            // Track all discovered IPs for Phase 2 hostname resolution
            let discovered: Mutex<HashMap<Ipv4Addr, Option<String>>> = Mutex::new(HashMap::new());

            // ═══ Phase 1: 10 parallel discovery methods ═══════════════════
            // Each method runs independently and streams results to pending.
            // All references are borrowed (not moved) via thread::scope.
            let targets_ref = &targets;
            let pending_ref = &pending;
            let discovered_ref = &discovered;
            let known_ref = &known_hostnames;
            let progress_ref = &progress;

            // Helper: convert probe hits to device updates and push to pending
            let push_hits = |hits: &[probes::ProbeHit]| {
                if hits.is_empty() { return; }
                let mut disc = discovered_ref.lock().unwrap();
                let mut updates = Vec::with_capacity(hits.len());
                for hit in hits {
                    let entry = disc.entry(hit.ip).or_insert(None);
                    if entry.is_none() && hit.mac.is_some() {
                        *entry = hit.mac.clone();
                    }
                    updates.push(DeviceUpdate {
                        ip: hit.ip,
                        mac: hit.mac.clone().unwrap_or_default(),
                        hostname: hit.hostname.clone().or_else(|| known_ref.get(&hit.ip).cloned()),
                        discovery_info: hit.method.to_string(),
                        open_ports: String::new(),
                    });
                }
                drop(disc);
                if let Ok(mut p) = pending_ref.lock() {
                    p.extend(updates);
                }
            };

            thread::scope(|s| {
                // 1. ARP Scan — Layer 2, returns MACs
                s.spawn(|| {
                    let hits = probes::arp_scan(targets_ref, ip);
                    progress_ref.0.fetch_add(total_targets / 2, Ordering::Relaxed);
                    push_hits(&hits);
                });
                // 2. ARP Cache — instant, zero traffic
                s.spawn(|| {
                    let hits = probes::arp_cache_read(targets_ref);
                    push_hits(&hits);
                });
                // 3. ICMP Ping Sweep — Layer 3, crosses VPN tunnels
                s.spawn(|| {
                    let hits = probes::icmp_ping_sweep(targets_ref);
                    progress_ref.0.fetch_add(total_targets / 4, Ordering::Relaxed);
                    push_hits(&hits);
                });
                // 4. TCP Connect Probe — finds hosts with open services
                s.spawn(|| {
                    let hits = probes::tcp_connect_probe(targets_ref);
                    push_hits(&hits);
                });
                // 5. NetBIOS NBSTAT — Windows/Samba hostname resolution
                s.spawn(|| {
                    let hits = probes::netbios_scan(targets_ref);
                    push_hits(&hits);
                });
                // 6. mDNS — Apple, IoT, Linux discovery
                s.spawn(|| {
                    let hits = probes::mdns_discover(ip);
                    push_hits(&hits);
                });
                // 7. SSDP/UPnP — routers, TVs, smart home
                s.spawn(|| {
                    let hits = probes::ssdp_discover(ip);
                    push_hits(&hits);
                });
                // 8. DNS PTR Reverse Lookup
                s.spawn(|| {
                    let hits = probes::dns_reverse_scan(targets_ref);
                    push_hits(&hits);
                });
                // 9. LLMNR — Link-Local Multicast Name Resolution
                s.spawn(|| {
                    let hits = probes::llmnr_discover(ip);
                    push_hits(&hits);
                });
                // 10. NetBIOS Broadcast — subnet-wide name query
                s.spawn(|| {
                    let hits = probes::nbt_broadcast(ip, mask);
                    push_hits(&hits);
                });
            });

            progress.0.store(total_targets, Ordering::Relaxed);

            // ═══ Phase 2: Hostname enrichment ═════════════════════════════
            // Resolve hostnames for ALL discovered IPs (from any method)
            let disc_map = discovered.into_inner().unwrap();
            let all_discovered_ips: Vec<Ipv4Addr> = disc_map.keys().copied().collect();
            // Always re-resolve all IPs so new methods can discover additional names
            let need_resolve = all_discovered_ips;

            if need_resolve.is_empty() {
                phase.store(SCAN_PHASE_IDLE, Ordering::Relaxed);
                scanning.store(false, Ordering::SeqCst);
                return;
            }

            phase.store(SCAN_PHASE_DNS, Ordering::Relaxed);
            progress.0.store(0, Ordering::Relaxed);
            progress.1.store(need_resolve.len(), Ordering::Relaxed);

            // Multi-method parallel hostname resolution (13+ methods)
            let dhcp_snap = dhcp_hostnames.lock().map(|h| h.clone()).unwrap_or_default();
            let resolved_map = super::hostnames::resolve_all(&need_resolve, gateway, &dhcp_snap);
            progress.0.store(need_resolve.len(), Ordering::Relaxed);

            // Stream resolved hostnames to pending buffer
            if !resolved_map.is_empty() {
                let updates: Vec<DeviceUpdate> = need_resolve.iter().filter_map(|ip| {
                    resolved_map.get(ip).map(|resolved| {
                        let hostname = if resolved.hostname.is_empty() {
                            None
                        } else {
                            Some(resolved.hostname.clone())
                        };
                        let ports_str = super::hostnames::format_ports(&resolved.open_ports);
                        // Use MAC from discovery phase if available
                        let mac = disc_map.get(ip).and_then(|m| m.clone()).unwrap_or_default();
                        DeviceUpdate {
                            ip: *ip,
                            mac,
                            hostname,
                            discovery_info: resolved.details.clone(),
                            open_ports: ports_str,
                        }
                    })
                }).collect();

                if let Ok(mut p) = pending.lock() {
                    p.extend(updates);
                }
            }

            phase.store(SCAN_PHASE_IDLE, Ordering::Relaxed);
            scanning.store(false, Ordering::SeqCst);
        });
    }

    /// Drain pending buffer and merge updates into device list.
    /// Called frequently (every 200ms) for maximum responsiveness.
    /// Returns previous device list if devices changed (for alert checking).
    pub fn poll_results(&mut self) -> Option<Vec<LanDevice>> {
        // Track scanning state transitions
        let currently_scanning = self.scanning.load(Ordering::SeqCst);
        if currently_scanning {
            self.was_scanning = true;
        }

        // Drain pending buffer
        let batch = {
            if let Ok(mut p) = self.pending.lock() {
                if p.is_empty() {
                    Vec::new()
                } else {
                    std::mem::take(&mut *p)
                }
            } else {
                Vec::new()
            }
        };

        let has_updates = !batch.is_empty();
        let scan_just_completed = self.was_scanning && !currently_scanning;

        if !has_updates && !scan_just_completed {
            return None;
        }

        let prev_devices = self.devices.clone();
        let now = Local::now().time();

        // Merge each update into device list
        for update in batch {
            let ip_addr = IpAddr::V4(update.ip);
            self.scan_seen_ips.insert(ip_addr);

            if let Some(existing) = self.devices.iter_mut().find(|d| d.ip == ip_addr) {
                if existing.mac != update.mac && !update.mac.is_empty() {
                    existing.vendor = mac_vendor(&update.mac);
                    existing.mac = update.mac.clone();
                }
                existing.last_seen = now;
                existing.is_online = true;
                existing.custom_name = self.custom_labels.get(&existing.mac).cloned();
                if let Some(ref new_name) = update.hostname {
                    if let Some(ref mut old_name) = existing.hostname {
                        // Merge: add any new comma-separated parts not already present
                        let existing_lower: std::collections::HashSet<String> = old_name
                            .split(", ")
                            .map(|s| s.trim().to_lowercase())
                            .collect();
                        for part in new_name.split(", ") {
                            let part = part.trim();
                            if !part.is_empty() && !existing_lower.contains(&part.to_lowercase()) {
                                old_name.push_str(", ");
                                old_name.push_str(part);
                            }
                        }
                    } else {
                        existing.hostname = update.hostname;
                    }
                }
                if !update.discovery_info.is_empty() {
                    if existing.discovery_info.is_empty() {
                        existing.discovery_info = update.discovery_info;
                    } else {
                        // Merge discovery info: add new tag:value entries not already present
                        let existing_tags: std::collections::HashSet<String> = existing.discovery_info
                            .split("  ")
                            .map(|s| s.trim().to_lowercase())
                            .collect();
                        for entry in update.discovery_info.split("  ") {
                            let entry = entry.trim();
                            if !entry.is_empty() && !existing_tags.contains(&entry.to_lowercase()) {
                                existing.discovery_info.push_str("  ");
                                existing.discovery_info.push_str(entry);
                            }
                        }
                    }
                }
                if !update.open_ports.is_empty() {
                    if existing.open_ports.is_empty() {
                        existing.open_ports = update.open_ports;
                    } else {
                        // Merge open ports
                        let existing_ports: std::collections::HashSet<String> = existing.open_ports
                            .split(' ')
                            .map(|s| s.trim().to_lowercase())
                            .collect();
                        for port in update.open_ports.split(' ') {
                            let port = port.trim();
                            if !port.is_empty() && !existing_ports.contains(&port.to_lowercase()) {
                                existing.open_ports.push(' ');
                                existing.open_ports.push_str(port);
                            }
                        }
                    }
                }
            } else {
                // Skip ghost entries: no MAC and no hostname = unresponsive IP
                if update.mac.is_empty() && update.hostname.is_none() {
                    continue;
                }
                self.devices.push(LanDevice {
                    ip: ip_addr,
                    mac: update.mac.clone(),
                    hostname: update.hostname,
                    vendor: mac_vendor(&update.mac),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: self.custom_labels.get(&update.mac).cloned(),
                    discovery_info: update.discovery_info,
                    open_ports: update.open_ports,
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }

        // When scan completes, mark unseen devices as offline
        if scan_just_completed {
            self.was_scanning = false;
            self.last_scan = Some(Instant::now());
            for device in &mut self.devices {
                if !self.scan_seen_ips.contains(&device.ip) {
                    device.is_online = false;
                }
            }
            self.scan_seen_ips.clear();
        }

        if has_updates || scan_just_completed {
            Some(prev_devices)
        } else {
            None
        }
    }

    /// Called each tick. Auto-triggers scan every N ticks.
    pub fn tick(&mut self) {
        self.scan_tick += 1;
        // Scan every 15 ticks (~15 seconds) for faster device discovery
        if self.scan_tick % 15 == 1 {
            self.start_scan();
        }
    }

    /// Is a scan currently in progress?
    pub fn is_scanning(&self) -> bool {
        self.scanning.load(Ordering::SeqCst)
    }

    /// Scan progress: (probed, total). Returns (0, 0) if not scanning.
    pub fn scan_progress(&self) -> (usize, usize) {
        (
            self.scan_progress.0.load(Ordering::Relaxed),
            self.scan_progress.1.load(Ordering::Relaxed),
        )
    }

    /// Current scan phase (SCAN_PHASE_IDLE / ARP / DNS).
    pub fn scan_phase(&self) -> u8 {
        self.scan_phase.load(Ordering::Relaxed)
    }

    fn labels_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("device_labels.json")
        } else {
            PathBuf::from("psnet_device_labels.json")
        }
    }

    fn load_labels(path: &PathBuf) -> HashMap<String, String> {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_labels(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.custom_labels) {
            let _ = std::fs::write(&self.labels_path, json);
        }
    }

    /// Set a custom label for a device (by MAC address).
    pub fn set_label(&mut self, mac: &str, label: String) {
        if label.is_empty() {
            self.custom_labels.remove(mac);
        } else {
            self.custom_labels.insert(mac.to_string(), label);
        }
        self.save_labels();
        // Apply immediately to in-memory devices
        for device in &mut self.devices {
            if device.mac == mac {
                device.custom_name = self.custom_labels.get(mac).cloned();
            }
        }
    }

    /// Online device count.
    pub fn online_count(&self) -> usize {
        self.devices.iter().filter(|d| d.is_online).count()
    }
}

// ─── MAC vendor lookup ──────────────────────────────────────────────────────

/// Check if a MAC address has the locally-administered bit set (bit 1 of octet 0).
fn is_locally_administered_mac(mac: &str) -> bool {
    if let Some(first_byte_str) = mac.split(':').next() {
        if let Ok(byte) = u8::from_str_radix(first_byte_str, 16) {
            return byte & 0x02 != 0;
        }
    }
    false
}

/// Known locally-administered MAC prefixes (not in IEEE OUI database).
/// These are virtual/container/tunnel adapters that use the LA bit but are
/// NOT random — they're assigned by specific software.
fn local_admin_vendor(mac: &str) -> Option<&'static str> {
    let upper = mac.to_uppercase();
    let bytes: Vec<&str> = upper.split(':').collect();
    if bytes.len() < 3 {
        return None;
    }

    // Match on first 2 bytes (common) or 3 bytes (specific)
    let prefix2 = format!("{}:{}", bytes[0], bytes[1]);
    let prefix3 = format!("{}:{}:{}", bytes[0], bytes[1], bytes[2]);

    match prefix3.as_str() {
        // Docker default bridge (02:42:AC:xx:xx:xx)
        s if s.starts_with("02:42:AC") => return Some("Docker Container"),
        _ => {}
    }

    match prefix2.as_str() {
        // Docker containers (02:42:xx)
        "02:42" => Some("Docker Container"),
        // Hyper-V (00:15:5D is in OUI, but some use locally-admin'd)
        "00:15" => Some("Hyper-V VM"),
        // Xen virtual machines
        "FE:FF" => Some("Xen VM"),
        // KVM/QEMU default (52:54:00 is common but 52 has LA bit)
        "52:54" => Some("KVM/QEMU VM"),
        // Parallels Desktop
        "00:1C" => None, // Let OUI handle it
        // OpenVPN TAP adapters
        "00:FF" => Some("OpenVPN TAP"),
        // WireGuard / other VPN
        "A6:4D" => Some("WireGuard"),
        // libvirt/virt-manager
        "FE:54" => Some("Libvirt VM"),
        // WSL2 (Hyper-V under the hood, but uses random LA MACs)
        // Windows typically assigns these in the 00:15:5D range
        _ => None,
    }
}

pub(crate) fn mac_vendor(mac: &str) -> Option<String> {
    // 1. Standard IEEE OUI lookup (39,000+ vendors)
    if let Some(vendor) = super::oui::lookup(mac) {
        return Some(vendor.to_string());
    }

    // 2. Known locally-administered prefixes (Docker, VMs, VPNs, etc.)
    if let Some(vendor) = local_admin_vendor(mac) {
        return Some(vendor.to_string());
    }

    // 3. Locally-administered but unrecognized → likely privacy-randomized
    if is_locally_administered_mac(mac) {
        return Some("Private MAC".to_string());
    }

    // 4. Unknown universally-administered MAC (vendor not in database)
    None
}
