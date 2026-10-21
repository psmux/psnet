//! VPN peer/client discovery module for Windows.
//!
//! Discovers VPN peers and clients using 7 parallel methods:
//!   1. Route Table Analysis     — Parse `route print` to find VPN subnets
//!   2. OpenVPN Management       — Connect to management interface for client list
//!   3. WireGuard CLI            — `wg show` for peers and allowed-ips
//!   4. OpenVPN Log Parsing      — Parse log files for peer connection info
//!   5. Windows VPN (RAS)        — `rasdial` to enumerate active VPN connections
//!   6. ICMP Ping Sweep          — IcmpSendEcho against discovered VPN subnets
//!   7. TCP Connect Probe        — Port probe against discovered VPN subnets

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write as IoWrite};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use chrono::Local;

use crate::types::{LanDevice, NetworkCategory, RemoteNetwork};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// ─── Win32 ICMP FFI ────────────────────────────────────────────────────────

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn IcmpCreateFile() -> isize;
    fn IcmpCloseHandle(IcmpHandle: isize) -> i32;
    fn IcmpSendEcho(
        IcmpHandle: isize,
        DestinationAddress: u32,
        RequestData: *const u8,
        RequestSize: u16,
        RequestOptions: *const u8,
        ReplyBuffer: *mut u8,
        ReplySize: u32,
        Timeout: u32,
    ) -> u32;
}

#[cfg(windows)]
const INVALID_HANDLE_VALUE: isize = -1;

// ─── Internal types ─────────────────────────────────────────────────────────

/// A VPN subnet discovered from route table or VPN tools.
#[derive(Clone, Debug)]
struct VpnSubnet {
    /// Network address (e.g., 10.8.0.0).
    network: Ipv4Addr,
    /// Prefix length (e.g., 24).
    prefix: u32,
    /// Mask derived from prefix.
    mask: Ipv4Addr,
    /// Interface/adapter name or IP (from route table).
    interface_hint: String,
    /// How this subnet was discovered.
    source: String,
}

/// A discovered VPN peer from any method.
#[derive(Clone, Debug)]
struct VpnPeer {
    ip: Ipv4Addr,
    hostname: Option<String>,
    /// Extra info (e.g., "WireGuard peer: <pubkey>", "OpenVPN client: CN=user").
    info: String,
    method: &'static str,
}

// ─── TCP probe ports ────────────────────────────────────────────────────────

const TCP_PROBE_PORTS: &[u16] = &[80, 443, 22, 3389, 445, 8080];

// ─── OpenVPN management ports to try ────────────────────────────────────────

const OPENVPN_MGMT_PORTS: &[u16] = &[7505, 7506, 7507, 1195, 7500];

// ─── Common OpenVPN log locations ───────────────────────────────────────────

fn openvpn_log_paths() -> Vec<String> {
    let mut paths = vec![
        r"C:\Program Files\OpenVPN\log\openvpn.log".to_string(),
        r"C:\Program Files\OpenVPN\log\client.log".to_string(),
        r"C:\Program Files (x86)\OpenVPN\log\openvpn.log".to_string(),
        r"C:\Program Files\OpenVPN\config\openvpn.log".to_string(),
    ];
    // Also check %USERPROFILE%\OpenVPN\log
    if let Ok(profile) = std::env::var("USERPROFILE") {
        paths.push(format!(r"{}\OpenVPN\log\openvpn.log", profile));
        paths.push(format!(r"{}\OpenVPN\log\client.log", profile));
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        paths.push(format!(r"{}\OpenVPN\log\openvpn.log", appdata));
    }
    if let Ok(programdata) = std::env::var("PROGRAMDATA") {
        paths.push(format!(r"{}\OpenVPN\log\openvpn.log", programdata));
    }
    paths
}

// ═════════════════════════════════════════════════════════════════════════════
// Public entry point
// ═════════════════════════════════════════════════════════════════════════════

/// Discover VPN peers using all available methods in parallel.
///
/// Returns a list of `RemoteNetwork` entries for each discovered VPN subnet,
/// populated with devices found by ICMP, TCP, and VPN-specific tools.
pub fn discover(primary_ip: Option<Ipv4Addr>) -> Vec<RemoteNetwork> {
    let subnets: Mutex<Vec<VpnSubnet>> = Mutex::new(Vec::new());
    let peers: Mutex<Vec<VpnPeer>> = Mutex::new(Vec::new());
    let ras_connections: Mutex<Vec<String>> = Mutex::new(Vec::new());

    // Phase 1: Discover VPN subnets and peers from all sources in parallel
    thread::scope(|s| {
        // 1. Route table analysis
        let sub_ref = &subnets;
        s.spawn(move || {
            if let Some(found) = route_table_vpn_subnets(primary_ip) {
                sub_ref.lock().unwrap().extend(found);
            }
        });

        // 2. OpenVPN management interface
        let peer_ref = &peers;
        s.spawn(move || {
            let found = openvpn_management_query();
            peer_ref.lock().unwrap().extend(found);
        });

        // 3. WireGuard CLI
        let peer_ref = &peers;
        let sub_ref = &subnets;
        s.spawn(move || {
            let (wg_peers, wg_subnets) = wireguard_show();
            peer_ref.lock().unwrap().extend(wg_peers);
            sub_ref.lock().unwrap().extend(wg_subnets);
        });

        // 4. OpenVPN log parsing
        let peer_ref = &peers;
        s.spawn(move || {
            let found = openvpn_log_parse();
            peer_ref.lock().unwrap().extend(found);
        });

        // 5. Windows RAS/VPN connections
        let ras_ref = &ras_connections;
        s.spawn(move || {
            if let Some(conns) = rasdial_enumerate() {
                ras_ref.lock().unwrap().extend(conns);
            }
        });
    });

    let mut all_subnets = subnets.into_inner().unwrap();
    let mut all_peers = peers.into_inner().unwrap();
    let ras_conns = ras_connections.into_inner().unwrap();

    // Deduplicate subnets by network address
    dedup_subnets(&mut all_subnets);

    // If no subnets found, nothing to scan
    if all_subnets.is_empty() && all_peers.is_empty() {
        return Vec::new();
    }

    // Phase 2: Active scanning — ICMP + TCP probe discovered subnets in parallel
    let scan_peers: Mutex<Vec<VpnPeer>> = Mutex::new(Vec::new());

    if !all_subnets.is_empty() {
        thread::scope(|s| {
            for subnet in &all_subnets {
                let targets = subnet_hosts(subnet.network, subnet.mask, primary_ip);
                if targets.is_empty() {
                    continue;
                }

                // 6. ICMP ping sweep
                let sp = &scan_peers;
                let tgts = targets.clone();
                s.spawn(move || {
                    let found = icmp_sweep_vpn(&tgts);
                    sp.lock().unwrap().extend(found);
                });

                // 7. TCP connect probe
                let sp = &scan_peers;
                s.spawn(move || {
                    let found = tcp_probe_vpn(&targets);
                    sp.lock().unwrap().extend(found);
                });
            }
        });
    }

    all_peers.extend(scan_peers.into_inner().unwrap());

    // Phase 3: Build RemoteNetwork results
    build_networks(all_subnets, all_peers, ras_conns, primary_ip)
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 1: Route Table Analysis
// ═════════════════════════════════════════════════════════════════════════════

fn route_table_vpn_subnets(primary_ip: Option<Ipv4Addr>) -> Option<Vec<VpnSubnet>> {
    let mut cmd = Command::new("route");
    cmd.args(["print"]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut subnets = Vec::new();
    let primary = primary_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);

    // Parse IPv4 route table lines:
    // Format: "Network Destination    Netmask          Gateway         Interface  Metric"
    // e.g.:   "10.8.0.0            255.255.255.0    10.8.0.1        10.8.0.2      30"
    let mut in_ipv4_table = false;
    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.contains("IPv4 Route Table") || trimmed.contains("IPv4") && trimmed.contains("Route") {
            in_ipv4_table = true;
            continue;
        }
        if trimmed.contains("IPv6 Route Table") {
            in_ipv4_table = false;
            continue;
        }
        if !in_ipv4_table {
            continue;
        }

        // Skip header lines
        if trimmed.starts_with("Network") || trimmed.starts_with("=") || trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Active") || trimmed.starts_with("Persistent") {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let dest: Ipv4Addr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let mask: Ipv4Addr = match parts[1].parse() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let _gateway: Ipv4Addr = match parts[2].parse() {
            Ok(g) => g,
            Err(_) => continue,
        };
        let iface: Ipv4Addr = match parts[3].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };

        // Skip default route, loopback, multicast, broadcast
        if dest == Ipv4Addr::UNSPECIFIED && mask == Ipv4Addr::UNSPECIFIED {
            continue;
        }
        if dest.is_loopback() || dest.octets()[0] >= 224 {
            continue;
        }
        // Skip if interface is the primary adapter
        if iface == primary {
            continue;
        }
        // Skip host routes (mask = 255.255.255.255) unless they look like VPN
        let prefix = u32::from(mask).count_ones();
        if prefix == 32 {
            continue;
        }
        // Skip very broad routes (/0, /1, /2) — those are usually VPN default route overrides, not subnets
        if prefix < 8 {
            continue;
        }
        // Skip link-local
        let octets = dest.octets();
        if octets[0] == 169 && octets[1] == 254 {
            continue;
        }

        // Check if this looks like a VPN subnet:
        // - Private ranges routed through non-primary interface
        // - Common VPN ranges: 10.x, 172.16-31.x, 192.168.x
        let is_private = octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168);

        if !is_private {
            continue;
        }

        subnets.push(VpnSubnet {
            network: dest,
            prefix,
            mask,
            interface_hint: iface.to_string(),
            source: format!("route-table via {}", iface),
        });
    }

    if subnets.is_empty() {
        None
    } else {
        Some(subnets)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 2: OpenVPN Management Interface
// ═════════════════════════════════════════════════════════════════════════════

fn openvpn_management_query() -> Vec<VpnPeer> {
    let mut all_peers = Vec::new();

    for &port in OPENVPN_MGMT_PORTS {
        if let Some(peers) = try_openvpn_mgmt(port) {
            all_peers.extend(peers);
            break; // Found a working management port
        }
    }

    all_peers
}

fn try_openvpn_mgmt(port: u16) -> Option<Vec<VpnPeer>> {
    let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(2000))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    // Read the banner/greeting
    let mut banner = [0u8; 512];
    let _ = stream.read(&mut banner);

    // Send status command
    stream.write_all(b"status\r\n").ok()?;

    // Read response
    let mut response = String::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.push_str(&String::from_utf8_lossy(&buf[..n]));
                if response.contains("END") {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Send quit
    let _ = stream.write_all(b"quit\r\n");

    parse_openvpn_status(&response)
}

fn parse_openvpn_status(status: &str) -> Option<Vec<VpnPeer>> {
    let mut peers = Vec::new();
    let mut in_client_list = false;
    let mut in_routing_table = false;

    for line in status.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("HEADER,CLIENT_LIST") || trimmed == "OpenVPN CLIENT LIST" {
            in_client_list = true;
            in_routing_table = false;
            continue;
        }
        if trimmed.starts_with("HEADER,ROUTING_TABLE") || trimmed == "ROUTING TABLE" {
            in_client_list = false;
            in_routing_table = true;
            continue;
        }
        if trimmed == "END" || trimmed.starts_with("GLOBAL STATS") {
            in_client_list = false;
            in_routing_table = false;
            continue;
        }

        // CLIENT_LIST format (status v2):
        // CLIENT_LIST,CN,real_addr:port,virtual_addr,virtual_ipv6,bytes_recv,bytes_sent,connected_since,...
        // CLIENT_LIST format (status v1):
        // Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
        if in_client_list {
            let parts: Vec<&str> = trimmed.split(',').collect();
            if parts.len() >= 4 {
                let offset = if parts[0] == "CLIENT_LIST" { 1 } else { 0 };
                let cn = parts.get(offset).unwrap_or(&"").trim();
                // Try to extract virtual address
                let virtual_addr = if parts.len() > offset + 2 {
                    parts[offset + 2].trim()
                } else {
                    ""
                };

                if let Ok(ip) = virtual_addr.parse::<Ipv4Addr>() {
                    peers.push(VpnPeer {
                        ip,
                        hostname: if cn.is_empty() { None } else { Some(cn.to_string()) },
                        info: format!("OpenVPN CN={}", cn),
                        method: "OVPN-Mgmt",
                    });
                }
            }
        }

        // ROUTING_TABLE format (status v2):
        // ROUTING_TABLE,virtual_addr,CN,real_addr:port,last_ref
        if in_routing_table {
            let parts: Vec<&str> = trimmed.split(',').collect();
            if parts.len() >= 3 {
                let offset = if parts[0] == "ROUTING_TABLE" { 1 } else { 0 };
                let vaddr = parts.get(offset).unwrap_or(&"").trim();
                let cn = parts.get(offset + 1).unwrap_or(&"").trim();

                // Could be a subnet route like "10.8.1.0/24" or a single IP
                if let Ok(ip) = vaddr.parse::<Ipv4Addr>() {
                    // Check if already added from client list
                    if !peers.iter().any(|p| p.ip == ip) {
                        peers.push(VpnPeer {
                            ip,
                            hostname: if cn.is_empty() { None } else { Some(cn.to_string()) },
                            info: format!("OpenVPN route CN={}", cn),
                            method: "OVPN-Mgmt",
                        });
                    }
                }
            }
        }
    }

    if peers.is_empty() { None } else { Some(peers) }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 3: WireGuard CLI
// ═════════════════════════════════════════════════════════════════════════════

fn wireguard_show() -> (Vec<VpnPeer>, Vec<VpnSubnet>) {
    let mut peers = Vec::new();
    let mut subnets = Vec::new();

    let mut cmd = Command::new("wg");
    cmd.args(["show"]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = match cmd.output() {
        Ok(o) if o.status.success() => o,
        _ => return (peers, subnets),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_iface = String::new();
    let mut current_peer_key = String::new();
    let mut current_endpoint = String::new();
    let mut current_handshake = String::new();
    let mut current_allowed_ips: Vec<String> = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();

        // Interface line: "interface: wg0"
        if trimmed.starts_with("interface:") {
            // Flush previous peer if any
            flush_wg_peer(
                &current_peer_key,
                &current_endpoint,
                &current_handshake,
                &current_allowed_ips,
                &current_iface,
                &mut peers,
                &mut subnets,
            );
            current_peer_key.clear();
            current_endpoint.clear();
            current_handshake.clear();
            current_allowed_ips.clear();
            current_iface = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            continue;
        }

        // Peer line: "peer: <base64 public key>"
        if trimmed.starts_with("peer:") {
            // Flush previous peer
            flush_wg_peer(
                &current_peer_key,
                &current_endpoint,
                &current_handshake,
                &current_allowed_ips,
                &current_iface,
                &mut peers,
                &mut subnets,
            );
            current_peer_key = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            current_endpoint.clear();
            current_handshake.clear();
            current_allowed_ips.clear();
            continue;
        }

        if trimmed.starts_with("endpoint:") {
            current_endpoint = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("latest handshake:") {
            current_handshake = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
        } else if trimmed.starts_with("allowed ips:") {
            let ips_str = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            current_allowed_ips = ips_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }

    // Flush last peer
    flush_wg_peer(
        &current_peer_key,
        &current_endpoint,
        &current_handshake,
        &current_allowed_ips,
        &current_iface,
        &mut peers,
        &mut subnets,
    );

    (peers, subnets)
}

fn flush_wg_peer(
    peer_key: &str,
    _endpoint: &str,
    handshake: &str,
    allowed_ips: &[String],
    iface: &str,
    peers: &mut Vec<VpnPeer>,
    subnets: &mut Vec<VpnSubnet>,
) {
    if peer_key.is_empty() {
        return;
    }

    let short_key = if peer_key.len() > 8 {
        &peer_key[..8]
    } else {
        peer_key
    };

    for cidr in allowed_ips {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            continue;
        }
        let ip: Ipv4Addr = match parts[0].parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };
        let prefix: u32 = match parts[1].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        if prefix == 32 {
            // Single host — this is a peer
            let info = if handshake.is_empty() {
                format!("WireGuard peer:{}.. iface:{}", short_key, iface)
            } else {
                format!(
                    "WireGuard peer:{}.. iface:{} handshake:{}",
                    short_key, iface, handshake
                )
            };
            peers.push(VpnPeer {
                ip,
                hostname: None,
                info,
                method: "WireGuard",
            });
        } else if prefix >= 8 && prefix < 32 {
            // Subnet — add to scan targets
            let mask_u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
            let net_u32 = u32::from(ip) & mask_u32;
            subnets.push(VpnSubnet {
                network: Ipv4Addr::from(net_u32),
                prefix,
                mask: Ipv4Addr::from(mask_u32),
                interface_hint: iface.to_string(),
                source: format!("WireGuard allowed-ips (peer:{}..)", short_key),
            });
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 4: OpenVPN Log Parsing
// ═════════════════════════════════════════════════════════════════════════════

fn openvpn_log_parse() -> Vec<VpnPeer> {
    let mut all_peers = Vec::new();

    for path in openvpn_log_paths() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut found = parse_openvpn_log_content(&content);
            all_peers.append(&mut found);
        }
    }

    // Deduplicate by IP
    let mut seen = HashSet::new();
    all_peers.retain(|p| seen.insert(p.ip));

    all_peers
}

fn parse_openvpn_log_content(content: &str) -> Vec<VpnPeer> {
    let mut peers = Vec::new();
    let mut seen_ips = HashSet::new();

    for line in content.lines() {
        // Look for peer connection lines like:
        //   "10.8.0.6 peer info..."
        //   "MULTI: Learn: 10.8.0.6 -> user/1.2.3.4:port"
        //   "ifconfig_pool_set ... 10.8.0.6"
        //   "peer/1.2.3.4:port PUSH ..."
        //   "/sbin/ip addr add dev tun0 local 10.8.0.1 peer 10.8.0.2"
        //   "CONNECTED,SUCCESS,10.8.0.6,..."

        // Pattern: "MULTI: Learn: <vpn_ip>"
        if line.contains("MULTI: Learn:") || line.contains("MULTI_sva: Learn:") {
            if let Some(ip) = extract_first_private_ip(line) {
                if seen_ips.insert(ip) {
                    let cn = extract_cn_from_line(line);
                    peers.push(VpnPeer {
                        ip,
                        hostname: cn.clone(),
                        info: format!("OpenVPN log ({})", cn.unwrap_or_default()),
                        method: "OVPN-Log",
                    });
                }
            }
        }

        // Pattern: "ifconfig_pool_set"
        if line.contains("ifconfig_pool_set") {
            if let Some(ip) = extract_first_private_ip(line) {
                if seen_ips.insert(ip) {
                    peers.push(VpnPeer {
                        ip,
                        hostname: None,
                        info: "OpenVPN log (pool assignment)".to_string(),
                        method: "OVPN-Log",
                    });
                }
            }
        }

        // Pattern: "CONNECTED,SUCCESS,<ip>"
        if line.contains("CONNECTED,SUCCESS") {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                if let Ok(ip) = parts[2].trim().parse::<Ipv4Addr>() {
                    if is_private_ip(ip) && seen_ips.insert(ip) {
                        peers.push(VpnPeer {
                            ip,
                            hostname: None,
                            info: "OpenVPN log (connected)".to_string(),
                            method: "OVPN-Log",
                        });
                    }
                }
            }
        }
    }

    peers
}

fn extract_first_private_ip(line: &str) -> Option<Ipv4Addr> {
    for word in line.split_whitespace() {
        // Strip trailing punctuation
        let clean = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        if let Ok(ip) = clean.parse::<Ipv4Addr>() {
            if is_private_ip(ip) && !ip.is_loopback() {
                return Some(ip);
            }
        }
    }
    None
}

fn extract_cn_from_line(line: &str) -> Option<String> {
    // Try to find "CN=<name>" or "user/<name>"
    if let Some(pos) = line.find("CN=") {
        let rest = &line[pos + 3..];
        let end = rest.find(|c: char| c == ',' || c == '/' || c == ' ').unwrap_or(rest.len());
        let cn = rest[..end].trim();
        if !cn.is_empty() {
            return Some(cn.to_string());
        }
    }
    // Try "-> user/" pattern
    if let Some(pos) = line.find("-> ") {
        let rest = &line[pos + 3..];
        let end = rest.find('/').unwrap_or(rest.len());
        let name = rest[..end].trim();
        if !name.is_empty() && !name.contains(' ') {
            return Some(name.to_string());
        }
    }
    None
}

fn is_private_ip(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 5: Windows RAS/VPN Connections (rasdial)
// ═════════════════════════════════════════════════════════════════════════════

fn rasdial_enumerate() -> Option<Vec<String>> {
    let mut cmd = Command::new("rasdial");
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut connections = Vec::new();

    // rasdial output format:
    // "Connected to" or lists connection names
    // "No connections" means no active VPN
    if text.to_lowercase().contains("no connections") {
        return None;
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip header/footer lines
        if trimmed.contains("Command completed")
            || trimmed.starts_with("Connected")
            || trimmed.starts_with("The following")
        {
            continue;
        }
        connections.push(trimmed.to_string());
    }

    if connections.is_empty() {
        None
    } else {
        Some(connections)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 6: ICMP Ping Sweep (IcmpSendEcho Win32 API)
// ═════════════════════════════════════════════════════════════════════════════

fn icmp_sweep_vpn(targets: &[Ipv4Addr]) -> Vec<VpnPeer> {
    let hits: Mutex<Vec<VpnPeer>> = Mutex::new(Vec::new());

    // 64 parallel per batch
    for chunk in targets.chunks(64) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                s.spawn(move || {
                    if icmp_ping_one(target) {
                        h.lock().unwrap().push(VpnPeer {
                            ip: target,
                            hostname: None,
                            info: "ICMP echo reply".to_string(),
                            method: "ICMP",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

/// Shares the hand-rolled ICMP echo from `probes`, so both sweeps use the same
/// ping-socket-then-raw-socket fallback rather than two copies of it.
#[cfg(not(windows))]
fn icmp_ping_one(target: Ipv4Addr) -> bool {
    super::probes::icmp_ping_one(target)
}

#[cfg(windows)]
fn icmp_ping_one(target: Ipv4Addr) -> bool {
    unsafe {
        let handle = IcmpCreateFile();
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return false;
        }

        let data = b"vpn\0";
        let mut reply_buf = [0u8; 64];
        let dest = u32::from(target).to_be();

        let ret = IcmpSendEcho(
            handle,
            dest,
            data.as_ptr(),
            data.len() as u16,
            std::ptr::null(),
            reply_buf.as_mut_ptr(),
            reply_buf.len() as u32,
            300, // 300ms timeout
        );

        IcmpCloseHandle(handle);
        ret > 0
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 7: TCP Connect Probe
// ═════════════════════════════════════════════════════════════════════════════

fn tcp_probe_vpn(targets: &[Ipv4Addr]) -> Vec<VpnPeer> {
    let hits: Mutex<Vec<VpnPeer>> = Mutex::new(Vec::new());
    let found: Mutex<HashSet<Ipv4Addr>> = Mutex::new(HashSet::new());

    // 32 parallel per batch
    for chunk in targets.chunks(32) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                let f = &found;
                s.spawn(move || {
                    let mut open = Vec::new();
                    for &port in TCP_PROBE_PORTS {
                        let addr = SocketAddr::V4(SocketAddrV4::new(target, port));
                        if TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok() {
                            open.push(port);
                        }
                    }
                    if !open.is_empty() && f.lock().unwrap().insert(target) {
                        let port_str = open
                            .iter()
                            .map(|p| p.to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        h.lock().unwrap().push(VpnPeer {
                            ip: target,
                            hostname: None,
                            info: format!("TCP open ports: {}", port_str),
                            method: "TCP",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

// ═════════════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════════════

/// Generate host IPs for a VPN subnet. Caps at 254 hosts.
fn subnet_hosts(
    network: Ipv4Addr,
    mask: Ipv4Addr,
    exclude: Option<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let net_u32 = u32::from(network);
    let mask_u32 = u32::from(mask);
    let net_start = net_u32 & mask_u32;
    let broadcast = net_start | !mask_u32;
    let host_count = broadcast - net_start;

    // Cap at /24 for large subnets
    let (start, end) = if host_count > 254 {
        let base = net_u32 & 0xFFFFFF00;
        (base + 1, base + 255)
    } else {
        (net_start + 1, broadcast)
    };

    (start..end)
        .map(Ipv4Addr::from)
        .filter(|&a| {
            if let Some(exc) = exclude {
                a != exc
            } else {
                true
            }
        })
        .filter(|a| !a.is_loopback() && !a.is_broadcast())
        .collect()
}

/// Deduplicate subnets by network address, keeping the one with the most info.
fn dedup_subnets(subnets: &mut Vec<VpnSubnet>) {
    let mut seen: HashSet<(Ipv4Addr, u32)> = HashSet::new();
    subnets.retain(|s| seen.insert((s.network, s.prefix)));
}

/// Build RemoteNetwork results from discovered subnets and peers.
fn build_networks(
    subnets: Vec<VpnSubnet>,
    peers: Vec<VpnPeer>,
    ras_connections: Vec<String>,
    primary_ip: Option<Ipv4Addr>,
) -> Vec<RemoteNetwork> {
    let now = Local::now().time();
    let primary = primary_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);

    // Group peers by which subnet they belong to
    let mut subnet_peers: HashMap<usize, Vec<&VpnPeer>> = HashMap::new();
    let mut unmatched_peers: Vec<&VpnPeer> = Vec::new();

    for peer in &peers {
        // Skip our own IP
        if peer.ip == primary {
            continue;
        }

        let mut matched = false;
        for (i, subnet) in subnets.iter().enumerate() {
            let peer_u32 = u32::from(peer.ip);
            let net_u32 = u32::from(subnet.network);
            let mask_u32 = u32::from(subnet.mask);
            if (peer_u32 & mask_u32) == (net_u32 & mask_u32) {
                subnet_peers.entry(i).or_default().push(peer);
                matched = true;
                break;
            }
        }
        if !matched {
            unmatched_peers.push(peer);
        }
    }

    let mut networks = Vec::new();

    // Build a RemoteNetwork for each VPN subnet
    for (i, subnet) in subnets.iter().enumerate() {
        let mut devices = Vec::new();
        let mut device_ips: HashSet<Ipv4Addr> = HashSet::new();

        if let Some(peers_in_subnet) = subnet_peers.get(&i) {
            for peer in peers_in_subnet {
                if !device_ips.insert(peer.ip) {
                    // Already have this IP, merge discovery info
                    if let Some(dev) = devices.iter_mut().find(|d: &&mut LanDevice| {
                        d.ip == IpAddr::V4(peer.ip)
                    }) {
                        if !dev.discovery_info.contains(peer.method) {
                            dev.discovery_info
                                .push_str(&format!(" | {}:{}", peer.method, peer.info));
                        }
                    }
                    continue;
                }

                devices.push(LanDevice {
                    ip: IpAddr::V4(peer.ip),
                    mac: String::new(),
                    hostname: peer.hostname.clone(),
                    vendor: Some("VPN Peer".to_string()),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: None,
                    discovery_info: format!("{}:{}", peer.method, peer.info),
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

        // Determine a good name for the network
        let name = if subnet.source.contains("WireGuard") {
            format!("WireGuard: {}", subnet.interface_hint)
        } else if subnet.source.contains("OpenVPN") || subnet.source.contains("OVPN") {
            format!("OpenVPN: {}/{}", subnet.network, subnet.prefix)
        } else {
            // Check if a RAS connection name matches
            let ras_name = ras_connections.first().cloned();
            if let Some(rn) = ras_name {
                format!("VPN: {} ({}/{})", rn, subnet.network, subnet.prefix)
            } else {
                format!("VPN: {}/{}", subnet.network, subnet.prefix)
            }
        };

        let cidr_str = format!("{}/{}", subnet.network, subnet.prefix);

        // Determine local IP — use interface hint if it parses as an IP
        let local_ip = subnet
            .interface_hint
            .parse::<Ipv4Addr>()
            .unwrap_or(subnet.network);

        networks.push(RemoteNetwork {
            name,
            category: NetworkCategory::Vpn,
            adapter_name: subnet.interface_hint.clone(),
            local_ip,
            subnet_mask: subnet.mask,
            subnet_cidr: cidr_str,
            gateway: None,
            devices,
        });
    }

    // Handle unmatched peers — group them into a catch-all VPN network
    if !unmatched_peers.is_empty() {
        let mut devices = Vec::new();
        let mut device_ips: HashSet<Ipv4Addr> = HashSet::new();

        for peer in &unmatched_peers {
            if !device_ips.insert(peer.ip) {
                if let Some(dev) = devices.iter_mut().find(|d: &&mut LanDevice| {
                    d.ip == IpAddr::V4(peer.ip)
                }) {
                    if !dev.discovery_info.contains(peer.method) {
                        dev.discovery_info
                            .push_str(&format!(" | {}:{}", peer.method, peer.info));
                    }
                }
                continue;
            }

            devices.push(LanDevice {
                ip: IpAddr::V4(peer.ip),
                mac: String::new(),
                hostname: peer.hostname.clone(),
                vendor: Some("VPN Peer".to_string()),
                first_seen: now,
                last_seen: now,
                is_online: true,
                custom_name: None,
                discovery_info: format!("{}:{}", peer.method, peer.info),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        }

        if !devices.is_empty() {
            // Use the first peer's /24 as a rough subnet
            let first_ip = unmatched_peers[0].ip;
            let octets = first_ip.octets();
            let net = Ipv4Addr::new(octets[0], octets[1], octets[2], 0);

            let name = if let Some(rn) = ras_connections.first() {
                format!("VPN: {} (peers)", rn)
            } else {
                "VPN Peers (discovered)".to_string()
            };

            networks.push(RemoteNetwork {
                name,
                category: NetworkCategory::Vpn,
                adapter_name: String::new(),
                local_ip: net,
                subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
                subnet_cidr: format!("{}/24", net),
                gateway: None,
                devices,
            });
        }
    }

    networks
}
