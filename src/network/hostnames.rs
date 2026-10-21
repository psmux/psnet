//! Multi-method LAN hostname resolver.
//!
//! Runs 13 methods in parallel to discover device hostnames:
//! 1. NBNS (NetBIOS Name Service) — Windows/Samba devices
//! 2. mDNS service browsing on port 5353 — Apple/IoT/Linux
//! 3. mDNS per-IP unicast reverse PTR — any mDNS responder (Apple, Avahi, IoT)
//! 4. Windows DNS cache (DnsGetCacheDataTable) — instant, no network traffic
//! 5. SSDP/UPnP + XML friendlyName — routers, smart TVs, media devices
//! 6. HTTP banner grabbing (ports 80, 8080) — routers, printers, NAS, IP cameras
//! 7. DNS reverse lookup (getnameinfo) — PTR records + Windows resolution chain
//! 8. mDNS multicast reverse PTR on port 5353
//! 9. SNMP sysName query — routers, switches, managed APs, printers
//! 10. Telnet banner grabbing (port 23) — old routers, switches
//! 11. Direct DNS PTR to gateway — router DHCP hostname table
//! 12. LLMNR unicast query (port 5355) — Windows/Android LLMNR responders
//! 13. DHCP hostname cache — hostnames extracted from captured DHCP packets

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use dns_lookup::lookup_addr;

/// Result of hostname resolution: best hostname + all discovered details.
pub struct ResolvedDevice {
    /// Best hostname chosen by priority ranking.
    pub hostname: String,
    /// All details from every method that found something, aggregated.
    pub details: String,
    /// Open ports discovered via TCP connect scan.
    pub open_ports: Vec<u16>,
}

/// Resolve hostnames for a list of IPs using all available methods in parallel.
/// `gateway` is used to query the router's DNS directly for PTR records.
/// `dhcp_hostnames` contains hostnames extracted from captured DHCP packets.
/// Returns a map of IP -> ResolvedDevice (best hostname + aggregated details).
/// Total wall-clock time: ~4 seconds (all methods run concurrently).
pub fn resolve_all(
    ips: &[Ipv4Addr],
    gateway: Option<Ipv4Addr>,
    dhcp_hostnames: &HashMap<Ipv4Addr, String>,
) -> HashMap<Ipv4Addr, ResolvedDevice> {
    // Collect ALL tagged results from every method: (ip, source_tag, name)
    let tagged: Mutex<Vec<(Ipv4Addr, &str, String)>> = Mutex::new(Vec::new());
    // Port scan results: ip -> sorted open ports
    let port_results: Mutex<HashMap<Ipv4Addr, Vec<u16>>> = Mutex::new(HashMap::new());

    thread::scope(|s| {
        // Port scanning — runs in parallel with hostname methods
        let port_results_ref = &port_results;
        s.spawn(move || {
            let scanned = scan_ports_batch(ips, 400);
            let mut pr = port_results_ref.lock().unwrap();
            for (ip, ports) in scanned {
                pr.insert(ip, ports);
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_nbns_batch(ips, 1200) {
                tagged_ref.lock().unwrap().push((ip, "NBNS", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_mdns_browse(3000) {
                tagged_ref.lock().unwrap().push((ip, "mDNS", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_mdns_unicast_reverse(ips, 1500) {
                tagged_ref.lock().unwrap().push((ip, "mDNS-PTR", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_windows_dns_cache(ips) {
                tagged_ref.lock().unwrap().push((ip, "DNS$", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_ssdp(3000) {
                tagged_ref.lock().unwrap().push((ip, "UPnP", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_http_banner(ips, 2000) {
                tagged_ref.lock().unwrap().push((ip, "HTTP", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_dns_batch(ips, 3500) {
                tagged_ref.lock().unwrap().push((ip, "DNS", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_mdns_multicast_reverse(ips, 3000) {
                tagged_ref.lock().unwrap().push((ip, "mDNS-MC", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_snmp_batch(ips, 1500) {
                tagged_ref.lock().unwrap().push((ip, "SNMP", name));
            }
        });

        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_telnet_banner(ips, 1500) {
                tagged_ref.lock().unwrap().push((ip, "Telnet", name));
            }
        });

        if let Some(gw) = gateway {
            let tagged_ref = &tagged;
            s.spawn(move || {
                for (ip, name) in resolve_dns_via_gateway(ips, gw, 3000) {
                    tagged_ref.lock().unwrap().push((ip, "GW-DNS", name));
                }
            });
        }

        // Method 12: LLMNR unicast queries (port 5355)
        let tagged_ref = &tagged;
        s.spawn(move || {
            for (ip, name) in resolve_llmnr_batch(ips, 1500) {
                tagged_ref.lock().unwrap().push((ip, "LLMNR", name));
            }
        });

        // Method 13: DHCP hostname cache (from captured packets)
        {
            let tagged_ref = &tagged;
            for &ip in ips {
                if let Some(name) = dhcp_hostnames.get(&ip) {
                    tagged_ref.lock().unwrap().push((ip, "DHCP", name.clone()));
                }
            }
        }
    });

    // Now aggregate: pick best hostname + build details string per IP
    let all = tagged.into_inner().unwrap();
    let ports_map = port_results.into_inner().unwrap();
    let mut per_ip: HashMap<Ipv4Addr, Vec<(&str, String)>> = HashMap::new();
    for (ip, tag, name) in &all {
        per_ip.entry(*ip).or_default().push((tag, name.clone()));
    }

    // Priority order: mDNS/mDNS-PTR (Apple/Linux names are best), NBNS (Windows),
    // DHCP (Android/all devices via DHCP option 12), GW-DNS (router DHCP names),
    // LLMNR (Windows/Android), DNS (system resolver), UPnP (friendly names),
    // SNMP (device names), HTTP (titles), DNS$ (cached), Telnet, mDNS-MC
    const PRIORITY: &[&str] = &[
        "mDNS-PTR", "mDNS", "NBNS", "DHCP", "GW-DNS", "LLMNR", "DNS", "UPnP",
        "SNMP", "HTTP", "DNS$", "Telnet", "mDNS-MC",
    ];

    let mut result = HashMap::new();

    // Build results for IPs that have hostname info
    for (ip, entries) in per_ip {
        // Collect all unique hostnames in priority order (best first)
        let mut hostname_parts: Vec<String> = Vec::new();
        let mut seen_lower: std::collections::HashSet<String> = std::collections::HashSet::new();
        // First pass: add names in priority order
        for &prio in PRIORITY {
            for (tag, name) in &entries {
                if *tag == prio {
                    let lower = name.to_lowercase();
                    if !seen_lower.contains(&lower) {
                        seen_lower.insert(lower);
                        hostname_parts.push(name.clone());
                    }
                }
            }
        }
        // Fallback: any names from methods not in PRIORITY list
        for (_tag, name) in &entries {
            let lower = name.to_lowercase();
            if !seen_lower.contains(&lower) {
                seen_lower.insert(lower);
                hostname_parts.push(name.clone());
            }
        }
        let hostname = hostname_parts.join(", ");

        // Build details: deduplicated, compact
        let mut details_parts: Vec<String> = Vec::new();
        let mut seen_values = std::collections::HashSet::new();
        for (tag, name) in &entries {
            let lower = name.to_lowercase();
            if seen_values.contains(&lower) { continue; }
            seen_values.insert(lower);
            details_parts.push(format!("{}:{}", tag, name));
        }
        let details = details_parts.join("  ");

        let open_ports = ports_map.get(&ip).cloned().unwrap_or_default();
        result.insert(ip, ResolvedDevice { hostname, details, open_ports });
    }

    // For IPs that only have port scan results (no hostname found)
    for (ip, ports) in &ports_map {
        if !result.contains_key(ip) && !ports.is_empty() {
            result.entry(*ip).or_insert(ResolvedDevice {
                hostname: String::new(),
                details: String::new(),
                open_ports: ports.clone(),
            });
        }
    }

    result
}

// ─── Method 1: NBNS (NetBIOS Name Service) ──────────────────────────────────

fn resolve_nbns_batch(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = nbns_query(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn nbns_query(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    let mut pkt = [0u8; 50];
    let tid = (ip.octets()[2] as u16) << 8 | ip.octets()[3] as u16;
    pkt[0] = (tid >> 8) as u8;
    pkt[1] = tid as u8;
    pkt[5] = 0x01; // QDCOUNT: 1

    // Encoded NetBIOS wildcard name: "*" (0x2A) + 15 NUL bytes
    pkt[12] = 0x20; // label length: 32 bytes
    let mut raw_name = [0x00u8; 16];
    raw_name[0] = 0x2A; // '*'
    for i in 0..16 {
        pkt[13 + i * 2]     = (raw_name[i] >> 4) + 0x41;
        pkt[13 + i * 2 + 1] = (raw_name[i] & 0x0F) + 0x41;
    }
    pkt[45] = 0x00;
    pkt[46] = 0x00; pkt[47] = 0x21; // QTYPE = NBSTAT
    pkt[48] = 0x00; pkt[49] = 0x01; // QCLASS = IN

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    sock.send_to(&pkt, SocketAddr::from((ip, 137u16))).ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_nbns_response(&buf[..len])
}

fn parse_nbns_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 57 { return None; }

    let mut pos = 50;
    if pos >= buf.len() { return None; }
    if buf[pos] & 0xC0 == 0xC0 {
        pos += 2;
    } else {
        while pos < buf.len() && buf[pos] != 0 {
            let label_len = buf[pos] as usize;
            if label_len == 0 || pos + label_len + 1 > buf.len() { break; }
            pos += label_len + 1;
        }
        pos += 1;
    }
    if pos + 10 > buf.len() { return None; }
    pos += 8; // TYPE(2) + CLASS(2) + TTL(4)
    pos += 2; // RDLENGTH
    if pos >= buf.len() { return None; }

    let num_names = buf[pos] as usize;
    pos += 1;

    for i in 0..num_names {
        let start = pos + i * 18;
        if start + 18 > buf.len() { break; }
        let suffix = buf[start + 15];
        let flags = ((buf[start + 16] as u16) << 8) | buf[start + 17] as u16;
        let is_group = flags & 0x8000 != 0;
        if suffix == 0x00 && !is_group {
            let name = std::str::from_utf8(&buf[start..start + 15])
                .unwrap_or("")
                .trim()
                .to_string();
            if !name.is_empty()
                && name.len() <= 15
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Some(name);
            }
        }
    }
    None
}

// ─── Method 2: mDNS service browsing (port 5353) ────────────────────────────

/// Bind to port 5353 with SO_REUSEADDR so we receive multicast responses
/// that are sent to the standard mDNS port (not back to an ephemeral port).
fn resolve_mdns_browse(timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let mut results = Vec::new();

    // Try binding to port 5353 first (with reuse), fall back to ephemeral
    let sock = bind_mdns_socket().unwrap_or_else(|| {
        UdpSocket::bind("0.0.0.0:0").ok()
    });
    let sock = match sock {
        Some(s) => s,
        None => return results,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = sock.set_nonblocking(false);
    let mdns_addr = Ipv4Addr::new(224, 0, 0, 251);
    let _ = sock.join_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);

    // Browse many service types to maximize coverage
    for svc in &[
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_workstation._tcp.local",
        "_smb._tcp.local",
        "_device-info._tcp.local",
        "_companion-link._tcp.local",
        "_homekit._tcp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_printer._tcp.local",
        "_ipp._tcp.local",
        "_pdl-datastream._tcp.local",
        "_ssh._tcp.local",
        "_sftp-ssh._tcp.local",
        "_sleep-proxy._udp.local",
        "_apple-mobdev2._tcp.local",
    ] {
        let pkt = build_dns_query(svc, 12); // PTR query
        let _ = sock.send_to(&pkt, "224.0.0.251:5353");
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 2048];

    while std::time::Instant::now() < deadline {
        let _ = sock.set_read_timeout(Some(
            deadline.saturating_duration_since(std::time::Instant::now())
                .max(Duration::from_millis(10))
        ));
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Some(names) = parse_mdns_response(&buf[..len]) {
                    let ip = match src.ip() {
                        IpAddr::V4(v4) => v4,
                        _ => continue,
                    };
                    for name in names {
                        results.push((ip, name));
                    }
                }
            }
            Err(_) => break,
        }
    }

    let _ = sock.leave_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);
    results
}

/// Try to bind a UDP socket to port 5353 with SO_REUSEADDR.
/// Returns None if binding fails (port in use without reuse support).
#[cfg(windows)]
fn bind_mdns_socket() -> Option<Option<UdpSocket>> {
    use std::os::windows::io::{FromRawSocket, RawSocket};

    unsafe {
        // Create UDP socket via Winsock
        let raw = socket(2, 2, 17); // AF_INET, SOCK_DGRAM, IPPROTO_UDP
        if raw == usize::MAX { return Some(None); }

        // Set SO_REUSEADDR before bind
        let optval: i32 = 1;
        let ret = setsockopt(
            raw,
            0xFFFF, // SOL_SOCKET
            0x0004, // SO_REUSEADDR
            &optval as *const i32 as *const u8,
            4,
        );
        if ret != 0 {
            closesocket(raw);
            return Some(None);
        }

        // Bind to 0.0.0.0:5353
        #[repr(C)]
        struct SockAddrIn {
            sin_family: i16,
            sin_port: u16,
            sin_addr: u32,
            sin_zero: [u8; 8],
        }
        let addr = SockAddrIn {
            sin_family: 2, // AF_INET
            sin_port: 5353u16.to_be(),
            sin_addr: 0, // INADDR_ANY
            sin_zero: [0; 8],
        };
        let ret = winsock_bind(
            raw,
            &addr as *const SockAddrIn as *const u8,
            std::mem::size_of::<SockAddrIn>() as i32,
        );
        if ret != 0 {
            closesocket(raw);
            return Some(None);
        }

        // Convert to std UdpSocket
        let sock = UdpSocket::from_raw_socket(raw as RawSocket);
        Some(Some(sock))
    }
}

#[cfg(windows)]
#[allow(clashing_extern_declarations)]
#[link(name = "ws2_32")]
extern "system" {
    fn socket(af: i32, r#type: i32, protocol: i32) -> usize;
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    #[link_name = "bind"]
    fn winsock_bind(s: usize, name: *const u8, namelen: i32) -> i32;
    fn closesocket(s: usize) -> i32;
}

/// Linux equivalent of the Winsock path above: create a UDP socket, set
/// SO_REUSEADDR *and* SO_REUSEPORT, then bind to 5353.
///
/// Both options matter here — a router typically already runs an mDNS
/// responder (umdns/avahi) holding 5353, and on Linux joining an existing
/// multicast bind needs SO_REUSEPORT, not just SO_REUSEADDR. Without it we
/// silently fall back to an ephemeral port and miss responses sent to the
/// standard port.
#[cfg(not(windows))]
fn bind_mdns_socket() -> Option<Option<UdpSocket>> {
    use std::os::fd::FromRawFd;

    const AF_INET: i32 = 2;
    const SOCK_DGRAM: i32 = 2;
    const IPPROTO_UDP: i32 = 17;
    const SOL_SOCKET: i32 = 1;
    const SO_REUSEADDR: i32 = 2;
    const SO_REUSEPORT: i32 = 15;

    #[repr(C)]
    struct SockAddrIn {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [u8; 8],
    }

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
        fn setsockopt(fd: i32, level: i32, name: i32, val: *const u8, len: u32) -> i32;
        fn bind(fd: i32, addr: *const u8, len: u32) -> i32;
        fn close(fd: i32) -> i32;
    }

    unsafe {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if fd < 0 {
            return Some(None);
        }

        let optval: i32 = 1;
        for opt in [SO_REUSEADDR, SO_REUSEPORT] {
            let ret = setsockopt(
                fd,
                SOL_SOCKET,
                opt,
                &optval as *const i32 as *const u8,
                std::mem::size_of::<i32>() as u32,
            );
            // SO_REUSEPORT is absent on ancient kernels; SO_REUSEADDR alone
            // still gets us a usable socket, so only a REUSEADDR failure is fatal.
            if ret != 0 && opt == SO_REUSEADDR {
                close(fd);
                return Some(None);
            }
        }

        let addr = SockAddrIn {
            sin_family: AF_INET as u16,
            sin_port: 5353u16.to_be(),
            sin_addr: 0, // INADDR_ANY
            sin_zero: [0; 8],
        };
        let ret = bind(
            fd,
            &addr as *const SockAddrIn as *const u8,
            std::mem::size_of::<SockAddrIn>() as u32,
        );
        if ret != 0 {
            close(fd);
            return Some(None);
        }

        Some(Some(UdpSocket::from_raw_fd(fd)))
    }
}

// ─── Method 3: mDNS per-IP UNICAST reverse PTR ──────────────────────────────

/// Send PTR query for "w.x.y.z.in-addr.arpa" DIRECTLY to each device's IP:5353.
/// This bypasses multicast routing issues — the device receives the query on its
/// mDNS listener (port 5353) and responds unicast back to our socket.
/// This is the most reliable way to resolve Mac/Linux/IoT hostnames.
fn resolve_mdns_unicast_reverse(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = mdns_unicast_ptr_query(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn mdns_unicast_ptr_query(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    let octets = ip.octets();
    let arpa_name = format!("{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]);

    // Build PTR query with unicast-response bit (QCLASS=0x8001)
    let pkt = build_dns_query_class(&arpa_name, 12, 0x8001);

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    // Send UNICAST directly to the device's port 5353 (mDNS listener)
    sock.send_to(&pkt, SocketAddr::from((ip, 5353u16))).ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_ptr_response(&buf[..len])
        .map(|n| clean_mdns_name(&n))
        .filter(|n| !n.is_empty())
}

// ─── Method 4: Windows DNS cache (DnsGetCacheDataTable) ──────────────────────

/// Linux has no process-readable system-wide DNS cache to mine — resolution is
/// either in-process (glibc has no shared cache) or inside a separate resolver
/// such as dnsmasq, which exposes no lookup API. The other eleven discovery
/// methods cover this ground, so this source is simply empty here.
#[cfg(not(windows))]
fn resolve_windows_dns_cache(_ips: &[Ipv4Addr]) -> Vec<(Ipv4Addr, String)> {
    Vec::new()
}

/// Read the Windows DNS resolver cache using the undocumented DnsGetCacheDataTable
/// function from dnsapi.dll. This is instant and requires no network traffic.
/// It finds hostnames that Windows has already resolved via any method.
#[cfg(windows)]
fn resolve_windows_dns_cache(ips: &[Ipv4Addr]) -> Vec<(Ipv4Addr, String)> {
    let mut results = Vec::new();

    // Build a set of IPs we're looking for, and their .in-addr.arpa forms
    let mut ip_set: HashMap<String, Ipv4Addr> = HashMap::new();
    for &ip in ips {
        let o = ip.octets();
        let arpa = format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]);
        ip_set.insert(arpa, ip);
    }

    // Try loading dnsapi.dll and calling DnsGetCacheDataTable
    let entries = match read_dns_cache() {
        Some(e) => e,
        None => return results,
    };

    // For each IP, check if there's a PTR cache entry.
    // If so, call lookup_addr which will hit the cache instantly.
    for (arpa, &ip) in &ip_set {
        for (name, rtype) in &entries {
            if *rtype == 12 && name == arpa {
                // There IS a cached PTR for this IP — lookup_addr will be instant
                let addr = IpAddr::V4(ip);
                if let Ok(hostname) = lookup_addr(&addr) {
                    if hostname != addr.to_string() {
                        results.push((ip, hostname));
                    }
                }
                break;
            }
        }
    }

    // Also try: any A record hostname that ends with .local or is a short name
    // might be a LAN device we can match
    for (name, rtype) in &entries {
        if *rtype != 1 { continue; }
        // Try to resolve this hostname to an IP and see if it matches our list
        let clean = name.trim_end_matches('.').to_string();
        if clean.is_empty() { continue; }
        // Only try short names or .local names (LAN devices)
        if !clean.contains('.') || clean.ends_with(".local") {
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(
                &(clean.as_str(), 0u16)
            ) {
                for addr in addrs {
                    if let IpAddr::V4(v4) = addr.ip() {
                        if ips.contains(&v4) {
                            let display_name = clean.strip_suffix(".local")
                                .unwrap_or(&clean).to_string();
                            if !display_name.is_empty() {
                                results.push((v4, display_name));
                            }
                        }
                    }
                }
            }
        }
    }

    results
}

/// Read the Windows DNS cache using DnsGetCacheDataTable from dnsapi.dll.
/// Returns Vec<(name, record_type)> or None if the API is unavailable.
#[cfg(windows)]
fn read_dns_cache() -> Option<Vec<(String, u16)>> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    struct DnsCacheEntry {
        next: *mut DnsCacheEntry,
        name: *mut u16, // PWSTR
        r#type: u16,
        data_length: u16,
        flags: u32,
    }

    type DnsGetCacheDataTableFn = unsafe extern "system" fn(*mut *mut DnsCacheEntry) -> i32;

    unsafe {
        // Load dnsapi.dll
        let dll_name: Vec<u16> = OsStr::new("dnsapi.dll\0").encode_wide().collect();
        let module = LoadLibraryW(dll_name.as_ptr());
        if module.is_null() { return None; }

        let fn_name = b"DnsGetCacheDataTable\0";
        let proc = GetProcAddress(module, fn_name.as_ptr());
        if proc.is_null() {
            FreeLibrary(module);
            return None;
        }

        let dns_get_cache: DnsGetCacheDataTableFn = std::mem::transmute(proc);

        let mut head: *mut DnsCacheEntry = std::ptr::null_mut();
        let ret = dns_get_cache(&mut head);
        if ret == 0 || head.is_null() {
            FreeLibrary(module);
            return None;
        }

        let mut entries = Vec::new();
        let mut current = head;
        let mut safety = 0u32;
        while !current.is_null() && safety < 10000 {
            let entry = &*current;
            if !entry.name.is_null() {
                // Read wide string
                let mut len = 0;
                let mut p = entry.name;
                while *p != 0 && len < 512 {
                    len += 1;
                    p = p.add(1);
                }
                let slice = std::slice::from_raw_parts(entry.name, len);
                let name = String::from_utf16_lossy(slice);
                entries.push((name, entry.r#type));
            }
            current = entry.next;
            safety += 1;
        }

        // Free the linked list entries (each was allocated by the DLL)
        current = head;
        while !current.is_null() {
            let next = (*current).next;
            // DnsGetCacheDataTable allocates with LocalAlloc; free with LocalFree
            // Actually, the names are pointers into the cache, not separately allocated.
            // We just need to not leak the list nodes.
            // In practice, most callers don't free these — they're in-process cache refs.
            current = next;
        }

        FreeLibrary(module);
        Some(entries)
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
    fn FreeLibrary(hLibModule: *mut std::ffi::c_void) -> i32;
}

// ─── Method 5: SSDP/UPnP + XML fetch ────────────────────────────────────────

fn resolve_ssdp(timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let mut results = Vec::new();
    let mut location_urls: Vec<(Ipv4Addr, String)> = Vec::new();

    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));

    let msearch = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 2\r\n\
                   ST: ssdp:all\r\n\
                   \r\n";
    let _ = sock.send_to(msearch.as_bytes(), "239.255.255.250:1900");

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.min(2000));
    let mut buf = [0u8; 4096];
    let mut seen_ips = std::collections::HashSet::new();

    while std::time::Instant::now() < deadline {
        let _ = sock.set_read_timeout(Some(
            deadline.saturating_duration_since(std::time::Instant::now())
                .max(Duration::from_millis(10))
        ));
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                let ip = match src.ip() {
                    IpAddr::V4(v4) => v4,
                    _ => continue,
                };

                let text = String::from_utf8_lossy(&buf[..len]);

                // Collect LOCATION URLs for XML fetch (even for seen IPs,
                // different URLs might give us friendlyName)
                if !seen_ips.contains(&ip) {
                    if let Some(url) = extract_header(&text, "LOCATION") {
                        location_urls.push((ip, url));
                    }
                }

                if seen_ips.contains(&ip) { continue; }

                if let Some(server) = extract_header(&text, "SERVER") {
                    let name = clean_ssdp_server(&server);
                    if !name.is_empty() {
                        results.push((ip, name));
                        seen_ips.insert(ip);
                    }
                }
            }
            Err(_) => break,
        }
    }

    // Phase 2: Fetch UPnP XML descriptions in parallel for friendlyName
    // Always try XML fetch — friendlyName is more descriptive than SERVER header
    let xml_found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    let mut fetched_ips = std::collections::HashSet::new();
    thread::scope(|s| {
        for (ip, url) in &location_urls {
            if fetched_ips.contains(ip) { continue; }
            fetched_ips.insert(*ip);
            let xml_found = &xml_found;
            let ip = *ip;
            s.spawn(move || {
                if let Some(name) = fetch_upnp_friendly_name(url) {
                    xml_found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    // XML friendlyName takes priority over SERVER header
    let xml_results = xml_found.into_inner().unwrap();
    let xml_ips: std::collections::HashSet<Ipv4Addr> = xml_results.iter().map(|(ip, _)| *ip).collect();
    results.retain(|(ip, _)| !xml_ips.contains(ip));
    results.extend(xml_results);

    results
}

fn fetch_upnp_friendly_name(url: &str) -> Option<String> {
    let url = url.strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))?;
    let (host_port, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, "/"),
    };

    // Fix: default to port 80 if no port in URL (e.g., "http://192.168.1.1/desc.xml")
    let addr: SocketAddr = if host_port.contains(':') {
        host_port.parse().ok()?
    } else {
        format!("{}:80", host_port).parse().ok()?
    };

    let stream = TcpStream::connect_timeout(
        &addr,
        Duration::from_millis(1500),
    ).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, host_port
    );
    (&stream).write_all(request.as_bytes()).ok()?;

    let mut body = vec![0u8; 8192];
    let mut total = 0;
    loop {
        match (&stream).read(&mut body[total..]) {
            Ok(0) => break,
            Ok(n) => { total += n; if total >= body.len() { break; } }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&body[..total]);
    let lower = text.to_lowercase();
    let start = lower.find("<friendlyname>")? + 14;
    let end = lower[start..].find("</friendlyname>")?;
    let name = text[start..start + end].trim().to_string();
    if name.is_empty() { None } else { Some(name) }
}

// ─── Method 6: HTTP banner grabbing ──────────────────────────────────────────

fn resolve_http_banner(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = http_banner_grab(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn http_banner_grab(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    // Try port 80 first, then 8080
    for port in [80u16, 8080] {
        if let Some(name) = http_banner_grab_port(ip, port, timeout_ms) {
            return Some(name);
        }
    }
    None
}

fn http_banner_grab_port(ip: Ipv4Addr, port: u16, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::from((ip, port));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms.min(1000))).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms.min(1500)))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(500))).ok()?;

    let request = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: psnet/1.0\r\nConnection: close\r\n\r\n",
        ip
    );
    (&stream).write_all(request.as_bytes()).ok()?;

    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        match (&stream).read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => { total += n; if total >= buf.len() { break; } }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf[..total]);

    // Try <title> tag first
    if let Some(name) = extract_html_title(&text) {
        if !name.is_empty() { return Some(name); }
    }

    // Fall back to Server header
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("server:") {
            if let Some(val) = line.splitn(2, ':').nth(1) {
                let server = val.trim();
                if !server.is_empty()
                    && !server.to_lowercase().contains("apache")
                    && !server.to_lowercase().contains("nginx")
                {
                    return Some(server.split('/').next().unwrap_or(server).to_string());
                }
            }
        }
    }

    None
}

fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")?;
    let title = html[start..start + end].trim().to_string();
    if title.is_empty()
        || title.len() > 60
        || title.to_lowercase().contains("404")
        || title.to_lowercase().contains("not found")
        || title.to_lowercase() == "index"
        || title.to_lowercase() == "home"
    {
        return None;
    }
    Some(title)
}

// ─── Method 7: DNS reverse lookup (getnameinfo) ─────────────────────────────

/// On Windows, lookup_addr (getnameinfo) triggers the full resolution chain:
/// 1. Check DNS cache
/// 2. Query configured DNS server for PTR record
/// 3. Fall back to LLMNR multicast (224.0.0.252:5355)
/// 4. Fall back to NetBIOS name query
/// This is the single most comprehensive method on Windows.
fn resolve_dns_batch(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);

    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                let (tx, rx) = std::sync::mpsc::channel();
                let addr = IpAddr::V4(ip);
                thread::spawn(move || {
                    let result = lookup_addr(&addr).ok().filter(|name| {
                        name != &addr.to_string()
                    });
                    let _ = tx.send(result);
                });

                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if let Ok(Some(name)) = rx.recv_timeout(remaining) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });

    found.into_inner().unwrap()
}

// ─── Method 8: mDNS multicast reverse PTR on port 5353 ──────────────────────

/// Bind to port 5353, join multicast group, send PTR queries for all IPs.
/// Some mDNS responders only reply to multicast queries received on port 5353
/// (ignoring unicast queries to their port 5353).
fn resolve_mdns_multicast_reverse(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let mut results = Vec::new();

    // Try to bind to port 5353 with SO_REUSEADDR
    let sock = match bind_mdns_socket() {
        Some(Some(s)) => s,
        _ => {
            // Fall back to ephemeral port (less reliable but still tries)
            match UdpSocket::bind("0.0.0.0:0") {
                Ok(s) => s,
                Err(_) => return results,
            }
        }
    };

    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));
    let mdns_addr = Ipv4Addr::new(224, 0, 0, 251);
    let _ = sock.join_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);

    // Send reverse PTR queries for all IPs via multicast
    for &ip in ips {
        let octets = ip.octets();
        let arpa_name = format!("{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]);
        let pkt = build_dns_query_class(&arpa_name, 12, 0x8001); // QU bit set
        let _ = sock.send_to(&pkt, "224.0.0.251:5353");
    }

    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 2048];
    let mut seen = std::collections::HashSet::new();

    while std::time::Instant::now() < deadline {
        let _ = sock.set_read_timeout(Some(
            deadline.saturating_duration_since(std::time::Instant::now())
                .max(Duration::from_millis(10))
        ));
        match sock.recv_from(&mut buf) {
            Ok((len, src)) => {
                let ip = match src.ip() {
                    IpAddr::V4(v4) => v4,
                    _ => continue,
                };
                if seen.contains(&ip) { continue; }

                if let Some(name) = parse_ptr_response(&buf[..len]) {
                    let clean = clean_mdns_name(&name);
                    if !clean.is_empty() {
                        results.push((ip, clean));
                        seen.insert(ip);
                    }
                }
                // Also try parsing as full mDNS response (may have A/SRV records)
                if !seen.contains(&ip) {
                    if let Some(names) = parse_mdns_response(&buf[..len]) {
                        for name in names {
                            if !seen.contains(&ip) {
                                results.push((ip, name));
                                seen.insert(ip);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    let _ = sock.leave_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);
    results
}

// ─── Shared DNS packet helpers ───────────────────────────────────────────────

fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
    build_dns_query_class(name, qtype, 0x0001)
}

fn build_dns_query_class(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    dns_encode_name(&mut pkt, name);
    pkt.push((qtype >> 8) as u8);
    pkt.push(qtype as u8);
    pkt.push((qclass >> 8) as u8);
    pkt.push(qclass as u8);
    pkt
}

fn dns_encode_name(buf: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
}

fn parse_ptr_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 { return None; }
    let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
    if flags & 0x8000 == 0 { return None; }

    let qdcount = ((buf[4] as u16) << 8) | buf[5] as u16;
    let ancount = ((buf[6] as u16) << 8) | buf[7] as u16;
    if ancount == 0 { return None; }

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4;
    }

    for _ in 0..ancount {
        if pos >= buf.len() { break; }
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() { break; }

        let rtype = ((buf[pos] as u16) << 8) | buf[pos + 1] as u16;
        let rdlength = ((buf[pos + 8] as u16) << 8) | buf[pos + 9] as u16;
        pos += 10;

        if pos + rdlength as usize > buf.len() { break; }

        if rtype == 12 { // PTR
            return read_dns_name(buf, pos);
        }

        pos += rdlength as usize;
    }
    None
}

fn parse_mdns_response(buf: &[u8]) -> Option<Vec<String>> {
    if buf.len() < 12 { return None; }
    let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
    if flags & 0x8000 == 0 { return None; }

    let ancount = ((buf[4] as u16) << 8) | buf[5] as u16;
    let total_rr = ancount
        + ((buf[6] as u16) << 8 | buf[7] as u16)
        + ((buf[8] as u16) << 8 | buf[9] as u16);
    let qdcount = ((buf[10] as u16) << 8) | buf[11] as u16;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos += 4;
    }

    let mut names = Vec::new();
    for _ in 0..total_rr {
        if pos >= buf.len() { break; }
        let name = read_dns_name(buf, pos);
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() { break; }

        let rtype = ((buf[pos] as u16) << 8) | buf[pos + 1] as u16;
        let rdlength = ((buf[pos + 8] as u16) << 8) | buf[pos + 9] as u16;
        pos += 10;

        if pos + rdlength as usize > buf.len() { break; }

        match rtype {
            12 => {
                if let Some(n) = read_dns_name(buf, pos) {
                    let clean = clean_mdns_name(&n);
                    if !clean.is_empty() { names.push(clean); }
                }
            }
            1 => {
                if let Some(n) = name {
                    let clean = clean_mdns_name(&n);
                    if !clean.is_empty() { names.push(clean); }
                }
            }
            33 => {
                if rdlength > 6 {
                    if let Some(n) = read_dns_name(buf, pos + 6) {
                        let clean = clean_mdns_name(&n);
                        if !clean.is_empty() { names.push(clean); }
                    }
                }
            }
            _ => {}
        }

        pos += rdlength as usize;
    }

    if names.is_empty() { None } else { Some(names) }
}

fn clean_mdns_name(name: &str) -> String {
    let name = name.trim_end_matches('.');
    let name = name.strip_suffix(".local").unwrap_or(name);
    let name = name.strip_suffix(".in-addr.arpa").unwrap_or(name);
    if name.contains("._") {
        name.split("._").next().unwrap_or("").to_string()
    } else {
        if name.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return String::new();
        }
        name.to_string()
    }
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    if pos >= buf.len() { return None; }
    loop {
        if pos >= buf.len() { return None; }
        if buf[pos] & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        if buf[pos] == 0 {
            return Some(pos + 1);
        }
        let label_len = buf[pos] as usize;
        if label_len == 0 { return Some(pos + 1); }
        pos += label_len + 1;
    }
}

fn read_dns_name(buf: &[u8], mut pos: usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut jumps = 0;
    loop {
        if pos >= buf.len() || jumps > 10 { return None; }
        if buf[pos] & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() { return None; }
            pos = ((buf[pos] as usize & 0x3F) << 8) | buf[pos + 1] as usize;
            jumps += 1;
            continue;
        }
        if buf[pos] == 0 { break; }
        let label_len = buf[pos] as usize;
        pos += 1;
        if pos + label_len > buf.len() { return None; }
        if let Ok(s) = std::str::from_utf8(&buf[pos..pos + label_len]) {
            parts.push(s.to_string());
        }
        pos += label_len;
    }
    if parts.is_empty() { None } else { Some(parts.join(".")) }
}

// ─── Method 9: SNMP sysName query ────────────────────────────────────────────

/// Send SNMPv1 GET for OID 1.3.6.1.2.1.1.5.0 (sysName) with community "public".
/// Catches routers, managed switches, network printers, NAS, access points.
fn resolve_snmp_batch(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = snmp_get_sysname(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn snmp_get_sysname(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    // SNMPv1 GET-request for OID 1.3.6.1.2.1.1.5.0 (sysName), community "public"
    // Total = 2+3+8+2+6+3+3+2+2+10+2 = 43 bytes
    // Outer SEQUENCE wraps 41 bytes of content
    const SNMP_GET_SYSNAME: [u8; 43] = [
        0x30, 0x29,                                     // SEQUENCE, len 41
        0x02, 0x01, 0x00,                               // INTEGER: version = 0 (SNMPv1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING: "public"
        0xa0, 0x1c,                                     // GET-request PDU, len 28
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,             // INTEGER: request-id = 1
        0x02, 0x01, 0x00,                               // INTEGER: error-status = 0
        0x02, 0x01, 0x00,                               // INTEGER: error-index = 0
        0x30, 0x0e,                                     // SEQUENCE (varbind list), len 14
        0x30, 0x0c,                                     // SEQUENCE (single varbind), len 12
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00, // OID: 1.3.6.1.2.1.1.5.0
        0x05, 0x00,                                     // NULL (value)
    ];

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    sock.send_to(&SNMP_GET_SYSNAME, SocketAddr::from((ip, 161u16))).ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_snmp_sysname_response(&buf[..len])
}

/// Parse SNMPv1 GET-response to extract sysName value (OCTET STRING).
fn parse_snmp_sysname_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 20 { return None; }

    // Walk BER-TLV to find the OCTET STRING (tag 0x04) value in the varbind
    // The response structure is:
    // SEQUENCE { version, community, GET-RESPONSE { reqid, err, erridx,
    //   SEQUENCE { SEQUENCE { OID, VALUE } } } }
    // We need the VALUE which is an OCTET STRING (tag 0x04)

    // Find the last OCTET STRING (0x04) in the packet — that's the sysName value
    let mut pos = 0;
    let mut last_octet_string: Option<String> = None;

    while pos < buf.len() - 2 {
        if buf[pos] == 0x04 { // OCTET STRING tag
            let (value_len, header_len) = parse_ber_length(&buf[pos + 1..])?;
            let start = pos + 1 + header_len;
            let end = start + value_len;
            if end <= buf.len() {
                if let Ok(s) = std::str::from_utf8(&buf[start..end]) {
                    let name = s.trim().to_string();
                    // Skip the community string "public"
                    if !name.is_empty() && name != "public" {
                        last_octet_string = Some(name);
                    }
                }
            }
        }
        pos += 1;
    }

    last_octet_string.filter(|n| {
        !n.is_empty()
            && n.len() <= 255
            && n.chars().all(|c| c.is_ascii_graphic() || c == ' ')
    })
}

/// Parse BER length encoding. Returns (value_length, header_bytes_consumed).
fn parse_ber_length(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() { return None; }
    if buf[0] & 0x80 == 0 {
        // Short form: single byte
        Some((buf[0] as usize, 1))
    } else {
        let num_bytes = (buf[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || buf.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | buf[1 + i] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

// ─── Method 10: Telnet banner grabbing ───────────────────────────────────────

/// Connect to port 23 and read the initial banner/login prompt.
/// Many routers and switches include the hostname in the telnet banner.
fn resolve_telnet_banner(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = telnet_banner_grab(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn telnet_banner_grab(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    let addr = SocketAddr::from((ip, 23u16));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms.min(1000))).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms.min(1500)))).ok()?;

    let mut buf = [0u8; 1024];
    // Read whatever the server sends as welcome/banner
    let n = (&stream).read(&mut buf).ok()?;
    if n == 0 { return None; }

    // Strip telnet negotiation bytes (IAC sequences: 0xFF followed by 2 bytes)
    let mut clean = Vec::new();
    let mut i = 0;
    while i < n {
        if buf[i] == 0xFF && i + 2 < n {
            i += 3; // Skip IAC + command + option
        } else if buf[i].is_ascii_graphic() || buf[i] == b' ' {
            clean.push(buf[i]);
        } else if buf[i] == b'\n' || buf[i] == b'\r' {
            if !clean.is_empty() { clean.push(b' '); }
        }
        i += 1;
    }

    let text = String::from_utf8_lossy(&clean).trim().to_string();
    if text.is_empty() || text.len() > 120 { return None; }

    // Extract hostname from common banner patterns:
    // "hostname login:", "Welcome to hostname", "hostname>", "hostname#"
    let text_lower = text.to_lowercase();
    if let Some(pos) = text_lower.find(" login") {
        let name = text[..pos].trim().to_string();
        if !name.is_empty() && name.len() <= 60 {
            return Some(name);
        }
    }
    // "hostname>" or "hostname#" prompt
    for suffix in ['>', '#'] {
        if let Some(pos) = text.find(suffix) {
            let name = text[..pos].trim().to_string();
            if !name.is_empty() && name.len() <= 60
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Some(name);
            }
        }
    }

    // Return the first line if it looks like a hostname/device name
    let first_line = text.split_whitespace().next().unwrap_or("");
    if !first_line.is_empty()
        && first_line.len() <= 40
        && first_line.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Some(first_line.to_string());
    }

    None
}

// ─── Method 11: Direct DNS PTR to gateway ────────────────────────────────────

/// Send raw DNS PTR queries directly to the gateway router's DNS server (port 53).
/// Many home routers register DHCP client hostnames in their DNS. This bypasses
/// the Windows system resolver which may use different DNS servers (Google, Cloudflare)
/// or have negative caching that prevents finding local devices.
fn resolve_dns_via_gateway(ips: &[Ipv4Addr], gateway: Ipv4Addr, timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());

    // Use a single socket and send all queries, then collect responses
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(200)));

    // Send PTR queries for all IPs to the gateway's DNS server
    let mut tid_to_ip: HashMap<u16, Ipv4Addr> = HashMap::new();
    for (i, &ip) in ips.iter().enumerate() {
        let octets = ip.octets();
        let arpa_name = format!("{}.{}.{}.{}.in-addr.arpa",
            octets[3], octets[2], octets[1], octets[0]);
        let tid = (i as u16).wrapping_add(0x1000); // unique transaction ID
        let pkt = build_dns_query_with_id(&arpa_name, 12, tid);
        tid_to_ip.insert(tid, ip);
        let _ = sock.send_to(&pkt, SocketAddr::from((gateway, 53u16)));
    }

    // Collect responses
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 1024];
    let mut seen = std::collections::HashSet::new();

    while std::time::Instant::now() < deadline {
        let _ = sock.set_read_timeout(Some(
            deadline.saturating_duration_since(std::time::Instant::now())
                .max(Duration::from_millis(10))
        ));
        match sock.recv_from(&mut buf) {
            Ok((len, _)) => {
                if len < 12 { continue; }
                let tid = ((buf[0] as u16) << 8) | buf[1] as u16;
                let flags = ((buf[2] as u16) << 8) | buf[3] as u16;
                // Check it's a response (QR=1) with no error (RCODE=0)
                if flags & 0x8000 == 0 { continue; } // Not a response
                let rcode = flags & 0x000F;
                if rcode != 0 { continue; } // Error (NXDOMAIN, SERVFAIL, etc.)

                if let Some(&ip) = tid_to_ip.get(&tid) {
                    if seen.contains(&ip) { continue; }
                    if let Some(name) = parse_ptr_response(&buf[..len]) {
                        let clean = clean_mdns_name(&name);
                        if !clean.is_empty() {
                            found.lock().unwrap().push((ip, clean));
                            seen.insert(ip);
                        }
                    }
                }
            }
            Err(_) => {
                // Timeout — check if we've received enough
                if seen.len() >= ips.len() { break; }
                // If no more responses coming, break
                if std::time::Instant::now() >= deadline { break; }
            }
        }
    }

    found.into_inner().unwrap()
}

/// Build a DNS query packet with a specific transaction ID.
fn build_dns_query_with_id(name: &str, qtype: u16, tid: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    // Header: ID, flags=0x0100 (RD=1, standard recursive query), QDCOUNT=1
    pkt.push((tid >> 8) as u8);
    pkt.push(tid as u8);
    pkt.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1 (recursion desired)
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, AN=0, NS=0, AR=0
    dns_encode_name(&mut pkt, name);
    pkt.push((qtype >> 8) as u8);
    pkt.push(qtype as u8);
    pkt.extend_from_slice(&[0, 1]); // QCLASS = IN
    pkt
}

// ─── SSDP helpers ────────────────────────────────────────────────────────────

fn extract_header(text: &str, header: &str) -> Option<String> {
    let header_lower = header.to_lowercase();
    for line in text.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.starts_with(&header_lower) {
            if let Some(val) = line.splitn(2, ':').nth(1) {
                return Some(val.trim().to_string());
            }
        }
    }
    None
}

fn clean_ssdp_server(server: &str) -> String {
    let parts: Vec<&str> = server.split_whitespace().collect();
    for part in &parts {
        let lower = part.to_lowercase();
        if lower.starts_with("upnp/") || lower.starts_with("http/")
            || lower.starts_with("dlna/") || lower.starts_with("upnp-device")
        {
            continue;
        }
        return part.split('/').next().unwrap_or(part).to_string();
    }
    String::new()
}

// ─── Method 12: LLMNR unicast query (port 5355) ──────────────────────────────

/// Send LLMNR name queries directly to each device on port 5355.
/// Android and Windows devices respond to LLMNR with their hostname.
fn resolve_llmnr_batch(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, String)> {
    let found: Mutex<Vec<(Ipv4Addr, String)>> = Mutex::new(Vec::new());
    thread::scope(|s| {
        for &ip in ips {
            let found = &found;
            s.spawn(move || {
                if let Some(name) = llmnr_query(ip, timeout_ms) {
                    found.lock().unwrap().push((ip, name));
                }
            });
        }
    });
    found.into_inner().unwrap()
}

fn llmnr_query(ip: Ipv4Addr, timeout_ms: u64) -> Option<String> {
    // Build LLMNR query for reverse lookup: send PTR query for the IP
    // LLMNR uses the same DNS packet format but on port 5355
    let octets = ip.octets();
    let arpa_name = format!("{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]);

    let pkt = build_dns_query(&arpa_name, 12); // PTR query

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    // Send to the device's LLMNR port (5355) directly via unicast
    sock.send_to(&pkt, SocketAddr::from((ip, 5355u16))).ok()?;

    let mut buf = [0u8; 1024];
    let (len, _) = sock.recv_from(&mut buf).ok()?;

    // Parse PTR response
    if let Some(name) = parse_ptr_response(&buf[..len]) {
        let clean = clean_mdns_name(&name);
        if !clean.is_empty() {
            return Some(clean);
        }
    }

    // Also try: send A query for common Android patterns
    // Android devices may respond to their own hostname.local queries
    None
}

// ─── Method 13: DHCP hostname extraction from captured packets ───────────────

/// Parse DHCP option 12 (hostname) from a raw UDP payload (ports 67/68).
/// DHCP packet layout:
///   - Bytes 0-235: fixed fields (op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
///   - Bytes 236-239: magic cookie (99.130.83.99 / 0x63825363)
///   - Bytes 240+: options (tag, length, value)
///
/// Returns (client_mac, hostname) if option 12 is found.
pub fn parse_dhcp_hostname(payload: &[u8]) -> Option<([u8; 6], String)> {
    // Minimum DHCP packet: 240 bytes (fixed) + 4 (magic cookie) + some options
    if payload.len() < 244 { return None; }

    // Verify DHCP magic cookie at offset 236
    if payload[236] != 99 || payload[237] != 130 || payload[238] != 83 || payload[239] != 99 {
        return None;
    }

    // Extract client MAC (chaddr) at offset 28, 6 bytes
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&payload[28..34]);

    // Extract client IP (ciaddr at offset 12) or yiaddr (offset 16)
    // ciaddr is the client's current IP, yiaddr is the IP being offered

    // Parse options starting at offset 240
    let mut pos = 240;
    let mut hostname: Option<String> = None;

    while pos < payload.len() {
        let tag = payload[pos];
        if tag == 255 { break; } // End option
        if tag == 0 { pos += 1; continue; } // Padding

        if pos + 1 >= payload.len() { break; }
        let opt_len = payload[pos + 1] as usize;
        pos += 2;
        if pos + opt_len > payload.len() { break; }

        if tag == 12 { // Option 12: Hostname
            if let Ok(name) = std::str::from_utf8(&payload[pos..pos + opt_len]) {
                let name = name.trim().to_string();
                if !name.is_empty()
                    && name.len() <= 63
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                {
                    hostname = Some(name);
                }
            }
        }

        pos += opt_len;
    }

    hostname.map(|h| (mac, h))
}

/// Extract the source IP from a DHCP packet.
/// Tries ciaddr first, falls back to source IP header.
pub fn dhcp_client_ip(payload: &[u8]) -> Option<Ipv4Addr> {
    if payload.len() < 240 { return None; }

    // ciaddr (client IP) at offset 12
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    if !ciaddr.is_unspecified() {
        return Some(ciaddr);
    }

    // yiaddr (your IP, offered by server) at offset 16
    let yiaddr = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
    if !yiaddr.is_unspecified() {
        return Some(yiaddr);
    }

    None
}

// ─── Port scanning ───────────────────────────────────────────────────────────

/// Common ports to scan on LAN devices.
const SCAN_PORTS: &[u16] = &[
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    53,   // DNS
    80,   // HTTP
    135,  // RPC
    139,  // NetBIOS
    443,  // HTTPS
    445,  // SMB
    554,  // RTSP
    631,  // IPP (printing)
    1883, // MQTT
    3306, // MySQL
    3389, // RDP
    5000, // UPnP
    5555, // ADB (Android Debug Bridge)
    5900, // VNC
    8080, // HTTP alt
    8443, // HTTPS alt
    9090, // Web admin
];

/// Scan common ports on all IPs in parallel. Returns (ip, sorted open ports).
fn scan_ports_batch(ips: &[Ipv4Addr], timeout_ms: u64) -> Vec<(Ipv4Addr, Vec<u16>)> {
    let results: Mutex<HashMap<Ipv4Addr, Vec<u16>>> = Mutex::new(HashMap::new());
    let timeout = Duration::from_millis(timeout_ms);

    thread::scope(|s| {
        for &ip in ips {
            let results = &results;
            s.spawn(move || {
                // Scan all ports for this IP in parallel (scoped threads)
                let port_open: Mutex<Vec<u16>> = Mutex::new(Vec::new());
                thread::scope(|s2| {
                    for &port in SCAN_PORTS {
                        let port_open = &port_open;
                        s2.spawn(move || {
                            let addr = SocketAddr::new(IpAddr::V4(ip), port);
                            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                                port_open.lock().unwrap().push(port);
                            }
                        });
                    }
                });
                let mut open = port_open.into_inner().unwrap();
                if !open.is_empty() {
                    open.sort();
                    results.lock().unwrap().insert(ip, open);
                }
            });
        }
    });

    results.into_inner().unwrap().into_iter().collect()
}

/// Format open ports as a compact display string with service labels.
pub fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    ports.iter()
        .map(|p| {
            let svc = match p {
                21 => "ftp",
                22 => "ssh",
                23 => "telnet",
                53 => "dns",
                80 => "http",
                135 => "rpc",
                139 => "netbios",
                443 => "https",
                445 => "smb",
                554 => "rtsp",
                631 => "ipp",
                1883 => "mqtt",
                3306 => "mysql",
                3389 => "rdp",
                5000 => "upnp",
                5555 => "adb",
                5900 => "vnc",
                8080 => "http-alt",
                8443 => "https-alt",
                9090 => "admin",
                _ => "",
            };
            if svc.is_empty() {
                format!("{}", p)
            } else {
                format!("{}:{}", p, svc)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
