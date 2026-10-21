//! Deep network probing — 10 parallel discovery methods for maximum host coverage.
//!
//! Methods:
//!   1. ARP (SendARP)              — Layer 2 neighbor resolution
//!   2. ARP Cache (GetIpNetTable)  — Read OS neighbor table (zero traffic)
//!   3. ICMP Ping (IcmpSendEcho)   — Layer 3 echo (crosses VPN tunnels!)
//!   4. TCP Connect Probe          — Layer 4 port probe (80,443,445,22,3389,8080,135,139,53)
//!   5. NetBIOS NBSTAT (UDP 137)   — Windows/Samba name resolution per-host
//!   6. mDNS (UDP 5353)            — Multicast DNS discovery (Apple, IoT, Linux)
//!   7. SSDP/UPnP (UDP 1900)      — Universal Plug and Play device discovery
//!   8. DNS PTR Reverse Lookup     — getnameinfo() reverse DNS per-host
//!   9. LLMNR (UDP 5355)           — Link-Local Multicast Name Resolution
//!  10. NetBIOS Broadcast (UDP 137)— Subnet-wide NetBIOS name broadcast

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

// ─── Win32 FFI ──────────────────────────────────────────────────────────────

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn SendARP(DestIP: u32, SrcIP: u32, pMacAddr: *mut u8, PhyAddrLen: *mut u32) -> u32;
    fn GetIpNetTable(pIpNetTable: *mut u8, pdwSize: *mut u32, bOrder: i32) -> u32;
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

/// sockaddr_in. The layout is identical on Windows and Linux (only the
/// signedness of the family field differs, which does not affect the ABI).
#[repr(C)]
#[allow(non_snake_case)]
struct SOCKADDR_IN {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32, // network byte order
    sin_zero: [u8; 8],
}

#[cfg(windows)]
#[link(name = "ws2_32")]
extern "system" {
    fn getnameinfo(
        sa: *const SOCKADDR_IN,
        salen: i32,
        host: *mut u8,
        hostlen: u32,
        serv: *mut u8,
        servlen: u32,
        flags: i32,
    ) -> i32;
}

// getnameinfo is POSIX and lives in libc on Linux, so the reverse-DNS path
// below is shared — only the linkage differs.
#[cfg(not(windows))]
extern "C" {
    fn getnameinfo(
        sa: *const SOCKADDR_IN,
        salen: u32,
        host: *mut u8,
        hostlen: u32,
        serv: *mut u8,
        servlen: u32,
        flags: i32,
    ) -> i32;
}

#[cfg(windows)]
const INVALID_HANDLE_VALUE: isize = -1;
#[cfg(windows)]
const ERROR_BUFFER_OVERFLOW: u32 = 111;
#[cfg(windows)]
const ERROR_SUCCESS: u32 = 0;
const AF_INET: i16 = 2;
/// NI_NAMEREQD — fail rather than return a numeric string. Same value on both
/// platforms.
const NI_NAMEREQD: i32 = 8;

// ─── Result types ───────────────────────────────────────────────────────────

/// A single probe hit from one discovery method.
pub(crate) struct ProbeHit {
    pub(crate) ip: Ipv4Addr,
    pub(crate) mac: Option<String>,
    pub(crate) hostname: Option<String>,
    pub(crate) method: &'static str,
}

/// Merged host after deduplication across all methods.
pub struct MergedHost {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub methods: Vec<&'static str>,
}

// ─── Main entry point ───────────────────────────────────────────────────────

/// Run ALL 10 probe methods in parallel against a subnet.
/// Returns deduplicated hosts with merged info from every method that found them.
pub fn deep_scan_subnet(
    local_ip: Ipv4Addr,
    mask: Ipv4Addr,
    _gateway: Option<Ipv4Addr>,
) -> Vec<MergedHost> {
    let targets = super::subnet_ips(local_ip, mask);
    if targets.is_empty() {
        return Vec::new();
    }

    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        // 1. ARP scan — Layer 2
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = arp_scan(t, local_ip);
                h.lock().unwrap().extend(r);
            });
        }
        // 2. ARP cache — GetIpNetTable (zero traffic, instant)
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = arp_cache_read(t);
                h.lock().unwrap().extend(r);
            });
        }
        // 3. ICMP ping sweep — crosses L3 tunnels (VPN!)
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = icmp_ping_sweep(t);
                h.lock().unwrap().extend(r);
            });
        }
        // 4. TCP connect probe — finds hosts with open services
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = tcp_connect_probe(t);
                h.lock().unwrap().extend(r);
            });
        }
        // 5. NetBIOS NBSTAT — Windows/Samba devices
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = netbios_scan(t);
                h.lock().unwrap().extend(r);
            });
        }
        // 6. mDNS multicast — Apple, Linux, IoT
        {
            let h = &hits;
            s.spawn(move || {
                let r = mdns_discover(local_ip);
                h.lock().unwrap().extend(r);
            });
        }
        // 7. SSDP/UPnP — routers, TVs, smart home
        {
            let h = &hits;
            s.spawn(move || {
                let r = ssdp_discover(local_ip);
                h.lock().unwrap().extend(r);
            });
        }
        // 8. DNS PTR reverse lookup
        {
            let h = &hits;
            let t = &targets;
            s.spawn(move || {
                let r = dns_reverse_scan(t);
                h.lock().unwrap().extend(r);
            });
        }
        // 9. LLMNR — Link-Local Multicast Name Resolution
        {
            let h = &hits;
            s.spawn(move || {
                let r = llmnr_discover(local_ip);
                h.lock().unwrap().extend(r);
            });
        }
        // 10. NetBIOS broadcast — subnet-wide name query
        {
            let h = &hits;
            s.spawn(move || {
                let r = nbt_broadcast(local_ip, mask);
                h.lock().unwrap().extend(r);
            });
        }
    });

    merge_hits(hits.into_inner().unwrap(), local_ip)
}

// ─── Merge / dedup ──────────────────────────────────────────────────────────

pub(crate) fn merge_hits(hits: Vec<ProbeHit>, local_ip: Ipv4Addr) -> Vec<MergedHost> {
    let mut map: HashMap<Ipv4Addr, MergedHost> = HashMap::new();

    for hit in hits {
        // Skip our own IP
        if hit.ip == local_ip {
            continue;
        }

        let entry = map.entry(hit.ip).or_insert_with(|| MergedHost {
            ip: hit.ip,
            mac: None,
            hostname: None,
            methods: Vec::new(),
        });

        // Prefer non-empty MACs
        if entry.mac.is_none() && hit.mac.is_some() {
            entry.mac = hit.mac;
        }

        // Prefer longer / more descriptive hostnames
        if let Some(h) = hit.hostname {
            if !h.is_empty() {
                let dominated = entry.hostname.as_ref()
                    .map(|existing| h.len() > existing.len())
                    .unwrap_or(true);
                if dominated {
                    entry.hostname = Some(h);
                }
            }
        }

        if !entry.methods.contains(&hit.method) {
            entry.methods.push(hit.method);
        }
    }

    let mut result: Vec<MergedHost> = map.into_values().collect();
    result.sort_by(|a, b| a.ip.cmp(&b.ip));
    result
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 1: ARP Scan (SendARP) — Layer 2
// ═════════════════════════════════════════════════════════════════════════════

/// Linux has no SendARP equivalent — there is no API that resolves one address
/// synchronously. The standard substitute is to provoke the kernel into doing
/// it: send a datagram to each target so the stack must resolve its MAC, then
/// read the neighbour table it just populated.
///
/// The UDP send targets a high, almost certainly closed port; we never look at
/// a response, only at the ARP entry the attempt creates.
#[cfg(not(windows))]
pub(crate) fn arp_scan(targets: &[Ipv4Addr], local_ip: Ipv4Addr) -> Vec<ProbeHit> {
    /// Unassigned high port — we want the ARP side-effect, not a reply.
    const POKE_PORT: u16 = 9;
    /// Time to let the kernel complete resolution before reading the table.
    const SETTLE: Duration = Duration::from_millis(400);

    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();

    // A single socket is enough: these are unconnected sends, and the point is
    // only to make the kernel resolve each destination.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        for &target in targets {
            let _ = sock.send_to(b"", SocketAddrV4::new(target, POKE_PORT));
        }
    }

    thread::sleep(SETTLE);

    let mut hits = Vec::new();
    for entry in crate::network::linux::arp_table() {
        if entry.ip == local_ip || !target_set.contains(&entry.ip) {
            continue;
        }
        hits.push(ProbeHit {
            ip: entry.ip,
            mac: Some(entry.mac.to_uppercase()),
            hostname: None,
            method: "ARP",
        });
    }

    hits
}

#[cfg(windows)]
pub(crate) fn arp_scan(targets: &[Ipv4Addr], local_ip: Ipv4Addr) -> Vec<ProbeHit> {
    let src = u32::from(local_ip).to_be();
    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());

    for chunk in targets.chunks(64) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                s.spawn(move || {
                    let dest = u32::from(target).to_be();
                    let mut mac = [0u8; 6];
                    let mut len: u32 = 6;
                    let ret = unsafe { SendARP(dest, src, mac.as_mut_ptr(), &mut len) };
                    if ret == 0 && len >= 6 {
                        h.lock().unwrap().push(ProbeHit {
                            ip: target,
                            mac: Some(format_mac(&mac)),
                            hostname: None,
                            method: "ARP",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 2: ARP Cache (GetIpNetTable) — zero traffic, reads OS table
// ═════════════════════════════════════════════════════════════════════════════

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

#[cfg(not(windows))]
pub(crate) fn arp_cache_read(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();

    crate::network::linux::arp_table()
        .into_iter()
        .filter(|e| target_set.contains(&e.ip))
        .map(|e| ProbeHit {
            ip: e.ip,
            mac: Some(e.mac.to_uppercase()),
            hostname: None,
            method: "ARP-Cache",
        })
        .collect()
}

#[cfg(windows)]
pub(crate) fn arp_cache_read(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let mut hits = Vec::new();
    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();

    unsafe {
        let mut size: u32 = 0;
        let ret = GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return hits;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetIpNetTable(buf.as_mut_ptr(), &mut size, 0);
        if ret != ERROR_SUCCESS {
            return hits;
        }

        let num_entries = *(buf.as_ptr() as *const u32);
        let rows_ptr = buf.as_ptr().add(4) as *const MIB_IPNETROW;

        for i in 0..num_entries as usize {
            let row = &*rows_ptr.add(i);
            // 3=dynamic, 4=static; skip invalid(2) and other(1)
            if row.dwType < 3 {
                continue;
            }
            let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
            if !target_set.contains(&ip) {
                continue;
            }

            let mac = if row.dwPhysAddrLen >= 6 {
                Some(format_mac(&row.bPhysAddr[..6].try_into().unwrap()))
            } else {
                None
            };

            hits.push(ProbeHit {
                ip,
                mac,
                hostname: None,
                method: "ARP-Cache",
            });
        }
    }

    hits
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 3: ICMP Ping Sweep (IcmpSendEcho) — Layer 3, crosses VPN tunnels!
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn icmp_ping_sweep(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());

    for chunk in targets.chunks(64) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                s.spawn(move || {
                    if icmp_ping_one(target) {
                        h.lock().unwrap().push(ProbeHit {
                            ip: target,
                            mac: None,
                            hostname: None,
                            method: "ICMP",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

/// ICMP echo on Linux.
///
/// There is no IcmpSendEcho equivalent, so we build the echo request by hand.
/// Two socket types can carry it:
///
///   SOCK_DGRAM/IPPROTO_ICMP — unprivileged "ping sockets", available when the
///     caller's gid is inside net.ipv4.ping_group_range. The kernel owns the
///     identifier field and rewrites it, so replies cannot be matched on id.
///   SOCK_RAW/IPPROTO_ICMP   — needs root or CAP_NET_RAW, and delivers replies
///     with the full IP header attached.
///
/// We try the unprivileged socket first and fall back to raw, so the probe
/// works both as root (the normal case on OpenWrt) and as a plain user.
#[cfg(not(windows))]
pub(crate) fn icmp_ping_one(target: Ipv4Addr) -> bool {
    use std::os::fd::FromRawFd;

    const AF_INET_C: i32 = 2;
    const SOCK_DGRAM: i32 = 2;
    const SOCK_RAW: i32 = 3;
    const IPPROTO_ICMP: i32 = 1;
    const ICMP_ECHO: u8 = 8;
    const ICMP_ECHOREPLY: u8 = 0;

    extern "C" {
        fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    }

    /// Internet checksum (RFC 1071) over the ICMP message.
    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let [last] = *chunks.remainder() {
            sum += (last as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    // Identifier is informational on ping sockets (the kernel overwrites it),
    // but is what distinguishes our echoes on a raw socket.
    let ident = std::process::id() as u16;
    let seq: u16 = 1;

    let mut pkt = Vec::with_capacity(12);
    pkt.push(ICMP_ECHO);
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(b"psnt");
    let ck = checksum(&pkt);
    pkt[2..4].copy_from_slice(&ck.to_be_bytes());

    // Try unprivileged ping socket, then raw.
    let (sock, is_raw) = unsafe {
        let mut fd = socket(AF_INET_C, SOCK_DGRAM, IPPROTO_ICMP);
        let mut raw = false;
        if fd < 0 {
            fd = socket(AF_INET_C, SOCK_RAW, IPPROTO_ICMP);
            raw = true;
        }
        if fd < 0 {
            return false;
        }
        (UdpSocket::from_raw_fd(fd), raw)
    };

    if sock
        .set_read_timeout(Some(Duration::from_millis(300)))
        .is_err()
    {
        return false;
    }
    if sock
        .send_to(&pkt, SocketAddrV4::new(target, 0))
        .is_err()
    {
        return false;
    }

    // Read until the timeout expires, ignoring replies from other addresses —
    // a raw socket sees every ICMP packet arriving at the host, including the
    // echoes belonging to the other threads in this sweep.
    let deadline = std::time::Instant::now() + Duration::from_millis(300);
    let mut buf = [0u8; 256];
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let _ = sock.set_read_timeout(Some(remaining));

        let (len, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => return false,
        };
        if src.ip() != std::net::IpAddr::V4(target) {
            continue;
        }

        // A raw socket hands back the IP header; a ping socket does not.
        let icmp = if is_raw {
            let ihl = ((buf[0] & 0x0F) as usize) * 4;
            if len < ihl + 8 {
                continue;
            }
            &buf[ihl..len]
        } else {
            if len < 8 {
                continue;
            }
            &buf[..len]
        };

        if icmp[0] == ICMP_ECHOREPLY {
            return true;
        }
    }
}

#[cfg(windows)]
fn icmp_ping_one(target: Ipv4Addr) -> bool {
    unsafe {
        let handle = IcmpCreateFile();
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return false;
        }

        let data = b"psnt";
        // ICMP_ECHO_REPLY is 28 bytes + data; 64 bytes is plenty
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
// Method 4: TCP Connect Probe — finds hosts with listening services
// ═════════════════════════════════════════════════════════════════════════════

const TCP_PROBE_PORTS: &[u16] = &[80, 443, 445, 22, 3389, 8080, 135, 139, 53];

pub(crate) fn tcp_connect_probe(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());
    let found: Mutex<HashSet<Ipv4Addr>> = Mutex::new(HashSet::new());

    for chunk in targets.chunks(32) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                let f = &found;
                s.spawn(move || {
                    for &port in TCP_PROBE_PORTS {
                        let addr = SocketAddrV4::new(target, port);
                        if TcpStream::connect_timeout(
                            &std::net::SocketAddr::V4(addr),
                            Duration::from_millis(250),
                        )
                        .is_ok()
                        {
                            if f.lock().unwrap().insert(target) {
                                h.lock().unwrap().push(ProbeHit {
                                    ip: target,
                                    mac: None,
                                    hostname: None,
                                    method: "TCP",
                                });
                            }
                            break;
                        }
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 5: NetBIOS NBSTAT Query (UDP 137) — per-host name resolution
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn netbios_scan(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());
    let query = build_nbstat_query();

    for chunk in targets.chunks(32) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                let q = &query;
                s.spawn(move || {
                    if let Some(name) = netbios_query_one(target, q) {
                        h.lock().unwrap().push(ProbeHit {
                            ip: target,
                            mac: None,
                            hostname: Some(name),
                            method: "NetBIOS",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

fn build_nbstat_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    // DNS-like header
    pkt.extend_from_slice(&[0x00, 0x01]); // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags: query
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional: 0
    // Name: "*" (wildcard) in NetBIOS first-level encoding
    // '*' = 0x2A -> 'C','K'; pad with 0x00 -> 'A','A' × 15
    pkt.push(0x20); // length = 32
    pkt.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    pkt.push(0x00); // end of name
    pkt.extend_from_slice(&[0x00, 0x21]); // Type: NBSTAT
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

fn netbios_query_one(target: Ipv4Addr, query: &[u8]) -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(400))).ok()?;
    sock.send_to(query, SocketAddrV4::new(target, 137)).ok()?;

    let mut buf = [0u8; 512];
    let (len, _) = sock.recv_from(&mut buf).ok()?;
    parse_nbstat_response(&buf[..len])
}

fn parse_nbstat_response(data: &[u8]) -> Option<String> {
    if data.len() < 57 {
        return None;
    }
    let name_count = data[56] as usize;
    if name_count == 0 || data.len() < 57 + 18 {
        return None;
    }
    // First name entry: 15 bytes name + 1 byte suffix + 2 bytes flags
    let name_bytes = &data[57..57 + 15];
    let name = std::str::from_utf8(name_bytes).ok()?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 6: mDNS Discovery (UDP 5353 multicast)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn mdns_discover(local_ip: Ipv4Addr) -> Vec<ProbeHit> {
    let mut hits = Vec::new();

    let sock = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return hits,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(2000)));
    let _ = sock.set_broadcast(true);

    // Join mDNS multicast group
    let _ = sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &local_ip);

    // Query for service discovery PTR
    let query = build_mdns_services_query();
    let _ = sock.send_to(&query, "224.0.0.251:5353");

    // Also send a general query to discover .local hosts
    let query2 = build_mdns_any_query();
    let _ = sock.send_to(&query2, "224.0.0.251:5353");

    let mut seen = HashSet::new();
    let mut buf = [0u8; 1500];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let ip = *v4.ip();
                    if ip == local_ip {
                        continue;
                    }
                    if seen.insert(ip) {
                        let hostname = parse_mdns_response(&buf[..len]);
                        hits.push(ProbeHit {
                            ip,
                            mac: None,
                            hostname,
                            method: "mDNS",
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    let _ = sock.leave_multicast_v4(&Ipv4Addr::new(224, 0, 0, 251), &local_ip);
    hits
}

fn build_mdns_services_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0x00, 0x00]); // ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]); // Answers
    pkt.extend_from_slice(&[0x00, 0x00]); // Authority
    pkt.extend_from_slice(&[0x00, 0x00]); // Additional
    // _services._dns-sd._udp.local PTR
    encode_dns_name(&mut pkt, "_services._dns-sd._udp.local");
    pkt.extend_from_slice(&[0x00, 0x0C]); // Type: PTR
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

fn build_mdns_any_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32);
    pkt.extend_from_slice(&[0x00, 0x00]); // ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Query for "local" domain with ANY type
    encode_dns_name(&mut pkt, "local");
    pkt.extend_from_slice(&[0x00, 0xFF]); // Type: ANY
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

fn encode_dns_name(pkt: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
}

fn parse_mdns_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }

    // Try to extract a hostname from answer or additional sections
    let an_count = u16::from_be_bytes([data[6], data[7]]) as usize;
    let _ns_count = u16::from_be_bytes([data[8], data[9]]) as usize;
    let ar_count = u16::from_be_bytes([data[10], data[11]]) as usize;

    if an_count == 0 && ar_count == 0 {
        return None;
    }

    // Skip questions
    let qd_count = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut pos = 12;
    for _ in 0..qd_count {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // type + class
    }

    // Scan answer + authority + additional sections for useful names
    let total_rr = an_count + _ns_count + ar_count;
    for _ in 0..total_rr {
        if pos >= data.len() {
            break;
        }
        let name = read_dns_name(data, pos);
        pos = skip_dns_name(data, pos)?;
        if pos + 10 > data.len() {
            break;
        }
        let _rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10 + rdlen;

        // Return the first clean hostname
        if let Some(n) = name {
            let clean = n
                .trim_end_matches(".local")
                .trim_end_matches('.')
                .to_string();
            if !clean.is_empty() && !clean.starts_with('_') && !clean.contains("._") {
                return Some(clean);
            }
        }
    }

    None
}

fn skip_dns_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len >= 0xC0 {
            return Some(pos + 2);
        } // pointer
        pos += 1 + len;
    }
}

fn read_dns_name(data: &[u8], mut pos: usize) -> Option<String> {
    let mut name = String::new();
    let mut jumps = 0;
    loop {
        if pos >= data.len() || jumps > 10 {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            let off = ((len & 0x3F) << 8) | (data.get(pos + 1).copied()? as usize);
            pos = off;
            jumps += 1;
            continue;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&data[pos..pos + len]));
        pos += len;
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 7: SSDP/UPnP Discovery (UDP 1900)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn ssdp_discover(local_ip: Ipv4Addr) -> Vec<ProbeHit> {
    let mut hits = Vec::new();

    let sock = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return hits,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(2000)));

    let msearch = b"M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 1\r\n\
        ST: ssdp:all\r\n\
        \r\n";

    let _ = sock.send_to(msearch, "239.255.255.250:1900");

    let mut seen = HashSet::new();
    let mut buf = [0u8; 2048];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let ip = *v4.ip();
                    if ip == local_ip {
                        continue;
                    }
                    if seen.insert(ip) {
                        let resp = String::from_utf8_lossy(&buf[..len]);
                        let server = resp
                            .lines()
                            .find(|l| l.to_lowercase().starts_with("server:"))
                            .map(|l| l[7..].trim().to_string());
                        hits.push(ProbeHit {
                            ip,
                            mac: None,
                            hostname: server,
                            method: "SSDP",
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    hits
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 8: DNS PTR Reverse Lookup (getnameinfo)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn dns_reverse_scan(targets: &[Ipv4Addr]) -> Vec<ProbeHit> {
    let hits: Mutex<Vec<ProbeHit>> = Mutex::new(Vec::new());

    for chunk in targets.chunks(32) {
        thread::scope(|s| {
            for &target in chunk {
                let h = &hits;
                s.spawn(move || {
                    if let Some(name) = reverse_dns(target) {
                        h.lock().unwrap().push(ProbeHit {
                            ip: target,
                            mac: None,
                            hostname: Some(name),
                            method: "DNS-PTR",
                        });
                    }
                });
            }
        });
    }

    hits.into_inner().unwrap()
}

fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let ip_u32 = u32::from(ip).to_be();
    let sa = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: 0,
        sin_addr: ip_u32,
        sin_zero: [0; 8],
    };

    let mut host = [0u8; 256];
    #[cfg(windows)]
    let salen = std::mem::size_of::<SOCKADDR_IN>() as i32;
    #[cfg(not(windows))]
    let salen = std::mem::size_of::<SOCKADDR_IN>() as u32;
    let ret = unsafe {
        getnameinfo(
            &sa,
            salen,
            host.as_mut_ptr(),
            host.len() as u32,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD,
        )
    };

    if ret == 0 {
        let end = host.iter().position(|&b| b == 0).unwrap_or(host.len());
        let name = String::from_utf8_lossy(&host[..end]).to_string();
        // Don't return if it's just the IP as a string
        if name != ip.to_string() && !name.is_empty() {
            return Some(name);
        }
    }
    None
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 9: LLMNR Discovery (UDP 5355 multicast)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn llmnr_discover(local_ip: Ipv4Addr) -> Vec<ProbeHit> {
    let mut hits = Vec::new();

    let sock = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return hits,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));

    // Join LLMNR multicast group
    let _ = sock.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 252), &local_ip);

    // Query commonly-used LLMNR names to solicit responses
    for name in &[b"wpad" as &[u8], b"isatap", b"localhost"] {
        let query = build_llmnr_query(name);
        let _ = sock.send_to(&query, "224.0.0.252:5355");
    }

    let mut seen = HashSet::new();
    let mut buf = [0u8; 1500];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((_len, addr)) => {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let ip = *v4.ip();
                    if ip == local_ip {
                        continue;
                    }
                    if seen.insert(ip) {
                        hits.push(ProbeHit {
                            ip,
                            mac: None,
                            hostname: None,
                            method: "LLMNR",
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    let _ = sock.leave_multicast_v4(&Ipv4Addr::new(224, 0, 0, 252), &local_ip);
    hits
}

fn build_llmnr_query(name: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(32 + name.len());
    pkt.extend_from_slice(&[0x00, 0x01]); // ID
    pkt.extend_from_slice(&[0x00, 0x00]); // Flags: query
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Question name
    pkt.push(name.len() as u8);
    pkt.extend_from_slice(name);
    pkt.push(0); // end
    pkt.extend_from_slice(&[0x00, 0x01]); // Type: A
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

// ═════════════════════════════════════════════════════════════════════════════
// Method 10: NetBIOS Broadcast (subnet broadcast to UDP 137)
// ═════════════════════════════════════════════════════════════════════════════

pub(crate) fn nbt_broadcast(local_ip: Ipv4Addr, mask: Ipv4Addr) -> Vec<ProbeHit> {
    let mut hits = Vec::new();

    let broadcast = {
        let ip_u32 = u32::from(local_ip);
        let mask_u32 = u32::from(mask);
        Ipv4Addr::from(ip_u32 | !mask_u32)
    };

    let sock = match UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)) {
        Ok(s) => s,
        Err(_) => return hits,
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));

    let query = build_nbt_broadcast_query();
    let _ = sock.send_to(&query, SocketAddrV4::new(broadcast, 137));

    let mut seen = HashSet::new();
    let mut buf = [0u8; 512];

    loop {
        match sock.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if let std::net::SocketAddr::V4(v4) = addr {
                    let ip = *v4.ip();
                    if ip == local_ip {
                        continue;
                    }
                    if seen.insert(ip) {
                        let hostname = parse_nbstat_response(&buf[..len]);
                        hits.push(ProbeHit {
                            ip,
                            mac: None,
                            hostname,
                            method: "NBT-BC",
                        });
                    }
                }
            }
            Err(_) => break,
        }
    }

    hits
}

fn build_nbt_broadcast_query() -> Vec<u8> {
    let mut pkt = Vec::with_capacity(50);
    pkt.extend_from_slice(&[0x00, 0x02]); // Transaction ID
    pkt.extend_from_slice(&[0x01, 0x10]); // Flags: broadcast, recursion desired
    pkt.extend_from_slice(&[0x00, 0x01]); // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&[0x00, 0x00]);
    // Name: "*" (wildcard) encoded
    pkt.push(0x20);
    pkt.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x21]); // Type: NBSTAT
    pkt.extend_from_slice(&[0x00, 0x01]); // Class: IN
    pkt
}

// ─── Public ARP cache reader (for instant first-pass) ───────────────────────

/// An ARP cache entry with interface index, IP, and optional MAC.
pub struct ArpCacheEntry {
    /// Interface index from the OS ARP table.
    pub if_index: u32,
    /// IPv4 address of the neighbor.
    pub ip: Ipv4Addr,
    /// MAC address (if available, 6+ byte physical address).
    pub mac: Option<String>,
}

/// Read ALL entries from the OS neighbour table (/proc/net/arp).
/// This is instant, zero network traffic, and returns entries from all interfaces.
#[cfg(not(windows))]
pub(crate) fn arp_cache_read_all() -> Vec<ArpCacheEntry> {
    use crate::network::linux;

    // /proc/net/arp names the device; the UI groups by a numeric index, so map
    // each name to its kernel ifindex once.
    let mut ifindex: HashMap<String, u32> = HashMap::new();

    let mut entries = Vec::new();
    for e in linux::arp_table() {
        // Skip link-local and broadcast
        let octets = e.ip.octets();
        if octets[0] == 169 && octets[1] == 254 {
            continue;
        }
        if octets[0] == 255 || e.ip.is_broadcast() || e.ip.is_loopback() {
            continue;
        }
        // Skip multicast (224-239.x.x.x)
        if octets[0] >= 224 && octets[0] <= 239 {
            continue;
        }

        let idx = *ifindex.entry(e.iface.clone()).or_insert_with(|| {
            linux::sysfs_attr(&e.iface, "ifindex")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        });

        entries.push(ArpCacheEntry {
            if_index: idx,
            ip: e.ip,
            mac: Some(e.mac.to_uppercase()),
        });
    }

    entries
}

/// Read ALL entries from the OS ARP cache (GetIpNetTable).
/// This is instant, zero network traffic, and returns entries from all interfaces.
/// Filters out invalid entries (type < 3).
#[cfg(windows)]
pub(crate) fn arp_cache_read_all() -> Vec<ArpCacheEntry> {
    let mut entries = Vec::new();

    unsafe {
        let mut size: u32 = 0;
        let ret = GetIpNetTable(std::ptr::null_mut(), &mut size, 0);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return entries;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetIpNetTable(buf.as_mut_ptr(), &mut size, 0);
        if ret != ERROR_SUCCESS {
            return entries;
        }

        let num_entries = *(buf.as_ptr() as *const u32);
        let rows_ptr = buf.as_ptr().add(4) as *const MIB_IPNETROW;

        for i in 0..num_entries as usize {
            let row = &*rows_ptr.add(i);
            // 3=dynamic, 4=static; skip invalid(2) and other(1)
            if row.dwType < 3 {
                continue;
            }
            let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));

            // Skip link-local and broadcast
            let octets = ip.octets();
            if octets[0] == 169 && octets[1] == 254 {
                continue;
            }
            if octets[0] == 255 || ip.is_broadcast() || ip.is_loopback() {
                continue;
            }
            // Skip multicast (224-239.x.x.x)
            if octets[0] >= 224 && octets[0] <= 239 {
                continue;
            }

            let mac = if row.dwPhysAddrLen >= 6 {
                Some(format_mac(&row.bPhysAddr[..6].try_into().unwrap()))
            } else {
                None
            };

            entries.push(ArpCacheEntry {
                if_index: row.dwIndex,
                ip,
                mac,
            });
        }
    }

    entries
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Only the Win32 paths hand back raw MAC bytes; /proc/net/arp already
/// formats them, so this is unused on Linux.
#[cfg(windows)]
pub(crate) fn format_mac(bytes: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}
