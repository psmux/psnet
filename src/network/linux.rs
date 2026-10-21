//! Linux data-acquisition backend.
//!
//! psnet's original data layer is built on Win32 (iphlpapi, ws2_32, dnsapi,
//! advapi32). This module provides the Linux equivalents that the rest of the
//! network layer is re-pointed at, sourced from procfs and sysfs:
//!
//!   /proc/net/{tcp,tcp6,udp,udp6}  — socket tables (replaces GetExtendedTcpTable)
//!   /proc/<pid>/fd                 — socket inode -> owning pid
//!   /proc/<pid>/{comm,exe}         — process name/path (replaces OpenProcess)
//!   /proc/net/arp                  — neighbour table (replaces GetIpNetTable)
//!   /proc/net/route                — routing table (replaces GetAdaptersInfo)
//!   /sys/class/net/*               — interface attributes
//!
//! Everything here is plain file parsing — no extra crate dependencies.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ─── /proc/net socket tables ────────────────────────────────────────────────

/// One row of /proc/net/{tcp,tcp6,udp,udp6}.
pub struct SocketEntry {
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    /// Raw Linux TCP state (see `tcp_state_to_mib`). Meaningless for UDP.
    pub state: u8,
    pub inode: u64,
}

/// Parse a hex address field as printed by the kernel.
///
/// The kernel formats the raw network-order address words with `%08X` in *host*
/// byte order, so recovering the octets means writing the parsed word back out
/// in native-endian order — which round-trips correctly on both LE and BE.
fn parse_hex_addr(s: &str) -> Option<IpAddr> {
    match s.len() {
        8 => {
            let v = u32::from_str_radix(s, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.to_ne_bytes())))
        }
        32 => {
            let mut octets = [0u8; 16];
            for i in 0..4 {
                let word = u32::from_str_radix(&s[i * 8..(i + 1) * 8], 16).ok()?;
                octets[i * 4..(i + 1) * 4].copy_from_slice(&word.to_ne_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Split an "ADDR:PORT" field. The port is printed already host-ordered.
fn parse_addr_port(field: &str) -> Option<(IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    Some((parse_hex_addr(addr)?, u16::from_str_radix(port, 16).ok()?))
}

/// Read and parse one of the /proc/net socket tables.
/// Returns an empty vec if the file is missing (e.g. IPv6 disabled).
pub fn read_socket_table(path: &str) -> Vec<SocketEntry> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    // First line is the column header.
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        if f.len() < 10 {
            continue;
        }
        let (local_addr, local_port) = match parse_addr_port(f[1]) {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = match parse_addr_port(f[2]) {
            Some(v) => v,
            None => continue,
        };
        let state = u8::from_str_radix(f[3], 16).unwrap_or(0);
        let inode = f[9].parse::<u64>().unwrap_or(0);

        out.push(SocketEntry {
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            inode,
        });
    }
    out
}

/// Translate a Linux TCP state (`include/net/tcp_states.h`) into the Windows
/// MIB_TCP_STATE numbering that `types::TcpState::from_raw` already decodes,
/// so the shared state enum and all its UI labels stay untouched.
pub fn tcp_state_to_mib(linux_state: u8) -> u32 {
    match linux_state {
        1 => 5,   // ESTABLISHED
        2 => 3,   // SYN_SENT
        3 => 4,   // SYN_RECV
        4 => 6,   // FIN_WAIT1
        5 => 7,   // FIN_WAIT2
        6 => 11,  // TIME_WAIT
        7 => 1,   // CLOSE      -> Closed
        8 => 8,   // CLOSE_WAIT
        9 => 10,  // LAST_ACK
        10 => 2,  // LISTEN
        11 => 9,  // CLOSING
        other => other as u32,
    }
}

// ─── socket inode -> pid ────────────────────────────────────────────────────

/// Build a map of socket inode -> owning pid by walking every process's fd
/// directory. This is how `ss`/`netstat` attribute sockets to processes; on
/// Linux the ownership is not carried in the socket table itself.
///
/// Processes we cannot read (permission, or exited mid-walk) are skipped, so a
/// non-root run simply yields fewer attributions rather than failing.
pub fn socket_inode_to_pid() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return map,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue, // non-numeric /proc entry
        };

        let fd_dir = match fs::read_dir(format!("/proc/{}/fd", pid)) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for fd in fd_dir.flatten() {
            if let Ok(target) = fs::read_link(fd.path()) {
                // Links look like "socket:[12345]"
                if let Some(inode) = target
                    .to_str()
                    .and_then(|t| t.strip_prefix("socket:["))
                    .and_then(|t| t.strip_suffix(']'))
                    .and_then(|t| t.parse::<u64>().ok())
                {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

// ─── process identity ───────────────────────────────────────────────────────

/// Short process name from /proc/<pid>/comm.
pub fn process_name(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok()?;
    let comm = comm.trim();
    if comm.is_empty() {
        None
    } else {
        Some(comm.to_string())
    }
}

/// Full executable path from /proc/<pid>/exe.
///
/// Kernel threads have no exe link, and a deleted binary yields a path with a
/// " (deleted)" suffix, which we strip so the value stays usable as a path.
pub fn process_exe(pid: u32) -> Option<String> {
    let path = fs::read_link(format!("/proc/{}/exe", pid)).ok()?;
    let path = path.to_string_lossy();
    let path = path.strip_suffix(" (deleted)").unwrap_or(&path);
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

// ─── neighbour table (/proc/net/arp) ────────────────────────────────────────

pub struct ArpEntry {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub iface: String,
}

/// Parse /proc/net/arp, skipping incomplete entries (flags 0x0), which are
/// pending lookups with an all-zero MAC.
pub fn arp_table() -> Vec<ArpEntry> {
    let content = match fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        // IP address | HW type | Flags | HW address | Mask | Device
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 {
            continue;
        }
        let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
        if flags == 0 {
            continue; // incomplete
        }
        let ip: Ipv4Addr = match f[0].parse() {
            Ok(i) => i,
            Err(_) => continue,
        };
        let mac = f[3].to_lowercase();
        if mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push(ArpEntry {
            ip,
            mac,
            iface: f[5].to_string(),
        });
    }
    out
}

// ─── routing table (/proc/net/route) ────────────────────────────────────────

/// Default gateway and the interface it is reached through, taken from the
/// first 0.0.0.0/0 route in /proc/net/route.
pub fn default_route() -> Option<(Ipv4Addr, String)> {
    let content = fs::read_to_string("/proc/net/route").ok()?;
    for line in content.lines().skip(1) {
        // Iface Destination Gateway Flags RefCnt Use Metric Mask ...
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        if f[1] != "00000000" {
            continue; // not the default route
        }
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        return Some((Ipv4Addr::from(gw.to_ne_bytes()), f[0].to_string()));
    }
    None
}

/// All routes as (destination, netmask, gateway, iface), for subnet detection.
pub fn routes() -> Vec<(Ipv4Addr, Ipv4Addr, Ipv4Addr, String)> {
    let content = match fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let dest = match u32::from_str_radix(f[1], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let gw = u32::from_str_radix(f[2], 16).unwrap_or(0);
        let mask = match u32::from_str_radix(f[7], 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        out.push((
            Ipv4Addr::from(dest.to_ne_bytes()),
            Ipv4Addr::from(mask.to_ne_bytes()),
            Ipv4Addr::from(gw.to_ne_bytes()),
            f[0].to_string(),
        ));
    }
    out
}

// ─── interface attributes (/sys/class/net) ──────────────────────────────────

/// Read a single sysfs attribute for an interface, e.g. ("eth0", "mtu").
pub fn sysfs_attr(iface: &str, attr: &str) -> Option<String> {
    fs::read_to_string(format!("/sys/class/net/{}/{}", iface, attr))
        .ok()
        .map(|s| s.trim().to_string())
}

/// Driver or device type backing an interface, used to give adapters a
/// human-meaningful description the way the Windows adapter description does.
///
/// Physical devices expose a driver symlink; virtual ones (bridges, VLANs,
/// tunnels) instead report a DEVTYPE in their uevent.
pub fn interface_driver(iface: &str) -> Option<String> {
    if let Ok(link) = fs::read_link(format!("/sys/class/net/{}/device/driver", iface)) {
        if let Some(name) = link.file_name().and_then(|n| n.to_str()) {
            return Some(name.to_string());
        }
    }
    let uevent = fs::read_to_string(format!("/sys/class/net/{}/uevent", iface)).ok()?;
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVTYPE=").map(|v| v.trim().to_string()))
}

// ─── getifaddrs ─────────────────────────────────────────────────────────────

#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

#[repr(C)]
struct SockaddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[repr(C)]
struct Ifaddrs {
    ifa_next: *mut Ifaddrs,
    ifa_name: *mut u8,
    ifa_flags: u32,
    ifa_addr: *mut u8,
    ifa_netmask: *mut u8,
    ifa_ifu: *mut u8,
    ifa_data: *mut std::ffi::c_void,
}

extern "C" {
    fn getifaddrs(ifap: *mut *mut Ifaddrs) -> i32;
    fn freeifaddrs(ifa: *mut Ifaddrs);
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// One address bound to an interface.
pub struct IfAddr {
    pub name: String,
    pub addr: IpAddr,
    /// Netmask, when the kernel reports one for this address.
    pub netmask: Option<IpAddr>,
}

/// Read an address out of a sockaddr pointer, if it is one we care about.
unsafe fn read_sockaddr(sa: *const u8) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // sa_family occupies the first two bytes of any sockaddr.
    match *(sa as *const u16) {
        AF_INET => {
            let sa = &*(sa as *const SockaddrIn);
            Some(IpAddr::V4(Ipv4Addr::from(sa.sin_addr.to_ne_bytes())))
        }
        AF_INET6 => {
            let sa = &*(sa as *const SockaddrIn6);
            Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr)))
        }
        _ => None,
    }
}

/// Interface addresses with their netmasks, via getifaddrs(3).
pub fn ifaddrs() -> Vec<IfAddr> {
    let mut out = Vec::new();
    unsafe {
        let mut head: *mut Ifaddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) != 0 || head.is_null() {
            return out;
        }

        let mut cur = head;
        while !cur.is_null() {
            let entry = &*cur;
            if !entry.ifa_name.is_null() {
                if let Some(addr) = read_sockaddr(entry.ifa_addr) {
                    let mut len = 0usize;
                    while *entry.ifa_name.add(len) != 0 && len < 256 {
                        len += 1;
                    }
                    let name = String::from_utf8_lossy(std::slice::from_raw_parts(
                        entry.ifa_name,
                        len,
                    ))
                    .to_string();

                    out.push(IfAddr {
                        name,
                        addr,
                        netmask: read_sockaddr(entry.ifa_netmask),
                    });
                }
            }
            cur = entry.ifa_next;
        }

        freeifaddrs(head);
    }
    out
}
