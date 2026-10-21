//! Network adapter enumeration.
//!
//! Discovers ALL network interfaces: Ethernet, WiFi, VPN tunnels,
//! Docker vEthernet, WSL vEthernet, Hyper-V switches, etc.
//!
//! Backed by Win32 GetAdaptersInfo on Windows and by getifaddrs(3) plus
//! /sys/class/net and /proc/net/route on Linux.

use std::net::Ipv4Addr;

// ─── Win32 FFI ───────────────────────────────────────────────────────────────

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

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersInfo(pAdapterInfo: *mut u8, pOutBufLen: *mut u32) -> u32;
}

#[cfg(windows)]
const ERROR_SUCCESS: u32 = 0;
#[cfg(windows)]
const ERROR_BUFFER_OVERFLOW: u32 = 111;

// ─── Adapter type constants ──────────────────────────────────────────────────

pub const IF_TYPE_PPP: u32 = 23;
pub const IF_TYPE_LOOPBACK: u32 = 24;
pub const IF_TYPE_SLIP: u32 = 28;
pub const IF_TYPE_TUNNEL: u32 = 131;

// ─── Public types ────────────────────────────────────────────────────────────

/// Information about a single network adapter.
#[derive(Clone, Debug)]
pub struct AdapterInfo {
    /// Internal adapter name (GUID).
    pub name: String,
    /// Human-readable description (e.g., "Intel(R) Wi-Fi 6 AX201").
    pub description: String,
    /// IPv4 address assigned to this adapter.
    pub ip: Ipv4Addr,
    /// Subnet mask.
    pub mask: Ipv4Addr,
    /// Default gateway (if configured).
    pub gateway: Option<Ipv4Addr>,
    /// MIB interface type (IF_TYPE_*).
    pub if_type: u32,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all network adapters with valid IPv4 addresses.
/// Returns every adapter, including virtual ones (Docker, WSL, VPN, Hyper-V).
#[cfg(windows)]
pub fn enumerate_all() -> Vec<AdapterInfo> {
    let mut result = Vec::new();

    unsafe {
        let mut size: u32 = 0;
        let ret = GetAdaptersInfo(std::ptr::null_mut(), &mut size);
        if ret != ERROR_BUFFER_OVERFLOW || size == 0 {
            return result;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetAdaptersInfo(buf.as_mut_ptr(), &mut size);
        if ret != ERROR_SUCCESS {
            return result;
        }

        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_INFO;
        while !adapter.is_null() {
            let ip_str = cstr_from_bytes(&(*adapter).IpAddressList.IpAddress);
            let mask_str = cstr_from_bytes(&(*adapter).IpAddressList.IpMask);
            let gw_str = cstr_from_bytes(&(*adapter).GatewayList.IpAddress);
            let desc = cstr_from_bytes(&(*adapter).Description);
            let name = cstr_from_bytes(&(*adapter).AdapterName);

            if let (Ok(ip), Ok(mask)) = (ip_str.parse::<Ipv4Addr>(), mask_str.parse::<Ipv4Addr>()) {
                if !ip.is_unspecified() && mask != Ipv4Addr::UNSPECIFIED {
                    let gw = gw_str.parse::<Ipv4Addr>().ok()
                        .filter(|g| !g.is_unspecified());

                    result.push(AdapterInfo {
                        name,
                        description: desc,
                        ip,
                        mask,
                        gateway: gw,
                        if_type: (*adapter).Type,
                    });
                }
            }

            adapter = (*adapter).Next;
        }
    }

    result
}

#[cfg(windows)]
fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

// ─── Linux implementation ────────────────────────────────────────────────────

/// Map a Linux ARPHRD_* hardware type (/sys/class/net/<if>/type) onto the MIB
/// IF_TYPE_* value the categorizer expects.
///
/// ARPHRD_NONE is what tun/tap and WireGuard devices report, so it maps to
/// IF_TYPE_TUNNEL — that is what makes wg0/tun0 categorize as a VPN even
/// though their names never match the description keywords.
#[cfg(not(windows))]
fn arphrd_to_if_type(arphrd: u32, is_wireless: bool) -> u32 {
    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;

    if is_wireless {
        return IF_TYPE_IEEE80211;
    }
    match arphrd {
        256 => IF_TYPE_SLIP,     // ARPHRD_SLIP
        512 => IF_TYPE_PPP,      // ARPHRD_PPP
        772 => IF_TYPE_LOOPBACK, // ARPHRD_LOOPBACK
        // ARPHRD_NONE / ARPHRD_VOID — tun, wg, and other point-to-point virtuals
        65534 | 65535 => IF_TYPE_TUNNEL,
        801..=803 => IF_TYPE_IEEE80211, // ARPHRD_IEEE80211*
        _ => IF_TYPE_ETHERNET_CSMACD,
    }
}

/// Enumerate all network adapters with valid IPv4 addresses.
/// Returns every adapter, including virtual ones (bridges, Docker, WireGuard).
///
/// The Windows adapter "description" is a vendor string; sysfs has no direct
/// equivalent, so we synthesise "<ifname> (<driver>)". That keeps the
/// description-keyword categorization working, since on Linux it is the
/// interface name that carries the meaning (docker0, tailscale0, br-lan).
#[cfg(not(windows))]
pub fn enumerate_all() -> Vec<AdapterInfo> {
    use crate::network::linux;
    use std::net::IpAddr;

    // Per-interface default gateways from the routing table.
    let mut gateways: std::collections::HashMap<String, Ipv4Addr> =
        std::collections::HashMap::new();
    for (dest, _mask, gw, iface) in linux::routes() {
        if dest.is_unspecified() && !gw.is_unspecified() {
            gateways.entry(iface).or_insert(gw);
        }
    }

    let mut result = Vec::new();
    for ifa in linux::ifaddrs() {
        // Only IPv4 addresses, matching the Windows implementation.
        let (ip, mask) = match (ifa.addr, ifa.netmask) {
            (IpAddr::V4(ip), Some(IpAddr::V4(mask))) => (ip, mask),
            _ => continue,
        };
        if ip.is_unspecified() || mask == Ipv4Addr::UNSPECIFIED {
            continue;
        }

        let name = ifa.name;
        let arphrd = linux::sysfs_attr(&name, "type")
            .and_then(|t| t.parse::<u32>().ok())
            .unwrap_or(1);
        let is_wireless =
            std::path::Path::new(&format!("/sys/class/net/{}/wireless", name)).exists();

        let description = match linux::interface_driver(&name) {
            Some(driver) => format!("{} ({})", name, driver),
            None => name.clone(),
        };

        result.push(AdapterInfo {
            gateway: gateways.get(&name).copied(),
            if_type: arphrd_to_if_type(arphrd, is_wireless),
            name,
            description,
            ip,
            mask,
        });
    }

    result
}
