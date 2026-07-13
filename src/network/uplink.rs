//! Identify which network interfaces are real internet uplinks so that traffic
//! totals count the physical adapter once and ignore virtual overlays (issue
//! #6). See `speed::aggregate_interface_bytes` for how the set is applied.

use std::collections::HashSet;

use sysinfo::Networks;

use crate::network::speed::aggregate_interface_bytes;

/// Aggregate received/sent bytes across the machine's real uplinks.
/// Returns (total_recv, total_sent, most_active_interface_name).
pub fn get_network_bytes(networks: &Networks) -> (u64, u64, String) {
    let ifaces: Vec<(String, u64, u64)> = networks
        .iter()
        .map(|(name, data)| (name.clone(), data.total_received(), data.total_transmitted()))
        .collect();
    let uplinks = uplink_interface_names();
    aggregate_interface_bytes(&ifaces, uplinks.as_ref())
}

/// Friendly names of interfaces that are operationally up and have a default
/// gateway configured (i.e. can actually reach off-machine). Virtual switches,
/// NAT, loopback and idle tunnel adapters have no gateway and are excluded.
///
/// Returns `None` when the platform query is unavailable or fails, so callers
/// fall back to the name-based shadow heuristic rather than losing all totals.
#[cfg(windows)]
pub fn uplink_interface_names() -> Option<HashSet<String>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;

    let buf = adapters_buffer()?;
    let mut names = HashSet::new();
    // SAFETY: on success buf holds a valid linked list of IP_ADAPTER_ADDRESSES_LH.
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        let up = adapter.OperStatus == IfOperStatusUp;
        let has_gateway = !adapter.FirstGatewayAddress.is_null();
        if up && has_gateway {
            if let Some(name) = wide_to_string(adapter.FriendlyName) {
                names.insert(name);
            }
        }
        cur = adapter.Next;
    }
    if names.is_empty() {
        None
    } else {
        Some(names)
    }
}

#[cfg(not(windows))]
pub fn uplink_interface_names() -> Option<HashSet<String>> {
    None
}

/// Raw IPv4 address (network byte order) of the first up adapter that owns a
/// default gateway — the machine's real internet uplink. The packet sniffer
/// binds here so it captures the wire the internet traffic actually crosses;
/// resolving the hostname instead can hand back a Hyper-V/WSL or VPN adapter
/// address depending on registration order (issue #6).
#[cfg(windows)]
pub fn uplink_ipv4() -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let buf = adapters_buffer()?;
    // SAFETY: on success buf holds a valid linked list of IP_ADAPTER_ADDRESSES_LH.
    let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let adapter = unsafe { &*cur };
        let up = adapter.OperStatus == IfOperStatusUp;
        let has_gateway = !adapter.FirstGatewayAddress.is_null();
        if up && has_gateway {
            let mut uni = adapter.FirstUnicastAddress;
            while !uni.is_null() {
                // SAFETY: unicast entries and their sockaddr pointers are
                // owned by the same buffer.
                let entry = unsafe { &*uni };
                let sa = entry.Address.lpSockaddr;
                if !sa.is_null() {
                    let family = unsafe { (*sa).sa_family };
                    if family == AF_INET {
                        let sin = unsafe { &*(sa as *const SOCKADDR_IN) };
                        // S_un is a union of u32 / bytes / words over the
                        // same 4 octets; the u32 view is already in network
                        // byte order.
                        let raw = unsafe { sin.sin_addr.S_un.S_addr };
                        if raw != 0 {
                            return Some(raw);
                        }
                    }
                }
                uni = entry.Next;
            }
        }
        cur = adapter.Next;
    }
    None
}

#[cfg(not(windows))]
pub fn uplink_ipv4() -> Option<u32> {
    None
}

/// Fetch the adapter table via GetAdaptersAddresses (with gateway info).
/// Returns the raw buffer holding the IP_ADAPTER_ADDRESSES_LH linked list,
/// or None when the query fails.
#[cfg(windows)]
fn adapters_buffer() -> Option<Vec<u8>> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    const ERROR_SUCCESS: u32 = 0;
    const ERROR_BUFFER_OVERFLOW: u32 = 111;

    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;

    // Size the buffer, growing if the adapter set does not fit.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u8> = Vec::new();
    let ret = loop {
        buf.resize(size as usize, 0);
        // SAFETY: buf holds `size` bytes; GetAdaptersAddresses writes at most
        // `size` and, on overflow, updates `size` with the length it needs.
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if ret != ERROR_BUFFER_OVERFLOW || size as usize <= buf.len() {
            break ret;
        }
    };
    if ret != ERROR_SUCCESS {
        return None;
    }
    Some(buf)
}

/// Read a NUL-terminated UTF-16 string from a Windows PWSTR.
#[cfg(windows)]
fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: ptr points to a NUL-terminated wide string owned by the buffer.
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16(std::slice::from_raw_parts(ptr, len)).ok()
    }
}
