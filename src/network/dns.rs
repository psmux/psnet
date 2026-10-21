use std::collections::HashMap;
use std::net::IpAddr;

// ─── Windows DNS Resolver Cache ──────────────────────────────────────────────
//
// Two approaches to read the OS DNS cache:
// 1. DnsGetCacheDataTable (dnsapi.dll) — fast, undocumented but widely used
// 2. Parsing `ipconfig /displaydns` output — reliable documented fallback
//
// We use both: the API for every tick, and ipconfig as supplement.

#[cfg(windows)]
const DNS_TYPE_A: u16 = 1;
#[cfg(windows)]
const DNS_TYPE_AAAA: u16 = 28;

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct DNS_CACHE_ENTRY {
    pNext: *mut DNS_CACHE_ENTRY,
    pszName: *mut u16,
    wType: u16,
    wDataLength: u16,
    dwFlags: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct DNS_RECORD {
    pNext: *mut DNS_RECORD,
    pName: *mut u16,
    wType: u16,
    wDataLength: u16,
    dwFlags: u32,
    dwTtl: u32,
    dwReserved: u32,
    Data: DNS_RECORD_DATA,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
union DNS_RECORD_DATA {
    a: DNS_A_DATA,
    aaaa: DNS_AAAA_DATA,
    _pad: [u8; 64],
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_snake_case, non_camel_case_types)]
struct DNS_A_DATA {
    IpAddress: u32,
}

#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
#[allow(non_snake_case, non_camel_case_types)]
struct DNS_AAAA_DATA {
    Ip6Address: [u8; 16],
}

#[cfg(windows)]
const DNS_QUERY_NO_WIRE_QUERY: u32 = 0x10;

#[cfg(windows)]
#[link(name = "dnsapi")]
extern "system" {
    fn DnsGetCacheDataTable(
        pEntry: *mut *mut DNS_CACHE_ENTRY,
    ) -> i32;

    fn DnsQuery_W(
        pszName: *const u16,
        wType: u16,
        Options: u32,
        pExtra: *mut std::ffi::c_void,
        ppQueryResults: *mut *mut DNS_RECORD,
        pReserved: *mut std::ffi::c_void,
    ) -> i32;

    fn DnsRecordListFree(
        pRecordList: *mut DNS_RECORD,
        FreeType: i32,
    );

    fn DnsFree(pData: *mut std::ffi::c_void, FreeType: i32);
}

/// DNS_FREE_TYPE::DnsFreeFlat — frees a single flat allocation.
#[cfg(windows)]
const DNS_FREE_FLAT: i32 = 0;

/// Read the Windows DNS resolver cache via DnsGetCacheDataTable API.
#[cfg(windows)]
pub fn read_dns_cache_api() -> HashMap<IpAddr, String> {
    let mut reverse_map: HashMap<IpAddr, String> = HashMap::new();

    unsafe {
        let mut head: *mut DNS_CACHE_ENTRY = std::ptr::null_mut();
        let ok = DnsGetCacheDataTable(&mut head);
        if ok == 0 || head.is_null() {
            return reverse_map;
        }

        // Every node of the table (and each node's name string) is allocated
        // by dnsapi and must be released with DnsFree, or the whole table
        // leaks on every call. This runs every couple of seconds, so the
        // missing frees compounded to gigabytes over long sessions (issue #5).
        let mut entry = head;
        while !entry.is_null() {
            let next = (*entry).pNext;
            let name_ptr = (*entry).pszName;
            let wtype = (*entry).wType;

            if !name_ptr.is_null() && (wtype == DNS_TYPE_A || wtype == DNS_TYPE_AAAA) {
                let hostname = wstr_to_string(name_ptr);

                if !hostname.is_empty() && hostname != "." {
                    let name_wide = string_to_wstr(&hostname);
                    let mut records: *mut DNS_RECORD = std::ptr::null_mut();

                    let status = DnsQuery_W(
                        name_wide.as_ptr(),
                        wtype,
                        DNS_QUERY_NO_WIRE_QUERY,
                        std::ptr::null_mut(),
                        &mut records,
                        std::ptr::null_mut(),
                    );

                    if status == 0 && !records.is_null() {
                        let mut rec = records;
                        while !rec.is_null() {
                            let ip: Option<IpAddr> = if (*rec).wType == DNS_TYPE_A {
                                let raw = (*rec).Data.a.IpAddress;
                                // IP in network byte order stored in DWORD —
                                // to_ne_bytes() extracts original memory bytes
                                Some(IpAddr::V4(std::net::Ipv4Addr::from(raw.to_ne_bytes())))
                            } else if (*rec).wType == DNS_TYPE_AAAA {
                                let raw = (*rec).Data.aaaa.Ip6Address;
                                Some(IpAddr::V6(std::net::Ipv6Addr::from(raw)))
                            } else {
                                None
                            };

                            if let Some(ip) = ip {
                                reverse_map.entry(ip).or_insert_with(|| hostname.clone());
                            }

                            rec = (*rec).pNext;
                        }
                        DnsRecordListFree(records, 1);
                    }
                }
            }

            if !name_ptr.is_null() {
                DnsFree(name_ptr as *mut std::ffi::c_void, DNS_FREE_FLAT);
            }
            DnsFree(entry as *mut std::ffi::c_void, DNS_FREE_FLAT);
            entry = next;
        }
    }

    reverse_map
}

/// Parse `ipconfig /displaydns` output — reliable documented fallback.
#[cfg(windows)]
pub fn read_dns_cache_ipconfig() -> HashMap<IpAddr, String> {
    let mut reverse_map: HashMap<IpAddr, String> = HashMap::new();

    let output = std::process::Command::new("ipconfig")
        .arg("/displaydns")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return reverse_map,
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_name: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();

        // "Record Name . . . . . : www.google.com"
        if trimmed.starts_with("Record Name") {
            if let Some(val) = trimmed.splitn(2, ':').nth(1) {
                let name = val.trim().to_string();
                if !name.is_empty() && name != "." {
                    current_name = Some(name);
                }
            }
        }
        // "A (Host) Record . . . : 142.250.80.46"
        else if trimmed.starts_with("A (Host) Record") || trimmed.starts_with("A (Host)") {
            if let Some(ref name) = current_name {
                if let Some(val) = trimmed.splitn(2, ':').nth(1) {
                    if let Ok(ip) = val.trim().parse::<std::net::Ipv4Addr>() {
                        reverse_map.entry(IpAddr::V4(ip)).or_insert_with(|| name.clone());
                    }
                }
            }
        }
        // "AAAA Record . . . . . : 2607:f8b0:..."
        else if trimmed.starts_with("AAAA Record") {
            if let Some(ref name) = current_name {
                // IPv6 addresses contain colons — use splitn(2, ": ") to get the full addr
                if let Some(val) = trimmed.splitn(2, ": ").nth(1) {
                    let ip_str = val.trim();
                    if let Ok(ip) = ip_str.parse::<std::net::Ipv6Addr>() {
                        reverse_map.entry(IpAddr::V6(ip)).or_insert_with(|| name.clone());
                    }
                }
            }
        }
    }

    reverse_map
}

// ─── System DNS server detection ──────────────────────────────────────────────

/// Get the system-configured DNS servers by parsing `ipconfig /all`.
#[cfg(windows)]
pub fn get_system_dns_servers() -> Vec<IpAddr> {
    let output = std::process::Command::new("ipconfig")
        .arg("/all")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();
    let mut in_dns_section = false;

    for line in text.lines() {
        let trimmed = line.trim();

        // "DNS Servers . . . . . . . . . . . : 192.168.1.1"
        if trimmed.contains("DNS Servers") || trimmed.contains("DNS-Server") {
            in_dns_section = true;
            if let Some(val) = trimmed.splitn(2, ':').nth(1) {
                let ip_str = val.trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        } else if in_dns_section {
            // Continuation lines (indented IPs without a label)
            if trimmed.is_empty() || trimmed.contains(". .") || trimmed.contains(":") && trimmed.contains(". ") {
                in_dns_section = false;
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            } else {
                in_dns_section = false;
            }
        }
    }

    servers
}

// ─── Linux implementations ───────────────────────────────────────────────────

/// Linux exposes no readable system-wide DNS cache. glibc's resolver keeps no
/// shared cache, and when a caching resolver is present (dnsmasq on OpenWrt,
/// systemd-resolved elsewhere) its cache is private to that daemon with no
/// query API. Reverse names still come from the resolver via `lookup_addr`.
#[cfg(not(windows))]
pub fn read_dns_cache_api() -> HashMap<IpAddr, String> {
    HashMap::new()
}

/// No `ipconfig /displaydns` equivalent exists — see `read_dns_cache_api`.
#[cfg(not(windows))]
pub fn read_dns_cache_ipconfig() -> HashMap<IpAddr, String> {
    HashMap::new()
}

/// Get the system-configured DNS servers from /etc/resolv.conf.
///
/// Note that on a router running dnsmasq this usually reports 127.0.0.1 — the
/// local resolver — which is correct: that is what the system queries.
#[cfg(not(windows))]
pub fn get_system_dns_servers() -> Vec<IpAddr> {
    let text = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        // Strip any zone index ("fe80::1%eth0"), which IpAddr won't parse.
        let addr = rest.trim();
        let addr = addr.split('%').next().unwrap_or(addr);
        if let Ok(ip) = addr.parse::<IpAddr>() {
            if !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }

    servers
}

// ─── Well-known port → service name mapping ──────────────────────────────────

pub fn port_service_name(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("FTP-DATA"),
        21 => Some("FTP"),
        22 => Some("SSH"),
        23 => Some("TELNET"),
        25 => Some("SMTP"),
        53 => Some("DNS"),
        67 => Some("DHCP-S"),
        68 => Some("DHCP-C"),
        80 => Some("HTTP"),
        110 => Some("POP3"),
        123 => Some("NTP"),
        143 => Some("IMAP"),
        161 => Some("SNMP"),
        389 => Some("LDAP"),
        443 => Some("HTTPS"),
        445 => Some("SMB"),
        465 => Some("SMTPS"),
        587 => Some("SUBMIT"),
        636 => Some("LDAPS"),
        993 => Some("IMAPS"),
        995 => Some("POP3S"),
        1433 => Some("MSSQL"),
        1723 => Some("PPTP"),
        3306 => Some("MySQL"),
        3389 => Some("RDP"),
        5060 => Some("SIP"),
        5222 => Some("XMPP"),
        5432 => Some("PostgreSQL"),
        5900 => Some("VNC"),
        6379 => Some("Redis"),
        8080 => Some("HTTP-Alt"),
        8443 => Some("HTTPS-Alt"),
        9090 => Some("Prometheus"),
        9200 => Some("Elastic"),
        27017 => Some("MongoDB"),
        _ => None,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

#[cfg(windows)]
unsafe fn wstr_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
}

#[cfg(windows)]
fn string_to_wstr(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
