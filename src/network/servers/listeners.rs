//! Enumerates all listening TCP and UDP ports on the local machine.
//!
//! On Windows this uses `GetExtendedTcpTable` / `GetExtendedUdpTable` with the
//! `TCP_TABLE_OWNER_PID_LISTENER` class (value 3), which returns ONLY listening
//! sockets — much faster than `TCP_TABLE_OWNER_PID_ALL`. Typical call completes
//! in 1-5 ms.
//!
//! On Linux the same information comes from /proc/net/{tcp,tcp6,udp,udp6},
//! filtered to the LISTEN state, with ownership joined via socket inodes.

use std::collections::HashMap;
#[cfg(windows)]
use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(windows)]
use std::net::{Ipv4Addr, Ipv6Addr};

use sysinfo::{Pid, ProcessesToUpdate, System};

use super::types::ListenProto;

// ─── Raw listener record ─────────────────────────────────────────────────────

/// A single listening socket discovered via the OS tables.
#[derive(Debug, Clone)]
pub struct RawListener {
    pub proto: ListenProto,
    pub bind_addr: IpAddr,
    pub port: u16,
    pub pid: u32,
}

// ─── Process info resolved via sysinfo ───────────────────────────────────────

/// Process metadata resolved from a PID.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    /// Product name from the executable's VersionInfo resource (e.g. "Google Chrome").
    pub product_name: String,
    /// File description from the executable's VersionInfo resource.
    pub file_description: String,
    /// Company name from the executable's VersionInfo resource.
    pub company_name: String,
}

// ─── Windows FFI declarations ────────────────────────────────────────────────

#[cfg(windows)]
#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        pTcpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;

    fn GetExtendedUdpTable(
        pUdpTable: *mut u8,
        pdwSize: *mut u32,
        bOrder: i32,
        ulAf: u32,
        TableClass: u32,
        Reserved: u32,
    ) -> u32;
}

#[cfg(windows)]
const AF_INET: u32 = 2;
#[cfg(windows)]
const AF_INET6: u32 = 23;

/// TCP_TABLE_OWNER_PID_LISTENER — returns only LISTENING TCP rows.
#[cfg(windows)]
const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;

/// UDP_TABLE_OWNER_PID — returns all UDP rows (UDP has no "listen" state).
#[cfg(windows)]
const UDP_TABLE_OWNER_PID: u32 = 1;

#[cfg(windows)]
const NO_ERROR: u32 = 0;

// ─── Windows SCM FFI (advapi32) for svchost service resolution ──────────────

#[cfg(windows)]
#[link(name = "advapi32")]
extern "system" {
    fn OpenSCManagerW(
        lpMachineName: *const u16,
        lpDatabaseName: *const u16,
        dwDesiredAccess: u32,
    ) -> *mut std::ffi::c_void;

    fn EnumServicesStatusExW(
        hSCManager: *mut std::ffi::c_void,
        InfoLevel: u32,
        dwServiceType: u32,
        dwServiceState: u32,
        lpServices: *mut u8,
        cbBufSize: u32,
        pcbBytesNeeded: *mut u32,
        lpServicesReturned: *mut u32,
        lpResumeHandle: *mut u32,
        pszGroupName: *const u16,
    ) -> i32;

    fn CloseServiceHandle(hSCObject: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
const SC_MANAGER_ENUMERATE_SERVICE: u32 = 0x0004;
#[cfg(windows)]
const SC_ENUM_PROCESS_INFO: u32 = 0;
#[cfg(windows)]
const SERVICE_WIN32: u32 = 0x30;
#[cfg(windows)]
const SERVICE_ACTIVE: u32 = 0x01;

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct ENUM_SERVICE_STATUS_PROCESSW {
    lpServiceName: *const u16,
    lpDisplayName: *const u16,
    ServiceStatusProcess: SERVICE_STATUS_PROCESS,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct SERVICE_STATUS_PROCESS {
    dwServiceType: u32,
    dwCurrentState: u32,
    dwControlsAccepted: u32,
    dwWin32ExitCode: u32,
    dwServiceSpecificExitCode: u32,
    dwCheckPoint: u32,
    dwWaitHint: u32,
    dwProcessId: u32,
    dwServiceFlags: u32,
}

/// Read a null-terminated UTF-16 string from a raw pointer.
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

/// Service-name resolution is a Windows SCM concept with no Linux counterpart:
/// there is no equivalent of svchost.exe multiplexing many services into one
/// process, so a PID already maps to a single identifiable program via
/// /proc/<pid>/{comm,exe,cmdline}.
#[cfg(not(windows))]
pub fn resolve_service_names(_pids: &[u32]) -> HashMap<u32, Vec<String>> {
    HashMap::new()
}

/// Resolve Windows service names for a set of PIDs using the SCM API.
/// Returns a map of PID -> Vec<service_name> (lowercase).
/// Equivalent to `tasklist /svc` for the given PIDs.
#[cfg(windows)]
pub fn resolve_service_names(pids: &[u32]) -> HashMap<u32, Vec<String>> {
    let mut result: HashMap<u32, Vec<String>> = HashMap::new();
    if pids.is_empty() {
        return result;
    }

    let pid_set: HashSet<u32> = pids.iter().copied().collect();

    unsafe {
        let scm = OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        );
        if scm.is_null() {
            return result;
        }

        // First call to get required buffer size
        let mut bytes_needed: u32 = 0;
        let mut services_returned: u32 = 0;
        let mut resume_handle: u32 = 0;

        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );

        if bytes_needed == 0 {
            CloseServiceHandle(scm);
            return result;
        }

        // Allocate buffer and enumerate
        let buf_size = bytes_needed;
        let mut buf = vec![0u8; buf_size as usize];
        resume_handle = 0;
        services_returned = 0;

        let ret = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_ACTIVE,
            buf.as_mut_ptr(),
            buf_size,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );

        if ret == 0 && services_returned == 0 {
            CloseServiceHandle(scm);
            return result;
        }

        let entries = std::slice::from_raw_parts(
            buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
            services_returned as usize,
        );

        for entry in entries {
            let pid = entry.ServiceStatusProcess.dwProcessId;
            if pid == 0 || !pid_set.contains(&pid) {
                continue;
            }
            let name = wstr_to_string(entry.lpServiceName).to_lowercase();
            result.entry(pid).or_default().push(name);
        }

        CloseServiceHandle(scm);
    }

    result
}

// ─── Windows Version Info FFI (version.dll) ─────────────────────────────────

#[cfg(windows)]
#[link(name = "version")]
extern "system" {
    fn GetFileVersionInfoSizeW(lptstrFilename: *const u16, lpdwHandle: *mut u32) -> u32;
    fn GetFileVersionInfoW(
        lptstrFilename: *const u16,
        dwHandle: u32,
        dwLen: u32,
        lpData: *mut u8,
    ) -> i32;
    fn VerQueryValueW(
        pBlock: *const u8,
        lpSubBlock: *const u16,
        lplpBuffer: *mut *const u8,
        puLen: *mut u32,
    ) -> i32;
}

/// Product info extracted from a Windows PE executable's VersionInfo resource.
#[derive(Debug, Clone, Default)]
pub struct ExeVersionInfo {
    pub product_name: String,
    pub file_description: String,
    pub company_name: String,
}

/// Encode a Rust string as null-terminated UTF-16 for Windows API calls.
#[cfg(windows)]
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ELF binaries carry no equivalent of the PE VersionInfo resource — there is
/// no standard place a Linux executable records its product/company name — so
/// the UI falls back to the process and executable names.
#[cfg(not(windows))]
pub fn read_exe_version_info(_exe_path: &str) -> Option<ExeVersionInfo> {
    None
}

/// Read VersionInfo strings from a PE executable file.
/// Returns None if the file has no version resource or cannot be read.
#[cfg(windows)]
pub fn read_exe_version_info(exe_path: &str) -> Option<ExeVersionInfo> {
    if exe_path.is_empty() {
        return None;
    }
    let wide_path = to_wide(exe_path);
    unsafe {
        let mut handle: u32 = 0;
        let size = GetFileVersionInfoSizeW(wide_path.as_ptr(), &mut handle);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if GetFileVersionInfoW(wide_path.as_ptr(), 0, size, buf.as_mut_ptr()) == 0 {
            return None;
        }

        // Try to find the translation table to get the right language/codepage
        let translation_key = to_wide("\\VarFileInfo\\Translation");
        let mut trans_ptr: *const u8 = std::ptr::null();
        let mut trans_len: u32 = 0;
        let has_translation = VerQueryValueW(
            buf.as_ptr(),
            translation_key.as_ptr(),
            &mut trans_ptr,
            &mut trans_len,
        ) != 0 && trans_len >= 4;

        // Build the lang/codepage prefix
        let lang_cp = if has_translation {
            let lang = *(trans_ptr as *const u16);
            let cp = *((trans_ptr as *const u16).add(1));
            format!("{:04x}{:04x}", lang, cp)
        } else {
            // Fallback: English US, Unicode codepage
            "040904b0".to_string()
        };

        let mut info = ExeVersionInfo::default();

        // Read each string field
        for (field, target) in [
            ("ProductName", &mut info.product_name),
            ("FileDescription", &mut info.file_description),
            ("CompanyName", &mut info.company_name),
        ] {
            let sub_key = to_wide(&format!("\\StringFileInfo\\{}\\{}", lang_cp, field));
            let mut val_ptr: *const u8 = std::ptr::null();
            let mut val_len: u32 = 0;
            if VerQueryValueW(buf.as_ptr(), sub_key.as_ptr(), &mut val_ptr, &mut val_len) != 0
                && val_len > 0
                && !val_ptr.is_null()
            {
                // val_len includes null terminator, in characters (u16)
                let chars = val_len.saturating_sub(1) as usize;
                let slice = std::slice::from_raw_parts(val_ptr as *const u16, chars);
                *target = String::from_utf16_lossy(slice);
            }
        }

        // If we got nothing with the detected translation, try the common fallback
        if info.product_name.is_empty() && info.file_description.is_empty() && has_translation {
            let fallback_cp = "040904b0";
            for (field, target) in [
                ("ProductName", &mut info.product_name),
                ("FileDescription", &mut info.file_description),
                ("CompanyName", &mut info.company_name),
            ] {
                let sub_key = to_wide(&format!("\\StringFileInfo\\{}\\{}", fallback_cp, field));
                let mut val_ptr: *const u8 = std::ptr::null();
                let mut val_len: u32 = 0;
                if VerQueryValueW(buf.as_ptr(), sub_key.as_ptr(), &mut val_ptr, &mut val_len) != 0
                    && val_len > 0
                    && !val_ptr.is_null()
                {
                    let chars = val_len.saturating_sub(1) as usize;
                    let slice = std::slice::from_raw_parts(val_ptr as *const u16, chars);
                    *target = String::from_utf16_lossy(slice);
                }
            }
        }

        if info.product_name.is_empty() && info.file_description.is_empty() {
            return None;
        }
        Some(info)
    }
}

// ─── MIB structs (repr C, matching Windows layout) ───────────────────────────

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCPROW_OWNER_PID {
    dwState: u32,
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwRemoteAddr: u32,
    dwRemotePort: u32,
    dwOwningPid: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCPROW_OWNER_PID; 1],
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCP6ROW_OWNER_PID {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    ucRemoteAddr: [u8; 16],
    dwRemoteScopeId: u32,
    dwRemotePort: u32,
    dwState: u32,
    dwOwningPid: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_TCP6TABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_TCP6ROW_OWNER_PID; 1],
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDPROW_OWNER_PID {
    dwLocalAddr: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDPTABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_UDPROW_OWNER_PID; 1],
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDP6ROW_OWNER_PID {
    ucLocalAddr: [u8; 16],
    dwLocalScopeId: u32,
    dwLocalPort: u32,
    dwOwningPid: u32,
}

#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct MIB_UDP6TABLE_OWNER_PID {
    dwNumEntries: u32,
    table: [MIB_UDP6ROW_OWNER_PID; 1],
}

// ─── Port byte-order conversion ──────────────────────────────────────────────

/// Convert a port value from network byte order (as stored in MIB tables)
/// to host byte order. The Windows API stores ports in a u32 where only the
/// lower 16 bits matter, but those 16 bits are in big-endian order.
#[cfg(windows)]
#[inline]
fn port_from_raw(raw: u32) -> u16 {
    (((raw >> 8) & 0xFF) | ((raw & 0xFF) << 8)) as u16
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Enumerate all listening TCP and UDP ports. Fast (~1-5 ms).
#[cfg(windows)]
pub fn enumerate_listeners() -> Vec<RawListener> {
    let mut result = Vec::new();
    enumerate_tcp4_listeners(&mut result);
    enumerate_tcp6_listeners(&mut result);
    enumerate_udp4_listeners(&mut result);
    enumerate_udp6_listeners(&mut result);
    result
}

/// Enumerate all listening TCP and UDP ports from procfs.
///
/// TCP rows are filtered to state 0x0A (LISTEN), the equivalent of asking
/// Windows for the TCP_TABLE_OWNER_PID_LISTENER class. All UDP rows are
/// returned, matching UDP_TABLE_OWNER_PID — UDP has no listen state.
#[cfg(not(windows))]
pub fn enumerate_listeners() -> Vec<RawListener> {
    use crate::network::linux;

    /// Linux TCP_LISTEN, from include/net/tcp_states.h.
    const TCP_LISTEN: u8 = 10;

    let owners = linux::socket_inode_to_pid();
    let mut result = Vec::new();

    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for e in linux::read_socket_table(path) {
            if e.state != TCP_LISTEN {
                continue;
            }
            result.push(RawListener {
                proto: ListenProto::Tcp,
                bind_addr: e.local_addr,
                port: e.local_port,
                pid: owners.get(&e.inode).copied().unwrap_or(0),
            });
        }
    }

    for path in ["/proc/net/udp", "/proc/net/udp6"] {
        for e in linux::read_socket_table(path) {
            result.push(RawListener {
                proto: ListenProto::Udp,
                bind_addr: e.local_addr,
                port: e.local_port,
                pid: owners.get(&e.inode).copied().unwrap_or(0),
            });
        }
    }

    result
}

/// Resolve process details for a set of PIDs.
/// Returns `HashMap<pid, ProcessInfo>` with name, exe path, and command line.
///
/// For svchost.exe processes where the command line is empty (common when running
/// without elevated privileges), queries the Windows Service Control Manager to
/// resolve the hosted service name(s) and populates the cmdline field.
pub fn resolve_process_info(pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    let mut map = HashMap::new();
    if pids.is_empty() {
        return map;
    }

    let mut sys = System::new();
    let sysinfo_pids: Vec<Pid> = pids.iter().map(|&p| Pid::from_u32(p)).collect();
    sys.refresh_processes(ProcessesToUpdate::Some(&sysinfo_pids), true);

    // Collect svchost PIDs that need service name resolution
    let mut svchost_pids: Vec<u32> = Vec::new();

    // Cache VersionInfo by exe path to avoid reading the same file multiple times
    let mut version_cache: HashMap<String, Option<ExeVersionInfo>> = HashMap::new();

    for &pid in pids {
        if let Some(proc) = sys.process(Pid::from_u32(pid)) {
            let name = proc.name().to_string_lossy().to_string();
            let exe_path = proc
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmdline = proc.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" ");

            if name.eq_ignore_ascii_case("svchost.exe") && cmdline.is_empty() {
                svchost_pids.push(pid);
            }

            // Read VersionInfo from the exe (cached per path)
            let ver_info = version_cache
                .entry(exe_path.clone())
                .or_insert_with(|| read_exe_version_info(&exe_path))
                .clone()
                .unwrap_or_default();

            map.insert(pid, ProcessInfo {
                name,
                exe_path,
                cmdline,
                product_name: ver_info.product_name,
                file_description: ver_info.file_description,
                company_name: ver_info.company_name,
            });
        }
    }

    // Resolve service names for svchost.exe processes with empty cmdlines
    if !svchost_pids.is_empty() {
        let svc_map = resolve_service_names(&svchost_pids);
        for (pid, services) in svc_map {
            if let Some(info) = map.get_mut(&pid) {
                if info.cmdline.is_empty() {
                    info.cmdline = format!("svchost.exe -k {}", services.join(","));
                }
            }
        }
    }

    map
}

// ─── TCP IPv4 listeners ──────────────────────────────────────────────────────

#[cfg(windows)]
fn enumerate_tcp4_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Tcp,
                bind_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── TCP IPv6 listeners ──────────────────────────────────────────────────────

#[cfg(windows)]
fn enumerate_tcp6_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Tcp,
                bind_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── UDP IPv4 listeners ──────────────────────────────────────────────────────

#[cfg(windows)]
fn enumerate_udp4_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Udp,
                bind_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}

// ─── UDP IPv6 listeners ──────────────────────────────────────────────────────

#[cfg(windows)]
fn enumerate_udp6_listeners(result: &mut Vec<RawListener>) {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if size == 0 {
            return;
        }

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr(),
            &mut size,
            0,
            AF_INET6,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != NO_ERROR {
            return;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
        let num = table.dwNumEntries as usize;
        if num == 0 {
            return;
        }
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), num);

        for row in rows {
            result.push(RawListener {
                proto: ListenProto::Udp,
                bind_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                port: port_from_raw(row.dwLocalPort),
                pid: row.dwOwningPid,
            });
        }
    }
}
