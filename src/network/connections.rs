use std::collections::HashSet;

use crate::types::{ConnProto, Connection, ModuleCache, PidCache, TcpState};

use sysinfo::{Pid, ProcessesToUpdate, System};

// ─── Platform socket-table backend ───────────────────────────────────────────
//
// `platform` provides the three operations the rest of this module needs:
//   query_process_image(pid) -> Option<(full_path, exe_name)>
//   fetch_all(&mut Vec<Connection>)
//   resolve_modules(&pids, &mut ModuleCache)
// backed by iphlpapi on Windows and by procfs on Linux.

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::utils::ntohs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ─── Win32 API structs ───────────────────────────────────────────────────

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

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCPTABLE_OWNER_PID {
        dwNumEntries: u32,
        table: [MIB_TCPROW_OWNER_PID; 1],
    }

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

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCP6TABLE_OWNER_PID {
        dwNumEntries: u32,
        table: [MIB_TCP6ROW_OWNER_PID; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDPROW_OWNER_PID {
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwOwningPid: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDPTABLE_OWNER_PID {
        dwNumEntries: u32,
        table: [MIB_UDPROW_OWNER_PID; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDP6ROW_OWNER_PID {
        ucLocalAddr: [u8; 16],
        dwLocalScopeId: u32,
        dwLocalPort: u32,
        dwOwningPid: u32,
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDP6TABLE_OWNER_PID {
        dwNumEntries: u32,
        table: [MIB_UDP6ROW_OWNER_PID; 1],
    }

    // ─── OWNER_MODULE variants (for GetOwnerModuleFrom*Entry) ────────────────

    const TCPIP_OWNING_MODULE_SIZE: usize = 16;

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCPROW_OWNER_MODULE {
        dwState: u32,
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwRemoteAddr: u32,
        dwRemotePort: u32,
        dwOwningPid: u32,
        liCreateTimestamp: i64,
        OwningModuleInfo: [u64; TCPIP_OWNING_MODULE_SIZE],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCPTABLE_OWNER_MODULE {
        dwNumEntries: u32,
        table: [MIB_TCPROW_OWNER_MODULE; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCP6ROW_OWNER_MODULE {
        ucLocalAddr: [u8; 16],
        dwLocalScopeId: u32,
        dwLocalPort: u32,
        ucRemoteAddr: [u8; 16],
        dwRemoteScopeId: u32,
        dwRemotePort: u32,
        dwState: u32,
        dwOwningPid: u32,
        liCreateTimestamp: i64,
        OwningModuleInfo: [u64; TCPIP_OWNING_MODULE_SIZE],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_TCP6TABLE_OWNER_MODULE {
        dwNumEntries: u32,
        table: [MIB_TCP6ROW_OWNER_MODULE; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDPROW_OWNER_MODULE {
        dwLocalAddr: u32,
        dwLocalPort: u32,
        dwOwningPid: u32,
        liCreateTimestamp: i64,
        dwFlags: i32,
        OwningModuleInfo: [u64; TCPIP_OWNING_MODULE_SIZE],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDPTABLE_OWNER_MODULE {
        dwNumEntries: u32,
        table: [MIB_UDPROW_OWNER_MODULE; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDP6ROW_OWNER_MODULE {
        ucLocalAddr: [u8; 16],
        dwLocalScopeId: u32,
        dwLocalPort: u32,
        dwOwningPid: u32,
        liCreateTimestamp: i64,
        dwFlags: i32,
        OwningModuleInfo: [u64; TCPIP_OWNING_MODULE_SIZE],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct MIB_UDP6TABLE_OWNER_MODULE {
        dwNumEntries: u32,
        table: [MIB_UDP6ROW_OWNER_MODULE; 1],
    }

    #[repr(C)]
    #[allow(non_snake_case, non_camel_case_types)]
    struct TCPIP_OWNER_MODULE_BASIC_INFO {
        pModuleName: *mut u16,
        pModulePath: *mut u16,
    }

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
    const UDP_TABLE_OWNER_PID: u32 = 1;
    const TCP_TABLE_OWNER_MODULE_ALL: u32 = 8;
    const UDP_TABLE_OWNER_MODULE: u32 = 2;
    const TCPIP_OWNER_MODULE_INFO_BASIC: u32 = 0;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

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
        fn GetOwnerModuleFromTcpEntry(
            pTcpEntry: *const MIB_TCPROW_OWNER_MODULE,
            Class: u32,
            pBuffer: *mut u8,
            pdwSize: *mut u32,
        ) -> u32;
        fn GetOwnerModuleFromTcp6Entry(
            pTcpEntry: *const MIB_TCP6ROW_OWNER_MODULE,
            Class: u32,
            pBuffer: *mut u8,
            pdwSize: *mut u32,
        ) -> u32;
        fn GetOwnerModuleFromUdpEntry(
            pUdpEntry: *const MIB_UDPROW_OWNER_MODULE,
            Class: u32,
            pBuffer: *mut u8,
            pdwSize: *mut u32,
        ) -> u32;
        fn GetOwnerModuleFromUdp6Entry(
            pUdpEntry: *const MIB_UDP6ROW_OWNER_MODULE,
            Class: u32,
            pBuffer: *mut u8,
            pdwSize: *mut u32,
        ) -> u32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> *mut std::ffi::c_void;
        fn CloseHandle(hObject: *mut std::ffi::c_void) -> i32;
        fn QueryFullProcessImageNameW(
            hProcess: *mut std::ffi::c_void,
            dwFlags: u32,
            lpExeName: *mut u16,
            lpdwSize: *mut u32,
        ) -> i32;
    }

    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

    /// Returns (full_path, exe_name) for a PID, or None if unavailable.
    pub(super) fn query_process_image(pid: u32) -> Option<(String, String)> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut size: u32 = 1024;
            let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
            CloseHandle(handle);
            if ok == 0 || size == 0 {
                return None;
            }
            let full_path = String::from_utf16_lossy(&buf[..size as usize]);
            let exe_name = full_path.rsplit('\\').next().unwrap_or(&full_path).to_string();
            Some((full_path, exe_name))
        }
    }

    pub(super) fn fetch_all(conns: &mut Vec<Connection>) {
        fetch_tcp4(conns);
        fetch_tcp6(conns);
        fetch_udp4(conns);
        fetch_udp6(conns);
    }

    fn fetch_tcp4(conns: &mut Vec<Connection>) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if ret != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(), table.dwNumEntries as usize,
            );
            for row in rows {
                conns.push(Connection {
                    proto: ConnProto::Tcp,
                    local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    local_port: ntohs(row.dwLocalPort),
                    remote_addr: Some(IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes()))),
                    remote_port: Some(ntohs(row.dwRemotePort)),
                    state: Some(TcpState::from_raw(row.dwState)),
                    pid: row.dwOwningPid,
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }
    }

    fn fetch_tcp6(conns: &mut Vec<Connection>) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedTcpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0,
            );
            if ret != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(), table.dwNumEntries as usize,
            );
            for row in rows {
                conns.push(Connection {
                    proto: ConnProto::Tcp,
                    local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    local_port: ntohs(row.dwLocalPort),
                    remote_addr: Some(IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr))),
                    remote_port: Some(ntohs(row.dwRemotePort)),
                    state: Some(TcpState::from_raw(row.dwState)),
                    pid: row.dwOwningPid,
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }
    }

    fn fetch_udp4(conns: &mut Vec<Connection>) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_PID, 0,
            );
            if ret != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(), table.dwNumEntries as usize,
            );
            for row in rows {
                conns.push(Connection {
                    proto: ConnProto::Udp,
                    local_addr: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    local_port: ntohs(row.dwLocalPort),
                    remote_addr: None,
                    remote_port: None,
                    state: None,
                    pid: row.dwOwningPid,
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }
    }

    fn fetch_udp6(conns: &mut Vec<Connection>) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            let ret = GetExtendedUdpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0,
            );
            if ret != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let rows = std::slice::from_raw_parts(
                table.table.as_ptr(), table.dwNumEntries as usize,
            );
            for row in rows {
                conns.push(Connection {
                    proto: ConnProto::Udp,
                    local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    local_port: ntohs(row.dwLocalPort),
                    remote_addr: None,
                    remote_port: None,
                    state: None,
                    pid: row.dwOwningPid,
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }
    }

    // ─── Owner module resolution (svchost service names) ─────────────────────

    pub(super) fn resolve_modules(pids: &HashSet<u32>, cache: &mut ModuleCache) {
        resolve_tcp4_modules(pids, cache);
        resolve_tcp6_modules(pids, cache);
        resolve_udp4_modules(pids, cache);
        resolve_udp6_modules(pids, cache);
    }

    /// Two-call pattern shared by all four GetOwnerModuleFrom*Entry wrappers:
    /// first call sizes the buffer, second fills TCPIP_OWNER_MODULE_BASIC_INFO
    /// (two pointers into the same buffer holding the name/path strings).
    unsafe fn read_module_name(call: &dyn Fn(*mut u8, *mut u32) -> u32) -> Option<String> {
        let mut size: u32 = 0;
        let ret = call(std::ptr::null_mut(), &mut size);
        if ret != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        if call(buf.as_mut_ptr(), &mut size) != 0 {
            return None;
        }
        let info = &*(buf.as_ptr() as *const TCPIP_OWNER_MODULE_BASIC_INFO);
        if info.pModuleName.is_null() {
            return None;
        }
        let mut len = 0usize;
        while *info.pModuleName.add(len) != 0 {
            len += 1;
        }
        let name = String::from_utf16_lossy(std::slice::from_raw_parts(info.pModuleName, len));
        let name = name.trim();
        if name.is_empty() { None } else { Some(name.to_string()) }
    }

    fn resolve_tcp4_modules(pids: &HashSet<u32>, cache: &mut ModuleCache) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0,
            ) != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_MODULE);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                if !pids.contains(&row.dwOwningPid) { continue; }
                let key = (row.dwOwningPid, ntohs(row.dwLocalPort), ConnProto::Tcp);
                if cache.contains_key(&key) { continue; }
                let name = read_module_name(&|b, s| {
                    GetOwnerModuleFromTcpEntry(row, TCPIP_OWNER_MODULE_INFO_BASIC, b, s)
                });
                cache.insert(key, name);
            }
        }
    }

    fn resolve_tcp6_modules(pids: &HashSet<u32>, cache: &mut ModuleCache) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedTcpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedTcpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0,
            ) != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_MODULE);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                if !pids.contains(&row.dwOwningPid) { continue; }
                let key = (row.dwOwningPid, ntohs(row.dwLocalPort), ConnProto::Tcp);
                if cache.contains_key(&key) { continue; }
                let name = read_module_name(&|b, s| {
                    GetOwnerModuleFromTcp6Entry(row, TCPIP_OWNER_MODULE_INFO_BASIC, b, s)
                });
                cache.insert(key, name);
            }
        }
    }

    fn resolve_udp4_modules(pids: &HashSet<u32>, cache: &mut ModuleCache) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_MODULE, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET, UDP_TABLE_OWNER_MODULE, 0,
            ) != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_MODULE);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                if !pids.contains(&row.dwOwningPid) { continue; }
                let key = (row.dwOwningPid, ntohs(row.dwLocalPort), ConnProto::Udp);
                if cache.contains_key(&key) { continue; }
                let name = read_module_name(&|b, s| {
                    GetOwnerModuleFromUdpEntry(row, TCPIP_OWNER_MODULE_INFO_BASIC, b, s)
                });
                cache.insert(key, name);
            }
        }
    }

    fn resolve_udp6_modules(pids: &HashSet<u32>, cache: &mut ModuleCache) {
        unsafe {
            let mut size: u32 = 0;
            GetExtendedUdpTable(
                std::ptr::null_mut(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_MODULE, 0,
            );
            if size == 0 { return; }
            let mut buf = vec![0u8; size as usize];
            if GetExtendedUdpTable(
                buf.as_mut_ptr(), &mut size, 0, AF_INET6, UDP_TABLE_OWNER_MODULE, 0,
            ) != 0 { return; }
            let table = &*(buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_MODULE);
            let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
            for row in rows {
                if !pids.contains(&row.dwOwningPid) { continue; }
                let key = (row.dwOwningPid, ntohs(row.dwLocalPort), ConnProto::Udp);
                if cache.contains_key(&key) { continue; }
                let name = read_module_name(&|b, s| {
                    GetOwnerModuleFromUdp6Entry(row, TCPIP_OWNER_MODULE_INFO_BASIC, b, s)
                });
                cache.insert(key, name);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use crate::network::linux;

    /// Returns (full_path, exe_name) for a PID, or None if unavailable.
    ///
    /// /proc/<pid>/exe is the equivalent of QueryFullProcessImageNameW. Kernel
    /// threads have no exe link, so we fall back to the (15-char truncated)
    /// name in /proc/<pid>/comm and report no path.
    pub(super) fn query_process_image(pid: u32) -> Option<(String, String)> {
        if let Some(path) = linux::process_exe(pid) {
            let name = path.rsplit('/').next().unwrap_or(&path).to_string();
            return Some((path, name));
        }
        linux::process_name(pid).map(|name| (String::new(), name))
    }

    pub(super) fn fetch_all(conns: &mut Vec<Connection>) {
        // Linux does not record socket ownership in the socket table itself,
        // so build the inode -> pid map once and join against it.
        let owners = linux::socket_inode_to_pid();

        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            for e in linux::read_socket_table(path) {
                conns.push(Connection {
                    proto: ConnProto::Tcp,
                    local_addr: e.local_addr,
                    local_port: e.local_port,
                    remote_addr: Some(e.remote_addr),
                    remote_port: Some(e.remote_port),
                    state: Some(TcpState::from_raw(linux::tcp_state_to_mib(e.state))),
                    pid: owners.get(&e.inode).copied().unwrap_or(0),
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }

        for path in ["/proc/net/udp", "/proc/net/udp6"] {
            for e in linux::read_socket_table(path) {
                // Windows' UDP table carries no peer at all; on Linux a peer is
                // present only for connected UDP sockets, so report it when set
                // and otherwise match the Windows shape.
                let connected = e.remote_port != 0;
                conns.push(Connection {
                    proto: ConnProto::Udp,
                    local_addr: e.local_addr,
                    local_port: e.local_port,
                    remote_addr: if connected { Some(e.remote_addr) } else { None },
                    remote_port: if connected { Some(e.remote_port) } else { None },
                    state: None,
                    pid: owners.get(&e.inode).copied().unwrap_or(0),
                    process_name: String::new(),
                    dns_hostname: None,
                    module_name: None,
                });
            }
        }
    }

    /// Windows asks the TCP/IP stack which service inside a shared svchost
    /// process owns a socket. Linux has no shared service host: every daemon
    /// is its own process, so the process name already says what owns the
    /// socket and there is nothing further to resolve.
    pub(super) fn resolve_modules(_pids: &HashSet<u32>, _cache: &mut ModuleCache) {}
}

// ─── Process name resolution ─────────────────────────────────────────────────

pub fn get_process_name(pid: u32) -> String {
    if pid == 0 { return "[Kernel]".to_string(); }
    #[cfg(windows)]
    if pid == 4 { return "System".to_string(); }
    platform::query_process_image(pid)
        .map(|(_, name)| name)
        .unwrap_or_else(|| format!("PID:{}", pid))
}

/// Returns the full executable path for a PID (e.g. C:\...\chrome.exe).
/// Used by the firewall to create rules that actually match the process.
pub fn get_process_full_path(pid: u32) -> Option<String> {
    if pid == 0 { return None; }
    #[cfg(windows)]
    if pid == 4 { return None; }
    platform::query_process_image(pid)
        .map(|(path, _)| path)
        .filter(|path| !path.is_empty())
}

// ─── Fetch all connections ───────────────────────────────────────────────────

pub fn fetch_connections(pid_cache: &mut PidCache) -> Vec<Connection> {
    let mut conns = Vec::with_capacity(512);

    platform::fetch_all(&mut conns);

    // Collect PIDs that need resolution
    let unresolved: Vec<u32> = conns.iter()
        .map(|c| c.pid)
        .filter(|pid| !pid_cache.contains_key(pid))
        .collect();

    if !unresolved.is_empty() {
        // Try the native API first, then fall back to sysinfo for failures
        let mut needs_sysinfo = Vec::new();
        for &pid in &unresolved {
            let name = get_process_name(pid);
            if name.starts_with("PID:") {
                needs_sysinfo.push(pid);
            } else {
                pid_cache.insert(pid, name);
            }
        }

        // Sysinfo fallback for unresolved PIDs
        if !needs_sysinfo.is_empty() {
            let mut sys = System::new();
            let pids: Vec<Pid> = needs_sysinfo.iter().map(|&p| Pid::from_u32(p)).collect();
            sys.refresh_processes(ProcessesToUpdate::Some(&pids), true);
            for &pid in &needs_sysinfo {
                if let Some(proc) = sys.process(Pid::from_u32(pid)) {
                    pid_cache.insert(pid, proc.name().to_string_lossy().to_string());
                }
                // Don't cache failures — retry next tick
            }
        }
    }

    for conn in &mut conns {
        if let Some(name) = pid_cache.get(&conn.pid) {
            conn.process_name = name.clone();
        } else if conn.pid != 0 {
            conn.process_name = format!("PID:{}", conn.pid);
        }
    }

    conns
}

// ─── Owner module resolution (svchost service names) ─────────────────────────

/// PIDs in the current table that host multiple services behind one exe name,
/// where the exe alone does not tell the user what owns the socket.
pub fn service_host_pids(conns: &[Connection], pid_cache: &PidCache) -> HashSet<u32> {
    conns
        .iter()
        .filter(|c| {
            pid_cache
                .get(&c.pid)
                .map(|n| n.eq_ignore_ascii_case("svchost.exe"))
                .unwrap_or(false)
        })
        .map(|c| c.pid)
        .collect()
}

/// Resolves the owning service/module for sockets whose PID is in `pids` and
/// applies results to `conns`. Failed lookups are cached as `None` so they are
/// not retried every tick; entries for dead sockets are pruned to keep the
/// cache bounded by the live table size.
pub fn resolve_owner_modules(
    conns: &mut [Connection],
    pids: &HashSet<u32>,
    module_cache: &mut ModuleCache,
) {
    if !pids.is_empty() {
        platform::resolve_modules(pids, module_cache);
    }

    let mut live_keys: HashSet<(u32, u16, ConnProto)> = HashSet::with_capacity(conns.len());
    for conn in conns.iter_mut() {
        let key = (conn.pid, conn.local_port, conn.proto.clone());
        if let Some(Some(name)) = module_cache.get(&key) {
            conn.module_name = Some(name.clone());
        }
        live_keys.insert(key);
    }
    module_cache.retain(|k, _| live_keys.contains(k));
}
