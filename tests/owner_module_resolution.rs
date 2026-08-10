// Tests for issue #3: the Connections table gained a PID column and svchost
// sockets resolve their owning service via GetOwnerModuleFromTcp/UdpEntry.
// These tests exercise the real Win32 FFI path against a live socket owned by
// this test process, proving struct layouts and the two-call buffer pattern
// work on the running OS rather than only in theory.

#![allow(dead_code)]

#[path = "../src/types.rs"]
mod types;

#[path = "../src/utils.rs"]
mod utils;

mod network {
    #[path = "../../src/network/connections.rs"]
    pub mod connections;
}

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, TcpListener};

use types::{ConnProto, Connection, ModuleCache, PidCache, TcpState};

fn conn_for(pid: u32, local_port: u16, proto: ConnProto) -> Connection {
    Connection {
        proto,
        local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        local_port,
        remote_addr: None,
        remote_port: None,
        state: Some(TcpState::Listen),
        pid,
        process_name: String::new(),
        dns_hostname: None,
        module_name: None,
    }
}

/// Owning a real listening socket, the OWNER_MODULE table walk plus
/// GetOwnerModuleFromTcpEntry must resolve a module name for our own PID.
/// For a plain exe the module name is the executable name, which proves the
/// entire FFI chain (struct layout, table class 8, two-call sizing) works.
#[test]
fn resolves_module_for_own_live_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test socket");
    let port = listener.local_addr().unwrap().port();
    let my_pid = std::process::id();

    let mut conns = vec![conn_for(my_pid, port, ConnProto::Tcp)];
    let mut cache = ModuleCache::new();
    let pids: HashSet<u32> = [my_pid].into_iter().collect();

    network::connections::resolve_owner_modules(&mut conns, &pids, &mut cache);

    let resolved = conns[0].module_name.as_deref().unwrap_or("");
    assert!(
        !resolved.is_empty(),
        "expected a module name for our own listening socket (pid {}, port {})",
        my_pid,
        port
    );
    drop(listener);
}

/// Kernel sockets (PID 0) have no owner module; resolution must not invent
/// one and must not crash. Windows returns ERROR_NOT_FOUND for these.
#[test]
fn kernel_pid_yields_no_module() {
    let mut conns = vec![conn_for(0, 139, ConnProto::Tcp)];
    let mut cache = ModuleCache::new();
    let pids: HashSet<u32> = [0u32].into_iter().collect();

    network::connections::resolve_owner_modules(&mut conns, &pids, &mut cache);

    assert!(
        conns[0].module_name.is_none(),
        "PID 0 must never resolve to a module name"
    );
}

/// The cache must stay bounded by the live table: entries for sockets that
/// disappeared are pruned on the next resolve pass (no unbounded growth,
/// the same failure mode as the issue #5 DNS cache leak).
#[test]
fn module_cache_prunes_dead_sockets() {
    let mut cache = ModuleCache::new();
    cache.insert((99999, 12345, ConnProto::Tcp), Some("ghost".to_string()));
    cache.insert((99999, 12346, ConnProto::Udp), None);

    let mut conns: Vec<Connection> = Vec::new();
    let pids: HashSet<u32> = HashSet::new();
    network::connections::resolve_owner_modules(&mut conns, &pids, &mut cache);

    assert!(
        cache.is_empty(),
        "cache entries for dead sockets must be pruned, found {} left",
        cache.len()
    );
}

/// Only svchost.exe PIDs are selected for module resolution; regular
/// processes already show a meaningful exe name.
#[test]
fn service_host_pids_selects_only_svchost() {
    let conns = vec![
        conn_for(100, 1000, ConnProto::Tcp),
        conn_for(200, 2000, ConnProto::Tcp),
        conn_for(0, 139, ConnProto::Tcp),
    ];
    let mut pid_cache = PidCache::new();
    pid_cache.insert(100, "svchost.exe".to_string());
    pid_cache.insert(200, "chrome.exe".to_string());
    pid_cache.insert(0, "[Kernel]".to_string());

    let pids = network::connections::service_host_pids(&conns, &pid_cache);

    assert!(pids.contains(&100), "svchost pid must be selected");
    assert!(!pids.contains(&200), "regular exe must not be selected");
    assert!(!pids.contains(&0), "kernel pseudo-pid must not be selected");
}
