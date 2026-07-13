// Regression tests for issue #6 follow-up: WSL2 / Hyper-V VM traffic never
// appeared in Top Apps. NAT-forwarded flows are routed by WinNAT in the
// kernel: no host process owns a socket for them, and Windows raw sockets
// (SIO_RCVALL) never surface the forwarded packets, so per-packet
// attribution is impossible. The virtual switch (vEthernet) byte counters do
// carry every one of those bytes; their per-tick deltas are credited to the
// [wsl/vm] pseudo-app via credit_virtual. Separately, packets that fail to
// match the connection table are now held one tick and retried against the
// fresh table, so flows newer than the snapshot reach their real owner.

#![allow(dead_code)]

#[path = "../src/types.rs"]
mod types;

#[path = "../src/utils.rs"]
mod utils;

mod network {
    #[path = "../../src/network/bandwidth.rs"]
    pub mod bandwidth;
}

use network::bandwidth::{BandwidthTracker, VIRTUAL_APP};
use std::net::{IpAddr, Ipv4Addr};
use types::{ConnProto, Connection, PacketDirection, PacketSnippet, TcpState};

fn packet(src_port: u16, dst_port: u16, inbound: bool, bytes: usize) -> PacketSnippet {
    PacketSnippet {
        timestamp: chrono::Local::now().time(),
        direction: if inbound {
            PacketDirection::Inbound
        } else {
            PacketDirection::Outbound
        },
        src_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        dst_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        src_port,
        dst_port,
        protocol: ConnProto::Tcp,
        snippet: String::new(),
        payload_size: bytes,
        ttl: 64,
        ip_total_len: bytes as u16,
        ip_id: 0,
        tcp_flags: 0x18,
        tcp_seq: 0,
        tcp_ack_num: 0,
        tcp_window: 0,
        raw_payload: Vec::new(),
    }
}

fn conn(local_port: u16, remote_port: u16, process: &str) -> Connection {
    Connection {
        proto: ConnProto::Tcp,
        local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
        local_port,
        remote_addr: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        remote_port: Some(remote_port),
        state: Some(TcpState::Established),
        pid: 1234,
        process_name: process.to_string(),
        dns_hostname: None,
    }
}

/// Virtual switch counter deltas surface as the [wsl/vm] pseudo-app with
/// the switch's sent bytes as the VM's downloads and its received bytes as
/// the VM's uploads.
#[test]
fn vm_traffic_credited_to_virtual_app_with_correct_direction() {
    let mut tracker = BandwidthTracker::new();

    tracker.credit_virtual(104_000_000, 700_000);

    let app = tracker.apps.get(VIRTUAL_APP).expect("[wsl/vm] entry expected");
    assert_eq!(app.download_bytes, 104_000_000);
    assert_eq!(app.upload_bytes, 700_000);
}

/// Idle switches (zero deltas) must not create a [wsl/vm] entry.
#[test]
fn zero_vm_deltas_create_no_entry() {
    let mut tracker = BandwidthTracker::new();

    tracker.credit_virtual(0, 0);

    assert!(tracker.apps.is_empty());
}

/// Repeated ticks accumulate into the same pseudo-app entry.
#[test]
fn vm_credits_accumulate_across_ticks() {
    let mut tracker = BandwidthTracker::new();

    tracker.credit_virtual(1_000, 100);
    tracker.credit_virtual(2_000, 200);

    let app = tracker.apps.get(VIRTUAL_APP).expect("[wsl/vm] entry expected");
    assert_eq!(app.download_bytes, 3_000);
    assert_eq!(app.upload_bytes, 300);
}

/// A packet from a brand-new host connection that raced ahead of the
/// connection-table refresh must be attributed to its real process on the
/// retry tick instead of being dropped.
#[test]
fn race_window_packet_attributed_to_real_process_on_retry() {
    let mut tracker = BandwidthTracker::new();

    // Tick 1: table does not know the flow yet.
    let pkts = vec![packet(443, 50123, true, 200_000)];
    tracker.ingest_packets(&pkts, &[]);
    assert!(tracker.apps.is_empty());

    // Tick 2: the refreshed table now owns the flow.
    let conns = vec![conn(50123, 443, "curl.exe")];
    tracker.ingest_packets(&[], &conns);

    let app = tracker.apps.get("curl.exe").expect("curl.exe entry expected");
    assert_eq!(app.download_bytes, 200_000);
}

/// Packets that match nothing on the arrival tick and nothing on the retry
/// tick are dropped, not misattributed.
#[test]
fn persistently_unmatched_packets_are_dropped() {
    let mut tracker = BandwidthTracker::new();
    let pkts = vec![packet(443, 61000, true, 1_000_000)];

    tracker.ingest_packets(&pkts, &[]);
    tracker.ingest_packets(&[], &[]);
    tracker.ingest_packets(&[], &[]);

    assert!(tracker.apps.is_empty());
}

/// Ordinary host traffic keeps matching the connection table directly on the
/// tick it arrives.
#[test]
fn host_traffic_still_attributed_directly() {
    let mut tracker = BandwidthTracker::new();
    let conns = vec![conn(50000, 443, "curl.exe")];
    let pkts = vec![
        packet(443, 50000, true, 750_000),
        packet(50000, 443, false, 25_000),
    ];

    tracker.ingest_packets(&pkts, &conns);

    let app = tracker.apps.get("curl.exe").expect("curl.exe entry expected");
    assert_eq!(app.download_bytes, 750_000);
    assert_eq!(app.upload_bytes, 25_000);
    assert!(!tracker.apps.contains_key(VIRTUAL_APP));
}

/// Packets owned by a host process whose name could not be resolved (PID:
/// placeholder rows) are skipped on the retry path too.
#[test]
fn pid_placeholder_flows_stay_skipped() {
    let mut tracker = BandwidthTracker::new();
    let conns = vec![conn(50000, 443, "PID:9999")];
    let pkts = vec![packet(443, 50000, true, 300_000)];

    tracker.ingest_packets(&pkts, &conns);
    tracker.ingest_packets(&[], &conns);

    assert!(tracker.apps.is_empty());
}
