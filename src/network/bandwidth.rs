//! Per-application bandwidth tracking.
//!
//! Tracks download/upload bytes per process by correlating packet sniffer
//! data with the connection table. Maintains rolling speed samples for
//! mini-sparklines per application.

use std::collections::HashMap;

use chrono::Local;

use crate::types::{AppBandwidth, Connection, ConnProto, PacketSnippet, PacketDirection, TcpState};

/// Pseudo-app bucket for NAT-forwarded traffic (WSL2, Hyper-V VMs). Those
/// flows are routed through WinNAT in the kernel, so no host process owns a
/// socket for them and they can never match the connection table (issue #6).
pub const VIRTUAL_APP: &str = "[wsl/vm]";

/// Unmatched packets are held for one tick before being attributed, so a
/// flow that is merely ahead of the connection-table refresh can still find
/// its real owner. Bounds memory if the table stops matching entirely.
const MAX_PENDING: usize = 20_000;

/// A packet that did not match the connection table on the tick it arrived.
struct PendingPacket {
    src_port: u16,
    dst_port: u16,
    is_tcp: bool,
    bytes: u64,
    inbound: bool,
}

/// Tracks bandwidth usage per application process.
pub struct BandwidthTracker {
    /// Per-app cumulative bandwidth. Key = lowercase process name.
    pub apps: HashMap<String, AppBandwidth>,
    /// Bytes-per-tick accumulator for speed calculation.
    tick_down: HashMap<String, u64>,
    tick_up: HashMap<String, u64>,
    /// Unmatched packets awaiting one retry against a fresher connection table.
    pending: Vec<PendingPacket>,
    /// Sort column for UI.
    pub sort_column: usize,
    pub sort_ascending: bool,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            tick_down: HashMap::new(),
            tick_up: HashMap::new(),
            pending: Vec::new(),
            sort_column: 0, // Total bytes
            sort_ascending: false,
        }
    }

    /// Credit NAT-forwarded VM traffic to the [`VIRTUAL_APP`] pseudo-app.
    ///
    /// WSL2 / Hyper-V flows are routed by WinNAT in the kernel: no host
    /// process owns a socket for them, and Windows raw sockets (SIO_RCVALL)
    /// never surface the forwarded packets, so the sniffer cannot attribute
    /// them (issue #6). The virtual switch byte counters do see every one of
    /// those bytes; the caller passes per-tick deltas of the vEthernet
    /// adapters. Bytes the switch sent into the VM are the VM's downloads,
    /// bytes it received from the VM are its uploads.
    pub fn credit_virtual(&mut self, down_bytes: u64, up_bytes: u64) {
        if down_bytes > 0 {
            self.credit(VIRTUAL_APP, down_bytes, true);
        }
        if up_bytes > 0 {
            self.credit(VIRTUAL_APP, up_bytes, false);
        }
    }

    /// Ingest sniffer packets to attribute bandwidth to processes.
    /// Matches packets against the connection table to resolve process
    /// ownership. Packets that match nothing are held one tick and retried
    /// against the next table refresh, so flows newer than the snapshot
    /// still reach their real owner instead of being dropped.
    pub fn ingest_packets(
        &mut self,
        packets: &[PacketSnippet],
        connections: &[Connection],
    ) {
        // Build a fast lookup: (local_port, remote_port, proto) -> process_name
        let mut port_proc: HashMap<(u16, u16, bool), &str> = HashMap::with_capacity(connections.len());
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            let is_tcp = conn.proto == ConnProto::Tcp;
            let rp = conn.remote_port.unwrap_or(0);
            if !conn.process_name.is_empty() {
                port_proc.insert((conn.local_port, rp, is_tcp), &conn.process_name);
                // Also insert reverse for inbound matching
                if rp > 0 {
                    port_proc.insert((rp, conn.local_port, is_tcp), &conn.process_name);
                }
            }
        }

        // Retry last tick's unmatched packets against the fresh connection
        // table: a flow that was ahead of the table refresh matches now.
        // What still has no owner after the retry is dropped — the host
        // sniffer cannot see who moved it (VM volume is credited separately
        // via `credit_virtual`).
        let pending = std::mem::take(&mut self.pending);
        for p in pending {
            let owner = port_proc
                .get(&(p.src_port, p.dst_port, p.is_tcp))
                .or_else(|| port_proc.get(&(p.dst_port, p.src_port, p.is_tcp)))
                .map(|s| s.to_string());
            if let Some(name) = owner {
                if !name.starts_with("PID:") {
                    self.credit(&name, p.bytes, p.inbound);
                }
            }
        }

        for pkt in packets {
            let is_tcp = pkt.protocol == ConnProto::Tcp;
            let inbound = pkt.direction == PacketDirection::Inbound;

            // Try to find owning process
            let process_name = port_proc
                .get(&(pkt.src_port, pkt.dst_port, is_tcp))
                .or_else(|| port_proc.get(&(pkt.dst_port, pkt.src_port, is_tcp)))
                .map(|s| s.to_string())
                .unwrap_or_default();

            if process_name.is_empty() {
                // No owner yet — the flow may be newer than the connection
                // table snapshot. Hold one tick and retry.
                if self.pending.len() < MAX_PENDING {
                    self.pending.push(PendingPacket {
                        src_port: pkt.src_port,
                        dst_port: pkt.dst_port,
                        is_tcp,
                        bytes: pkt.payload_size as u64,
                        inbound,
                    });
                }
                continue;
            }
            if process_name.starts_with("PID:") {
                // Owned by a host process whose name could not be resolved —
                // a real host flow, never VM traffic. Skip as before.
                continue;
            }

            self.credit(&process_name, pkt.payload_size as u64, inbound);
        }
    }

    /// Add bytes to a process's tick accumulators and cumulative totals.
    fn credit(&mut self, process_name: &str, bytes: u64, inbound: bool) {
        let key = process_name.to_lowercase();

        if inbound {
            *self.tick_down.entry(key.clone()).or_insert(0) += bytes;
        } else {
            *self.tick_up.entry(key.clone()).or_insert(0) += bytes;
        }

        let app = self
            .apps
            .entry(key)
            .or_insert_with(|| AppBandwidth::new(process_name.to_string()));
        if inbound {
            app.download_bytes += bytes;
        } else {
            app.upload_bytes += bytes;
        }
        app.last_seen = Local::now().time();
    }

    /// Estimate per-app bandwidth from the connection table when the sniffer
    /// is not capturing packets (non-admin). Distributes system-wide speed
    /// proportionally by active connection count per process.
    pub fn estimate_from_connections(
        &mut self,
        connections: &[Connection],
        total_down_bps: f64,
        total_up_bps: f64,
    ) {
        // Only estimate if sniffer produced nothing this tick
        if !self.tick_down.is_empty() || !self.tick_up.is_empty() {
            return;
        }

        // Count established connections per process
        let mut conn_counts: HashMap<String, usize> = HashMap::new();
        let mut total_active = 0usize;
        for conn in connections {
            if !matches!(conn.state.as_ref(), Some(TcpState::Established)) {
                continue;
            }
            if conn.process_name.is_empty() || conn.process_name.starts_with("PID:") {
                continue;
            }
            let key = conn.process_name.to_lowercase();
            *conn_counts.entry(key).or_insert(0) += 1;
            total_active += 1;
        }

        if total_active == 0 || (total_down_bps < 100.0 && total_up_bps < 100.0) {
            return;
        }

        // Distribute bandwidth proportionally
        for (key, count) in &conn_counts {
            let fraction = *count as f64 / total_active as f64;
            let down = (total_down_bps * fraction) as u64;
            let up = (total_up_bps * fraction) as u64;

            // Find original-case process name from connections
            let display_name = connections.iter()
                .find(|c| c.process_name.to_lowercase() == *key)
                .map(|c| c.process_name.clone())
                .unwrap_or_else(|| key.clone());

            let app = self.apps.entry(key.clone())
                .or_insert_with(|| AppBandwidth::new(display_name));
            app.download_bytes += down;
            app.upload_bytes += up;
            app.last_seen = Local::now().time();

            *self.tick_down.entry(key.clone()).or_insert(0) += down;
            *self.tick_up.entry(key.clone()).or_insert(0) += up;
        }
    }

    /// Update active connection counts and flush tick speed data.
    /// Call once per tick after ingest_packets.
    pub fn finish_tick(&mut self, connections: &[Connection]) {
        // Count active connections per process
        let mut conn_counts: HashMap<String, usize> = HashMap::new();
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen) | Some(TcpState::Closed)) {
                continue;
            }
            if !conn.process_name.is_empty() {
                *conn_counts.entry(conn.process_name.to_lowercase()).or_insert(0) += 1;
            }
        }

        // Update connection counts and push speed samples.
        // When an app had no measured traffic this tick but still has active
        // connections, decay the previous value instead of slamming to 0.
        // This prevents all rows flickering to "idle" when the sniffer
        // produces no packets for a few consecutive ticks.
        for (key, app) in &mut self.apps {
            app.active_connections = conn_counts.get(key).copied().unwrap_or(0);

            let has_tick_data = self.tick_down.contains_key(key) || self.tick_up.contains_key(key);
            let down = self.tick_down.get(key).copied().unwrap_or(0) as f64;
            let up = self.tick_up.get(key).copied().unwrap_or(0) as f64;

            let (push_down, push_up) = if has_tick_data {
                // Real data this tick — use it directly
                (down, up)
            } else if app.active_connections > 0 {
                // No data this tick but app has active connections — decay previous
                let prev_d = app.recent_down.back().copied().unwrap_or(0.0);
                let prev_u = app.recent_up.back().copied().unwrap_or(0.0);
                (prev_d * 0.6, prev_u * 0.6)
            } else {
                // No connections — truly idle
                (0.0, 0.0)
            };

            app.recent_down.push_back(push_down);
            app.recent_up.push_back(push_up);
            if app.recent_down.len() > 20 {
                app.recent_down.pop_front();
            }
            if app.recent_up.len() > 20 {
                app.recent_up.pop_front();
            }
        }

        self.tick_down.clear();
        self.tick_up.clear();
    }

}
