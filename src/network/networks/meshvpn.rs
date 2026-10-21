//! Mesh VPN discovery — Tailscale, ZeroTier, and Nebula.
//!
//! Discovery methods (all run in parallel):
//!   1. Tailscale  — `tailscale status --json` for peers with IPs, hostnames, OS
//!   2. ZeroTier   — `zerotier-cli listnetworks` + `zerotier-cli listpeers`
//!   3. Nebula     — check for nebula config files
//!
//! Returns Vec<RemoteNetwork> with category MeshVpn.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Mutex;
use std::thread;

use chrono::Local;

use crate::types::{LanDevice, NetworkCategory, RemoteNetwork};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn quiet_command(program: &str) -> Command {
    // `mut` is only needed for the Windows-only creation_flags call below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Discover all mesh VPN networks in parallel.
pub fn discover() -> Vec<RemoteNetwork> {
    let results: Mutex<Vec<RemoteNetwork>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        let r = &results;
        s.spawn(move || {
            let nets = discover_tailscale();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });

        let r = &results;
        s.spawn(move || {
            let nets = discover_zerotier();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });

        let r = &results;
        s.spawn(move || {
            let nets = discover_nebula();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });
    });

    results.into_inner().unwrap()
}

// ─── Tailscale ──────────────────────────────────────────────────────────────

fn discover_tailscale() -> Vec<RemoteNetwork> {
    let output = quiet_command("tailscale")
        .args(["status", "--json"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let now = Local::now().time();
    let mut devices = Vec::new();

    // Get self IP for local_ip
    let self_ip = json.get("Self")
        .and_then(|s| s.get("TailscaleIPs"))
        .and_then(|ips| ips.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::new(100, 64, 0, 1));

    // Parse peers
    if let Some(peers) = json.get("Peer").and_then(|p| p.as_object()) {
        for (_key, peer) in peers {
            let hostname = peer.get("HostName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_end_matches('.')
                .to_string();

            let os = peer.get("OS")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let online = peer.get("Online")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let ips = peer.get("TailscaleIPs")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let ip = ips.first().copied().unwrap_or(Ipv4Addr::UNSPECIFIED);

            let relay = peer.get("Relay")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let rx_bytes = peer.get("RxBytes").and_then(|v| v.as_u64()).unwrap_or(0);
            let tx_bytes = peer.get("TxBytes").and_then(|v| v.as_u64()).unwrap_or(0);

            devices.push(LanDevice {
                ip: IpAddr::V4(ip),
                mac: String::new(),
                hostname: if hostname.is_empty() { None } else { Some(hostname) },
                vendor: Some(format!("Tailscale ({})", os)),
                first_seen: now,
                last_seen: now,
                is_online: online,
                custom_name: None,
                discovery_info: format!(
                    "Tailscale  OS:{}  Relay:{}  RX:{}  TX:{}",
                    os, relay, rx_bytes, tx_bytes
                ),
                open_ports: String::new(),
                bytes_sent: tx_bytes,
                bytes_received: rx_bytes,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        }
    }

    if devices.is_empty() {
        return Vec::new();
    }

    vec![RemoteNetwork {
        name: "Tailscale".to_string(),
        category: NetworkCategory::MeshVpn,
        adapter_name: "Tailscale".to_string(),
        local_ip: self_ip,
        subnet_mask: Ipv4Addr::new(255, 192, 0, 0),
        subnet_cidr: "100.64.0.0/10".to_string(),
        gateway: None,
        devices,
    }]
}

// ─── ZeroTier ──────────────────────────────────────────────────────────────

fn discover_zerotier() -> Vec<RemoteNetwork> {
    // Get networks
    let net_output = quiet_command("zerotier-cli")
        .arg("listnetworks")
        .output();

    let net_output = match net_output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let now = Local::now().time();
    let net_text = String::from_utf8_lossy(&net_output.stdout);
    let mut networks = Vec::new();

    // Parse listnetworks output (table format):
    // 200 listnetworks <nwid> <name> <mac> <status> <type> <dev> <ZT assigned ips>
    for line in net_text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 9 {
            continue;
        }

        let nwid = parts[2];
        let net_name = parts[3];
        let _mac = parts[4];
        let _status = parts[5];
        let assigned_ips = parts[8..].join(" ");

        // Parse assigned IP
        let local_ip = assigned_ips
            .split(',')
            .find_map(|s| {
                let ip_part = s.split('/').next()?;
                ip_part.parse::<Ipv4Addr>().ok()
            })
            .unwrap_or(Ipv4Addr::new(10, 147, 0, 1));

        // Get peers for this network
        let peers = discover_zt_peers(nwid, now);

        networks.push(RemoteNetwork {
            name: format!("ZeroTier: {}", net_name),
            category: NetworkCategory::MeshVpn,
            adapter_name: format!("zt-{}", nwid),
            local_ip,
            subnet_mask: Ipv4Addr::new(255, 255, 0, 0),
            subnet_cidr: format!("{}/16", local_ip),
            gateway: None,
            devices: peers,
        });
    }

    networks
}

fn discover_zt_peers(_nwid: &str, now: chrono::NaiveTime) -> Vec<LanDevice> {
    let output = quiet_command("zerotier-cli")
        .arg("listpeers")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    // Format: 200 listpeers <ztaddr> <ver> <role> <path> <latency>
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        let zt_addr = parts[2];
        let version = parts[3];
        let role = parts[4];
        let path = parts[5];

        // Extract IP from path (format: ip/port)
        let peer_ip = path.split('/')
            .next()
            .and_then(|s| s.parse::<Ipv4Addr>().ok());

        let ip = peer_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let latency = parts.get(6).unwrap_or(&"-");

        devices.push(LanDevice {
            ip: IpAddr::V4(ip),
            mac: String::new(),
            hostname: Some(format!("ZT-{}", zt_addr)),
            vendor: Some(format!("ZeroTier {} ({})", version, role)),
            first_seen: now,
            last_seen: now,
            is_online: path != "-",
            custom_name: None,
            discovery_info: format!("ZeroTier  Role:{}  Path:{}  Latency:{}", role, path, latency),
            open_ports: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        });
    }

    devices
}

// ─── Nebula ──────────────────────────────────────────────────────────────

fn discover_nebula() -> Vec<RemoteNetwork> {
    // Check common Nebula config locations
    let config_paths = [
        "C:\\ProgramData\\Nebula\\config.yml",
        "C:\\Program Files\\Nebula\\config.yml",
        "C:\\nebula\\config.yml",
    ];

    let mut found_config = false;
    for path in &config_paths {
        if std::path::Path::new(path).exists() {
            found_config = true;
            break;
        }
    }

    if !found_config {
        return Vec::new();
    }

    // Check if nebula process is running
    let output = quiet_command("tasklist")
        .args(["/FI", "IMAGENAME eq nebula.exe", "/FO", "CSV", "/NH"])
        .output();

    let is_running = match output {
        Ok(o) => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.to_lowercase().contains("nebula.exe")
        }
        Err(_) => false,
    };

    if !is_running {
        return Vec::new();
    }

    let now = Local::now().time();

    // Nebula doesn't have a CLI to list peers, but we can report it exists
    vec![RemoteNetwork {
        name: "Nebula Mesh".to_string(),
        category: NetworkCategory::MeshVpn,
        adapter_name: "nebula".to_string(),
        local_ip: Ipv4Addr::new(10, 0, 0, 1),
        subnet_mask: Ipv4Addr::new(255, 0, 0, 0),
        subnet_cidr: "10.0.0.0/8".to_string(),
        gateway: None,
        devices: vec![LanDevice {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            mac: String::new(),
            hostname: Some("Nebula Lighthouse".to_string()),
            vendor: Some("Nebula Mesh VPN".to_string()),
            first_seen: now,
            last_seen: now,
            is_online: true,
            custom_name: None,
            discovery_info: "Nebula mesh overlay detected".to_string(),
            open_ports: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        }],
    }]
}
