//! Tunnel discovery — SSH tunnels, SOCKS proxies, and tunneling processes.
//!
//! Discovery methods:
//!   1. SSH/PuTTY tunnels — scan for ssh.exe/putty.exe/plink.exe processes
//!   2. SOCKS proxies — check common proxy ports (1080, 8080, 3128)
//!   3. Tunnel processes — look for stunnel, ngrok, cloudflared, bore, chisel
//!
//! Returns Vec<RemoteNetwork> with category Tunnel.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::process::Command;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

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

/// Discover tunnel networks.
pub fn discover() -> Vec<RemoteNetwork> {
    let results: Mutex<Vec<RemoteNetwork>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        let r = &results;
        s.spawn(move || {
            let nets = discover_ssh_tunnels();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });

        let r = &results;
        s.spawn(move || {
            let nets = discover_proxy_ports();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });

        let r = &results;
        s.spawn(move || {
            let nets = discover_tunnel_processes();
            if !nets.is_empty() {
                r.lock().unwrap().extend(nets);
            }
        });
    });

    results.into_inner().unwrap()
}

// ─── SSH / PuTTY tunnels ─────────────────────────────────────────────────

fn discover_ssh_tunnels() -> Vec<RemoteNetwork> {
    let now = Local::now().time();

    // Check for ssh.exe, putty.exe, plink.exe processes
    let ssh_procs = ["ssh.exe", "putty.exe", "plink.exe"];
    let mut tunnel_devices = Vec::new();

    for proc_name in &ssh_procs {
        let output = quiet_command("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", proc_name), "/FO", "CSV", "/NH"])
            .output();

        let has_proc = match output {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                text.to_lowercase().contains(&proc_name.to_lowercase())
            }
            Err(_) => false,
        };

        if !has_proc {
            continue;
        }

        // Found a tunnel process — check for listening ports
        let listeners = find_tunnel_listeners(proc_name);

        if listeners.is_empty() {
            // Process exists but no detected forwarded ports
            tunnel_devices.push(LanDevice {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                mac: String::new(),
                hostname: Some(proc_name.to_string()),
                vendor: Some("SSH Tunnel".to_string()),
                first_seen: now,
                last_seen: now,
                is_online: true,
                custom_name: None,
                discovery_info: format!("{} process detected", proc_name),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        } else {
            for (port, remote_info) in &listeners {
                tunnel_devices.push(LanDevice {
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    mac: String::new(),
                    hostname: Some(format!("{}:{}", proc_name, port)),
                    vendor: Some("SSH Port Forward".to_string()),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: None,
                    discovery_info: format!(
                        "{} tunnel  Local:{}  Remote:{}",
                        proc_name, port, remote_info
                    ),
                    open_ports: port.to_string(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }
    }

    if tunnel_devices.is_empty() {
        return Vec::new();
    }

    vec![RemoteNetwork {
        name: "SSH Tunnels".to_string(),
        category: NetworkCategory::Tunnel,
        adapter_name: "ssh-tunnel".to_string(),
        local_ip: Ipv4Addr::LOCALHOST,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 255),
        subnet_cidr: "127.0.0.1/32".to_string(),
        gateway: None,
        devices: tunnel_devices,
    }]
}

/// Find listening ports associated with a process name by examining netstat output.
fn find_tunnel_listeners(proc_name: &str) -> Vec<(u16, String)> {
    let output = quiet_command("netstat")
        .args(["-ano"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);

    // Get PIDs of the process
    let pid_output = quiet_command("tasklist")
        .args(["/FI", &format!("IMAGENAME eq {}", proc_name), "/FO", "CSV", "/NH"])
        .output();

    let pids: Vec<String> = match pid_output {
        Ok(o) => {
            let csv = String::from_utf8_lossy(&o.stdout);
            csv.lines()
                .filter_map(|l| {
                    let fields: Vec<&str> = l.split(',').collect();
                    fields.get(1).map(|s| s.trim_matches('"').to_string())
                })
                .filter(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty())
                .collect()
        }
        Err(_) => return Vec::new(),
    };

    if pids.is_empty() {
        return Vec::new();
    }

    let mut listeners = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        // Look for LISTENING or ESTABLISHED connections from our process
        let pid = parts[parts.len() - 1];
        if !pids.contains(&pid.to_string()) {
            continue;
        }

        let state = parts[3];
        if state != "LISTENING" {
            continue;
        }

        let local_addr = parts[1];
        if let Some(port_str) = local_addr.rsplit(':').next() {
            if let Ok(port) = port_str.parse::<u16>() {
                // Skip well-known ports that probably aren't tunnels
                if port < 1024 || port > 65000 {
                    continue;
                }
                let remote = parts[2].to_string();
                listeners.push((port, remote));
            }
        }
    }

    listeners
}

// ─── SOCKS / HTTP Proxies ──────────────────────────────────────────────────

fn discover_proxy_ports() -> Vec<RemoteNetwork> {
    let now = Local::now().time();
    let proxy_ports: Vec<(u16, &str)> = vec![
        (1080, "SOCKS5"),
        (1081, "SOCKS5"),
        (3128, "HTTP Proxy"),
        (8080, "HTTP Proxy"),
        (8118, "Privoxy"),
        (9050, "Tor SOCKS"),
        (9150, "Tor Browser SOCKS"),
    ];

    let open: Mutex<Vec<(u16, &str)>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        for &(port, label) in &proxy_ports {
            let o = &open;
            s.spawn(move || {
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
                if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                    o.lock().unwrap().push((port, label));
                }
            });
        }
    });

    let found = open.into_inner().unwrap();
    if found.is_empty() {
        return Vec::new();
    }

    let devices: Vec<LanDevice> = found
        .iter()
        .map(|(port, label)| LanDevice {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            mac: String::new(),
            hostname: Some(format!("{} :{}", label, port)),
            vendor: Some(label.to_string()),
            first_seen: now,
            last_seen: now,
            is_online: true,
            custom_name: None,
            discovery_info: format!("{} proxy on port {}", label, port),
            open_ports: port.to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        })
        .collect();

    vec![RemoteNetwork {
        name: "Local Proxies".to_string(),
        category: NetworkCategory::Tunnel,
        adapter_name: "proxy".to_string(),
        local_ip: Ipv4Addr::LOCALHOST,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 255),
        subnet_cidr: "127.0.0.1/32".to_string(),
        gateway: None,
        devices,
    }]
}

// ─── Tunnel processes (ngrok, cloudflared, stunnel, etc.) ──────────────────

fn discover_tunnel_processes() -> Vec<RemoteNetwork> {
    let now = Local::now().time();

    let tunnel_apps: Vec<(&str, &str)> = vec![
        ("ngrok.exe", "ngrok"),
        ("cloudflared.exe", "Cloudflare Tunnel"),
        ("stunnel.exe", "stunnel"),
        ("bore.exe", "bore"),
        ("chisel.exe", "chisel"),
        ("frpc.exe", "frp client"),
        ("localtunnel.exe", "localtunnel"),
    ];

    let mut devices = Vec::new();

    for (exe, label) in &tunnel_apps {
        let output = quiet_command("tasklist")
            .args(["/FI", &format!("IMAGENAME eq {}", exe), "/FO", "CSV", "/NH"])
            .output();

        let has_proc = match output {
            Ok(o) => {
                let text = String::from_utf8_lossy(&o.stdout);
                text.to_lowercase().contains(&exe.to_lowercase())
            }
            Err(_) => false,
        };

        if !has_proc {
            continue;
        }

        devices.push(LanDevice {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            mac: String::new(),
            hostname: Some(label.to_string()),
            vendor: Some(format!("{} Tunnel", label)),
            first_seen: now,
            last_seen: now,
            is_online: true,
            custom_name: None,
            discovery_info: format!("{} process active", exe),
            open_ports: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            tick_sent: 0,
            tick_received: 0,
            speed_sent: 0.0,
            speed_received: 0.0,
        });
    }

    if devices.is_empty() {
        return Vec::new();
    }

    vec![RemoteNetwork {
        name: "Tunnel Services".to_string(),
        category: NetworkCategory::Tunnel,
        adapter_name: "tunnel".to_string(),
        local_ip: Ipv4Addr::LOCALHOST,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 255),
        subnet_cidr: "127.0.0.1/32".to_string(),
        gateway: None,
        devices,
    }]
}
