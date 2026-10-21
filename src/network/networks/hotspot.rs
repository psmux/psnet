//! Mobile Hotspot and USB tethering discovery for Windows.
//!
//! Discovery methods:
//!   1. netsh wlan show hostednetwork — Windows Mobile Hotspot status
//!   2. ARP table parsing — find connected clients on hotspot adapter subnet
//!   3. Adapter detection — RNDIS / CDC Ethernet for USB tethering
//!
//! Returns Vec<RemoteNetwork> with category Hotspot.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

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

fn quiet_powershell() -> Command {
    let mut cmd = Command::new("powershell");
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.args(["-NoProfile", "-NonInteractive", "-Command"]);
    cmd
}

/// Discover hotspot and tethering networks.
pub fn discover() -> Vec<RemoteNetwork> {
    let mut networks = Vec::new();

    // Check Windows Mobile Hotspot
    if let Some(net) = discover_mobile_hotspot() {
        networks.push(net);
    }

    // Check USB tethering adapters
    let tether_nets = discover_usb_tethering();
    networks.extend(tether_nets);

    networks
}

// ─── Windows Mobile Hotspot ────────────────────────────────────────────────

fn discover_mobile_hotspot() -> Option<RemoteNetwork> {
    let now = Local::now().time();

    // Check hosted network status
    let output = quiet_command("netsh")
        .args(["wlan", "show", "hostednetwork"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);

    // Parse status
    let is_started = text.lines()
        .any(|l| l.to_lowercase().contains("status") && l.to_lowercase().contains("started"));

    if !is_started {
        // Also check via PowerShell for the newer Mobile Hotspot feature
        let ps_output = quiet_powershell()
            .arg("[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile([Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()).TetheringOperationalState")
            .output();

        let is_on = match ps_output {
            Ok(o) if o.status.success() => {
                let s = String::from_utf8_lossy(&o.stdout);
                s.trim() == "On"
            }
            _ => false,
        };

        if !is_on {
            return None;
        }
    }

    // Parse SSID from hosted network output
    let ssid = text.lines()
        .find(|l| l.to_lowercase().contains("ssid name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| "Mobile Hotspot".to_string());

    // Find hotspot adapter IP (usually 192.168.137.1)
    let hotspot_ip = discover_hotspot_adapter_ip()
        .unwrap_or(Ipv4Addr::new(192, 168, 137, 1));

    // Get connected clients from ARP table
    let clients = discover_hotspot_clients(hotspot_ip, now);

    let client_count = clients.len();

    Some(RemoteNetwork {
        name: format!("Hotspot: {}", ssid),
        category: NetworkCategory::Hotspot,
        adapter_name: "Mobile Hotspot".to_string(),
        local_ip: hotspot_ip,
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        subnet_cidr: format!("{}/24", hotspot_ip),
        gateway: None,
        devices: if client_count > 0 { clients } else {
            vec![LanDevice {
                ip: IpAddr::V4(hotspot_ip),
                mac: String::new(),
                hostname: Some("Hotspot Gateway".to_string()),
                vendor: Some("Windows Mobile Hotspot".to_string()),
                first_seen: now,
                last_seen: now,
                is_online: true,
                custom_name: None,
                discovery_info: format!("Hotspot SSID:{} active", ssid),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            }]
        },
    })
}

fn discover_hotspot_adapter_ip() -> Option<Ipv4Addr> {
    let output = quiet_powershell()
        .arg("Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Microsoft Wi-Fi Direct Virtual*' -or $_.InterfaceDescription -like '*Hosted Network*' } | Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress")
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse::<Ipv4Addr>().ok()
}

fn discover_hotspot_clients(hotspot_ip: Ipv4Addr, now: chrono::NaiveTime) -> Vec<LanDevice> {
    let output = quiet_command("arp")
        .arg("-a")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let hotspot_prefix = {
        let octets = hotspot_ip.octets();
        format!("{}.{}.{}.", octets[0], octets[1], octets[2])
    };

    let mut devices = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with(&hotspot_prefix) {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let ip_str = parts[0];
        let mac_str = parts[1];
        let entry_type = parts[2];

        if entry_type == "static" || mac_str == "ff-ff-ff-ff-ff-ff" {
            continue;
        }

        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        if ip == hotspot_ip {
            continue;
        }

        let mac = mac_str.replace('-', ":").to_uppercase();
        let vendor = if !mac.is_empty() {
            crate::network::scanner::mac_vendor(&mac)
        } else {
            None
        };

        devices.push(LanDevice {
            ip: IpAddr::V4(ip),
            mac,
            hostname: None,
            vendor,
            first_seen: now,
            last_seen: now,
            is_online: true,
            custom_name: None,
            discovery_info: "Hotspot client".to_string(),
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

// ─── USB Tethering ──────────────────────────────────────────────────────────

fn discover_usb_tethering() -> Vec<RemoteNetwork> {
    let now = Local::now().time();

    // Look for RNDIS or CDC Ethernet adapters (USB tethering)
    let output = quiet_powershell()
        .arg("Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*RNDIS*' -or $_.InterfaceDescription -like '*CDC Ethernet*' -or $_.InterfaceDescription -like '*USB Ethernet*' -or $_.InterfaceDescription -like '*Android*' -or $_.InterfaceDescription -like '*iPhone*' } | Select-Object Name,InterfaceDescription,Status,MacAddress | ConvertTo-Json -Compress")
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }

    let mut networks = Vec::new();
    let mut adapters: Vec<serde_json::Value> = Vec::new();

    if let Ok(arr) = serde_json::from_str::<Vec<serde_json::Value>>(text) {
        adapters = arr;
    } else if let Ok(obj) = serde_json::from_str::<serde_json::Value>(text) {
        adapters.push(obj);
    }

    for adapter in &adapters {
        let name = adapter.get("Name").and_then(|v| v.as_str()).unwrap_or("USB Tethering");
        let desc = adapter.get("InterfaceDescription").and_then(|v| v.as_str()).unwrap_or("USB Ethernet");
        let status = adapter.get("Status").and_then(|v| v.as_str()).unwrap_or("Disconnected");
        let is_up = status == "Up";

        if !is_up {
            continue;
        }

        // Get IP for this adapter
        let ip = get_adapter_ip(name).unwrap_or(Ipv4Addr::new(192, 168, 42, 1));

        networks.push(RemoteNetwork {
            name: format!("USB Tethering: {}", desc),
            category: NetworkCategory::Hotspot,
            adapter_name: name.to_string(),
            local_ip: ip,
            subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
            subnet_cidr: format!("{}/24", ip),
            gateway: None,
            devices: vec![LanDevice {
                ip: IpAddr::V4(ip),
                mac: String::new(),
                hostname: Some(desc.to_string()),
                vendor: Some("USB Tethering".to_string()),
                first_seen: now,
                last_seen: now,
                is_online: true,
                custom_name: None,
                discovery_info: format!("USB tethering via {}", desc),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            }],
        });
    }

    networks
}

fn get_adapter_ip(name: &str) -> Option<Ipv4Addr> {
    let output = quiet_powershell()
        .arg(format!(
            "Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress",
            name
        ))
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    text.trim().parse::<Ipv4Addr>().ok()
}
