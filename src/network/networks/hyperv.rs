//! Hyper-V virtual machine discovery via PowerShell cmdlets.
//!
//! Three discovery queries running in parallel:
//!   1. `Get-VM` — list all VMs with name, state, ID
//!   2. `Get-VMNetworkAdapter` — network adapter details (IPs, MACs, switches)
//!   3. `Get-VMSwitch` — virtual switch configuration
//!
//! Results are grouped by switch name into separate `RemoteNetwork` entries.
//! Silently returns empty if Hyper-V is not installed or not available.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::Mutex;
use std::thread;

use chrono::Local;

use crate::types::{LanDevice, NetworkCategory, RemoteNetwork};

/// CREATE_NO_WINDOW flag to prevent console flash on Windows.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a PowerShell Command with CREATE_NO_WINDOW on Windows.
fn quiet_powershell() -> Command {
    // `mut` is only needed for the Windows-only creation_flags call below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = Command::new("powershell");
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Run a PowerShell command and return parsed JSON, or None on failure.
fn run_ps_json(script: &str) -> Option<serde_json::Value> {
    let output = quiet_powershell()
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    serde_json::from_str(trimmed).ok()
}

/// Ensure a JSON value is always an array (single objects become one-element arrays).
fn as_array(val: serde_json::Value) -> Vec<serde_json::Value> {
    match val {
        serde_json::Value::Array(arr) => arr,
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    }
}

/// Format a MAC address from PowerShell format (AABBCCDDEEFF or AA-BB-CC-DD-EE-FF)
/// into standard XX:XX:XX:XX:XX:XX notation.
fn format_mac(raw: &str) -> String {
    // Strip dashes and any whitespace
    let clean: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return raw.to_string();
    }
    format!(
        "{}:{}:{}:{}:{}:{}",
        &clean[0..2],
        &clean[2..4],
        &clean[4..6],
        &clean[6..8],
        &clean[8..10],
        &clean[10..12],
    )
    .to_uppercase()
}

/// VM info from Get-VM.
#[derive(Clone, Debug)]
struct VmInfo {
    name: String,
    state: String,
    #[allow(dead_code)]
    id: String,
}

/// Network adapter info from Get-VMNetworkAdapter.
#[derive(Clone, Debug)]
struct VmAdapterInfo {
    vm_name: String,
    ip_addresses: Vec<String>,
    mac_address: String,
    switch_name: String,
    #[allow(dead_code)]
    status: String,
}

/// Switch info from Get-VMSwitch.
#[derive(Clone, Debug)]
struct VmSwitchInfo {
    name: String,
    switch_type: String,
    #[allow(dead_code)]
    net_adapter_description: String,
}

/// Discover Hyper-V VMs and group them by virtual switch into RemoteNetworks.
pub fn discover() -> Vec<RemoteNetwork> {
    // Run all three PowerShell queries in parallel
    let vms_result: Mutex<Vec<VmInfo>> = Mutex::new(Vec::new());
    let adapters_result: Mutex<Vec<VmAdapterInfo>> = Mutex::new(Vec::new());
    let switches_result: Mutex<Vec<VmSwitchInfo>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        let vms_ref = &vms_result;
        s.spawn(move || {
            *vms_ref.lock().unwrap() = query_vms();
        });

        let adapters_ref = &adapters_result;
        s.spawn(move || {
            *adapters_ref.lock().unwrap() = query_adapters();
        });

        let switches_ref = &switches_result;
        s.spawn(move || {
            *switches_ref.lock().unwrap() = query_switches();
        });
    });

    let vms = vms_result.into_inner().unwrap();
    let adapters = adapters_result.into_inner().unwrap();
    let switches = switches_result.into_inner().unwrap();

    if vms.is_empty() {
        return Vec::new();
    }

    // Build lookup: VM name → VmInfo
    let vm_map: HashMap<String, &VmInfo> = vms.iter().map(|v| (v.name.clone(), v)).collect();

    // Build lookup: switch name → VmSwitchInfo
    let switch_map: HashMap<String, &VmSwitchInfo> =
        switches.iter().map(|sw| (sw.name.clone(), sw)).collect();

    // Group adapters by switch name
    let mut by_switch: HashMap<String, Vec<&VmAdapterInfo>> = HashMap::new();
    for adapter in &adapters {
        let key = if adapter.switch_name.is_empty() {
            "(No Switch)".to_string()
        } else {
            adapter.switch_name.clone()
        };
        by_switch.entry(key).or_default().push(adapter);
    }

    // Also include VMs that have no adapter entries
    let vms_with_adapters: std::collections::HashSet<String> =
        adapters.iter().map(|a| a.vm_name.clone()).collect();
    for vm in &vms {
        if !vms_with_adapters.contains(&vm.name) {
            by_switch
                .entry("(No Switch)".to_string())
                .or_default();
            // We'll handle orphan VMs below
        }
    }

    let now = Local::now().time();
    let mut networks = Vec::new();

    for (switch_name, switch_adapters) in &by_switch {
        let mut devices = Vec::new();
        let mut seen_vms: std::collections::HashSet<String> = std::collections::HashSet::new();

        for adapter in switch_adapters {
            seen_vms.insert(adapter.vm_name.clone());

            let vm_state = vm_map
                .get(&adapter.vm_name)
                .map(|v| v.state.as_str())
                .unwrap_or("Unknown");
            let is_online = vm_state.eq_ignore_ascii_case("Running");

            // Pick the first IPv4 address, or fallback to 0.0.0.0
            let ip = adapter
                .ip_addresses
                .iter()
                .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                .next()
                .unwrap_or(Ipv4Addr::UNSPECIFIED);

            let mac = format_mac(&adapter.mac_address);

            let discovery_info = format!(
                "State:{}  Switch:{}",
                vm_state,
                if adapter.switch_name.is_empty() {
                    "None"
                } else {
                    &adapter.switch_name
                }
            );

            devices.push(LanDevice {
                ip: IpAddr::V4(ip),
                mac,
                hostname: Some(adapter.vm_name.clone()),
                vendor: Some("Hyper-V VM".to_string()),
                first_seen: now,
                last_seen: now,
                is_online,
                custom_name: None,
                discovery_info,
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        }

        // Add orphan VMs (no adapters) to "(No Switch)" group
        if switch_name == "(No Switch)" {
            for vm in &vms {
                if !vms_with_adapters.contains(&vm.name) && !seen_vms.contains(&vm.name) {
                    let is_online = vm.state.eq_ignore_ascii_case("Running");
                    devices.push(LanDevice {
                        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        mac: String::new(),
                        hostname: Some(vm.name.clone()),
                        vendor: Some("Hyper-V VM".to_string()),
                        first_seen: now,
                        last_seen: now,
                        is_online,
                        custom_name: None,
                        discovery_info: format!("State:{}  Switch:None", vm.state),
                        open_ports: String::new(),
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

        if devices.is_empty() {
            continue;
        }

        // Determine switch type for the network name
        let switch_type_str = switch_map
            .get(switch_name.as_str())
            .map(|sw| sw.switch_type.as_str())
            .unwrap_or("Unknown");

        let network_name = if switch_name == "(No Switch)" {
            "Hyper-V: (No Switch)".to_string()
        } else {
            format!("Hyper-V: {} ({})", switch_name, switch_type_str)
        };

        // Use a default internal subnet for Hyper-V VMs
        // Try to derive from first device with a real IP
        let first_ip = devices
            .iter()
            .map(|d| match d.ip {
                IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::UNSPECIFIED,
            })
            .find(|ip| !ip.is_unspecified())
            .unwrap_or(Ipv4Addr::new(172, 16, 0, 0));

        let net_u32 = u32::from(first_ip) & 0xFFFFFF00;
        let local_ip = Ipv4Addr::from(net_u32 | 1);
        let subnet_mask = Ipv4Addr::new(255, 255, 255, 0);
        let subnet_cidr = format!("{}/24", Ipv4Addr::from(net_u32));

        networks.push(RemoteNetwork {
            name: network_name,
            category: NetworkCategory::HyperV,
            adapter_name: switch_name.clone(),
            local_ip,
            subnet_mask,
            subnet_cidr,
            gateway: None,
            devices,
        });
    }

    networks
}

// ─── PowerShell query functions ──────────────────────────────────────────────

fn query_vms() -> Vec<VmInfo> {
    let json = match run_ps_json(
        "Get-VM | Select-Object Name, State, Id | ConvertTo-Json",
    ) {
        Some(v) => v,
        None => return Vec::new(),
    };

    as_array(json)
        .into_iter()
        .filter_map(|obj| {
            let name = obj.get("Name")?.as_str()?.to_string();
            // State can be a string or integer depending on PS version
            let state = match obj.get("State") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Number(n)) => {
                    // Hyper-V VM state enum: 2=Running, 3=Off, 6=Saved, etc.
                    match n.as_u64() {
                        Some(2) => "Running".to_string(),
                        Some(3) => "Off".to_string(),
                        Some(6) => "Saved".to_string(),
                        Some(9) => "Paused".to_string(),
                        Some(v) => format!("State({})", v),
                        None => "Unknown".to_string(),
                    }
                }
                _ => "Unknown".to_string(),
            };
            let id = obj
                .get("Id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some(VmInfo { name, state, id })
        })
        .collect()
}

fn query_adapters() -> Vec<VmAdapterInfo> {
    let json = match run_ps_json(
        "Get-VMNetworkAdapter -All | Select-Object VMName, IPAddresses, MacAddress, SwitchName, Status | ConvertTo-Json",
    ) {
        Some(v) => v,
        None => return Vec::new(),
    };

    as_array(json)
        .into_iter()
        .filter_map(|obj| {
            let vm_name = obj.get("VMName")?.as_str()?.to_string();
            // Skip management OS adapters (VMName is null/empty)
            if vm_name.is_empty() {
                return None;
            }

            let ip_addresses = match obj.get("IPAddresses") {
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
                Some(serde_json::Value::String(s)) => vec![s.clone()],
                _ => Vec::new(),
            };

            let mac_address = obj
                .get("MacAddress")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let switch_name = obj
                .get("SwitchName")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let status = obj
                .get("Status")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Some(VmAdapterInfo {
                vm_name,
                ip_addresses,
                mac_address,
                switch_name,
                status,
            })
        })
        .collect()
}

fn query_switches() -> Vec<VmSwitchInfo> {
    let json = match run_ps_json(
        "Get-VMSwitch | Select-Object Name, SwitchType, NetAdapterInterfaceDescription | ConvertTo-Json",
    ) {
        Some(v) => v,
        None => return Vec::new(),
    };

    as_array(json)
        .into_iter()
        .filter_map(|obj| {
            let name = obj.get("Name")?.as_str()?.to_string();

            let switch_type = match obj.get("SwitchType") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Number(n)) => {
                    // SwitchType enum: 0=Private, 1=Internal, 2=External
                    match n.as_u64() {
                        Some(0) => "Private".to_string(),
                        Some(1) => "Internal".to_string(),
                        Some(2) => "External".to_string(),
                        Some(v) => format!("Type({})", v),
                        None => "Unknown".to_string(),
                    }
                }
                _ => "Unknown".to_string(),
            };

            let net_adapter_description = obj
                .get("NetAdapterInterfaceDescription")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Some(VmSwitchInfo {
                name,
                switch_type,
                net_adapter_description,
            })
        })
        .collect()
}
