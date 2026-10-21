//! Docker container and network discovery via Docker Engine API + CLI.
//!
//! Four discovery strategies running in parallel:
//!   1. **Docker Engine API via named pipe** (PRIMARY) — `\\.\pipe\docker_engine`
//!   2. **Docker CLI** (fallback) — `docker ps` + `docker inspect` + `docker network`
//!   3. **Docker Compose** — `docker compose ls` + `docker compose ps`
//!   4. **Docker System Info** — `docker info` for daemon metadata
//!
//! Silently returns empty if Docker is not installed or daemon is not running.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::Mutex;
use std::thread;

/// CREATE_NO_WINDOW flag to prevent console flash on Windows.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Named pipe path for Docker Engine on Windows.
#[cfg(target_os = "windows")]
const DOCKER_PIPE: &str = r"\\.\pipe\docker_engine";

/// A discovered Docker container with network details.
#[derive(Clone, Debug)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ip: Option<Ipv4Addr>,
    pub mac: String,
    pub gateway: Option<Ipv4Addr>,
    pub network: String,
    pub ports: String,
}

/// A Docker network with its IPAM config.
#[derive(Clone, Debug)]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub subnet: Option<String>,
    pub gateway: Option<Ipv4Addr>,
    pub containers: Vec<DockerContainer>,
}

/// Create a Command with CREATE_NO_WINDOW on Windows.
fn quiet_command(program: &str) -> Command {
    // `mut` is only needed for the Windows-only creation_flags call below.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut cmd = Command::new(program);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Named Pipe — Docker Engine API
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Send an HTTP GET request over the Docker named pipe and return the JSON body.
#[cfg(target_os = "windows")]
fn pipe_get(path: &str) -> Option<serde_json::Value> {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};

    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DOCKER_PIPE)
        .ok()?;

    let request = format!(
        "GET {} HTTP/1.0\r\nHost: localhost\r\n\r\n",
        path
    );
    pipe.write_all(request.as_bytes()).ok()?;

    let mut raw = Vec::with_capacity(64 * 1024);
    let mut buf = [0u8; 8192];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }

    // Split headers from body at \r\n\r\n
    let sep = b"\r\n\r\n";
    let body_start = raw
        .windows(4)
        .position(|w| w == sep)
        .map(|pos| pos + 4)?;

    let body = &raw[body_start..];
    serde_json::from_slice(body).ok()
}

#[cfg(not(target_os = "windows"))]
fn pipe_get(_path: &str) -> Option<serde_json::Value> {
    None
}

/// Discover containers via Docker Engine API named pipe.
/// GET /containers/json?all=true
fn api_discover_containers() -> Vec<DockerContainer> {
    let json = match pipe_get("/containers/json?all=true") {
        Some(v) => v,
        None => return Vec::new(),
    };

    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut containers = Vec::new();

    for entry in arr {
        let id = entry["Id"]
            .as_str()
            .unwrap_or("")
            .chars()
            .take(12)
            .collect::<String>();

        let name = entry["Names"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim_start_matches('/')
            .to_string();

        let image = entry["Image"].as_str().unwrap_or("").to_string();
        let status = entry["Status"].as_str().unwrap_or("").to_string();
        let state = entry["State"].as_str().unwrap_or("");

        // Use State if Status is empty
        let status = if status.is_empty() {
            state.to_string()
        } else {
            status
        };

        // Extract ports from Ports array
        let ports = format_api_ports(&entry["Ports"]);

        // Extract network info from NetworkSettings.Networks
        let networks_obj = &entry["NetworkSettings"]["Networks"];

        if let Some(nets) = networks_obj.as_object() {
            // Container may be on multiple networks; emit one entry per network
            // but we pick the first one with an IP for the primary
            let mut found = false;
            for (net_name, net_cfg) in nets {
                let ip_str = net_cfg["IPAddress"].as_str().unwrap_or("");
                let ip = ip_str.parse::<Ipv4Addr>().ok();
                let mac = net_cfg["MacAddress"]
                    .as_str()
                    .unwrap_or("")
                    .to_uppercase();
                let gw_str = net_cfg["Gateway"].as_str().unwrap_or("");
                let gateway = gw_str.parse::<Ipv4Addr>().ok();

                if ip.is_some() || !found {
                    containers.push(DockerContainer {
                        id: id.clone(),
                        name: name.clone(),
                        image: image.clone(),
                        status: status.clone(),
                        ip,
                        mac,
                        gateway,
                        network: net_name.clone(),
                        ports: ports.clone(),
                    });
                    found = true;
                    if ip.is_some() {
                        break; // prefer entry with IP
                    }
                }
            }

            if !found {
                containers.push(DockerContainer {
                    id,
                    name,
                    image,
                    status,
                    ip: None,
                    mac: String::new(),
                    gateway: None,
                    network: String::new(),
                    ports,
                });
            }
        } else {
            containers.push(DockerContainer {
                id,
                name,
                image,
                status,
                ip: None,
                mac: String::new(),
                gateway: None,
                network: String::new(),
                ports,
            });
        }
    }

    containers
}

/// Format the Ports array from the Docker API into a human-readable string.
/// API returns: [{"IP":"0.0.0.0","PrivatePort":80,"PublicPort":8080,"Type":"tcp"}, ...]
fn format_api_ports(ports_val: &serde_json::Value) -> String {
    let arr = match ports_val.as_array() {
        Some(a) => a,
        None => return String::new(),
    };

    let parts: Vec<String> = arr
        .iter()
        .filter_map(|p| {
            let private = p["PrivatePort"].as_u64()?;
            let proto = p["Type"].as_str().unwrap_or("tcp");

            if let Some(public) = p["PublicPort"].as_u64() {
                let ip = p["IP"].as_str().unwrap_or("0.0.0.0");
                Some(format!("{}:{}->{}/{}", ip, public, private, proto))
            } else {
                Some(format!("{}/{}", private, proto))
            }
        })
        .collect();

    parts.join(", ")
}

/// Discover networks via Docker Engine API named pipe.
/// GET /networks  +  GET /networks/{id} for each network
fn api_discover_networks() -> Vec<DockerNetwork> {
    let json = match pipe_get("/networks") {
        Some(v) => v,
        None => return Vec::new(),
    };

    let arr = match json.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };

    let mut networks = Vec::new();

    for entry in arr {
        let name = entry["Name"].as_str().unwrap_or("").to_string();
        let driver = entry["Driver"].as_str().unwrap_or("").to_string();

        // Skip host and none networks
        if name == "host" || name == "none" || driver == "host" || driver == "null" {
            continue;
        }

        let id = entry["Id"].as_str().unwrap_or("").to_string();

        // IPAM config
        let (subnet, gateway) = parse_ipam_config(&entry["IPAM"]);

        // Containers connected to this network
        let containers = parse_network_containers(
            &entry["Containers"],
            &name,
            gateway,
        );

        // If /networks response doesn't have container details, try /networks/{id}
        let containers = if containers.is_empty() {
            api_inspect_network_containers(&id, &name, gateway)
        } else {
            containers
        };

        networks.push(DockerNetwork {
            id: id.chars().take(12).collect(),
            name,
            driver,
            subnet,
            gateway,
            containers,
        });
    }

    networks
}

/// Parse IPAM configuration from a network JSON entry.
fn parse_ipam_config(ipam: &serde_json::Value) -> (Option<String>, Option<Ipv4Addr>) {
    let configs = match ipam["Config"].as_array() {
        Some(a) => a,
        None => return (None, None),
    };

    for cfg in configs {
        let subnet = cfg["Subnet"].as_str().map(|s| s.to_string());
        let gw = cfg["Gateway"]
            .as_str()
            .and_then(|s| s.parse::<Ipv4Addr>().ok());

        if subnet.is_some() {
            return (subnet, gw);
        }
    }

    (None, None)
}

/// Parse containers from a network inspect Containers object.
fn parse_network_containers(
    containers_obj: &serde_json::Value,
    net_name: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<DockerContainer> {
    let map = match containers_obj.as_object() {
        Some(m) => m,
        None => return Vec::new(),
    };

    let mut containers = Vec::new();

    for (cid, val) in map {
        let cname = val["Name"].as_str().unwrap_or("").to_string();
        let ip_str = val["IPv4Address"].as_str().unwrap_or("");
        // Strip CIDR notation: "172.17.0.2/16" -> "172.17.0.2"
        let ip = ip_str
            .split('/')
            .next()
            .unwrap_or("")
            .parse::<Ipv4Addr>()
            .ok();
        let mac = val["MacAddress"]
            .as_str()
            .unwrap_or("")
            .to_uppercase();

        containers.push(DockerContainer {
            id: cid.chars().take(12).collect(),
            name: cname,
            image: String::new(),
            status: String::new(),
            ip,
            mac,
            gateway,
            network: net_name.to_string(),
            ports: String::new(),
        });
    }

    containers
}

/// Inspect a single network via API for its containers.
fn api_inspect_network_containers(
    net_id: &str,
    net_name: &str,
    gateway: Option<Ipv4Addr>,
) -> Vec<DockerContainer> {
    let path = format!("/networks/{}", net_id);
    let json = match pipe_get(&path) {
        Some(v) => v,
        None => return Vec::new(),
    };

    parse_network_containers(&json["Containers"], net_name, gateway)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Docker CLI — Fallback
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Discover containers via `docker ps -a` + `docker inspect`.
fn cli_discover_containers() -> Vec<DockerContainer> {
    let output = quiet_command("docker")
        .args([
            "ps",
            "-a",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut containers = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }

        let id = parts[0].to_string();
        let name = parts[1].to_string();
        let image = parts[2].to_string();
        let status = parts.get(3).unwrap_or(&"").to_string();
        let ports = parts.get(4).unwrap_or(&"").to_string();

        let (ip, mac, gateway, network) = cli_inspect_container(&id);

        containers.push(DockerContainer {
            id,
            name,
            image,
            status,
            ip,
            mac,
            gateway,
            network,
            ports,
        });
    }

    containers
}

/// Inspect a single container via CLI for network details.
fn cli_inspect_container(id: &str) -> (Option<Ipv4Addr>, String, Option<Ipv4Addr>, String) {
    let output = quiet_command("docker")
        .args([
            "inspect",
            "--format",
            "{{range $net, $config := .NetworkSettings.Networks}}{{$net}}\t{{$config.IPAddress}}\t{{$config.MacAddress}}\t{{$config.Gateway}}\n{{end}}",
            id,
        ])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return (None, String::new(), None, String::new()),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let network = parts[0].to_string();
        let ip = parts[1].parse::<Ipv4Addr>().ok();
        let mac = parts[2].to_uppercase();
        let gateway = parts[3].parse::<Ipv4Addr>().ok();

        if ip.is_some() {
            return (ip, mac, gateway, network);
        }
    }

    (None, String::new(), None, String::new())
}

/// Discover networks via `docker network ls` + `docker network inspect`.
fn cli_discover_networks() -> Vec<DockerNetwork> {
    let output = quiet_command("docker")
        .args([
            "network",
            "ls",
            "--format",
            "{{.ID}}\t{{.Name}}\t{{.Driver}}",
        ])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let network_list: Vec<(String, String, String)> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                Some((
                    parts[0].to_string(),
                    parts[1].to_string(),
                    parts[2].to_string(),
                ))
            } else {
                None
            }
        })
        .collect();

    // Inspect each network in parallel
    let results: Mutex<Vec<DockerNetwork>> = Mutex::new(Vec::new());

    thread::scope(|s| {
        for (id, name, driver) in &network_list {
            let r = &results;
            s.spawn(move || {
                if let Some(net) = cli_inspect_network(id, name, driver) {
                    r.lock().unwrap().push(net);
                }
            });
        }
    });

    results.into_inner().unwrap()
}

/// Deep inspect a Docker network via CLI: IPAM config + connected containers.
fn cli_inspect_network(id: &str, name: &str, driver: &str) -> Option<DockerNetwork> {
    // Skip host and none networks
    if name == "host" || name == "none" || driver == "host" || driver == "null" {
        return None;
    }

    let ipam_output = quiet_command("docker")
        .args([
            "network",
            "inspect",
            "--format",
            "{{range .IPAM.Config}}{{.Subnet}}\t{{.Gateway}}{{end}}",
            id,
        ])
        .output();

    let (subnet, gateway) = match ipam_output {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout);
            let parts: Vec<&str> = s.trim().split('\t').collect();
            let subnet = parts
                .first()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            let gw = parts
                .get(1)
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            (subnet, gw)
        }
        _ => (None, None),
    };

    let containers_output = quiet_command("docker")
        .args([
            "network",
            "inspect",
            "--format",
            "{{range $key, $val := .Containers}}{{$val.Name}}\t{{$val.IPv4Address}}\t{{$val.MacAddress}}\t{{$key}}\n{{end}}",
            id,
        ])
        .output();

    let containers_output = match containers_output {
        Ok(o) if o.status.success() => o,
        _ => return None,
    };

    let stdout = String::from_utf8_lossy(&containers_output.stdout);
    let mut containers = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }

        let cname = parts[0].to_string();
        let ip_str = parts[1].split('/').next().unwrap_or("");
        let ip = ip_str.parse::<Ipv4Addr>().ok();
        let mac = parts[2].to_uppercase();
        let cid = parts.get(3).unwrap_or(&"").to_string();

        if ip.is_some() {
            containers.push(DockerContainer {
                id: cid.chars().take(12).collect(),
                name: cname,
                image: String::new(),
                status: String::new(),
                ip,
                mac,
                gateway,
                network: name.to_string(),
                ports: String::new(),
            });
        }
    }

    Some(DockerNetwork {
        id: id.to_string(),
        name: name.to_string(),
        driver: driver.to_string(),
        subnet,
        gateway,
        containers,
    })
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Docker Compose Discovery
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Discover containers via `docker compose ls` + `docker compose ps`.
fn compose_discover_containers() -> Vec<DockerContainer> {
    // List compose projects
    let output = quiet_command("docker")
        .args(["compose", "ls", "--format", "json"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let projects: Vec<String> = match serde_json::from_str::<serde_json::Value>(&stdout) {
        Ok(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v["Name"].as_str().map(|s| s.to_string()))
            .collect(),
        _ => return Vec::new(),
    };

    let mut all_containers = Vec::new();

    for project in &projects {
        let output = quiet_command("docker")
            .args(["compose", "-p", project, "ps", "--format", "json"])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => continue,
        };

        let stdout = String::from_utf8_lossy(&output.stdout);

        // docker compose ps --format json may output one JSON object per line
        // or a JSON array, depending on version
        let entries: Vec<serde_json::Value> =
            if let Ok(serde_json::Value::Array(arr)) = serde_json::from_str(&stdout) {
                arr
            } else {
                stdout
                    .lines()
                    .filter_map(|line| serde_json::from_str(line).ok())
                    .collect()
            };

        for entry in &entries {
            let id = entry["ID"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(12)
                .collect::<String>();
            let name = entry["Name"].as_str().unwrap_or("").to_string();
            let image = entry["Image"].as_str().unwrap_or("").to_string();
            let status = entry["Status"].as_str()
                .or_else(|| entry["State"].as_str())
                .unwrap_or("")
                .to_string();
            let ports = entry["Ports"].as_str().unwrap_or("").to_string();

            if !id.is_empty() {
                all_containers.push(DockerContainer {
                    id,
                    name,
                    image,
                    status,
                    ip: None,
                    mac: String::new(),
                    gateway: None,
                    network: String::new(),
                    ports,
                });
            }
        }
    }

    all_containers
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Docker System Info
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Daemon metadata from `docker info`. Currently used for enrichment;
/// the return value can be expanded in the future.
#[derive(Default)]
struct DockerDaemonInfo {
    /// Default network driver (e.g. "bridge")
    pub _default_driver: String,
}

fn docker_system_info() -> DockerDaemonInfo {
    // Try API first
    if let Some(json) = pipe_get("/info") {
        let driver = json["DefaultRuntime"]
            .as_str()
            .unwrap_or("bridge")
            .to_string();
        return DockerDaemonInfo {
            _default_driver: driver,
        };
    }

    // Fallback to CLI
    let output = quiet_command("docker")
        .args(["info", "--format", "{{.DefaultRuntime}}"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            DockerDaemonInfo {
                _default_driver: if s.is_empty() {
                    "bridge".to_string()
                } else {
                    s
                },
            }
        }
        _ => DockerDaemonInfo::default(),
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Main Entry Point — Parallel Discovery + Merge
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Deep Docker discovery: runs API, CLI, Compose, and system info in parallel,
/// then merges all results for maximum coverage.
///
/// Docker Engine API via named pipe is the PRIMARY source.
/// CLI and Compose are FALLBACK / supplemental sources.
pub fn discover_deep() -> Vec<DockerNetwork> {
    let api_containers: Mutex<Vec<DockerContainer>> = Mutex::new(Vec::new());
    let api_networks: Mutex<Vec<DockerNetwork>> = Mutex::new(Vec::new());
    let cli_containers: Mutex<Vec<DockerContainer>> = Mutex::new(Vec::new());
    let cli_networks: Mutex<Vec<DockerNetwork>> = Mutex::new(Vec::new());
    let compose_containers: Mutex<Vec<DockerContainer>> = Mutex::new(Vec::new());
    let _daemon_info: Mutex<DockerDaemonInfo> = Mutex::new(DockerDaemonInfo::default());

    thread::scope(|s| {
        // 1. Docker Engine API — containers
        let ac = &api_containers;
        s.spawn(move || {
            *ac.lock().unwrap() = api_discover_containers();
        });

        // 2. Docker Engine API — networks
        let an = &api_networks;
        s.spawn(move || {
            *an.lock().unwrap() = api_discover_networks();
        });

        // 3. Docker CLI — containers (fallback)
        let cc = &cli_containers;
        s.spawn(move || {
            *cc.lock().unwrap() = cli_discover_containers();
        });

        // 4. Docker CLI — networks (fallback)
        let cn = &cli_networks;
        s.spawn(move || {
            *cn.lock().unwrap() = cli_discover_networks();
        });

        // 5. Docker Compose — containers
        let cpc = &compose_containers;
        s.spawn(move || {
            *cpc.lock().unwrap() = compose_discover_containers();
        });

        // 6. Docker system info
        let di = &_daemon_info;
        s.spawn(move || {
            *di.lock().unwrap() = docker_system_info();
        });
    });

    let api_containers = api_containers.into_inner().unwrap();
    let api_networks = api_networks.into_inner().unwrap();
    let cli_containers = cli_containers.into_inner().unwrap();
    let cli_networks = cli_networks.into_inner().unwrap();
    let compose_containers = compose_containers.into_inner().unwrap();

    // Build unified container list: API first (primary), then CLI, then Compose
    let mut all_containers: Vec<DockerContainer> = Vec::new();
    let mut seen_ids: HashMap<String, usize> = HashMap::new(); // id -> index

    // Helper: merge a container into the list
    let merge_container = |containers: &mut Vec<DockerContainer>,
                           seen: &mut HashMap<String, usize>,
                           c: DockerContainer| {
        if c.id.is_empty() {
            containers.push(c);
            return;
        }

        if let Some(&idx) = seen.get(&c.id) {
            // Enrich existing entry with missing fields
            let existing = &mut containers[idx];
            if existing.image.is_empty() && !c.image.is_empty() {
                existing.image = c.image;
            }
            if existing.status.is_empty() && !c.status.is_empty() {
                existing.status = c.status;
            }
            if existing.ip.is_none() && c.ip.is_some() {
                existing.ip = c.ip;
            }
            if existing.mac.is_empty() && !c.mac.is_empty() {
                existing.mac = c.mac;
            }
            if existing.gateway.is_none() && c.gateway.is_some() {
                existing.gateway = c.gateway;
            }
            if existing.network.is_empty() && !c.network.is_empty() {
                existing.network = c.network;
            }
            if existing.ports.is_empty() && !c.ports.is_empty() {
                existing.ports = c.ports;
            }
        } else {
            let idx = containers.len();
            seen.insert(c.id.clone(), idx);
            containers.push(c);
        }
    };

    // API containers are primary
    for c in api_containers {
        merge_container(&mut all_containers, &mut seen_ids, c);
    }
    // CLI containers fill gaps
    for c in cli_containers {
        merge_container(&mut all_containers, &mut seen_ids, c);
    }
    // Compose containers fill remaining gaps
    for c in compose_containers {
        merge_container(&mut all_containers, &mut seen_ids, c);
    }

    // Build unified network list: API networks first, then CLI networks
    let mut networks: Vec<DockerNetwork> = Vec::new();
    let mut net_by_name: HashMap<String, usize> = HashMap::new();

    let merge_network = |networks: &mut Vec<DockerNetwork>,
                         by_name: &mut HashMap<String, usize>,
                         net: DockerNetwork| {
        if let Some(&idx) = by_name.get(&net.name) {
            // Merge containers into existing network
            let existing = &mut networks[idx];
            if existing.subnet.is_none() && net.subnet.is_some() {
                existing.subnet = net.subnet;
            }
            if existing.gateway.is_none() && net.gateway.is_some() {
                existing.gateway = net.gateway;
            }
            if existing.driver.is_empty() && !net.driver.is_empty() {
                existing.driver = net.driver;
            }
            if existing.id.is_empty() && !net.id.is_empty() {
                existing.id = net.id;
            }
            for c in net.containers {
                let already = existing
                    .containers
                    .iter()
                    .any(|ec| ec.id == c.id || ec.name == c.name);
                if !already {
                    existing.containers.push(c);
                }
            }
        } else {
            let idx = networks.len();
            by_name.insert(net.name.clone(), idx);
            networks.push(net);
        }
    };

    // API networks are primary
    for net in api_networks {
        merge_network(&mut networks, &mut net_by_name, net);
    }
    // CLI networks fill gaps
    for net in cli_networks {
        merge_network(&mut networks, &mut net_by_name, net);
    }

    // Place any remaining containers (not yet in a network) into the right network
    let container_map: HashMap<String, &DockerContainer> = all_containers
        .iter()
        .filter(|c| !c.id.is_empty())
        .map(|c| (c.id.clone(), c))
        .collect();

    for container in &all_containers {
        let already_in_network = networks.iter().any(|net| {
            net.containers
                .iter()
                .any(|c| c.id == container.id || c.name == container.name)
        });

        if !already_in_network {
            let net = networks.iter_mut().find(|n| n.name == container.network);
            if let Some(net) = net {
                net.containers.push(container.clone());
            } else if !container.network.is_empty() {
                let idx = networks.len();
                net_by_name.insert(container.network.clone(), idx);
                networks.push(DockerNetwork {
                    id: String::new(),
                    name: container.network.clone(),
                    driver: "bridge".to_string(),
                    subnet: None,
                    gateway: container.gateway,
                    containers: vec![container.clone()],
                });
            }
        }
    }

    // Enrich: fill in image/status/ports for network-discovered containers
    for net in &mut networks {
        for c in &mut net.containers {
            if (c.image.is_empty() || c.status.is_empty() || c.ports.is_empty())
                && !c.id.is_empty()
            {
                if let Some(full_c) = container_map.get(&c.id) {
                    if c.image.is_empty() {
                        c.image = full_c.image.clone();
                    }
                    if c.status.is_empty() {
                        c.status = full_c.status.clone();
                    }
                    if c.ports.is_empty() {
                        c.ports = full_c.ports.clone();
                    }
                }
            }
        }
    }

    // Remove networks with no containers
    networks.retain(|n| !n.containers.is_empty());

    networks
}
