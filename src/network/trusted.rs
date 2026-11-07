//! Trusted addresses for the Alerts tab (issue #11).
//!
//! An alert whose subject is a trusted address (a suspicious host, an RDP
//! peer, an ARP or device change) is not raised. The list lives in
//! `trusted_ips.txt` next to `alerts.json`, one entry per line: a single
//! address (`203.0.113.7`, `fe80::1`) or a CIDR range (`100.64.0.0/10`).
//! Lines starting with `#` are comments. Press `w` on an alert to add its
//! address; edit the file by hand to add ranges or remove entries.

use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl TrustedNet {
    /// Parse `1.2.3.4`, `1.2.3.0/24`, `::1` or `2001:db8::/32`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip.trim(), Some(p.trim().parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = ip.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }

    fn is_single(&self) -> bool {
        self.prefix == if self.addr.is_ipv4() { 32 } else { 128 }
    }
}

impl std::fmt::Display for TrustedNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

/// Map an IPv4-mapped IPv6 address (`::ffff:1.2.3.4`) to plain IPv4 so one
/// entry covers both forms the connection table can report.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub struct TrustedIps {
    pub entries: Vec<TrustedNet>,
    path: Option<PathBuf>,
}

impl TrustedIps {
    /// An empty list that is never written to disk.
    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self { entries: Vec::new(), path: None }
    }

    /// Load the list from `path`; a missing file is an empty list.
    pub fn load(path: PathBuf) -> Self {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        Self { entries: parse_list(&text), path: Some(path) }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        self.entries.iter().any(|n| n.contains(ip))
    }

    /// Trust `ip` if it is not trusted yet, otherwise stop trusting it.
    /// Untrusting removes single address entries and any range that covers
    /// it. Returns true when the address is trusted afterwards.
    pub fn toggle(&mut self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        if self.contains(ip) {
            self.entries.retain(|n| !n.contains(ip));
            self.save();
            false
        } else {
            let prefix = if ip.is_ipv4() { 32 } else { 128 };
            self.entries.push(TrustedNet { addr: ip, prefix });
            self.save();
            true
        }
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        let mut out = String::from(
            "# psnet trusted addresses: alerts about these are not raised.\n\
             # One address or CIDR range per line, for example 100.64.0.0/10\n",
        );
        for n in &self.entries {
            out.push_str(&n.to_string());
            out.push('\n');
        }
        let _ = std::fs::write(path, out);
    }
}

pub fn parse_list(text: &str) -> Vec<TrustedNet> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .filter_map(TrustedNet::parse)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_addresses_ranges_and_comments() {
        let list = parse_list(
            "# header\n203.0.113.7\n100.64.0.0/10  # tailscale\n\nfe80::/10\nnot an ip\n1.2.3.4/33\n",
        );
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].to_string(), "203.0.113.7");
        assert_eq!(list[1].to_string(), "100.64.0.0/10");
        assert_eq!(list[2].to_string(), "fe80::/10");
    }

    #[test]
    fn ranges_match_only_their_members() {
        let t = TrustedIps { entries: parse_list("100.64.0.0/10\n2001:db8::/32"), path: None };
        assert!(t.contains(ip("100.101.102.103")));
        assert!(t.contains(ip("100.127.255.255")));
        assert!(!t.contains(ip("100.128.0.1")));
        assert!(t.contains(ip("2001:db8:1::5")));
        assert!(!t.contains(ip("2001:db9::5")));
        // v4 entries also cover the v4-mapped v6 form
        assert!(t.contains(ip("::ffff:100.64.0.9")));
    }

    #[test]
    fn toggle_adds_then_removes_and_persists() {
        let dir = std::env::temp_dir().join(format!("psnet-trusted-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("trusted_ips.txt");
        let _ = std::fs::remove_file(&path);

        let mut t = TrustedIps::load(path.clone());
        assert!(t.toggle(ip("198.51.100.20")));
        let reloaded = TrustedIps::load(path.clone());
        assert!(reloaded.contains(ip("198.51.100.20")));

        assert!(!t.toggle(ip("198.51.100.20")));
        assert!(!TrustedIps::load(path.clone()).contains(ip("198.51.100.20")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
