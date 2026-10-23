//! Linux firewall backend for PSNET, built on nftables.
//!
//! Windows blocks an application by its executable path through Windows Firewall
//! (`netsh advfirewall`). netfilter has no concept of "the chrome.exe process",
//! so this backend matches an app by the kernel identity its live sockets carry:
//!
//!   * **cgroup v2** — the control-group a process already lives in
//!     (`socket cgroupv2`). Preferred: each service/daemon has its own cgroup on
//!     procd and systemd, so this isolates one app without touching the others
//!     and without moving any process between groups.
//!   * **owner UID** — `meta skuid`, used only when no isolating cgroup exists.
//!     Skipped for root (uid 0): dropping all of root's traffic would cut the
//!     box off, so a root daemon that also shares the root cgroup simply cannot
//!     be isolated and its block is recorded but not enforced.
//!
//! The managed ruleset lives in its own `inet psnet` table so it composes with
//! (and never clobbers) the system firewall (OpenWrt's `fw4`, firewalld, …).
//! Everything is applied atomically through `nft -f -`; there are no extra crate
//! dependencies, matching the rest of the Linux data layer.

use std::collections::BTreeSet;
use std::io::Write;
use std::process::{Command, Stdio};

use crate::network::linux;
use crate::types::{FirewallAppAction, FirewallRule};

/// Name of the PSNET-owned nftables table (family `inet`, so it covers v4+v6).
const TABLE: &str = "psnet";

// ─── App → netfilter identity ─────────────────────────────────────────────────

/// How an application's packets can be matched in netfilter, derived from the
/// kernel identity of its currently-running processes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppMatch {
    /// cgroup-v2 paths (relative to the cgroup2 mount, never the root cgroup).
    pub cgroups: BTreeSet<String>,
    /// Non-root owner UIDs (used only when no cgroup is available).
    pub uids: BTreeSet<u32>,
}

impl AppMatch {
    /// True when at least one selector that isolates *this* app is available.
    pub fn is_usable(&self) -> bool {
        !self.cgroups.is_empty() || !self.uids.is_empty()
    }
}

/// Resolve the netfilter identity of an app from the PIDs of its live sockets.
///
/// cgroups are preferred when any is usable: they pin the exact service, whereas
/// a UID can be shared by unrelated daemons. The root cgroup and uid 0 are both
/// rejected because matching them would hit far more than the target app.
pub fn resolve_match(pids: &[u32]) -> AppMatch {
    let mut m = AppMatch::default();
    for &pid in pids {
        if pid == 0 {
            continue;
        }
        if let Some(cg) = linux::process_cgroup2(pid) {
            if !cg.is_empty() {
                m.cgroups.insert(cg);
            }
        }
        if let Some(uid) = linux::process_uid(pid) {
            if uid != 0 {
                m.uids.insert(uid);
            }
        }
    }
    // A precise cgroup match makes the UID fallback unnecessary — and the UID
    // would widen the match to any sibling daemon sharing it, so drop it.
    if !m.cgroups.is_empty() {
        m.uids.clear();
    }
    m
}

/// PIDs whose process identity matches `key` (an app name, lowercased), scanned
/// from /proc. The exe basename is preferred over `comm`, which the kernel
/// truncates to 15 bytes; `comm` is the fallback when the exe link is unreadable.
pub fn pids_for_app(key: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return pids,
    };
    for ent in dir.flatten() {
        let pid: u32 = match ent.file_name().to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let name = linux::process_exe(pid)
            .map(|p| p.rsplit('/').next().unwrap_or(&p).to_string())
            .or_else(|| linux::process_name(pid));
        if let Some(name) = name {
            if name.to_lowercase() == key {
                pids.push(pid);
            }
        }
    }
    pids
}

// ─── Policy specification ─────────────────────────────────────────────────────

/// One app's enforced action together with how to match it.
pub struct AppPolicy {
    pub action: FirewallAppAction,
    pub matcher: AppMatch,
}

/// The complete PSNET-managed policy to render into the `inet psnet` table.
pub struct PolicySpec {
    /// `true` = deny-all (default-drop output, allow only the safe set + Allowed
    /// apps); `false` = allow-all (drop only Denied/Dropped apps).
    pub default_deny: bool,
    /// Apps with a usable matcher. Apps that cannot be isolated are excluded by
    /// the caller so an unenforceable block never silently widens the policy.
    pub apps: Vec<AppPolicy>,
}

impl PolicySpec {
    /// Nothing needs enforcing: allow-all policy with no app actually blocked.
    fn is_noop(&self) -> bool {
        !self.default_deny
            && !self
                .apps
                .iter()
                .any(|a| matches!(a.action, FirewallAppAction::Deny | FirewallAppAction::Drop))
    }
}

// ─── Ruleset rendering ────────────────────────────────────────────────────────

/// nftables depth of a cgroup path (`services/nginx` → 2), as the `level`
/// operand `socket cgroupv2` expects.
fn cgroup_level(path: &str) -> usize {
    path.split('/').filter(|c| !c.is_empty()).count()
}

/// Emit the match lines for one app with the given verdict (`accept`/`drop`).
fn emit_app(out: &mut String, m: &AppMatch, verdict: &str) {
    for cg in &m.cgroups {
        out.push_str(&format!(
            "        socket cgroupv2 level {} \"{}\" {}\n",
            cgroup_level(cg),
            cg,
            verdict
        ));
    }
    for uid in &m.uids {
        out.push_str(&format!("        meta skuid {} {}\n", uid, verdict));
    }
}

/// Render the full `nft -f` script that atomically replaces the `inet psnet`
/// table with the desired policy. The add/delete/add preamble makes the replace
/// idempotent even on the first run, when the table does not yet exist.
pub fn render(spec: &PolicySpec) -> String {
    let mut s = String::new();
    s.push_str(&format!("table inet {TABLE}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));
    s.push_str("    chain output {\n");

    if spec.default_deny {
        // Deny-all: drop new outbound by default, but keep the box reachable and
        // able to resolve names / renew leases so management access survives.
        s.push_str("        type filter hook output priority 0; policy drop;\n");
        s.push_str("        ct state established,related accept\n");
        s.push_str("        oifname \"lo\" accept\n");
        s.push_str("        meta l4proto { icmp, ipv6-icmp } accept\n");
        s.push_str("        udp dport { 53, 67, 68 } accept\n");
        s.push_str("        tcp dport { 22, 53 } accept\n");
        for app in &spec.apps {
            if matches!(app.action, FirewallAppAction::Allow) {
                emit_app(&mut s, &app.matcher, "accept");
            }
        }
        // Denied/Dropped apps and everything unlisted fall through to policy drop.
    } else {
        // Allow-all: only the explicitly Denied/Dropped apps are blocked.
        s.push_str("        type filter hook output priority 0; policy accept;\n");
        for app in &spec.apps {
            if matches!(app.action, FirewallAppAction::Deny | FirewallAppAction::Drop) {
                emit_app(&mut s, &app.matcher, "drop");
            }
        }
    }

    s.push_str("    }\n");
    s.push_str("}\n");
    s
}

// ─── System interaction ───────────────────────────────────────────────────────

/// Run a command, returning its stdout on success (exit 0), else None.
fn run(args: &[&str]) -> Option<String> {
    let out = Command::new(args[0]).args(&args[1..]).output().ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        None
    }
}

/// Feed `script` to `nft -f -`. Returns true on success.
fn nft_apply(script: &str) -> bool {
    let mut child = match Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false, // nft not installed → enforcement unavailable
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(script.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Apply the desired policy. Tears the table down when nothing needs enforcing.
/// Returns true when the system now reflects the request.
pub fn apply(spec: &PolicySpec) -> bool {
    if spec.is_noop() {
        teardown();
        return true;
    }
    nft_apply(&render(spec))
}

/// Remove the PSNET-managed table, restoring the system firewall to its own rules.
pub fn teardown() {
    let script = format!("table inet {TABLE}\ndelete table inet {TABLE}\n");
    let _ = nft_apply(&script);
}

/// Whether a packet-filtering firewall is currently active on this host.
///
/// This drives the "Shield" status. Any loaded nftables base chain (a `hook`)
/// counts — that includes OpenWrt's `fw4`, firewalld, and PSNET's own table —
/// with a legacy-iptables fallback for hosts still on `ip_tables`.
pub fn is_enabled() -> bool {
    if let Some(out) = run(&["nft", "list", "ruleset"]) {
        if out.contains("hook ") {
            return true;
        }
    }
    if let Some(out) = run(&["iptables", "-S"]) {
        let policies_locked = out
            .lines()
            .any(|l| l.starts_with("-P ") && (l.ends_with("DROP") || l.ends_with("REJECT")));
        let has_rules = out.lines().any(|l| l.starts_with("-A "));
        if policies_locked || has_rules {
            return true;
        }
    }
    false
}

/// Rule list for the UI. PSNET's Linux table is rebuilt declaratively rather
/// than tracked rule-by-rule, so the authoritative per-app state lives in the
/// manager; this reports the live base chains for parity with the Windows view.
pub fn fetch_rules() -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    if let Some(out) = run(&["nft", "list", "table", "inet", TABLE]) {
        // Count the managed verdicts so the UI can reflect that PSNET is active.
        for line in out.lines() {
            let t = line.trim();
            if t.ends_with(" drop") && (t.starts_with("socket ") || t.starts_with("meta skuid")) {
                rules.push(FirewallRule {
                    name: format!("PSNET_Block_{}", rules.len()),
                    enabled: true,
                });
            }
        }
    }
    rules
}
