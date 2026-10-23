//! Firewall integration: per-app block/allow, deny-all policy, lockdown mode,
//! and ask-to-connect tracking.
//!
//! The cross-platform [`FirewallManager`] state lives here. The system-affecting
//! primitives are split by platform: Windows drives `netsh advfirewall` (below),
//! while Linux drives nftables through the [`sys`] backend. The public API is the
//! same on both so the UI and app loop never branch on platform.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::types::{FirewallAppAction, FirewallMode, FirewallRule};

#[cfg(not(windows))]
use crate::types::Connection;

#[cfg(not(windows))]
#[path = "firewall_linux.rs"]
mod sys;

/// Manages firewall state and rules.
pub struct FirewallManager {
    /// Cached firewall rules.
    pub rules: Vec<FirewallRule>,
    /// Current firewall mode.
    pub mode: FirewallMode,
    /// Apps that have been approved in ask-to-connect mode.
    pub approved_apps: HashSet<String>,
    /// Apps that have been blocked in ask-to-connect mode.
    pub blocked_apps: HashSet<String>,
    /// Apps pending approval (detected in current session but not yet approved).
    pub pending_apps: Vec<String>,
    /// Whether the firewall is globally enabled.
    pub enabled: bool,
    /// Scroll position for UI.
    pub scroll_offset: usize,
    /// Ticks since last rule refresh.
    refresh_tick: u32,
    /// Filter text for rules.
    pub filter_text: String,
    /// Background refresh result (rules, enabled).
    refresh_result: Arc<Mutex<Option<(Vec<FirewallRule>, bool)>>>,
    /// Per-app actions managed by PSNET (persisted to disk).
    pub app_actions: HashMap<String, FirewallAppAction>,
    /// Path to the app action state file.
    state_path: PathBuf,
    /// Default policy: false = allow-all (block what you block),
    ///                  true  = deny-all  (only allow what you allow).
    pub default_deny: bool,
    /// Linux-only: resolved netfilter identity (cgroup/UID) per managed app,
    /// refreshed from live PIDs so nft rules keep matching across respawns.
    #[cfg(not(windows))]
    app_matches: HashMap<String, sys::AppMatch>,
    /// Linux-only: last nft script applied, used to skip redundant reloads.
    #[cfg(not(windows))]
    last_applied: Option<String>,
}

impl FirewallManager {
    pub fn new() -> Self {
        // Defer is_firewall_enabled() — it runs `netsh` which blocks 100-500ms.
        // Start with enabled=true (safe default), fix on first background tick.
        let state_path = Self::default_state_path();
        let app_actions = Self::load_state_from_disk(&state_path);
        let blocked_apps: HashSet<String> = app_actions.iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Deny | FirewallAppAction::Drop))
            .map(|(name, _)| name.clone())
            .collect();
        let approved_apps: HashSet<String> = app_actions.iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Allow))
            .map(|(name, _)| name.clone())
            .collect();
        Self {
            rules: Vec::new(),
            mode: FirewallMode::Normal,
            approved_apps,
            blocked_apps,
            pending_apps: Vec::new(),
            enabled: true, // assume enabled; background check will correct
            scroll_offset: 0,
            refresh_tick: 0,
            filter_text: String::new(),
            refresh_result: Arc::new(Mutex::new(None)),
            app_actions,
            state_path,
            default_deny: false,
            #[cfg(not(windows))]
            app_matches: HashMap::new(),
            #[cfg(not(windows))]
            last_applied: None,
        }
    }

    /// Default path: %APPDATA%/psnet/firewall_state.json
    fn default_state_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("firewall_state.json")
        } else {
            PathBuf::from("psnet_firewall_state.json")
        }
    }

    fn load_state_from_disk(path: &PathBuf) -> HashMap<String, FirewallAppAction> {
        match std::fs::read_to_string(path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => HashMap::new(),
        }
    }

    fn save_state_to_disk(&self) {
        if let Ok(json) = serde_json::to_string_pretty(&self.app_actions) {
            let _ = std::fs::write(&self.state_path, json);
        }
    }

    /// Refresh rules from system. Periodic refresh runs on a background thread
    /// to avoid blocking the UI for 2-5 seconds while netsh executes.
    pub fn tick(&mut self) {
        self.refresh_tick += 1;

        // Poll background refresh result
        if let Ok(mut r) = self.refresh_result.lock() {
            if let Some((rules, enabled)) = r.take() {
                self.rules = rules;
                self.enabled = enabled;
            }
        }

        // Spawn background refresh every 30 ticks
        if self.refresh_tick % 30 == 1 {
            let result = Arc::clone(&self.refresh_result);
            std::thread::spawn(move || {
                let rules = fetch_firewall_rules();
                let enabled = is_firewall_enabled();
                if let Ok(mut r) = result.lock() {
                    *r = Some((rules, enabled));
                }
            });
        }
    }

    /// Fetch current firewall rules from the system (blocking — use for user-initiated refresh).
    pub fn refresh_rules(&mut self) {
        self.rules = fetch_firewall_rules();
        self.enabled = is_firewall_enabled();
    }

    /// Block an application by creating outbound + inbound block rules.
    ///
    /// `process_path` should be the **full executable path**
    /// (e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`).
    /// Windows Firewall silently ignores the `program=` filter when only
    /// a filename is given — the full path is required for the rule to match.
    pub fn block_app(&mut self, process_path: &str) -> bool {
        self.apply_action(process_path, Some(process_path), FirewallAppAction::Deny)
    }

    /// Toggle ask-to-connect mode (tracking only — no actual firewall changes).
    pub fn toggle_ask_to_connect(&mut self) {
        self.mode = match self.mode {
            FirewallMode::AskToConnect => FirewallMode::Normal,
            _ => FirewallMode::AskToConnect,
        };
    }

    /// In ask-to-connect mode, check if a process is pending approval.
    pub fn check_pending(&mut self, process_name: &str) {
        if self.mode != FirewallMode::AskToConnect {
            return;
        }
        let key = process_name.to_lowercase();
        if !self.approved_apps.contains(&key) && !self.blocked_apps.contains(&key) {
            if !self.pending_apps.contains(&key) {
                self.pending_apps.push(key);
            }
        }
    }

    /// Check if an app is blocked by a PSNET-created rule (Deny or Drop).
    pub fn is_psnet_blocked(&self, app_name: &str) -> bool {
        let key = app_name.to_lowercase();
        if self.blocked_apps.contains(&key) {
            return true;
        }
        let block_name = format!("PSNET_Block_{}", app_name);
        let drop_name = format!("PSNET_Drop_{}", app_name);
        self.rules.iter().any(|r| {
            r.enabled && (r.name.eq_ignore_ascii_case(&block_name) || r.name.eq_ignore_ascii_case(&drop_name))
        })
    }

    /// Apply a firewall action (Allow / Deny / Drop) for an app.
    /// Removes any previous PSNET rules for this app first, then creates new ones.
    pub fn apply_action(&mut self, app_name: &str, process_path: Option<&str>, action: FirewallAppAction) -> bool {
        let _ = process_path; // Linux matches by cgroup/UID, not the exe path
        let base = app_basename(app_name);
        let key = base.to_lowercase();

        #[cfg(not(windows))]
        {
            // Linux enforces the whole policy declaratively through nftables, so
            // record the intent, (re)resolve how this app is matched from its
            // live PIDs, then rebuild the managed table.
            self.blocked_apps.remove(&key);
            self.approved_apps.remove(&key);
            match &action {
                FirewallAppAction::Deny | FirewallAppAction::Drop => {
                    self.blocked_apps.insert(key.clone());
                }
                FirewallAppAction::Allow => {
                    self.approved_apps.insert(key.clone());
                }
            }
            self.app_matches
                .insert(key.clone(), sys::resolve_match(&sys::pids_for_app(&key)));
            self.app_actions.insert(key, action);
            self.save_state_to_disk();
            return self.linux_enforce();
        }

        #[cfg(windows)]
        {
        // Remove any existing PSNET rules for this app
        self.remove_psnet_rules(base);

        let path = process_path.unwrap_or(app_name);

        let ok = match &action {
            FirewallAppAction::Allow => {
                let rule_out = format!("PSNET_Allow_{}", base);
                let rule_in = format!("PSNET_Allow_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "allow", path);
                let _ = netsh_add_rule(&rule_in, "in", "allow", path);
                ok
            }
            FirewallAppAction::Deny => {
                let rule_out = format!("PSNET_Block_{}", base);
                let rule_in = format!("PSNET_Block_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "block", path);
                let _ = netsh_add_rule(&rule_in, "in", "block", path);
                ok
            }
            FirewallAppAction::Drop => {
                let rule_out = format!("PSNET_Drop_{}", base);
                let rule_in = format!("PSNET_Drop_{}_In", base);
                let ok = netsh_add_rule(&rule_out, "out", "block", path);
                let _ = netsh_add_rule(&rule_in, "in", "block", path);
                ok
            }
        };

        if ok {
            self.blocked_apps.remove(&key);
            self.approved_apps.remove(&key);
            match &action {
                FirewallAppAction::Deny | FirewallAppAction::Drop => {
                    self.blocked_apps.insert(key.clone());
                }
                FirewallAppAction::Allow => {
                    self.approved_apps.insert(key.clone());
                }
            }
            self.app_actions.insert(key, action);
            self.save_state_to_disk();
            self.refresh_rules();
        }
        ok
        }
    }

    /// Remove all PSNET-created rules (Block, Allow, Drop) for a specific app.
    #[cfg(windows)]
    fn remove_psnet_rules(&mut self, app_name: &str) {
        for prefix in &["PSNET_Block_", "PSNET_Allow_", "PSNET_Drop_"] {
            let rule = format!("{}{}", prefix, app_name);
            let rule_in = format!("{}{}_In", prefix, app_name);
            let _ = netsh_delete_rule(&rule);
            let _ = netsh_delete_rule(&rule_in);
        }
    }

    /// Remove ALL PSNET firewall rules and reset state to defaults.
    pub fn reset_all_psnet_rules(&mut self) {
        #[cfg(windows)]
        {
            let apps: Vec<String> = self.app_actions.keys().cloned().collect();
            for key in &apps {
                let base = app_basename(key);
                self.remove_psnet_rules(base);
            }
            for rule in &self.rules {
                if rule.name.starts_with("PSNET_") {
                    let _ = netsh_delete_rule(&rule.name);
                }
            }
        }

        self.app_actions.clear();
        self.blocked_apps.clear();
        self.approved_apps.clear();
        self.mode = FirewallMode::Normal;
        self.default_deny = false;

        #[cfg(not(windows))]
        {
            self.app_matches.clear();
            sys::teardown();
            self.last_applied = None;
            self.enabled = is_firewall_enabled();
        }

        self.save_state_to_disk();

        #[cfg(windows)]
        self.refresh_rules();
    }

    /// Get the current PSNET action for an app, if any.
    pub fn get_app_action(&self, app_name: &str) -> Option<&FirewallAppAction> {
        self.app_actions.get(&app_name.to_lowercase())
    }

    /// Toggle default policy between allow-all and deny-all.
    pub fn toggle_default_policy(&mut self) {
        self.default_deny = !self.default_deny;
        #[cfg(not(windows))]
        {
            // Deny-all must know every allowed app's identity to let it through,
            // so refresh matches from live PIDs before rebuilding the table.
            self.refresh_app_matches();
            self.linux_enforce();
        }
    }

    /// Linux: re-resolve how each managed app is matched in netfilter from its
    /// currently-running PIDs, dropping identities for apps no longer managed.
    #[cfg(not(windows))]
    fn refresh_app_matches(&mut self) {
        self.app_matches.retain(|k, _| self.app_actions.contains_key(k));
        let keys: Vec<String> = self.app_actions.keys().cloned().collect();
        for key in keys {
            let m = sys::resolve_match(&sys::pids_for_app(&key));
            self.app_matches.insert(key, m);
        }
    }

    /// Linux: refresh identities from the live connection table (cheaper than a
    /// full /proc scan — the firewall tab only acts on apps that have sockets)
    /// and rebuild the nft table if anything changed. Called from the app tick.
    #[cfg(not(windows))]
    pub fn update_identities(&mut self, conns: &[Connection]) {
        if self.app_actions.is_empty() && !self.default_deny {
            return;
        }
        // Group live PIDs by app key for the apps we manage.
        let mut pids: HashMap<String, Vec<u32>> = HashMap::new();
        for c in conns {
            if c.pid == 0 || c.process_name.is_empty() {
                continue;
            }
            let key = c.process_name.to_lowercase();
            if self.app_actions.contains_key(&key) {
                pids.entry(key).or_default().push(c.pid);
            }
        }
        self.app_matches.retain(|k, _| self.app_actions.contains_key(k));
        for (key, pid_list) in pids {
            let m = sys::resolve_match(&pid_list);
            // Keep a previously-resolved identity for an app that momentarily has
            // no live sockets rather than forgetting how to match it.
            if m.is_usable() {
                self.app_matches.insert(key, m);
            }
        }
        self.linux_enforce();
    }

    /// Linux: build the policy spec from managed state, rebuild the nft table if
    /// it changed since the last apply, and refresh the shield status. Returns
    /// whether the system now reflects the request.
    #[cfg(not(windows))]
    fn linux_enforce(&mut self) -> bool {
        let mut apps = Vec::new();
        for (key, action) in &self.app_actions {
            let matcher = match self.app_matches.get(key) {
                Some(m) if m.is_usable() => m.clone(),
                _ => continue, // not running / cannot isolate → nothing to enforce
            };
            // Deny-all needs rules for Allow (accept) and Deny (reject); Drop is
            // the policy itself. Allow-all needs rules for Deny and Drop only.
            let relevant = match (self.default_deny, action) {
                (true, FirewallAppAction::Allow | FirewallAppAction::Deny) => true,
                (false, FirewallAppAction::Deny | FirewallAppAction::Drop) => true,
                _ => false,
            };
            if relevant {
                apps.push(sys::AppPolicy { action: action.clone(), matcher });
            }
        }
        let spec = sys::PolicySpec { default_deny: self.default_deny, apps };
        let script = sys::render(&spec);
        if self.last_applied.as_deref() == Some(script.as_str()) {
            return true; // already applied — skip the reload (and the status probe)
        }
        let ok = sys::apply(&spec);
        if ok {
            self.last_applied = Some(script);
        }
        // Only probe the shield status when we actually changed the ruleset; the
        // periodic background refresh in tick() handles the steady state.
        self.enabled = is_firewall_enabled();
        ok
    }

    /// Effective status of an app considering default policy.
    /// Returns (status_label, is_blocked).
    pub fn effective_status(&self, app_name: &str) -> (&'static str, bool) {
        let action = self.get_app_action(app_name);
        match action {
            Some(FirewallAppAction::Deny) => ("DENY", true),
            Some(FirewallAppAction::Drop) => ("DROP", true),
            Some(FirewallAppAction::Allow) => ("ALLOW", false),
            None => {
                if self.default_deny {
                    ("BLOCKED", true)
                } else if self.blocked_apps.contains(&app_name.to_lowercase()) {
                    ("BLOCKED", true)
                } else {
                    ("ALLOWED", false)
                }
            }
        }
    }

}

/// The app's base name, tolerant of both Windows (`\`) and POSIX (`/`) paths so
/// a full executable path and a bare process name both key the same entry.
fn app_basename(app_name: &str) -> &str {
    app_name
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(app_name)
}

// ─── Netsh helpers (Windows) ──────────────────────────────────────────────────

#[cfg(windows)]
fn netsh_add_rule(name: &str, dir: &str, action: &str, program: &str) -> bool {
    Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={}", name),
            &format!("dir={}", dir),
            &format!("action={}", action),
            &format!("program={}", program),
            "enable=yes",
            "profile=any",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn netsh_delete_rule(name: &str) -> bool {
    Command::new("netsh")
        .args([
            "advfirewall", "firewall", "delete", "rule",
            &format!("name={}", name),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// ─── System queries ──────────────────────────────────────────────────────────

/// Linux: a packet-filtering firewall (fw4, firewalld, PSNET's own table, …) is
/// loaded. Drives the "Shield" status.
#[cfg(not(windows))]
fn is_firewall_enabled() -> bool {
    sys::is_enabled()
}

/// Linux: PSNET's managed nft table is rebuilt declaratively, so the rule list
/// comes straight from the live table rather than being tracked rule-by-rule.
#[cfg(not(windows))]
fn fetch_firewall_rules() -> Vec<FirewallRule> {
    sys::fetch_rules()
}

/// Check if Windows Firewall is enabled.
#[cfg(windows)]
fn is_firewall_enabled() -> bool {
    let output = Command::new("netsh")
        .args(["advfirewall", "show", "allprofiles", "state"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("ON")
        }
        _ => false,
    }
}

/// Fetch firewall rules from netsh.
#[cfg(windows)]
fn fetch_firewall_rules() -> Vec<FirewallRule> {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", "name=all", "verbose"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_firewall_rules(&text)
}

#[cfg(windows)]
fn parse_firewall_rules(text: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    let mut current_name = String::new();
    let mut current_enabled = true;
    let mut in_rule = false;

    for line in text.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("Rule Name:") {
            // Save previous rule
            if in_rule && !current_name.is_empty() {
                rules.push(FirewallRule {
                    name: current_name.clone(),
                    enabled: current_enabled,
                });
            }
            current_name = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim().to_string();
            current_enabled = true;
            in_rule = true;
        } else if trimmed.starts_with("Enabled:") {
            let val = trimmed.splitn(2, ':').nth(1).unwrap_or("").trim();
            current_enabled = val.eq_ignore_ascii_case("yes");
        }
    }

    // Push the last rule
    if in_rule && !current_name.is_empty() {
        rules.push(FirewallRule {
            name: current_name,
            enabled: current_enabled,
        });
    }

    rules
}
