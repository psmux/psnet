//! Detail popup overlay — shown when user presses Enter on any selected row.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::network::dns::port_service_name;
use crate::types::{DetailKind, FirewallAppAction};
use crate::utils::{format_bytes, format_speed};

/// Render the detail popup overlay if one is active.
pub fn draw_detail_popup(f: &mut Frame, app: &App) {
    let Some(ref detail) = app.detail_popup else { return };

    match detail {
        DetailKind::Connection(conn) => {
            let area = centered_rect(70, 60, f.area());
            f.render_widget(Clear, area);
            draw_connection_detail(f, area, conn, app);
        }
        DetailKind::Alert(alert) => {
            let area = centered_rect(70, 60, f.area());
            f.render_widget(Clear, area);
            draw_alert_detail(f, area, alert);
        }
        DetailKind::Device(device) => {
            let area = centered_rect(75, 85, f.area());
            f.render_widget(Clear, area);
            draw_device_detail(f, area, device, app);
        }
        DetailKind::FirewallApp(detail) => {
            let area = centered_rect(75, 70, f.area());
            f.render_widget(Clear, area);
            draw_firewall_app_detail(f, area, detail, app);
        }
        DetailKind::Server { .. } => {
            let area = centered_rect(75, 85, f.area());
            f.render_widget(Clear, area);
            draw_server_detail(f, area, detail);
        }
    }
}

// ─── Connection detail ───────────────────────────────────────────────────────

fn draw_connection_detail(f: &mut Frame, area: Rect, conn: &crate::types::Connection, app: &App) {
    let geo = conn.remote_addr
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .and_then(|ip| app.geoip.lookup(ip));

    let port = conn.remote_port.unwrap_or(conn.local_port);
    let service = port_service_name(port)
        .map(|s| format!("{} (port {})", s, port))
        .unwrap_or_else(|| format!("port {}", port));

    let remote_host = conn.dns_hostname.clone()
        .or_else(|| conn.remote_addr.map(|ip| ip.to_string()))
        .unwrap_or_else(|| "*".to_string());

    let state_str = conn.state.as_ref().map(|s| s.label().to_string()).unwrap_or_else(|| "\u{2014}".to_string());
    let state_color = conn.state.as_ref().map(|s| s.color()).unwrap_or(Color::Gray);
    let country_str = geo.map(|g| format!("{} {} ({})", g.flag, g.name, g.code)).unwrap_or_else(|| "Local / Private".to_string());
    let remote_addr_str = conn.remote_addr
        .map(|ip| format!("{}:{}", ip, conn.remote_port.unwrap_or(0)))
        .unwrap_or_else(|| "\u{2014}".to_string());

    let mut lines = header_lines(" Connection Detail ");
    lines.push(row("Protocol",    conn.proto.label().to_string(),                   Color::Rgb(100, 220, 255)));
    lines.push(row("Process",     conn.process_name.clone(),                        Color::Rgb(130, 200, 140)));
    lines.push(row("PID",         conn.pid.to_string(),                             Color::Rgb(120, 130, 160)));
    lines.push(row("Direction",   if conn.is_outbound() { "Outbound \u{2192}" } else { "Inbound \u{2190}" }.to_string(), Color::Rgb(200, 180, 100)));
    lines.push(row("Local",       format!("{}:{}", conn.local_addr, conn.local_port), Color::Rgb(150, 160, 190)));
    lines.push(row("Remote",      remote_addr_str,                                  Color::Rgb(170, 185, 210)));
    lines.push(row("DNS Name",    remote_host,                                      Color::Rgb(100, 220, 255)));
    lines.push(row("Service",     service,                                          Color::Rgb(200, 180, 80)));
    lines.push(row("State",       state_str,                                        state_color));
    lines.push(row("Country",     country_str,                                      Color::Rgb(170, 200, 230)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());

    render_popup(f, area, lines);
}

// ─── Alert detail ────────────────────────────────────────────────────────────

fn draw_alert_detail(f: &mut Frame, area: Rect, alert: &crate::types::Alert) {
    let severity = alert.kind.severity();
    let sev_color = severity.color();

    let mut lines = header_lines(" Alert Detail ");
    lines.push(row("Time",     alert.timestamp.format("%H:%M:%S").to_string(), Color::Rgb(120, 130, 160)));
    lines.push(row("Severity", severity.label().to_string(),                   sev_color));
    lines.push(row("Type",     alert.kind.label().to_string(),                 Color::Rgb(180, 190, 220)));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", alert.kind.description()),
        Style::default().fg(Color::Rgb(200, 210, 230)).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    match &alert.kind {
        crate::types::AlertKind::SuspiciousHost { process_name, ip, reason } => {
            lines.push(row("Process", process_name.clone(), Color::Rgb(130, 200, 140)));
            lines.push(row("IP",      ip.to_string(),       Color::Rgb(255, 120, 80)));
            lines.push(row("Reason",  reason.clone(),       Color::Rgb(255, 180, 80)));
        }
        crate::types::AlertKind::NewAppFirstConnection { process_name, remote } => {
            lines.push(row("Process", process_name.clone(), Color::Rgb(130, 200, 140)));
            lines.push(row("Remote",  remote.clone(),       Color::Rgb(100, 220, 255)));
        }
        crate::types::AlertKind::BandwidthSpike { direction, speed_bps, threshold_bps } => {
            lines.push(row("Direction", direction.clone(),           Color::Rgb(200, 180, 100)));
            lines.push(row("Speed",     format_speed(*speed_bps),    Color::Rgb(255, 120, 80)));
            lines.push(row("Threshold", format_speed(*threshold_bps), Color::Rgb(150, 160, 180)));
        }
        crate::types::AlertKind::NewDevice { ip, mac, hostname } => {
            lines.push(row("IP",       ip.to_string(),                                   Color::Rgb(100, 220, 255)));
            lines.push(row("MAC",      mac.clone(),                                      Color::Rgb(150, 160, 180)));
            lines.push(row("Hostname", hostname.clone().unwrap_or_else(|| "unknown".to_string()), Color::Rgb(180, 190, 140)));
        }
        crate::types::AlertKind::ArpAnomaly { ip, expected_mac, actual_mac } => {
            lines.push(row("IP",           ip.to_string(),        Color::Rgb(100, 220, 255)));
            lines.push(row("Expected MAC", expected_mac.clone(),  Color::Rgb(150, 160, 180)));
            lines.push(row("Actual MAC",   actual_mac.clone(),    Color::Rgb(255, 120, 80)));
        }
        crate::types::AlertKind::BandwidthOverage { used_bytes, limit_bytes } => {
            lines.push(row("Used",  format_bytes(*used_bytes),  Color::Rgb(255, 120, 80)));
            lines.push(row("Limit", format_bytes(*limit_bytes), Color::Rgb(150, 160, 180)));
        }
        crate::types::AlertKind::TrafficAnomaly { process_name, current_bytes, baseline_bytes } => {
            lines.push(row("Process",  process_name.clone(),        Color::Rgb(130, 200, 140)));
            lines.push(row("Current",  format_bytes(*current_bytes), Color::Rgb(255, 180, 80)));
            lines.push(row("Baseline", format_bytes(*baseline_bytes), Color::Rgb(150, 160, 180)));
        }
        _ => {}
    }

    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Device detail ───────────────────────────────────────────────────────────

fn draw_device_detail(f: &mut Frame, area: Rect, device: &crate::types::LanDevice, app: &App) {
    let is_gateway = app.network_scanner.gateway
        .map(|gw| device.ip == std::net::IpAddr::V4(gw))
        .unwrap_or(false);

    let status_color = if device.is_online { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 100, 120) };
    let status_str = if device.is_online { "\u{25cf} Online" } else { "\u{25cb} Offline" };

    let mut lines = header_lines(" Device Detail ");

    // ─── Identity ───
    lines.push(row("Status",     status_str.to_string(), status_color));
    lines.push(row("Role",       if is_gateway { "Gateway / Router" } else { "Host" }.to_string(),
        if is_gateway { Color::Rgb(255, 200, 80) } else { Color::Rgb(150, 160, 190) }));
    lines.push(row("IP Address", device.ip.to_string(), Color::Rgb(100, 180, 255)));
    // Show each hostname on its own line for readability
    if let Some(ref names) = device.hostname {
        let parts: Vec<&str> = names.split(", ").collect();
        if parts.len() == 1 {
            lines.push(row("Hostname", parts[0].to_string(), Color::Rgb(130, 200, 140)));
        } else {
            lines.push(row("Hostnames", format!("({} names found)", parts.len()), Color::Rgb(130, 200, 140)));
            for name in &parts {
                lines.push(Line::from(vec![
                    Span::styled(
                        "               ",
                        Style::default(),
                    ),
                    Span::styled(
                        format!("\u{2022} {}", name.trim()),
                        Style::default().fg(Color::Rgb(130, 200, 140)),
                    ),
                ]));
            }
        }
    } else {
        lines.push(row("Hostname", "\u{2014}".to_string(), Color::Rgb(90, 100, 120)));
    }
    if let Some(ref custom) = device.custom_name {
        lines.push(row("Custom Name", custom.clone(), Color::Rgb(255, 220, 100)));
    }

    // ─── Hardware ───
    lines.push(section_divider("Hardware"));
    lines.push(row("MAC Address", device.mac.clone(), Color::Rgb(150, 160, 180)));
    lines.push(row("Vendor",     device.vendor.clone().unwrap_or_else(|| "Unknown".to_string()), Color::Rgb(180, 170, 140)));

    // Detect locally administered / random MAC
    let first_octet = device.mac.split(':').next()
        .and_then(|s| u8::from_str_radix(s, 16).ok())
        .unwrap_or(0);
    if first_octet & 0x02 != 0 {
        lines.push(row("MAC Type", "Locally Administered (Randomized)".to_string(), Color::Rgb(200, 160, 100)));
    } else {
        lines.push(row("MAC Type", "Globally Unique (Manufacturer)".to_string(), Color::Rgb(120, 160, 140)));
    }

    // ─── Open Ports ───
    if !device.open_ports.is_empty() {
        lines.push(section_divider("Open Ports"));
        // Parse the port string and show each on its own line for clarity
        for port_entry in device.open_ports.split(' ') {
            let port_entry = port_entry.trim();
            if port_entry.is_empty() { continue; }
            if let Some((port_num, svc_name)) = port_entry.split_once(':') {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<8}", port_num),
                        Style::default().fg(Color::Rgb(180, 200, 120)).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        svc_name.to_string(),
                        Style::default().fg(Color::Rgb(120, 160, 180)),
                    ),
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("  {}", port_entry),
                    Style::default().fg(Color::Rgb(180, 200, 120)).add_modifier(Modifier::BOLD),
                )));
            }
        }
    } else {
        lines.push(section_divider("Open Ports"));
        lines.push(Line::from(Span::styled(
            "  No open ports detected",
            Style::default().fg(Color::Rgb(70, 80, 100)),
        )));
    }

    // ─── Bandwidth ───
    lines.push(section_divider("Bandwidth"));
    lines.push(row("Received", if device.bytes_received > 0 {
        format!("{} ({}/s)", format_bytes(device.bytes_received), format_speed(device.speed_received))
    } else {
        "\u{2014}".to_string()
    }, if device.speed_received > 0.0 { Color::Rgb(80, 200, 255) } else { Color::Rgb(90, 100, 120) }));

    lines.push(row("Sent", if device.bytes_sent > 0 {
        format!("{} ({}/s)", format_bytes(device.bytes_sent), format_speed(device.speed_sent))
    } else {
        "\u{2014}".to_string()
    }, if device.speed_sent > 0.0 { Color::Rgb(255, 180, 100) } else { Color::Rgb(90, 100, 120) }));

    lines.push(row("Total", if device.bytes_received + device.bytes_sent > 0 {
        format_bytes(device.bytes_received + device.bytes_sent)
    } else {
        "\u{2014}".to_string()
    }, Color::Rgb(170, 185, 210)));

    // ─── Timing ───
    lines.push(section_divider("Timing"));
    lines.push(row("First Seen", device.first_seen.format("%H:%M:%S").to_string(), Color::Rgb(120, 130, 160)));
    lines.push(row("Last Seen",  device.last_seen.format("%H:%M:%S").to_string(),  Color::Rgb(120, 130, 160)));

    // ─── Discovery Details ───
    lines.push(section_divider("Discovery Methods"));
    if !device.discovery_info.is_empty() {
        // Each method result is separated by double-space in the details string
        for entry in device.discovery_info.split("  ") {
            let entry = entry.trim();
            if entry.is_empty() { continue; }
            if let Some((tag, value)) = entry.split_once(':') {
                let method_desc = match tag {
                    "mDNS-PTR" => "mDNS Reverse PTR",
                    "mDNS"     => "mDNS Service Browse",
                    "mDNS-MC"  => "mDNS Multicast PTR",
                    "NBNS"     => "NetBIOS Name Service",
                    "DHCP"     => "DHCP Option 12",
                    "GW-DNS"   => "Gateway DNS PTR",
                    "LLMNR"    => "LLMNR Query",
                    "DNS"      => "DNS Reverse Lookup",
                    "DNS$"     => "Windows DNS Cache",
                    "UPnP"     => "SSDP/UPnP",
                    "SNMP"     => "SNMP sysName",
                    "HTTP"     => "HTTP Banner",
                    "Telnet"   => "Telnet Banner",
                    _          => tag,
                };
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("  {:<22}", method_desc),
                        Style::default().fg(Color::Rgb(100, 140, 180)).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        value.to_string(),
                        Style::default().fg(Color::Rgb(180, 190, 200)),
                    ),
                ]));
            } else {
                lines.push(Line::from(Span::styled(
                    format!("  {}", entry),
                    Style::default().fg(Color::Rgb(140, 160, 130)),
                )));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  No discovery data yet (scan in progress or pending)",
            Style::default().fg(Color::Rgb(70, 80, 100)),
        )));
    }

    // ─── DHCP Info ───
    if let std::net::IpAddr::V4(v4) = device.ip {
        if let Ok(cache) = app.network_scanner.dhcp_hostnames.lock() {
            if let Some(dhcp_name) = cache.get(&v4) {
                lines.push(section_divider("DHCP"));
                lines.push(row("DHCP Hostname", dhcp_name.clone(), Color::Rgb(180, 140, 255)));
            }
        }
    }

    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Firewall + Bandwidth detail (combined) ─────────────────────────────────

fn draw_firewall_app_detail(f: &mut Frame, area: Rect, detail: &crate::types::FirewallAppDetail, app: &App) {
    let _ = app; // available for future use (geoip etc.)

    let action_str = match &detail.current_action {
        Some(FirewallAppAction::Allow) => "ALLOW",
        Some(FirewallAppAction::Deny) => "DENY",
        Some(FirewallAppAction::Drop) => "DROP",
        None if detail.is_blocked => "BLOCKED",
        None => "ALLOWED",
    };
    let action_color = match &detail.current_action {
        Some(FirewallAppAction::Allow) => Color::Rgb(80, 200, 255),
        Some(FirewallAppAction::Deny) => Color::Rgb(255, 80, 80),
        Some(FirewallAppAction::Drop) => Color::Rgb(255, 140, 40),
        None if detail.is_blocked => Color::Rgb(255, 80, 80),
        None => Color::Rgb(80, 200, 120),
    };

    let conn_str = if detail.conn_count > 0 {
        format!("{} active", detail.conn_count)
    } else {
        "idle".to_string()
    };
    let conn_color = if detail.conn_count > 0 { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 110, 130) };

    let mut lines = header_lines(" App Detail & Actions ");
    lines.push(row("Application",  detail.app_name.clone(),           Color::Rgb(130, 200, 140)));
    lines.push(row("Status",       action_str.to_string(),            action_color));
    lines.push(row("Connections",  conn_str,                          conn_color));
    lines.push(Line::from(""));

    // Bandwidth section
    lines.push(Line::from(Span::styled(
        "  \u{2500}\u{2500}\u{2500} Bandwidth \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        Style::default().fg(Color::Rgb(40, 55, 80)),
    )));
    lines.push(row("Downloaded",   format_bytes(detail.download_bytes),  Color::Rgb(80, 180, 255)));
    lines.push(row("Uploaded",     format_bytes(detail.upload_bytes),    Color::Rgb(180, 120, 255)));
    lines.push(row("Total",        format_bytes(detail.download_bytes + detail.upload_bytes), Color::Rgb(170, 185, 210)));
    lines.push(row("Speed \u{2193}",      format_speed(detail.current_down_speed),  Color::Rgb(80, 200, 160)));
    lines.push(row("Speed \u{2191}",      format_speed(detail.current_up_speed),    Color::Rgb(200, 140, 255)));
    lines.push(row("Peak \u{2193}",       format_speed(detail.peak_down_speed),     Color::Rgb(80, 180, 255)));
    lines.push(row("Peak \u{2191}",       format_speed(detail.peak_up_speed),       Color::Rgb(180, 120, 255)));
    lines.push(row("Last Seen",    detail.last_seen.clone(),             Color::Rgb(120, 130, 160)));
    lines.push(Line::from(""));

    // Action section
    lines.push(Line::from(Span::styled(
        "  \u{2500}\u{2500}\u{2500} Actions \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        Style::default().fg(Color::Rgb(40, 55, 80)),
    )));

    let options: [(usize, &str, Color); 4] = [
        (0, "Allow  - permit all traffic", Color::Rgb(80, 200, 120)),
        (1, "Deny   - block and refuse connections", Color::Rgb(255, 80, 80)),
        (2, "Drop   - silently drop all traffic", Color::Rgb(255, 140, 40)),
        (3, "Back   - close without changes", Color::Rgb(140, 150, 170)),
    ];

    for (idx, label, color) in &options {
        let is_sel = detail.selected_action == *idx;
        let is_current = match (&detail.current_action, idx) {
            (Some(FirewallAppAction::Allow), 0) => true,
            (Some(FirewallAppAction::Deny), 1) => true,
            (Some(FirewallAppAction::Drop), 2) => true,
            _ => false,
        };

        let prefix = if is_sel { "  \u{25b6} " } else { "    " };
        let suffix = if is_current { " \u{25cf}" } else { "" };

        let mut spans = vec![
            Span::styled(prefix, Style::default().fg(Color::Rgb(255, 200, 80))),
            Span::styled(
                label.to_string(),
                Style::default().fg(*color).add_modifier(if is_sel { Modifier::BOLD } else { Modifier::empty() }),
            ),
        ];
        if !suffix.is_empty() {
            spans.push(Span::styled(suffix, Style::default().fg(Color::Rgb(80, 200, 120))));
        }
        lines.push(Line::from(spans));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  [ \u{2191}\u{2193} select | Enter apply | Esc close ]",
        Style::default().fg(Color::Rgb(65, 80, 110)).add_modifier(Modifier::ITALIC),
    )));

    render_popup(f, area, lines);
}

// ─── Server detail ────────────────────────────────────────────────────────────

fn draw_server_detail(f: &mut Frame, area: Rect, detail: &DetailKind) {
    let DetailKind::Server {
        kind_label, kind_icon, category, port, proto, bind_addr,
        pid, process_name, exe_path, cmdline, product_name, company_name,
        version, http_title,
        banner, response_headers, active_connections, first_seen,
        is_responsive, tls_detected, category_color,
        detected_techs,
    } = detail else { return };

    let cat_color = Color::Rgb(category_color.0, category_color.1, category_color.2);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!("  {} {} ", kind_icon, kind_label),
                Style::default().fg(Color::Rgb(200, 220, 255)).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} ", category),
                Style::default().fg(cat_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::Rgb(35, 50, 80)),
        )),
        Line::from(""),
    ];

    // ─── Network ───
    lines.push(section_divider("Network"));
    lines.push(row("Port",         format!("{}", port),         Color::Rgb(100, 220, 255)));
    lines.push(row("Protocol",     proto.clone(),               Color::Rgb(100, 220, 255)));
    lines.push(row("Bind Address", bind_addr.clone(),           Color::Rgb(150, 160, 190)));

    let (status_str, status_color) = if *is_responsive {
        ("\u{25cf} UP".to_string(), Color::Rgb(80, 200, 120))
    } else {
        ("\u{25cb} DOWN".to_string(), Color::Rgb(100, 100, 120))
    };
    lines.push(row("Status",      status_str,                  status_color));

    if *tls_detected {
        lines.push(row("TLS",     "\u{1f512} Yes".to_string(), Color::Rgb(80, 200, 120)));
    } else {
        lines.push(row("TLS",     "No".to_string(),            Color::Rgb(120, 130, 160)));
    }

    // ─── Process ───
    lines.push(section_divider("Process"));
    lines.push(row("PID",          format!("{}", pid),          Color::Rgb(120, 130, 160)));
    lines.push(row("Process Name", process_name.clone(),        Color::Rgb(130, 200, 140)));
    lines.push(row("Executable",   exe_path.clone(),            Color::Rgb(170, 185, 210)));

    let cmd_display = if cmdline.chars().count() > 100 {
        format!("{}...", cmdline.chars().take(100).collect::<String>())
    } else {
        cmdline.clone()
    };
    lines.push(row("Command Line", cmd_display,                 Color::Rgb(150, 160, 190)));

    if !product_name.is_empty() {
        lines.push(row("Product",      product_name.clone(),    Color::Rgb(180, 200, 140)));
    }
    if !company_name.is_empty() {
        lines.push(row("Company",      company_name.clone(),    Color::Rgb(160, 180, 140)));
    }

    // ─── Detection ───
    lines.push(section_divider("Detection"));
    lines.push(row("Version",      if version.is_empty() { "\u{2014}".to_string() } else { version.clone() },
        Color::Rgb(200, 180, 80)));

    if !http_title.is_empty() {
        lines.push(row("HTTP Title",  http_title.clone(),       Color::Rgb(180, 200, 120)));
    }

    if !banner.is_empty() {
        let banner_display = if banner.chars().count() > 80 {
            format!("{}...", banner.chars().take(80).collect::<String>())
        } else {
            banner.clone()
        };
        lines.push(row("Banner",      banner_display,           Color::Rgb(180, 170, 140)));
    }

    // ─── HTTP Headers ───
    if !response_headers.is_empty() {
        lines.push(section_divider("HTTP Headers"));
        for (key, value) in response_headers {
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:<22}", key),
                    Style::default().fg(Color::Rgb(100, 140, 180)).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    value.clone(),
                    Style::default().fg(Color::Rgb(180, 190, 200)),
                ),
            ]));
        }
    }

    // ─── Detected Technologies (Wappalyzer) ───
    if !detected_techs.is_empty() {
        lines.push(section_divider("Detected Technologies"));
        for (name, cat, ver) in detected_techs {
            let display = if ver.is_empty() {
                format!("{} [{}]", name, cat)
            } else {
                format!("{} {} [{}]", name, ver, cat)
            };
            lines.push(Line::from(vec![
                Span::styled("  \u{25B8} ", Style::default().fg(Color::Rgb(80, 200, 120))),
                Span::styled(
                    display,
                    Style::default().fg(Color::Rgb(180, 160, 240)),
                ),
            ]));
        }
    }

    // ─── Stats ───
    lines.push(section_divider("Stats"));
    lines.push(row("Active Conns", format!("{}", active_connections),
        if *active_connections > 0 { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 110, 130) }));
    lines.push(row("First Seen",   first_seen.clone(),          Color::Rgb(120, 130, 160)));

    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

fn header_lines(title: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            format!("  {}", title),
            Style::default()
                .fg(Color::Rgb(200, 220, 255))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::Rgb(35, 50, 80)),
        )),
        Line::from(""),
    ]
}

/// A labeled row with right-hand value — all strings owned.
fn row(label: &'static str, value: String, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<16}", label),
            Style::default().fg(Color::Rgb(90, 105, 135)),
        ),
        Span::styled(value, Style::default().fg(value_color).add_modifier(Modifier::BOLD)),
    ])
}

fn section_divider(title: &str) -> Line<'static> {
    let bar = "\u{2500}".repeat(40usize.saturating_sub(title.len() + 6));
    Line::from(Span::styled(
        format!("  \u{2500}\u{2500}\u{2500} {} {}", title, bar),
        Style::default().fg(Color::Rgb(40, 55, 80)),
    ))
}

fn dismiss_line() -> Line<'static> {
    Line::from(Span::styled(
        "  [ Enter / Esc to close ]",
        Style::default().fg(Color::Rgb(65, 80, 110)).add_modifier(Modifier::ITALIC),
    ))
}

fn render_popup(f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(60, 100, 180)))
        .style(Style::default().bg(Color::Rgb(10, 14, 28)));

    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(Color::Rgb(10, 14, 28))),
        inner,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let pad_v = (100u16.saturating_sub(percent_y)) / 2;
    let pad_h = (100u16.saturating_sub(percent_x)) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(pad_v),
            Constraint::Percentage(percent_y),
            Constraint::Percentage(pad_v),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(pad_h),
            Constraint::Percentage(percent_x),
            Constraint::Percentage(pad_h),
        ])
        .split(vertical[1])[1]
}
