//! Packets tab UI — Wireshark-style packet inspector with expert severity
//! indicators, DNS hostname resolution, protocol-layered detail pane,
//! geo-IP enrichment, and context-sensitive keybinding hints.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::types::{ConnProto, PacketDirection, PacketSnippet};

// ─── Theme constants ─────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(8, 12, 24);
const BG_EVEN: Color = Color::Rgb(8, 12, 24);
const BG_ODD: Color = Color::Rgb(10, 16, 28);
const BG_SELECTED: Color = Color::Rgb(25, 40, 65);
const BORDER: Color = Color::Rgb(30, 50, 85);
const MUTED: Color = Color::Rgb(90, 110, 140);
const HDR_FG: Color = Color::Rgb(160, 180, 220);
const HDR_BG: Color = Color::Rgb(18, 25, 42);
const DIR_IN: Color = Color::Rgb(80, 200, 120);
const DIR_OUT: Color = Color::Rgb(100, 160, 255);
const SCROLLBAR: Color = Color::Rgb(40, 70, 120);
const DETAIL_BG: Color = Color::Rgb(10, 14, 26);
const DETAIL_BORDER: Color = Color::Rgb(35, 55, 90);
const DETAIL_LABEL: Color = Color::Rgb(120, 140, 180);
const DETAIL_VALUE: Color = Color::Rgb(200, 210, 230);
const HEX_OFFSET: Color = Color::Rgb(80, 100, 140);
const HEX_BYTE: Color = Color::Rgb(140, 160, 200);
const HEX_ASCII: Color = Color::Rgb(100, 180, 140);

// ─── Expert severity ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum ExpertLevel {
    Error, // red   — sensitive data in cleartext, suspicious patterns
    Warn,  // yellow — large payload, unusual port, HTTP on non-standard port
    Note,  // cyan   — notable protocol activity (DNS, HTTP, TLS, SSH)
    Chat,  // dim    — normal traffic
}

fn expert_severity(pkt: &PacketSnippet) -> ExpertLevel {
    let upper: String = pkt.snippet.chars().take(64).collect::<String>().to_uppercase();

    // Sensitive data in cleartext (not HTTPS) = Error
    if pkt.protocol == ConnProto::Tcp && pkt.dst_port != 443 && pkt.src_port != 443 {
        if upper.contains("PASSWORD")
            || upper.contains("AUTHORIZATION:")
            || upper.contains("COOKIE:")
            || upper.contains("SET-COOKIE")
        {
            return ExpertLevel::Error;
        }
    }

    // Very large payload = Warn
    if pkt.payload_size > 50_000 {
        return ExpertLevel::Warn;
    }

    // HTTP on non-standard port = Warn
    if (upper.starts_with("GET ") || upper.starts_with("POST ") || upper.starts_with("PUT "))
        && pkt.dst_port != 80
        && pkt.dst_port != 8080
        && pkt.dst_port != 443
    {
        return ExpertLevel::Warn;
    }

    // DNS = Note
    if pkt.src_port == 53 || pkt.dst_port == 53 {
        return ExpertLevel::Note;
    }

    // HTTP / TLS / SSH = Note
    if matches!(pkt.dst_port, 80 | 443 | 8080 | 8443 | 22)
        || matches!(pkt.src_port, 80 | 443 | 8080 | 8443 | 22)
        || upper.starts_with("HTTP/")
        || upper.starts_with("GET ")
        || upper.starts_with("POST ")
        || upper.starts_with("SSH-")
    {
        return ExpertLevel::Note;
    }

    ExpertLevel::Chat
}

fn expert_indicator(level: ExpertLevel) -> (&'static str, Style) {
    match level {
        ExpertLevel::Error => (
            "\u{25CF}",
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        ExpertLevel::Warn => ("\u{25B2}", Style::default().fg(Color::Yellow)),
        ExpertLevel::Note => ("\u{00B7}", Style::default().fg(Color::Cyan)),
        ExpertLevel::Chat => (" ", Style::default()),
    }
}

fn expert_row_tint(level: ExpertLevel) -> Option<Color> {
    match level {
        ExpertLevel::Error => Some(Color::Rgb(40, 12, 12)),
        ExpertLevel::Warn => Some(Color::Rgb(30, 26, 10)),
        _ => None,
    }
}

// ─── Port-to-service label ───────────────────────────────────────────────────

fn port_service_label(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        465 => "SMTPS",
        587 => "SMTP",
        993 => "IMAPS",
        995 => "POP3S",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PgSQL",
        6379 => "Redis",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        27017 => "MongoDB",
        _ => "",
    }
}

// ─── Protocol coloring ──────────────────────────────────────────────────────

fn protocol_style(proto: &ConnProto, port: u16) -> (Style, &'static str) {
    // Derive application-level protocol label from port
    let app_proto: &'static str = match port {
        53 => "DNS",
        80 | 8080 => "HTTP",
        443 | 8443 => "TLS",
        22 => "SSH",
        _ => match proto {
            ConnProto::Tcp => "TCP",
            ConnProto::Udp => "UDP",
        },
    };
    let style = match app_proto {
        "TCP" => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        "UDP" => Style::default()
            .fg(Color::Blue)
            .add_modifier(Modifier::BOLD),
        "DNS" => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        "HTTP" => Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
        "TLS" | "HTTPS" => Style::default()
            .fg(Color::Rgb(100, 200, 255))
            .add_modifier(Modifier::BOLD),
        "SSH" => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        _ => Style::default().fg(Color::White),
    };
    (style, app_proto)
}

// ─── Content-type coloring ───────────────────────────────────────────────────

fn snippet_content_color(snippet: &str) -> Color {
    let upper: String = snippet.chars().take(32).collect::<String>().to_uppercase();

    if upper.starts_with("HTTP/")
        || upper.starts_with("GET ")
        || upper.starts_with("POST ")
        || upper.starts_with("PUT ")
        || upper.starts_with("DELETE ")
        || upper.starts_with("HEAD ")
        || upper.starts_with("OPTIONS ")
    {
        return Color::Rgb(80, 220, 160); // green — HTTP
    }
    if upper.starts_with("SSH-") || upper.starts_with("EHLO ") || upper.starts_with("STARTTLS") {
        return Color::Rgb(180, 140, 255); // purple — protocol handshake
    }
    if snippet.starts_with('{') || snippet.starts_with('[') {
        return Color::Rgb(100, 200, 255); // cyan — JSON
    }
    if upper.contains("<!DOCTYPE") || upper.contains("<HTML") || upper.contains("<?XML") {
        return Color::Rgb(220, 180, 80); // yellow — markup
    }
    if upper.contains("CONTENT-TYPE") || upper.contains("HOST:") || upper.contains("USER-AGENT") {
        return Color::Rgb(140, 200, 160); // light green — HTTP headers
    }
    if snippet.contains('\x16') || upper.contains("CERTIFICATE") {
        return Color::Rgb(200, 160, 100); // amber — TLS
    }
    Color::Rgb(130, 140, 165) // default muted
}

// ─── Compact size formatting ─────────────────────────────────────────────────

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ─── Filter matching ─────────────────────────────────────────────────────────

fn matches_filter(pkt: &PacketSnippet, filter: &str, app: &App) -> bool {
    if filter.is_empty() {
        return true;
    }
    let ft = filter.to_lowercase();

    // IP addresses
    if pkt.src_ip.to_string().contains(&ft) || pkt.dst_ip.to_string().contains(&ft) {
        return true;
    }
    // Ports
    if pkt.src_port.to_string().contains(&ft) || pkt.dst_port.to_string().contains(&ft) {
        return true;
    }
    // Protocol
    if pkt.protocol.label().to_lowercase().contains(&ft) {
        return true;
    }
    // Application-level protocol from port
    let (_, app_proto) = protocol_style(&pkt.protocol, pkt.dst_port);
    if app_proto.to_lowercase().contains(&ft) {
        return true;
    }
    // Service label
    let src_svc = port_service_label(pkt.src_port);
    let dst_svc = port_service_label(pkt.dst_port);
    if (!src_svc.is_empty() && src_svc.to_lowercase().contains(&ft))
        || (!dst_svc.is_empty() && dst_svc.to_lowercase().contains(&ft))
    {
        return true;
    }
    // DNS hostname
    if let Some(Some(name)) = app.dns_cache.get(&pkt.src_ip) {
        if name.to_lowercase().contains(&ft) {
            return true;
        }
    }
    if let Some(Some(name)) = app.dns_cache.get(&pkt.dst_ip) {
        if name.to_lowercase().contains(&ft) {
            return true;
        }
    }
    // Snippet content
    if pkt.snippet.to_lowercase().contains(&ft) {
        return true;
    }
    false
}

// ─── Address display helper ──────────────────────────────────────────────────

fn format_address(
    ip: std::net::IpAddr,
    port: u16,
    app: &App,
    max_w: usize,
) -> String {
    let svc = port_service_label(port);
    let hostname = app
        .dns_cache
        .get(&ip)
        .and_then(|opt| opt.as_deref());

    let label = if let Some(host) = hostname {
        // Truncate long hostnames
        if host.chars().count() > max_w.saturating_sub(8) {
            let keep = max_w.saturating_sub(11);
            format!("{}...:{}", host.chars().take(keep).collect::<String>(), port)
        } else if !svc.is_empty() {
            format!("{}:{} ({})", host, port, svc)
        } else {
            format!("{}:{}", host, port)
        }
    } else if !svc.is_empty() {
        format!("{}:{} ({})", ip, port, svc)
    } else {
        format!("{}:{}", ip, port)
    };

    if label.chars().count() > max_w {
        format!("{}...", label.chars().take(max_w.saturating_sub(3)).collect::<String>())
    } else {
        label
    }
}

// ─── Main draw function ──────────────────────────────────────────────────────

pub fn draw_packets_tab(f: &mut Frame, area: Rect, app: &App) {
    let max_packets = 2000;
    let all_packets = app.sniffer.recent(max_packets);
    let total_all = all_packets.len();
    let total_captured = app
        .sniffer
        .snippets
        .lock()
        .map(|s| s.len())
        .unwrap_or(total_all);

    // Apply filter
    let filtered: Vec<&PacketSnippet> = all_packets
        .iter()
        .filter(|p| matches_filter(p, &app.packets_filter, app))
        .collect();
    let total = filtered.len();

    // ── Layout: header | packet list [| detail pane] | footer ──
    let chunks = if app.packets_detail_open && total > 0 {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),      // header
                Constraint::Percentage(55), // packet list
                Constraint::Min(8),         // detail pane
                Constraint::Length(1),      // footer
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),  // header
                Constraint::Min(5),    // packet list
                Constraint::Length(1), // footer
            ])
            .split(area)
    };

    // 1. Header
    render_header(f, chunks[0], app, total, total_all, total_captured);

    // 2. Packet list
    render_packet_list(f, chunks[1], app, &filtered, total);

    // 3. Detail pane (when open)
    if app.packets_detail_open && chunks.len() > 3 {
        let selected = if total > 0 {
            app.packets_scroll.min(total - 1)
        } else {
            0
        };
        if let Some(pkt) = filtered.get(selected) {
            render_detail_pane(f, chunks[2], app, pkt, selected);
        }
    }

    // 4. Footer
    let footer_idx = chunks.len() - 1;
    render_footer(f, chunks[footer_idx], app);
}

// ─── Header ──────────────────────────────────────────────────────────────────

fn render_header(
    f: &mut Frame,
    area: Rect,
    app: &App,
    filtered_count: usize,
    total_count: usize,
    buffered_count: usize,
) {
    let (status_icon, status_color) = if app.packets_paused {
        ("\u{25CB} PAUSED", Color::Rgb(255, 200, 80))
    } else {
        ("\u{25CF} CAPTURING", Color::Rgb(80, 255, 120))
    };

    let now = chrono::Local::now().format("%H:%M:%S").to_string();

    // Compute protocol breakdown from buffered packets
    let max_packets = 2000;
    let all_for_stats = app.sniffer.recent(max_packets);
    let stats_pkts: Vec<&PacketSnippet> = all_for_stats
        .iter()
        .filter(|p| matches_filter(p, &app.packets_filter, app))
        .collect();
    let tcp_count = stats_pkts.iter().filter(|p| p.protocol == ConnProto::Tcp).count();
    let udp_count = stats_pkts.iter().filter(|p| p.protocol == ConnProto::Udp).count();
    let syn_count = stats_pkts.iter().filter(|p| p.tcp_flags & 0x02 != 0).count();
    let fin_count = stats_pkts.iter().filter(|p| p.tcp_flags & 0x01 != 0).count();
    let rst_count = stats_pkts.iter().filter(|p| p.tcp_flags & 0x04 != 0).count();

    // Line 1: capture status + interface + count + time + protocol breakdown
    let mut line1 = vec![
        Span::styled(
            format!(" {} ", status_icon),
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" on {} ", app.interface_name),
            Style::default().fg(MUTED),
        ),
    ];

    if !app.packets_filter.is_empty() && filtered_count != total_count {
        line1.push(Span::styled(
            format!(" ({} / {} pkts, {} buffered) ", filtered_count, total_count, buffered_count),
            Style::default().fg(Color::Rgb(160, 170, 190)),
        ));
    } else {
        line1.push(Span::styled(
            format!(" ({} pkts, {} buffered) ", total_count, buffered_count),
            Style::default().fg(Color::Rgb(160, 170, 190)),
        ));
    }

    // Protocol breakdown stats
    line1.push(Span::styled(
        format!(" TCP:{}", tcp_count),
        Style::default().fg(Color::Magenta),
    ));
    line1.push(Span::styled(
        format!(" UDP:{}", udp_count),
        Style::default().fg(Color::Blue),
    ));
    if syn_count > 0 {
        line1.push(Span::styled(
            format!(" SYN:{}", syn_count),
            Style::default().fg(Color::Cyan),
        ));
    }
    if fin_count > 0 {
        line1.push(Span::styled(
            format!(" FIN:{}", fin_count),
            Style::default().fg(Color::Magenta),
        ));
    }
    if rst_count > 0 {
        line1.push(Span::styled(
            format!(" RST:{}", rst_count),
            Style::default().fg(Color::Red),
        ));
    }

    line1.push(Span::styled(
        format!(" {} ", now),
        Style::default().fg(Color::Rgb(70, 85, 110)),
    ));

    // Line 2: filter / error
    let line2 = if let Some(err) = app.sniffer.get_error() {
        Line::from(vec![
            Span::styled(
                " \u{26A0} ",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(err, Style::default().fg(Color::Red)),
        ])
    } else if !app.packets_filter.is_empty() {
        Line::from(vec![
            Span::styled(
                " Filter: ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                app.packets_filter.clone(),
                Style::default().fg(Color::White),
            ),
            Span::styled(
                "\u{2588}",
                Style::default().fg(Color::White),
            ),
        ])
    } else {
        Line::from(Span::styled(
            " Type to filter \u{2022} / clears with Esc",
            Style::default().fg(Color::Rgb(50, 65, 90)),
        ))
    };

    let header = Paragraph::new(vec![Line::from(line1), line2]).style(
        Style::default()
            .bg(Color::Rgb(14, 20, 36)),
    );
    f.render_widget(header, area);
}

// ─── Packet list table ───────────────────────────────────────────────────────

fn render_packet_list(
    f: &mut Frame,
    area: Rect,
    app: &App,
    packets: &[&PacketSnippet],
    total: usize,
) {
    let hdr = Style::default()
        .fg(HDR_FG)
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("!", hdr)),
        Cell::from(Span::styled("#", hdr)),
        Cell::from(Span::styled("Time", hdr)),
        Cell::from(Span::styled("Dir", hdr)),
        Cell::from(Span::styled("Source", hdr)),
        Cell::from(Span::styled("Destination", hdr)),
        Cell::from(Span::styled("Proto", hdr)),
        Cell::from(Span::styled("Len", hdr)),
        Cell::from(Span::styled("Info", hdr)),
    ])
    .height(1)
    .style(Style::default().bg(HDR_BG));

    let visible_height = area.height.saturating_sub(4) as usize;
    let selected = if total > 0 {
        app.packets_scroll.min(total - 1)
    } else {
        0
    };

    // Viewport centered on selection
    let viewport_start = if total <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected <= half {
            0
        } else if selected >= total.saturating_sub(half) {
            total.saturating_sub(visible_height)
        } else {
            selected.saturating_sub(half)
        }
    };

    let src_col_w = 26usize;
    let dst_col_w = 26usize;

    let rows: Vec<Row> = packets
        .iter()
        .enumerate()
        .skip(viewport_start)
        .take(visible_height)
        .map(|(idx, pkt)| {
            let is_selected = idx == selected;
            let expert = expert_severity(pkt);
            let (expert_icon, expert_style) = expert_indicator(expert);

            // # column
            let seq = format!("{}", idx + 1);

            // Time
            let time_str = pkt.timestamp.format("%H:%M:%S").to_string();

            // Direction
            let (dir_icon, dir_color) = match pkt.direction {
                PacketDirection::Inbound => ("\u{25C0}IN", DIR_IN),
                PacketDirection::Outbound => ("\u{25B6}OT", DIR_OUT),
            };

            // Source / Destination with DNS resolution
            let src_str = format_address(pkt.src_ip, pkt.src_port, app, src_col_w);
            let dst_str = format_address(pkt.dst_ip, pkt.dst_port, app, dst_col_w);

            // Protocol (application-level when possible)
            let relevant_port = if pkt.direction == PacketDirection::Outbound {
                pkt.dst_port
            } else {
                pkt.src_port
            };
            let (proto_style, proto_label) = protocol_style(&pkt.protocol, relevant_port);

            // Length
            let len_str = format_size(pkt.payload_size);

            // Info (snippet) with TCP flags prepended
            let max_info = area.width.saturating_sub(85) as usize;
            let flags_str = pkt.tcp_flags_str();
            let info_base = if !flags_str.is_empty() && !pkt.snippet.is_empty() {
                format!("{} {}", flags_str, pkt.snippet)
            } else if !flags_str.is_empty() {
                flags_str.clone()
            } else {
                pkt.snippet.clone()
            };
            let info_str = if info_base.chars().count() > max_info && max_info > 3 {
                let t: String = info_base.chars().take(max_info.saturating_sub(3)).collect();
                format!("{}...", t)
            } else {
                info_base
            };
            // Color based on flags presence or snippet content
            let info_color = if !flags_str.is_empty() {
                if pkt.tcp_flags & 0x04 != 0 {
                    Color::Red        // RST
                } else if pkt.tcp_flags & 0x02 != 0 {
                    Color::Cyan       // SYN
                } else if pkt.tcp_flags & 0x01 != 0 {
                    Color::Magenta    // FIN
                } else if pkt.snippet.is_empty() {
                    Color::DarkGray   // ACK-only with no snippet
                } else {
                    snippet_content_color(&pkt.snippet)
                }
            } else {
                snippet_content_color(&pkt.snippet)
            };

            // Row background
            let row_bg = if is_selected {
                BG_SELECTED
            } else if let Some(tint) = expert_row_tint(expert) {
                tint
            } else if idx % 2 == 0 {
                BG_EVEN
            } else {
                BG_ODD
            };

            let fg = if is_selected {
                Color::White
            } else {
                Color::Rgb(180, 190, 210)
            };

            Row::new(vec![
                Cell::from(Span::styled(expert_icon, expert_style)),
                Cell::from(Span::styled(
                    seq,
                    Style::default().fg(if is_selected {
                        Color::Rgb(140, 155, 180)
                    } else {
                        Color::Rgb(55, 65, 85)
                    }),
                )),
                Cell::from(Span::styled(
                    time_str,
                    Style::default().fg(if is_selected {
                        Color::Rgb(180, 195, 220)
                    } else {
                        Color::Rgb(100, 110, 130)
                    }),
                )),
                Cell::from(Span::styled(
                    dir_icon,
                    Style::default()
                        .fg(dir_color)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(src_str, Style::default().fg(if is_selected { fg } else {
                    match pkt.direction {
                        PacketDirection::Outbound => Color::Rgb(140, 180, 220),
                        PacketDirection::Inbound => Color::Rgb(160, 170, 190),
                    }
                }))),
                Cell::from(Span::styled(dst_str, Style::default().fg(if is_selected { fg } else {
                    match pkt.direction {
                        PacketDirection::Inbound => Color::Rgb(140, 180, 220),
                        PacketDirection::Outbound => Color::Rgb(160, 170, 190),
                    }
                }))),
                Cell::from(Span::styled(proto_label, proto_style)),
                Cell::from(Span::styled(
                    len_str,
                    Style::default().fg(if is_selected {
                        Color::Rgb(180, 190, 210)
                    } else {
                        Color::Rgb(100, 100, 130)
                    }),
                )),
                Cell::from(Span::styled(
                    info_str,
                    Style::default().fg(if is_selected {
                        Color::Rgb(220, 230, 245)
                    } else {
                        info_color
                    }),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // Title with filter status
    let mut title_parts = vec![Span::styled(
        " \u{1F50D} Packets ",
        Style::default()
            .fg(Color::Rgb(160, 180, 220))
            .add_modifier(Modifier::BOLD),
    )];
    if !app.packets_filter.is_empty() {
        title_parts.push(Span::styled(
            format!("({} / {}) ", total, packets.len()),
            Style::default().fg(Color::Rgb(255, 220, 100)),
        ));
    } else {
        title_parts.push(Span::styled(
            format!("({}) ", total),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(2),  // !
            Constraint::Length(5),  // #
            Constraint::Length(9),  // Time
            Constraint::Length(4),  // Dir
            Constraint::Length(26), // Source
            Constraint::Length(26), // Destination
            Constraint::Length(5),  // Proto
            Constraint::Length(6),  // Len
            Constraint::Min(10),   // Info
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_parts))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(BG)),
    );

    f.render_widget(table, area);

    // Scrollbar
    if total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state =
            ScrollbarState::new(total.saturating_sub(visible_height)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(SCROLLBAR)),
            sb_area,
            &mut sb_state,
        );
    }
}

// ─── Detail pane ─────────────────────────────────────────────────────────────

fn render_detail_pane(
    f: &mut Frame,
    area: Rect,
    app: &App,
    pkt: &PacketSnippet,
    selected_idx: usize,
) {
    let available = area.height.saturating_sub(2) as usize;
    let mut lines: Vec<Line> = Vec::with_capacity(available);

    let (dir_label, dir_color) = match pkt.direction {
        PacketDirection::Inbound => ("INBOUND", DIR_IN),
        PacketDirection::Outbound => ("OUTBOUND", DIR_OUT),
    };

    let relevant_port = if pkt.direction == PacketDirection::Outbound {
        pkt.dst_port
    } else {
        pkt.src_port
    };
    let (_, proto_label) = protocol_style(&pkt.protocol, relevant_port);

    // ── Protocol layer 1: Frame ──
    lines.push(Line::from(vec![
        Span::styled("  Frame: ", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!(
                "#{}, {} bytes captured at {}",
                selected_idx + 1,
                pkt.payload_size,
                pkt.timestamp.format("%H:%M:%S%.3f")
            ),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!("  [{}]", dir_label),
            Style::default()
                .fg(dir_color)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    // ── Protocol layer 2: Network (IPv4/IPv6) ──
    if lines.len() < available {
        let src_host = app
            .dns_cache
            .get(&pkt.src_ip)
            .and_then(|o| o.as_deref());
        let dst_host = app
            .dns_cache
            .get(&pkt.dst_ip)
            .and_then(|o| o.as_deref());

        let src_display = if let Some(h) = src_host {
            format!("{} ({})", pkt.src_ip, h)
        } else {
            pkt.src_ip.to_string()
        };
        let dst_display = if let Some(h) = dst_host {
            format!("{} ({})", pkt.dst_ip, h)
        } else {
            pkt.dst_ip.to_string()
        };

        let ip_version = if pkt.src_ip.is_ipv4() { "IPv4" } else { "IPv6" };
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}: ", ip_version),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(src_display, Style::default().fg(Color::Rgb(140, 200, 255))),
            Span::styled(
                " \u{2192} ",
                Style::default()
                    .fg(Color::Rgb(80, 120, 170))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(dst_display, Style::default().fg(Color::Rgb(255, 200, 140))),
            Span::styled(
                format!("  TTL: {}, ID: 0x{:04X}, Total Length: {}", pkt.ttl, pkt.ip_id, pkt.ip_total_len),
                Style::default().fg(DETAIL_LABEL),
            ),
        ]));
    }

    // ── Protocol layer 3: Transport (TCP/UDP) ──
    if lines.len() < available {
        let src_svc = port_service_label(pkt.src_port);
        let dst_svc = port_service_label(pkt.dst_port);
        let src_port_s = if !src_svc.is_empty() {
            format!("{} ({})", pkt.src_port, src_svc)
        } else {
            pkt.src_port.to_string()
        };
        let dst_port_s = if !dst_svc.is_empty() {
            format!("{} ({})", pkt.dst_port, dst_svc)
        } else {
            pkt.dst_port.to_string()
        };

        let transport_color = match pkt.protocol {
            ConnProto::Tcp => Color::Magenta,
            ConnProto::Udp => Color::Blue,
        };

        let mut transport_spans = vec![
            Span::styled(
                format!("  {}: ", pkt.protocol.label()),
                Style::default()
                    .fg(transport_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} \u{2192} {}", src_port_s, dst_port_s),
                Style::default().fg(DETAIL_VALUE),
            ),
            Span::styled(
                format!(", Payload: {} bytes", pkt.payload_size),
                Style::default().fg(DETAIL_LABEL),
            ),
        ];

        if pkt.protocol == ConnProto::Tcp {
            let flags_display = pkt.tcp_flags_str();
            let flags_color = if pkt.tcp_flags & 0x04 != 0 {
                Color::Red
            } else if pkt.tcp_flags & 0x02 != 0 {
                Color::Cyan
            } else if pkt.tcp_flags & 0x01 != 0 {
                Color::Magenta
            } else {
                DETAIL_LABEL
            };
            transport_spans.push(Span::styled(
                format!("  Seq: {}, Ack: {}, Flags: ", pkt.tcp_seq, pkt.tcp_ack_num),
                Style::default().fg(DETAIL_LABEL),
            ));
            transport_spans.push(Span::styled(
                flags_display,
                Style::default().fg(flags_color).add_modifier(Modifier::BOLD),
            ));
            transport_spans.push(Span::styled(
                format!(", Win: {}", pkt.tcp_window),
                Style::default().fg(DETAIL_LABEL),
            ));
        }

        lines.push(Line::from(transport_spans));
    }

    // ── Geo-IP enrichment ──
    if lines.len() < available {
        let mut geo_spans: Vec<Span> = Vec::new();
        for (label, ip) in [("Src", pkt.src_ip), ("Dst", pkt.dst_ip)] {
            if let Some(geo) = app.geoip.lookup(ip) {
                if !geo_spans.is_empty() {
                    geo_spans.push(Span::styled("  ", Style::default()));
                }
                geo_spans.push(Span::styled(
                    format!("  Geo {}: {} {} ({})", label, geo.flag, geo.name, geo.code),
                    Style::default().fg(Color::Rgb(100, 180, 255)),
                ));
            }
        }
        if !geo_spans.is_empty() {
            lines.push(Line::from(geo_spans));
        }
    }

    // ── Separator: Payload ──
    if lines.len() < available {
        lines.push(Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500} Payload \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::Rgb(40, 60, 90)),
        )));
    }

    // ── Payload text ──
    if lines.len() < available && !pkt.snippet.is_empty() {
        let snip_color = snippet_content_color(&pkt.snippet);
        let max_chars = (area.width as usize).saturating_sub(6);
        let display: String = if pkt.snippet.chars().count() > max_chars && max_chars > 3 {
            let t: String = pkt.snippet.chars().take(max_chars.saturating_sub(3)).collect();
            format!("{}...", t)
        } else {
            pkt.snippet.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(display, Style::default().fg(snip_color)),
        ]));
    }

    // ── Separator: Hex Dump ──
    if lines.len() < available {
        lines.push(Line::from(Span::styled(
            "  \u{2500}\u{2500}\u{2500} Hex Dump \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            Style::default().fg(Color::Rgb(40, 60, 90)),
        )));
    }

    // ── Hex dump with ASCII column (using raw_payload for actual binary data) ──
    let hex_bytes = if !pkt.raw_payload.is_empty() {
        &pkt.raw_payload[..]
    } else {
        pkt.snippet.as_bytes()
    };
    let bytes_per_row = 16;
    let mut offset = 0usize;

    while offset < hex_bytes.len() && lines.len() < available {
        let chunk_end = (offset + bytes_per_row).min(hex_bytes.len());
        let chunk = &hex_bytes[offset..chunk_end];

        let offset_str = format!("  {:04X}  ", offset);

        // Hex bytes with midpoint gap
        let mut hex = String::with_capacity(bytes_per_row * 3 + 2);
        for (i, byte) in chunk.iter().enumerate() {
            hex.push_str(&format!("{:02X} ", byte));
            if i == 7 {
                hex.push(' ');
            }
        }
        // Pad short rows
        let expected = bytes_per_row * 3 + 1;
        while hex.len() < expected {
            hex.push(' ');
        }

        // ASCII
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();

        lines.push(Line::from(vec![
            Span::styled(offset_str, Style::default().fg(HEX_OFFSET)),
            Span::styled(hex, Style::default().fg(HEX_BYTE)),
            Span::styled(" \u{2502}", Style::default().fg(Color::Rgb(40, 55, 80))),
            Span::styled(ascii, Style::default().fg(HEX_ASCII)),
            Span::styled("\u{2502}", Style::default().fg(Color::Rgb(40, 55, 80))),
        ]));

        offset += bytes_per_row;
    }

    // ── Block ──
    let expert = expert_severity(pkt);
    let (ei, es) = expert_indicator(expert);
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " Protocol Detail ",
                Style::default()
                    .fg(Color::Rgb(200, 180, 255))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" #{} ", selected_idx + 1),
                Style::default().fg(MUTED),
            ),
            Span::styled(
                format!("{} {} ", ei, proto_label),
                es,
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(DETAIL_BORDER))
        .style(Style::default().bg(DETAIL_BG));

    let detail = Paragraph::new(lines).block(block);
    f.render_widget(detail, area);
}

// ─── Footer ──────────────────────────────────────────────────────────────────

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let pause_label = if app.packets_paused { "Space:Resume" } else { "Space:Pause" };
    let detail_label = if app.packets_detail_open { "d:Collapse" } else { "d:Expand" };

    let mut hints = vec![
        Span::styled(
            format!(" {}", pause_label),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("  ", Style::default()),
        Span::styled("Enter:Detail", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled(detail_label, Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("c:Clear", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("\u{2191}\u{2193}:Navigate", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("PgUp/Dn:Scroll", Style::default().fg(Color::Yellow)),
    ];

    if !app.packets_filter.is_empty() {
        hints.push(Span::styled("  ", Style::default()));
        hints.push(Span::styled("Esc:Clear filter", Style::default().fg(Color::Yellow)));
        hints.push(Span::styled("  ", Style::default()));
        hints.push(Span::styled(
            format!("[FILTER: {}]", app.packets_filter),
            Style::default()
                .fg(Color::Rgb(255, 220, 100))
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        hints.push(Span::styled("  ", Style::default()));
        hints.push(Span::styled("Type:Filter", Style::default().fg(Color::Rgb(60, 80, 110))));
    }

    let footer = Paragraph::new(Line::from(hints))
        .style(Style::default().bg(Color::Rgb(12, 16, 30)));
    f.render_widget(footer, area);
}
