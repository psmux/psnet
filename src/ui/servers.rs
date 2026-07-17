//! Servers tab UI — card-based layout grouped by TCP/UDP protocol.

use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::Frame;

use crate::app::App;
use crate::network::servers::types::{ListenProto, ListeningPort, ServerCategory};

// ─── Theme ──────────────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(12, 15, 26);
const CARD_BG: Color = Color::Rgb(16, 20, 36);
const CARD_ALT: Color = Color::Rgb(14, 18, 32);
const SEL_BG: Color = Color::Rgb(20, 36, 68);
const SEL_ACCENT: Color = Color::Rgb(60, 130, 240);
const UNRESPONSIVE_BG: Color = Color::Rgb(10, 12, 22);
const BORDER: Color = Color::Rgb(30, 42, 65);
const DIM: Color = Color::Rgb(50, 60, 80);
const LABEL: Color = Color::Rgb(70, 85, 110);
const TEXT: Color = Color::Rgb(140, 158, 190);
const BRIGHT: Color = Color::Rgb(200, 215, 240);
const GREEN: Color = Color::Rgb(70, 195, 110);
const YELLOW: Color = Color::Rgb(220, 185, 60);
const TCP_COLOR: Color = Color::Rgb(80, 150, 240);
const UDP_COLOR: Color = Color::Rgb(220, 170, 50);

// ─── Helpers ────────────────────────────────────────────────────────────────

fn cat_color(cat: &ServerCategory) -> Color {
    let (r, g, b) = cat.color();
    Color::Rgb(r, g, b)
}

fn trunc(s: &str, max: usize) -> String {
    if s.chars().count() > max && max > 1 {
        let end = s.char_indices()
            .nth(max.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}\u{2026}", &s[..end])
    } else {
        s.to_string()
    }
}

// ─── Display rows ───────────────────────────────────────────────────────────

enum Row<'a> {
    /// Protocol section header: "TCP Services (12)" or "UDP Services (5)"
    ProtoHeader { proto: ListenProto, count: usize },

    /// Server card line 1: icon + name + port + status badges
    CardTop { server: &'a ListeningPort, idx: usize, conns: usize },
    /// Server card line 2: category tag + process + description/path
    CardBot { server: &'a ListeningPort, idx: usize },
    /// Blank separator between cards
    Spacer,
}

// ─── Main draw ──────────────────────────────────────────────────────────────

pub fn draw_servers(f: &mut Frame, area: Rect, app: &App) {
    let sc = &app.servers_scanner;
    let all = &sc.servers;
    let filtered = sc.filtered_servers();

    // Connection counts per port
    let conn_counts: HashMap<u16, usize> = {
        let mut m = HashMap::new();
        for c in &app.connections {
            let listen = c.state.as_ref()
                .map(|s| matches!(s, crate::types::TcpState::Listen))
                .unwrap_or(false);
            if !listen { *m.entry(c.local_port).or_insert(0) += 1; }
        }
        m
    };

    // Split filtered into TCP and UDP, then sub-group by category
    let tcp_servers: Vec<&ListeningPort> = filtered.iter()
        .filter(|s| matches!(s.proto, ListenProto::Tcp))
        .copied().collect();
    let udp_servers: Vec<&ListeningPort> = filtered.iter()
        .filter(|s| matches!(s.proto, ListenProto::Udp))
        .copied().collect();

    // Build flat row list: TCP first, then UDP (flat, no category grouping)
    let mut rows: Vec<Row> = Vec::new();
    let mut entry_count: usize = 0;

    for (proto, servers) in [(ListenProto::Tcp, &tcp_servers), (ListenProto::Udp, &udp_servers)] {
        if servers.is_empty() { continue; }

        rows.push(Row::ProtoHeader { proto, count: servers.len() });

        let mut sorted: Vec<&ListeningPort> = servers.clone();
        sorted.sort_by_key(|s| s.port);

        for (i, s) in sorted.iter().enumerate() {
            if i > 0 { rows.push(Row::Spacer); }
            let conns = conn_counts.get(&s.port).copied().unwrap_or(0);
            rows.push(Row::CardTop { server: s, idx: entry_count, conns });
            rows.push(Row::CardBot { server: s, idx: entry_count });
            entry_count += 1;
        }
    }

    let selected = if entry_count > 0 { sc.scroll_offset.min(entry_count - 1) } else { 0 };

    // Stats
    let tcp_total = all.iter().filter(|s| matches!(s.proto, ListenProto::Tcp)).count();
    let udp_total = all.len() - tcp_total;
    let up = all.iter().filter(|s| s.is_responsive).count();

    // TCP bind address breakdown
    let tcp_all: Vec<&ListeningPort> = all.iter()
        .filter(|s| matches!(s.proto, ListenProto::Tcp))
        .collect();
    let bind_stats = BindStats::from_servers(&tcp_all);

    let total_conns: usize = conn_counts.values().sum();
    let tls_count = all.iter().filter(|s| s.details.contains("TLS: yes")).count();

    // Layout: dashboard strip + filter? + main list + detail panel
    let has_filter = !sc.filter_text.is_empty() || app.filter_editing;
    let filter_h = if has_filter { 1 } else { 0 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(filter_h),
            Constraint::Min(6),
            Constraint::Length(5),
        ])
        .split(area);

    draw_dashboard(f, chunks[0], all.len(), tcp_total, udp_total, up,
                   total_conns, tls_count, &bind_stats, sc.is_scanning());
    if has_filter {
        draw_filter_bar(f, chunks[1], &sc.filter_text, entry_count, app.filter_editing);
    }
    draw_list(f, chunks[2], &rows, selected);
    draw_detail(f, chunks[3], &filtered, selected, &conn_counts);
}

// ─── Bind address stats ─────────────────────────────────────────────────────

struct BindStats {
    /// 0.0.0.0 — listening on all interfaces
    all_interfaces: usize,
    /// 127.0.0.1
    loopback_v4: usize,
    /// ::1
    loopback_v6: usize,
    /// :: — IPv6 all interfaces
    all_interfaces_v6: usize,
    /// Specific IPs (not 0.0.0.0/127.0.0.1/::/::1) → (ip_string, count)
    specific: Vec<(String, usize)>,
    tcp_total: usize,
}

impl BindStats {
    fn from_servers(tcp: &[&ListeningPort]) -> Self {
        use std::net::IpAddr;
        let mut all_if = 0usize;
        let mut lo4 = 0usize;
        let mut lo6 = 0usize;
        let mut all_if6 = 0usize;
        let mut specific_map: HashMap<String, usize> = HashMap::new();

        for s in tcp {
            match s.bind_addr {
                IpAddr::V4(v4) if v4.is_unspecified() => all_if += 1,
                IpAddr::V4(v4) if v4.is_loopback() => lo4 += 1,
                IpAddr::V6(v6) if v6.is_unspecified() => all_if6 += 1,
                IpAddr::V6(v6) if v6.is_loopback() => lo6 += 1,
                other => {
                    *specific_map.entry(other.to_string()).or_insert(0) += 1;
                }
            }
        }

        let mut specific: Vec<(String, usize)> = specific_map.into_iter().collect();
        specific.sort_by(|a, b| b.1.cmp(&a.1));

        Self {
            all_interfaces: all_if,
            loopback_v4: lo4,
            loopback_v6: lo6,
            all_interfaces_v6: all_if6,
            specific,
            tcp_total: tcp.len(),
        }
    }
}

// ─── Dashboard strip ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn draw_dashboard(
    f: &mut Frame, area: Rect,
    total: usize, tcp: usize, udp: usize, up: usize,
    total_conns: usize, tls_count: usize,
    bind_stats: &BindStats,
    scanning: bool,
) {
    // Split into 3 panels: Bind Addresses | Exposure Summary | Quick Stats
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(38),
            Constraint::Percentage(36),
            Constraint::Percentage(26),
        ])
        .split(area);

    draw_bind_panel(f, panels[0], bind_stats, scanning);
    draw_exposure_panel(f, panels[1], bind_stats);
    draw_stats_panel(f, panels[2], total, tcp, udp, up, total_conns, tls_count);
}

/// Left panel: TCP bind address breakdown
fn draw_bind_panel(f: &mut Frame, area: Rect, bs: &BindStats, scanning: bool) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(Color::Rgb(20, 30, 50)))
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let w = inner.width as usize;
    let max_count = [bs.all_interfaces, bs.loopback_v4, bs.loopback_v6, bs.all_interfaces_v6]
        .iter()
        .copied()
        .chain(bs.specific.iter().map(|(_, c)| *c))
        .max()
        .unwrap_or(1)
        .max(1);

    // Title line
    let mut title_spans = vec![
        Span::styled(" TCP BIND ", Style::default().fg(Color::Rgb(20, 30, 50)).bg(TCP_COLOR).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {} listeners", bs.tcp_total), Style::default().fg(TEXT)),
    ];
    if scanning {
        title_spans.push(Span::styled("  \u{25CC} scanning\u{2026}", Style::default().fg(YELLOW)));
    }

    let label_w = 14;
    let bar_w = w.saturating_sub(label_w + 5);

    // Build rows: show each bind type that has >0 count
    let mut entries: Vec<(String, usize, Color)> = Vec::new();
    if bs.all_interfaces > 0 {
        entries.push(("0.0.0.0  *".into(), bs.all_interfaces, Color::Rgb(100, 200, 240)));
    }
    if bs.loopback_v4 > 0 {
        entries.push(("127.0.0.1".into(), bs.loopback_v4, Color::Rgb(180, 140, 255)));
    }
    if bs.all_interfaces_v6 > 0 {
        entries.push(("[::]  *".into(), bs.all_interfaces_v6, Color::Rgb(80, 180, 200)));
    }
    if bs.loopback_v6 > 0 {
        entries.push(("[::1]".into(), bs.loopback_v6, Color::Rgb(150, 120, 220)));
    }
    for (ip, count) in bs.specific.iter().take(2) {
        let ip_display = if ip.len() > 13 { &ip[..13] } else { ip.as_str() };
        entries.push((ip_display.to_string(), *count, Color::Rgb(200, 180, 100)));
    }

    let mut lines: Vec<Line> = vec![Line::from(title_spans)];

    for (label, count, color) in entries.iter().take(4) {
        let fill = (*count * bar_w) / max_count;
        let fill = fill.max(if *count > 0 { 1 } else { 0 });
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<lw$}", label.as_str(), lw = label_w), Style::default().fg(*color)),
            Span::styled(
                "\u{2588}".repeat(fill),
                Style::default().fg(*color),
            ),
            Span::styled(
                "\u{2500}".repeat(bar_w.saturating_sub(fill)),
                Style::default().fg(Color::Rgb(18, 25, 40)),
            ),
            Span::styled(
                format!(" {:>2}", count),
                Style::default().fg(BRIGHT),
            ),
        ]));
    }

    // Pad remaining lines if fewer than 4 entries
    while lines.len() < 5 {
        lines.push(Line::from(""));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

/// Center panel: TCP exposure summary — how exposed is this system?
fn draw_exposure_panel(f: &mut Frame, area: Rect, bs: &BindStats) {
    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(Style::default().fg(Color::Rgb(20, 30, 50)))
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let exposed = bs.all_interfaces + bs.all_interfaces_v6
        + bs.specific.iter().map(|(_, c)| *c).sum::<usize>();
    let local_only = bs.loopback_v4 + bs.loopback_v6;
    let total = bs.tcp_total;

    // Exposure ratio bar
    let bar_w = inner.width.saturating_sub(4) as usize;
    let exposed_fill = if total > 0 { (exposed * bar_w) / total.max(1) } else { 0 };
    let local_fill = if total > 0 { (local_only * bar_w) / total.max(1) } else { 0 };
    let remainder = bar_w.saturating_sub(exposed_fill + local_fill);

    let exposure_color = if exposed == 0 {
        Color::Rgb(70, 195, 110) // green — fully local
    } else if exposed <= local_only {
        Color::Rgb(220, 185, 60) // yellow — moderate
    } else {
        Color::Rgb(255, 100, 80) // red — mostly exposed
    };

    let (level_label, level_color) = if exposed == 0 {
        ("Minimal", Color::Rgb(70, 195, 110))
    } else if exposed <= 3 {
        ("Low", Color::Rgb(100, 200, 140))
    } else if exposed <= local_only {
        ("Moderate", Color::Rgb(220, 185, 60))
    } else {
        ("High", Color::Rgb(255, 100, 80))
    };

    let l0 = Line::from(vec![
        Span::styled(" TCP EXPOSURE ", Style::default().fg(Color::Rgb(20, 30, 50)).bg(exposure_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {}", level_label), Style::default().fg(level_color).add_modifier(Modifier::BOLD)),
    ]);

    let l1 = Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled("\u{2588}".repeat(exposed_fill), Style::default().fg(Color::Rgb(255, 100, 80))),
        Span::styled("\u{2588}".repeat(local_fill), Style::default().fg(Color::Rgb(80, 180, 230))),
        Span::styled("\u{2500}".repeat(remainder), Style::default().fg(Color::Rgb(18, 25, 40))),
    ]);

    let l2 = Line::from(vec![
        Span::styled(" \u{25CF} ", Style::default().fg(Color::Rgb(255, 100, 80))),
        Span::styled(format!("{}", exposed), Style::default().fg(BRIGHT).add_modifier(Modifier::BOLD)),
        Span::styled(" network-facing", Style::default().fg(TEXT)),
        Span::styled("   \u{25CF} ", Style::default().fg(Color::Rgb(80, 180, 230))),
        Span::styled(format!("{}", local_only), Style::default().fg(BRIGHT).add_modifier(Modifier::BOLD)),
        Span::styled(" localhost", Style::default().fg(TEXT)),
    ]);

    let pct = if total > 0 { exposed * 100 / total } else { 0 };
    let l3 = Line::from(vec![
        Span::styled(format!(" {}% ", pct), Style::default().fg(exposure_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!("of {} TCP ports reachable from network", total), Style::default().fg(LABEL)),
    ]);

    f.render_widget(Paragraph::new(vec![l0, l1, l2, l3]), inner);
}

/// Right panel: Quick stats summary
fn draw_stats_panel(
    f: &mut Frame, area: Rect,
    total: usize, tcp: usize, udp: usize, up: usize,
    total_conns: usize, tls_count: usize,
) {
    let block = Block::default()
        .borders(Borders::NONE)
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let down = total.saturating_sub(up);

    let l1 = Line::from(vec![
        Span::styled(format!(" {} ", total), Style::default().fg(BRIGHT).add_modifier(Modifier::BOLD)),
        Span::styled("services  ", Style::default().fg(TEXT)),
        Span::styled(" TCP ", Style::default().fg(Color::Rgb(20, 30, 50)).bg(TCP_COLOR).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", tcp), Style::default().fg(BRIGHT)),
    ]);

    let l2 = Line::from(vec![
        Span::styled(" \u{25CF} ", Style::default().fg(GREEN)),
        Span::styled(format!("{} up", up), Style::default().fg(GREEN)),
        Span::styled("  \u{25CB} ", Style::default().fg(DIM)),
        Span::styled(format!("{} silent", down), Style::default().fg(DIM)),
    ]);

    let l3 = Line::from(vec![
        Span::styled(" \u{21C4} ", Style::default().fg(Color::Rgb(100, 160, 230))),
        Span::styled(format!("{} conn", total_conns), Style::default().fg(TEXT)),
        Span::styled("  \u{1F512} ", Style::default().fg(GREEN)),
        Span::styled(format!("{} tls", tls_count), Style::default().fg(TEXT)),
    ]);

    let l4 = Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(" UDP ", Style::default().fg(Color::Rgb(30, 30, 10)).bg(UDP_COLOR).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" {} ", udp), Style::default().fg(BRIGHT)),
    ]);

    f.render_widget(Paragraph::new(vec![l1, l2, l3, l4]), inner);
}

/// Filter bar (shown only when filter is active)
fn draw_filter_bar(f: &mut Frame, area: Rect, filter: &str, filtered: usize, editing: bool) {
    let text = if editing { format!("{}_", filter) } else { filter.to_string() };
    let line = Line::from(vec![
        Span::styled(" \u{1F50D} ", Style::default().fg(YELLOW)),
        Span::styled(text, Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  {} match{}", filtered, if filtered == 1 { "" } else { "es" }),
            Style::default().fg(DIM),
        ),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(BG)),
        area,
    );
}

// ─── Card list ──────────────────────────────────────────────────────────────

fn draw_list(f: &mut Frame, area: Rect, rows: &[Row], selected: usize) {
    let block = Block::default()
        .borders(Borders::NONE)
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if rows.is_empty() {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No listening services detected. Press 's' to scan.",
                Style::default().fg(DIM),
            )),
        ]).style(Style::default().bg(BG));
        f.render_widget(msg, inner);
        return;
    }

    let h = inner.height as usize;
    let w = inner.width as usize;

    // Find the display position of the selected entry's CardTop
    let sel_pos = rows.iter()
        .position(|r| matches!(r, Row::CardTop { idx, .. } if *idx == selected))
        .unwrap_or(0);

    // Viewport centering
    let total = rows.len();
    let start = if total <= h { 0 }
    else {
        let half = h / 2;
        if sel_pos <= half { 0 }
        else if sel_pos >= total.saturating_sub(half) { total.saturating_sub(h) }
        else { sel_pos.saturating_sub(half) }
    };

    for (i, row) in rows.iter().skip(start).take(h).enumerate() {
        let y = inner.y + i as u16;
        let row_area = Rect::new(inner.x, y, inner.width, 1);

        match row {
            Row::ProtoHeader { proto, count } => {
                render_proto_header(f, row_area, *proto, *count, w);
            }

            Row::CardTop { server, idx, conns } => {
                render_card_top(f, row_area, server, *idx == selected, *conns, w);
            }
            Row::CardBot { server, idx } => {
                render_card_bot(f, row_area, server, *idx == selected, w);
            }
            Row::Spacer => {
                f.render_widget(
                    Paragraph::new("").style(Style::default().bg(BG)),
                    row_area,
                );
            }
        }
    }

    // Scrollbar
    if total > h {
        let sb_area = Rect {
            x: area.x + area.width - 1, y: inner.y,
            width: 1, height: inner.height,
        };
        let mut state = ScrollbarState::new(total.saturating_sub(h)).position(start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(30, 50, 90))),
            sb_area, &mut state,
        );
    }
}

// ─── Protocol section header ────────────────────────────────────────────────

fn render_proto_header(f: &mut Frame, area: Rect, proto: ListenProto, count: usize, w: usize) {
    let (label, color, icon) = match proto {
        ListenProto::Tcp => ("TCP SERVICES", TCP_COLOR, "\u{25C6}"),
        ListenProto::Udp => ("UDP SERVICES", UDP_COLOR, "\u{25C7}"),
    };

    let prefix = format!(" {} {} ", icon, label);
    let suffix = format!(" {} ", count);
    let fill_len = w.saturating_sub(prefix.len() + suffix.len());
    let fill: String = "\u{2500}".repeat(fill_len);

    let line = Line::from(vec![
        Span::styled(prefix, Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled(fill, Style::default().fg(Color::Rgb(25, 38, 60))),
        Span::styled(suffix, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::Rgb(12, 16, 30))),
        area,
    );
}

// ─── Card line 1: icon + name + port + status ───────────────────────────────

fn render_card_top(f: &mut Frame, area: Rect, s: &ListeningPort, sel: bool, conns: usize, w: usize) {
    let (kr, kg, kb) = s.server_kind.color();
    let kc = Color::Rgb(kr, kg, kb);
    let proto_color = match s.proto {
        ListenProto::Tcp => TCP_COLOR,
        ListenProto::Udp => UDP_COLOR,
    };

    let mut spans: Vec<Span> = Vec::new();

    // Left accent bar + selection
    if sel {
        spans.push(Span::styled(" \u{2588}\u{25B8}", Style::default().fg(SEL_ACCENT)));
    } else {
        spans.push(Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(25, 35, 55))));
    }

    // Icon
    spans.push(Span::styled(format!("{} ", s.display_icon()), Style::default().fg(kc)));

    // Name (bold, category-colored)
    let name_max = if w > 110 { 26 } else if w > 80 { 20 } else { 16 };
    spans.push(Span::styled(
        format!("{:<w$}", trunc(&s.display_name(), name_max), w = name_max),
        Style::default().fg(kc).add_modifier(Modifier::BOLD),
    ));

    // Port with protocol color
    let proto_tag = match s.proto { ListenProto::Tcp => "tcp", ListenProto::Udp => "udp" };
    spans.push(Span::styled(
        format!(" :{}/{}", s.port, proto_tag),
        Style::default().fg(proto_color).add_modifier(Modifier::BOLD),
    ));

    // Bind address badge
    {
        use std::net::IpAddr;
        let (bind_label, bind_fg, bind_bg) = match s.bind_addr {
            IpAddr::V4(v4) if v4.is_unspecified() => ("*", Color::Rgb(20, 10, 10), Color::Rgb(255, 100, 80)),
            IpAddr::V6(v6) if v6.is_unspecified() => ("*", Color::Rgb(20, 10, 10), Color::Rgb(220, 140, 80)),
            IpAddr::V4(v4) if v4.is_loopback() => ("127.0.0.1", Color::Rgb(10, 20, 30), Color::Rgb(80, 180, 230)),
            IpAddr::V6(v6) if v6.is_loopback() => ("::1", Color::Rgb(10, 20, 30), Color::Rgb(100, 160, 210)),
            other => {
                let s = other.to_string();
                // Leak is fine: these are a small fixed set of system IPs
                let label: &'static str = Box::leak(s.into_boxed_str());
                (label, Color::Rgb(20, 20, 10), Color::Rgb(200, 180, 100))
            }
        };
        spans.push(Span::styled(
            format!(" {} ", bind_label),
            Style::default().fg(bind_fg).bg(bind_bg).add_modifier(Modifier::BOLD),
        ));
    }

    // Status
    spans.push(Span::styled("  ", Style::default()));
    if s.is_responsive {
        spans.push(Span::styled("\u{25CF} UP", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)));
    } else {
        spans.push(Span::styled("\u{25CB} \u{2014}\u{2014}", Style::default().fg(DIM)));
    }

    // TLS
    if s.details.contains("TLS: yes") {
        spans.push(Span::styled("  \u{1F512}", Style::default().fg(GREEN)));
    }

    // Version badge
    if let Some(ref ver) = s.version {
        spans.push(Span::styled(format!("  v{}", trunc(ver, 10)), Style::default().fg(YELLOW)));
    }

    // Active connections
    if conns > 0 {
        let cc = if conns > 10 { Color::Rgb(255, 140, 90) } else { GREEN };
        spans.push(Span::styled(
            format!("  \u{2022}{}conn", conns),
            Style::default().fg(cc),
        ));
    }

    let bg = if sel { SEL_BG }
    else if !s.is_responsive { UNRESPONSIVE_BG }
    else { CARD_BG };

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
        area,
    );
}

// ─── Card line 2: category + process + description ──────────────────────────

fn render_card_bot(f: &mut Frame, area: Rect, s: &ListeningPort, sel: bool, w: usize) {
    let cat = s.server_kind.category();
    let cc = cat_color(&cat);

    let mut spans: Vec<Span> = Vec::new();

    // Left accent continuation
    if sel {
        spans.push(Span::styled(" \u{2588} ", Style::default().fg(SEL_ACCENT)));
    } else {
        spans.push(Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(25, 35, 55))));
    }

    // Category tag (colored pill)
    let cat_label = cat.label();
    spans.push(Span::styled(
        format!(" {} ", cat_label),
        Style::default().fg(cc),
    ));

    // Process name + PID
    spans.push(Span::styled("  ", Style::default()));
    if !s.process_name.is_empty() {
        let stem = s.process_name.strip_suffix(".exe")
            .or_else(|| s.process_name.strip_suffix(".EXE"))
            .unwrap_or(&s.process_name);
        spans.push(Span::styled(
            trunc(stem, 18),
            Style::default().fg(Color::Rgb(100, 170, 110)),
        ));
        spans.push(Span::styled(
            format!("({})", s.pid),
            Style::default().fg(LABEL),
        ));
    }

    // Fill remaining with description or path
    let used: usize = spans.iter().map(|sp| sp.content.len()).sum();
    let remaining = w.saturating_sub(used + 2);
    if remaining > 10 {
        spans.push(Span::styled("  ", Style::default()));
        let desc = s.display_description();
        if desc.len() > 3 && desc != s.server_kind.description() {
            spans.push(Span::styled(trunc(&desc, remaining), Style::default().fg(LABEL)));
        } else if !s.exe_path.is_empty() {
            spans.push(Span::styled(trunc(&s.exe_path, remaining), Style::default().fg(DIM)));
        }
    }

    let bg = if sel { SEL_BG }
    else if !s.is_responsive { UNRESPONSIVE_BG }
    else { CARD_ALT };

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
        area,
    );
}

// ─── Detail panel ───────────────────────────────────────────────────────────

fn draw_detail(
    f: &mut Frame, area: Rect,
    filtered: &[&ListeningPort], selected: usize,
    conn_counts: &HashMap<u16, usize>,
) {
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));

    if filtered.is_empty() || selected >= filtered.len() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "  \u{2191}\u{2193} browse  Enter detail  s scan  o open folder  y copy path  \u{2190}\u{2192} collapse/expand",
            Style::default().fg(DIM),
        ))).block(block);
        f.render_widget(empty, area);
        return;
    }

    let s = filtered[selected];
    let conns = conn_counts.get(&s.port).copied().unwrap_or(0);
    let (kr, kg, kb) = s.server_kind.color();
    let kc = Color::Rgb(kr, kg, kb);
    let pipe = || Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(25, 35, 55)));
    let proto_color = match s.proto { ListenProto::Tcp => TCP_COLOR, ListenProto::Udp => UDP_COLOR };

    // Line 1: Identity + status
    let proto_tag = match s.proto { ListenProto::Tcp => "TCP", ListenProto::Udp => "UDP" };
    let mut l1 = vec![
        Span::styled(format!(" {} ", s.display_icon()), Style::default().fg(kc)),
        Span::styled(s.display_name(), Style::default().fg(kc).add_modifier(Modifier::BOLD)),
        pipe(),
        Span::styled(format!(" {} ", proto_tag), Style::default().fg(Color::Rgb(20, 25, 40)).bg(proto_color).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" :{}", s.port), Style::default().fg(proto_color).add_modifier(Modifier::BOLD)),
    ];
    if let Some(ref v) = s.version {
        l1.push(pipe());
        l1.push(Span::styled(format!("v{}", v), Style::default().fg(YELLOW)));
    }
    l1.push(pipe());
    l1.push(Span::styled(
        if s.is_responsive { "\u{25CF} Responding" } else { "\u{25CB} Not responding" },
        Style::default().fg(if s.is_responsive { GREEN } else { DIM }),
    ));
    if conns > 0 {
        l1.push(pipe());
        l1.push(Span::styled(format!("{} connection{}", conns, if conns == 1 { "" } else { "s" }), Style::default().fg(TEXT)));
    }
    let has_tls = s.details.contains("TLS: yes");
    if has_tls {
        l1.push(pipe());
        l1.push(Span::styled("\u{1F512} TLS", Style::default().fg(GREEN).add_modifier(Modifier::BOLD)));
    }

    // Line 2: Process + path
    let exe = if s.exe_path.is_empty() { "\u{2014}".to_string() } else { trunc(&s.exe_path, 70) };
    let l2 = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(&s.process_name, Style::default().fg(Color::Rgb(100, 170, 110))),
        Span::styled(format!(" ({})", s.pid), Style::default().fg(LABEL)),
        pipe(),
        Span::styled(exe, Style::default().fg(Color::Rgb(90, 105, 140))),
    ]);

    // Line 3: Detected techs / banner / description
    let mut l3: Vec<Span> = vec![Span::styled("  ", Style::default())];
    if !s.detected_techs.is_empty() {
        l3.push(Span::styled("Tech: ", Style::default().fg(LABEL)));
        for (i, t) in s.detected_techs.iter().take(6).enumerate() {
            if i > 0 { l3.push(Span::styled(" \u{00B7} ", Style::default().fg(DIM))); }
            let label = if t.version.is_empty() { t.name.clone() } else { format!("{}/{}", t.name, t.version) };
            l3.push(Span::styled(label, Style::default().fg(Color::Rgb(160, 145, 230))));
        }
        if s.detected_techs.len() > 6 {
            l3.push(Span::styled(format!("  +{}", s.detected_techs.len() - 6), Style::default().fg(DIM)));
        }
    } else if let Some(ref title) = s.http_title {
        l3.push(Span::styled(format!("Title: \u{201C}{}\u{201D}", trunc(title, 50)), Style::default().fg(TEXT)));
    } else if let Some(ref banner) = s.banner {
        let clean = banner.replace(['\r', '\n'], " ");
        l3.push(Span::styled(format!("Banner: {}", trunc(&clean, 55)), Style::default().fg(LABEL)));
    } else {
        l3.push(Span::styled(s.display_description(), Style::default().fg(LABEL)));
    }

    let detail = Paragraph::new(vec![Line::from(l1), l2, Line::from(l3)]).block(block);
    f.render_widget(detail, area);
}
