use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::network::dns::port_service_name;
use crate::types::TcpState;

pub fn draw_connections(f: &mut Frame, area: Rect, app: &App) {
    let filtered = app.filtered_connections();
    let total = filtered.len();

    let sort_ind = |col: usize| -> &str {
        if app.sort_column == col {
            if app.sort_ascending { " \u{25B2}" } else { " \u{25BC}" }
        } else {
            ""
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    // ── Redesigned columns: Process | Remote Host | Country | Service | State | Local ──
    let header = Row::new(vec![
        Cell::from(Span::styled(format!("Process{}", sort_ind(6)), hdr_style)),
        Cell::from(Span::styled(format!("Remote Host{}", sort_ind(3)), hdr_style)),
        Cell::from(Span::styled("Geo", hdr_style)),
        Cell::from(Span::styled(format!("Service{}", sort_ind(4)), hdr_style)),
        Cell::from(Span::styled(format!("State{}", sort_ind(5)), hdr_style)),
        Cell::from(Span::styled(format!("Local{}", sort_ind(2)), hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let visible_height = area.height.saturating_sub(5) as usize;
    let selected = if total > 0 { app.conn_scroll.min(total - 1) } else { 0 };

    // Viewport follows selection (centered)
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

    let rows: Vec<Row> = filtered
        .iter()
        .enumerate()
        .skip(viewport_start)
        .take(visible_height)
        .map(|(idx, conn)| {
            let is_selected = idx == selected;
            // ── Process name ──
            let proc_name = &conn.process_name;
            let proc_display = {
                let base = if proc_name.starts_with("PID:") {
                    format!("[{}]", &proc_name[4..])
                } else {
                    proc_name.clone()
                };
                // Truncate to fit the 20-char Process column (2 chars used by prefix)
                let base = if base.chars().count() > 18 {
                    format!("{}…", base.chars().take(17).collect::<String>())
                } else {
                    base
                };
                if is_selected { format!("\u{25B8} {}", base) } else { format!("  {}", base) }
            };
            let proc_color = if proc_name.starts_with("PID:") || proc_name.starts_with('[') {
                Color::Rgb(90, 100, 125)
            } else {
                Color::Rgb(130, 200, 140)
            };

            // ── Remote Host (the star column) ──
            let (remote_display, remote_color) = match (&conn.dns_hostname, conn.remote_addr) {
                (Some(dns), _) if dns != "localhost" => {
                    // Cap at 44 chars to prevent rows overflowing in embedded terminals
                    let host = if dns.chars().count() > 44 { format!("{}…", dns.chars().take(43).collect::<String>()) } else { dns.clone() };
                    (format!("\u{2192} {}", host), Color::Rgb(100, 220, 255))
                }
                (Some(_), Some(ip)) if ip.is_loopback() => {
                    ("\u{2192} localhost".to_string(), Color::Rgb(75, 85, 108))
                }
                (None, Some(ip)) if ip.is_unspecified() => {
                    ("*".to_string(), Color::Rgb(55, 65, 85))
                }
                (None, Some(ip)) => {
                    (format!("\u{2192} {}", ip), Color::Rgb(155, 170, 195))
                }
                _ => ("*".to_string(), Color::Rgb(55, 65, 85)),
            };
            let remote_bold = conn.dns_hostname.is_some()
                && conn.dns_hostname.as_deref() != Some("localhost");

            // ── Service (port + label + protocol) — single lookup ──
            let port = conn.remote_port.unwrap_or(conn.local_port);
            let proto = conn.proto.label();
            let svc_name = port_service_name(port);
            let service_str = if let Some(svc) = svc_name {
                format!("{}/{}", svc, proto)
            } else {
                format!("{}/{}", port, proto)
            };
            let service_color = match svc_name {
                Some("HTTPS") => Color::Rgb(80, 200, 120),
                Some("HTTP") => Color::Rgb(220, 180, 60),
                Some("DNS") => Color::Rgb(100, 180, 255),
                Some("SSH") => Color::Rgb(180, 130, 255),
                Some("RDP") => Color::Rgb(255, 150, 100),
                _ => Color::Rgb(180, 170, 130),
            };

            // ── State ──
            let state_str = conn
                .state
                .as_ref()
                .map(|s| s.label().to_string())
                .unwrap_or_else(|| "-".to_string());
            let state_color = conn
                .state
                .as_ref()
                .map(|s| s.color())
                .unwrap_or(Color::Rgb(80, 100, 140));

            // ── GeoIP country ──
            // Use plain ASCII code only — flag emoji (Regional Indicator pairs) have
            // ambiguous width (Unicode counts each as W=2) that confuses vt100 parsers
            // in embedded terminals like psmux, causing accumulating column offsets.
            let (geo_str, geo_color) = match conn.remote_addr {
                Some(ip) if !ip.is_loopback() && !ip.is_unspecified() => {
                    match app.geoip.lookup(ip) {
                        Some(info) => (
                            info.code.to_string(),
                            Color::Rgb(170, 200, 230),
                        ),
                        None => ("-".to_string(), Color::Rgb(55, 65, 85)),
                    }
                }
                _ => ("-".to_string(), Color::Rgb(55, 65, 85)),
            };

            // ── Local port ──
            let local_str = conn.local_port.to_string();

            // Row dimming for passive states
            let dim = matches!(
                conn.state.as_ref(),
                Some(TcpState::Listen)
                    | Some(TcpState::Closed)
                    | Some(TcpState::TimeWait)
                    | Some(TcpState::DeleteTcb)
            );
            let row_bg = if is_selected {
                Color::Rgb(25, 45, 85)
            } else if dim {
                Color::Rgb(8, 10, 18)
            } else {
                Color::Rgb(12, 16, 28)
            };

            Row::new(vec![
                Cell::from(Span::styled(proc_display, Style::default().fg(proc_color))),
                Cell::from(Span::styled(
                    remote_display,
                    Style::default().fg(remote_color).add_modifier(
                        if remote_bold && !dim {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        },
                    ),
                )),
                Cell::from(Span::styled(
                    geo_str,
                    Style::default().fg(if dim { Color::Rgb(50, 55, 70) } else { geo_color }),
                )),
                Cell::from(Span::styled(
                    service_str,
                    Style::default().fg(if dim {
                        Color::Rgb(70, 80, 100)
                    } else {
                        service_color
                    }),
                )),
                Cell::from(Span::styled(
                    state_str,
                    Style::default()
                        .fg(state_color)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    local_str,
                    Style::default().fg(Color::Rgb(75, 85, 108)),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // ── Title bar with tabs ──
    let filter_info = if app.filter_text.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", app.filter_text)
    };
    let localhost_info = if app.hide_localhost_conn {
        " \u{1F310} WAN"
    } else {
        " \u{1F517} ALL"
    };

    let mut title_spans = vec![
        Span::styled(
            " Connections ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} total ", total),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
        Span::styled(
            localhost_info.to_string(),
            Style::default().fg(Color::Rgb(80, 160, 200)),
        ),
    ];
    if !filter_info.is_empty() {
        title_spans.push(Span::styled(
            filter_info,
            Style::default().fg(Color::Yellow),
        ));
    }

    // Detail bar for selected connection
    let detail_line = if let Some(conn) = filtered.get(selected) {
        let geo_detail = conn.remote_addr
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
            .and_then(|ip| app.geoip.lookup(ip))
            .map(|g| format!("{} {}", g.code, g.name))
            .unwrap_or_else(|| "Local/Private".to_string());
        let remote_str = conn.dns_hostname.clone()
            .or_else(|| conn.remote_addr.map(|ip| ip.to_string()))
            .unwrap_or_else(|| "*".to_string());
        Line::from(vec![
            Span::styled(" \u{25B8} ", Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD)),
            Span::styled(conn.process_name.clone(), Style::default().fg(Color::Rgb(130, 200, 140)).add_modifier(Modifier::BOLD)),
            Span::styled(" \u{2192} ", Style::default().fg(Color::Rgb(60, 80, 110))),
            Span::styled(remote_str, Style::default().fg(Color::Rgb(100, 220, 255))),
            Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(40, 55, 80))),
            Span::styled(geo_detail, Style::default().fg(Color::Rgb(170, 200, 230))),
        ])
    } else {
        Line::from("")
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),  // Process (wider for ▸ prefix)
            Constraint::Min(22),     // Remote Host (widest — the star)
            Constraint::Length(7),   // Geo (flag + code)
            Constraint::Length(14),  // Service
            Constraint::Length(14),  // State
            Constraint::Length(7),   // Local port
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_spans))
            .title_bottom(detail_line)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28))),
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
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}
