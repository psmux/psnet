//! Network Topology tab — hub-and-spoke diagram showing the local machine
//! connected to infrastructure nodes (gateway, DNS), LAN devices discovered
//! by the network scanner, and remote hosts from active connections.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::Frame;

use crate::app::App;
use crate::types::TcpState;
use crate::utils::format_speed;

// ─── Theme palette ───────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(8, 12, 24);
const BORDER: Color = Color::Rgb(30, 50, 85);
const SELECTED: Color = Color::Rgb(255, 200, 80);
const ACTIVE: Color = Color::Rgb(80, 200, 120);
const INACTIVE: Color = Color::Rgb(60, 70, 90);
const OFFLINE: Color = Color::Rgb(200, 60, 60);
const TEXT: Color = Color::Rgb(140, 160, 190);
const TEXT_MUTED: Color = Color::Rgb(90, 110, 140);
const HUB_BORDER: Color = Color::Rgb(100, 180, 255);
const GATEWAY_BORDER: Color = Color::Rgb(80, 200, 120);
const DNS_BORDER: Color = Color::Rgb(80, 200, 255);
const LAN_BORDER: Color = Color::Rgb(170, 140, 255);
const LAN_HEADER: Color = Color::Rgb(200, 170, 255);

// ─── Column widths ───────────────────────────────────────────────────────────

const LEFT_COL: u16 = 20;
const EDGE_COL: u16 = 4;
const CENTER_COL: u16 = 20;

// ─── Aggregated remote host ──────────────────────────────────────────────────

struct RemoteNode {
    ip: IpAddr,
    hostname: Option<String>,
    country_code: Option<String>,
    #[allow(dead_code)]
    country_name: Option<String>,
    conn_count: usize,
    tcp_count: usize,
    udp_count: usize,
    top_process: String,
    has_established: bool,
}

struct RemoteNodePos {
    y: u16,
    height: u16,
    conn_count: usize,
}

// ─── Public entry point ──────────────────────────────────────────────────────

pub fn draw_topology(f: &mut Frame, area: Rect, app: &App) {
    if area.height < 6 || area.width < 50 {
        let msg = Paragraph::new("Terminal too small for topology view")
            .style(Style::default().fg(TEXT_MUTED).bg(BG));
        f.render_widget(msg, area);
        return;
    }

    // ── Aggregate data ──
    let remote_nodes = aggregate_remote_nodes(app);
    let total_remote = remote_nodes.len();
    let total_conns: usize = remote_nodes.iter().map(|n| n.conn_count).sum();
    let unique_countries: usize = {
        let mut seen = std::collections::HashSet::new();
        for n in &remote_nodes {
            if let Some(ref c) = n.country_code {
                seen.insert(c.clone());
            }
        }
        seen.len()
    };
    let lan_count = app.network_scanner.devices.len();

    // ── Outer block ──
    let outer_block = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " \u{1F5A7} Topology ",
                Style::default()
                    .fg(Color::Rgb(160, 180, 220))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {} hosts, {} LAN ", total_remote, lan_count),
                Style::default().fg(Color::Rgb(100, 120, 150)),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));

    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    if inner.height < 4 {
        return;
    }

    // ── Layout: diagram + summary + footer ──
    let vsplit = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // diagram area
            Constraint::Length(1), // summary line
            Constraint::Length(1), // footer keybindings
        ])
        .split(inner);

    let diagram_area = vsplit[0];
    let summary_area = vsplit[1];
    let footer_area = vsplit[2];

    // ── 5-column layout: left | edge | center | edge | right ──
    let right_col = diagram_area
        .width
        .saturating_sub(LEFT_COL + EDGE_COL + CENTER_COL + EDGE_COL);
    let hsplit = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(LEFT_COL),
            Constraint::Length(EDGE_COL),
            Constraint::Length(CENTER_COL),
            Constraint::Length(EDGE_COL),
            Constraint::Length(right_col.max(16)),
        ])
        .split(diagram_area);

    let left_area = hsplit[0];
    let left_edge = hsplit[1];
    let center_area = hsplit[2];
    let right_edge = hsplit[3];
    let right_area = hsplit[4];

    // ── Draw columns ──
    let infra_positions = draw_infrastructure_and_lan(f, left_area, app);
    draw_hub(f, center_area, app);
    let (_vp_start, remote_positions) = draw_remote_nodes(f, right_area, app, &remote_nodes);
    draw_left_edges(f, left_edge, &infra_positions, center_area);
    draw_right_edges(f, right_edge, center_area, &remote_positions);

    // ── Summary + footer ──
    draw_summary(
        f,
        summary_area,
        total_remote,
        total_conns,
        unique_countries,
        lan_count,
        app,
    );
    draw_footer(f, footer_area);
}

// ─── Infrastructure + LAN devices (left column) ─────────────────────────────

/// Positions of left-column nodes for edge-line drawing.
struct LeftNodePos {
    y: u16,
    height: u16,
    color: Color,
}

fn draw_infrastructure_and_lan(
    f: &mut Frame,
    area: Rect,
    app: &App,
) -> Vec<LeftNodePos> {
    let mut positions = Vec::new();
    let mut y_cursor = area.y;

    // ── Gateway box (4 lines) ──
    let gw_height = 4u16;
    if y_cursor + gw_height <= area.y + area.height {
        let gw_area = Rect {
            x: area.x,
            y: y_cursor,
            width: area.width,
            height: gw_height,
        };

        let gateway_ip = app
            .network_scanner
            .gateway
            .map(|gw| gw.to_string())
            .unwrap_or_else(|| "Gateway".to_string());

        let gw_lines = vec![
            Line::from(Span::styled(
                truncate_str(&gateway_ip, area.width.saturating_sub(2) as usize),
                Style::default().fg(TEXT),
            )),
            Line::from(Span::styled(
                "\u{25CF} Online",
                Style::default()
                    .fg(ACTIVE)
                    .add_modifier(Modifier::BOLD),
            )),
        ];

        let gw_block = Block::default()
            .title(Span::styled(
                " Gateway ",
                Style::default()
                    .fg(GATEWAY_BORDER)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(GATEWAY_BORDER));

        f.render_widget(
            Paragraph::new(gw_lines)
                .block(gw_block)
                .style(Style::default().bg(BG)),
            gw_area,
        );

        positions.push(LeftNodePos {
            y: y_cursor,
            height: gw_height,
            color: GATEWAY_BORDER,
        });
        y_cursor += gw_height + 1;
    }

    // ── DNS box (dynamic height based on server count) ──
    let dns_servers = detect_dns_servers(app);
    let server_count = dns_servers.len();
    // 2 for top/bottom border + 1 line per server (minimum 1)
    let dns_height = (2 + server_count.max(1)) as u16;
    if y_cursor + dns_height <= area.y + area.height {
        let dns_area = Rect {
            x: area.x,
            y: y_cursor,
            width: area.width,
            height: dns_height,
        };

        let max_w = area.width.saturating_sub(2) as usize;

        let dns_lines: Vec<Line> = dns_servers
            .iter()
            .map(|(ip_str, is_active)| {
                if *is_active {
                    Line::from(vec![
                        Span::styled(
                            "\u{25CF} ",
                            Style::default()
                                .fg(ACTIVE)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            truncate_str(ip_str, max_w.saturating_sub(11)),
                            Style::default().fg(TEXT),
                        ),
                        Span::styled(
                            " (Active)",
                            Style::default()
                                .fg(ACTIVE)
                                .add_modifier(Modifier::BOLD),
                        ),
                    ])
                } else {
                    Line::from(vec![
                        Span::styled(
                            "\u{25CB} ",
                            Style::default().fg(TEXT_MUTED),
                        ),
                        Span::styled(
                            truncate_str(ip_str, max_w.saturating_sub(2)),
                            Style::default().fg(TEXT_MUTED),
                        ),
                    ])
                }
            })
            .collect();

        let title_label = if server_count > 1 {
            format!(" DNS ({} servers) ", server_count)
        } else {
            " DNS ".to_string()
        };

        let dns_block = Block::default()
            .title(Span::styled(
                title_label,
                Style::default()
                    .fg(DNS_BORDER)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(DNS_BORDER));

        f.render_widget(
            Paragraph::new(dns_lines)
                .block(dns_block)
                .style(Style::default().bg(BG)),
            dns_area,
        );

        positions.push(LeftNodePos {
            y: y_cursor,
            height: dns_height,
            color: DNS_BORDER,
        });
        y_cursor += dns_height + 1;
    }

    // ── LAN Devices section ──
    let devices = &app.network_scanner.devices;
    if !devices.is_empty() && y_cursor + 2 <= area.y + area.height {
        // Section header
        let header_area = Rect {
            x: area.x,
            y: y_cursor,
            width: area.width,
            height: 1,
        };
        let dev_header = format!(
            "\u{2500}\u{2500} LAN ({}) \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
            devices.len()
        );
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_str(&dev_header, area.width as usize),
                Style::default()
                    .fg(LAN_HEADER)
                    .add_modifier(Modifier::BOLD),
            )))
            .style(Style::default().bg(BG)),
            header_area,
        );
        y_cursor += 1;

        // Device boxes (3 lines each)
        let dev_height = 3u16;
        for device in devices.iter() {
            if y_cursor + dev_height > area.y + area.height {
                break;
            }

            let dev_area = Rect {
                x: area.x,
                y: y_cursor,
                width: area.width,
                height: dev_height,
            };

            let max_w = area.width.saturating_sub(3) as usize;

            // Display name: custom_name > hostname > vendor > MAC
            let display_name = device
                .custom_name
                .as_deref()
                .or(device.hostname.as_deref())
                .or(device.vendor.as_deref())
                .unwrap_or(&device.mac);

            let (status_icon, status_color) = if device.is_online {
                ("\u{25CF}", ACTIVE)
            } else {
                ("\u{25CB}", OFFLINE)
            };

            let ip_str = device.ip.to_string();
            let dev_line = Line::from(vec![
                Span::styled(
                    format!("{} ", status_icon),
                    Style::default().fg(status_color),
                ),
                Span::styled(
                    truncate_str(&ip_str, max_w.saturating_sub(2)).to_string(),
                    Style::default().fg(TEXT_MUTED),
                ),
            ]);

            let border_color = if device.is_online { LAN_BORDER } else { INACTIVE };

            let dev_block = Block::default()
                .title(Span::styled(
                    format!(" {} ", truncate_str(display_name, max_w.saturating_sub(2))),
                    Style::default()
                        .fg(if device.is_online {
                            Color::Rgb(180, 160, 255)
                        } else {
                            TEXT_MUTED
                        })
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color));

            f.render_widget(
                Paragraph::new(vec![dev_line])
                    .block(dev_block)
                    .style(Style::default().bg(BG)),
                dev_area,
            );

            positions.push(LeftNodePos {
                y: y_cursor,
                height: dev_height,
                color: border_color,
            });
            y_cursor += dev_height;
        }
    }

    positions
}

// ─── Center hub (local machine) ──────────────────────────────────────────────

fn draw_hub(f: &mut Frame, area: Rect, app: &App) {
    if area.height < 4 {
        return;
    }

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string());

    let local_ip = app
        .network_scanner
        .local_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| detect_local_ip(app));

    let max_w = area.width.saturating_sub(4) as usize;
    let iface = truncate_str(&app.interface_name, max_w);
    let down_speed = format!("\u{25BC} {}", format_speed(app.current_down_speed));
    let up_speed = format!("\u{25B2} {}", format_speed(app.current_up_speed));

    let fw_status = if app.firewall_manager.enabled {
        Span::styled(
            "\u{25CF} FW ON",
            Style::default()
                .fg(ACTIVE)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "\u{25CB} FW OFF",
            Style::default()
                .fg(Color::Rgb(255, 80, 80))
                .add_modifier(Modifier::BOLD),
        )
    };

    let mut lines = vec![
        Line::from(Span::styled(
            truncate_str(&hostname, max_w),
            Style::default()
                .fg(Color::Rgb(220, 230, 255))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            truncate_str(&local_ip, max_w),
            Style::default().fg(Color::Rgb(100, 180, 255)),
        )),
        Line::from(Span::styled(iface.to_string(), Style::default().fg(TEXT_MUTED))),
        Line::from(Span::styled(
            truncate_str(&down_speed, max_w),
            Style::default().fg(Color::Rgb(80, 200, 255)),
        )),
        Line::from(Span::styled(
            truncate_str(&up_speed, max_w),
            Style::default().fg(Color::Rgb(255, 150, 80)),
        )),
        Line::from(fw_status),
    ];

    let max_lines = area.height.saturating_sub(2) as usize;
    lines.truncate(max_lines);

    // Center vertically
    let hub_height = (lines.len() as u16 + 2).min(area.height);
    let hub_y = area.y + (area.height.saturating_sub(hub_height)) / 2;
    let hub_area = Rect {
        x: area.x,
        y: hub_y,
        width: area.width,
        height: hub_height,
    };

    let hub_block = Block::default()
        .title(Span::styled(
            " THIS PC ",
            Style::default()
                .fg(HUB_BORDER)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(ratatui::widgets::BorderType::Double)
        .border_style(Style::default().fg(HUB_BORDER));

    f.render_widget(
        Paragraph::new(lines)
            .block(hub_block)
            .style(Style::default().bg(Color::Rgb(12, 18, 35))),
        hub_area,
    );
}

// ─── Remote nodes (right column) ─────────────────────────────────────────────

fn draw_remote_nodes(
    f: &mut Frame,
    area: Rect,
    app: &App,
    nodes: &[RemoteNode],
) -> (u16, Vec<RemoteNodePos>) {
    if nodes.is_empty() || area.height < 4 {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No remote connections",
            Style::default().fg(TEXT_MUTED),
        )))
        .style(Style::default().bg(BG));
        f.render_widget(empty, area);
        return (0, Vec::new());
    }

    let node_height: u16 = 4;
    let spacing: u16 = 1;
    let total = nodes.len();
    let max_visible = ((area.height + spacing) / (node_height + spacing)).max(1) as usize;
    let selected = app.topology_scroll.min(total.saturating_sub(1));

    // Viewport centered on selection
    let viewport_start = if total <= max_visible {
        0
    } else {
        let half = max_visible / 2;
        if selected <= half {
            0
        } else if selected >= total.saturating_sub(half) {
            total.saturating_sub(max_visible)
        } else {
            selected.saturating_sub(half)
        }
    };

    let mut positions = Vec::new();
    let mut y_offset = area.y;

    for (_vis_idx, node_idx) in (viewport_start..)
        .take(max_visible.min(total - viewport_start))
        .enumerate()
    {
        let node = &nodes[node_idx];
        let is_selected = node_idx == selected;

        let remaining_h = area.y + area.height - y_offset;
        if remaining_h < node_height {
            break;
        }

        let node_area = Rect {
            x: area.x,
            y: y_offset,
            width: area.width,
            height: node_height.min(remaining_h),
        };

        draw_single_remote_node(f, node_area, node, is_selected);
        positions.push(RemoteNodePos {
            y: y_offset,
            height: node_height.min(remaining_h),
            conn_count: node.conn_count,
        });

        y_offset += node_height + spacing;
    }

    // Scrollbar
    if total > max_visible {
        let sb_area = Rect {
            x: area.x + area.width.saturating_sub(1),
            y: area.y,
            width: 1,
            height: area.height,
        };
        let mut sb_state =
            ScrollbarState::new(total.saturating_sub(max_visible)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }

    (viewport_start as u16, positions)
}

fn draw_single_remote_node(f: &mut Frame, area: Rect, node: &RemoteNode, is_selected: bool) {
    let max_w = area.width.saturating_sub(3) as usize;

    // Line 1: hostname or "(no DNS)"
    let host_display = node.hostname.as_deref().unwrap_or("").to_string();
    let host_line = if host_display.is_empty() {
        Line::from(Span::styled("(no DNS)", Style::default().fg(TEXT_MUTED)))
    } else {
        Line::from(Span::styled(
            truncate_str(&host_display, max_w),
            Style::default().fg(Color::Rgb(100, 220, 255)),
        ))
    };

    // Line 2: protocol summary + process
    let proto_str = if node.tcp_count > 0 && node.udp_count > 0 {
        format!("{}xTCP+{}xUDP", node.tcp_count, node.udp_count)
    } else if node.tcp_count > 0 {
        format!("{}x TCP", node.tcp_count)
    } else {
        format!("{}x UDP", node.udp_count)
    };
    let proc_display = truncate_str(
        &node.top_process,
        max_w.saturating_sub(proto_str.len() + 3),
    );
    let conn_line = Line::from(vec![
        Span::styled(proto_str, Style::default().fg(TEXT)),
        Span::styled(" (", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            proc_display.to_string(),
            Style::default().fg(Color::Rgb(130, 200, 140)),
        ),
        Span::styled(")", Style::default().fg(TEXT_MUTED)),
    ]);

    let lines = vec![host_line, conn_line];

    // Border color
    let border_color = if is_selected {
        SELECTED
    } else if node.has_established {
        ACTIVE
    } else {
        INACTIVE
    };

    // Title: IP + country code.
    // Plain ASCII code only — the country flag emoji (Regional Indicator pair)
    // has ambiguous width (Unicode counts each indicator as W=2) that confuses
    // vt100 parsers in embedded terminals like psmux, producing accumulating
    // column offsets that push each node box past the panel border. See the
    // matching note in ui/connections.rs. (issue #7)
    let mut title_parts = vec![Span::styled(
        format!(" {} ", node.ip),
        Style::default()
            .fg(if is_selected {
                SELECTED
            } else {
                Color::Rgb(180, 195, 220)
            })
            .add_modifier(Modifier::BOLD),
    )];
    if let Some(ref code) = node.country_code {
        title_parts.push(Span::styled(
            format!("{} ", code),
            Style::default().fg(Color::Rgb(140, 160, 190)),
        ));
    }

    let block = Block::default()
        .title(Line::from(title_parts))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(if is_selected {
            Color::Rgb(16, 24, 45)
        } else {
            BG
        }));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ─── Edge lines ──────────────────────────────────────────────────────────────

fn draw_left_edges(
    f: &mut Frame,
    edge_area: Rect,
    left_positions: &[LeftNodePos],
    center_area: Rect,
) {
    let center_mid_y = center_area.y + center_area.height / 2;

    // Build connection rows from left node midpoints
    let mut conn_rows: Vec<(u16, Color)> = Vec::new();
    for pos in left_positions {
        let mid = pos.y + pos.height / 2;
        if mid >= edge_area.y && mid < edge_area.y + edge_area.height {
            conn_rows.push((mid, pos.color));
        }
    }

    for y in edge_area.y..edge_area.y + edge_area.height {
        let row_area = Rect {
            x: edge_area.x,
            y,
            width: edge_area.width,
            height: 1,
        };

        if let Some((_, color)) = conn_rows.iter().find(|(cy, _)| *cy == y) {
            // Horizontal connection line
            let seg = "\u{2500}".repeat(edge_area.width as usize);
            let line = Line::from(Span::styled(seg, Style::default().fg(*color)));
            f.render_widget(
                Paragraph::new(vec![line]).style(Style::default().bg(BG)),
                row_area,
            );
        } else {
            // Check for vertical connector between a connection row and center
            let needs_vert = conn_rows.iter().any(|(cy, _)| {
                let (lo, hi) = if *cy < center_mid_y {
                    (*cy, center_mid_y)
                } else {
                    (center_mid_y, *cy)
                };
                y > lo && y < hi
            });

            if needs_vert {
                let pad = " ".repeat(edge_area.width.saturating_sub(1) as usize);
                let line = Line::from(vec![
                    Span::styled(pad, Style::default()),
                    Span::styled("\u{2502}", Style::default().fg(Color::Rgb(40, 60, 100))),
                ]);
                f.render_widget(
                    Paragraph::new(vec![line]).style(Style::default().bg(BG)),
                    row_area,
                );
            } else {
                let blank = " ".repeat(edge_area.width as usize);
                f.render_widget(
                    Paragraph::new(vec![Line::from(Span::raw(blank))])
                        .style(Style::default().bg(BG)),
                    row_area,
                );
            }
        }
    }
}

fn draw_right_edges(
    f: &mut Frame,
    edge_area: Rect,
    center_area: Rect,
    positions: &[RemoteNodePos],
) {
    let center_mid_y = center_area.y + center_area.height / 2;

    let conn_rows: Vec<(u16, usize)> = positions
        .iter()
        .map(|pos| (pos.y + pos.height / 2, pos.conn_count))
        .collect();

    for y in edge_area.y..edge_area.y + edge_area.height {
        let row_area = Rect {
            x: edge_area.x,
            y,
            width: edge_area.width,
            height: 1,
        };

        if let Some((_cy, count)) = conn_rows.iter().find(|(cy, _)| *cy == y) {
            let label = format!("{}", count);
            let w = edge_area.width as usize;
            let line = if w >= label.len() + 2 {
                let left_dashes = (w - label.len()) / 2;
                let right_dashes = w - label.len() - left_dashes;
                Line::from(vec![
                    Span::styled(
                        "\u{2500}".repeat(left_dashes),
                        Style::default().fg(Color::Rgb(60, 100, 150)),
                    ),
                    Span::styled(
                        label,
                        Style::default()
                            .fg(Color::Rgb(180, 200, 230))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "\u{2500}".repeat(right_dashes),
                        Style::default().fg(Color::Rgb(60, 100, 150)),
                    ),
                ])
            } else {
                Line::from(Span::styled(
                    "\u{2500}".repeat(w),
                    Style::default().fg(Color::Rgb(60, 100, 150)),
                ))
            };
            f.render_widget(
                Paragraph::new(vec![line]).style(Style::default().bg(BG)),
                row_area,
            );
        } else {
            let needs_vert = conn_rows.iter().any(|(cy, _)| {
                let (lo, hi) = if *cy < center_mid_y {
                    (*cy, center_mid_y)
                } else {
                    (center_mid_y, *cy)
                };
                y > lo && y < hi
            });

            if needs_vert {
                let line = Line::from(vec![
                    Span::styled(
                        "\u{2502}",
                        Style::default().fg(Color::Rgb(40, 60, 100)),
                    ),
                    Span::styled(
                        " ".repeat(edge_area.width.saturating_sub(1) as usize),
                        Style::default(),
                    ),
                ]);
                f.render_widget(
                    Paragraph::new(vec![line]).style(Style::default().bg(BG)),
                    row_area,
                );
            } else {
                let blank = " ".repeat(edge_area.width as usize);
                f.render_widget(
                    Paragraph::new(vec![Line::from(Span::raw(blank))])
                        .style(Style::default().bg(BG)),
                    row_area,
                );
            }
        }
    }
}

// ─── Summary line ────────────────────────────────────────────────────────────

fn draw_summary(
    f: &mut Frame,
    area: Rect,
    total_remote: usize,
    total_conns: usize,
    unique_countries: usize,
    lan_count: usize,
    app: &App,
) {
    let established = app
        .connections
        .iter()
        .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
        .count();

    let summary = Line::from(vec![
        Span::styled(" \u{25C8} ", Style::default().fg(HUB_BORDER)),
        Span::styled(
            format!("{} remote", total_remote),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("  \u{2502}  ", Style::default().fg(Color::Rgb(40, 55, 80))),
        Span::styled(
            format!("{} conn ({} est)", total_conns, established),
            Style::default().fg(TEXT),
        ),
        Span::styled("  \u{2502}  ", Style::default().fg(Color::Rgb(40, 55, 80))),
        Span::styled(
            format!("{} countries", unique_countries),
            Style::default().fg(Color::Rgb(170, 200, 230)),
        ),
        Span::styled("  \u{2502}  ", Style::default().fg(Color::Rgb(40, 55, 80))),
        Span::styled(
            format!(
                "{} LAN devices",
                lan_count,
            ),
            Style::default().fg(LAN_HEADER),
        ),
    ]);

    f.render_widget(
        Paragraph::new(vec![summary]).style(Style::default().bg(BG)),
        area,
    );
}

// ─── Footer ──────────────────────────────────────────────────────────────────

fn draw_footer(f: &mut Frame, area: Rect) {
    let hints = Line::from(vec![
        Span::styled(
            " \u{2191}\u{2193}:Select",
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("  ", Style::default()),
        Span::styled("Enter:Detail", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("PgUp/Dn:Scroll", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("s:Scan LAN", Style::default().fg(Color::Yellow)),
        Span::styled("  ", Style::default()),
        Span::styled("Tab:Next tab", Style::default().fg(Color::Rgb(60, 80, 110))),
    ]);

    f.render_widget(
        Paragraph::new(vec![hints]).style(Style::default().bg(Color::Rgb(12, 16, 30))),
        area,
    );
}

// ─── Helper: aggregate connections by remote IP ──────────────────────────────

fn aggregate_remote_nodes(app: &App) -> Vec<RemoteNode> {
    let mut map: HashMap<IpAddr, RemoteNode> = HashMap::new();

    for conn in &app.connections {
        let ip = match conn.remote_addr {
            Some(ip) if !ip.is_unspecified() && !ip.is_loopback() => ip,
            _ => continue,
        };

        let entry = map.entry(ip).or_insert_with(|| {
            let hostname = app.dns_cache.get(&ip).and_then(|opt| opt.clone());

            let (country_code, country_name) = match app.geoip.lookup(ip) {
                Some(info) => (Some(info.code.to_string()), Some(info.name.to_string())),
                None => (None, None),
            };

            RemoteNode {
                ip,
                hostname,
                country_code,
                country_name,
                conn_count: 0,
                tcp_count: 0,
                udp_count: 0,
                top_process: String::new(),
                has_established: false,
            }
        });

        entry.conn_count += 1;
        match conn.proto {
            crate::types::ConnProto::Tcp => entry.tcp_count += 1,
            crate::types::ConnProto::Udp => entry.udp_count += 1,
        }

        if matches!(conn.state.as_ref(), Some(TcpState::Established)) {
            entry.has_established = true;
        }

        if entry.top_process.is_empty() && !conn.process_name.is_empty() {
            entry.top_process = conn.process_name.clone();
        }
    }

    let mut nodes: Vec<RemoteNode> = map.into_values().collect();
    nodes.sort_by(|a, b| {
        b.conn_count
            .cmp(&a.conn_count)
            .then_with(|| a.ip.to_string().cmp(&b.ip.to_string()))
    });

    nodes
}

// ─── Helper: detect DNS servers ──────────────────────────────────────────────

/// Returns all known DNS servers as (ip_string, is_active) pairs.
/// Uses `app.dns_servers` for configured servers, falling back to port 53
/// connection detection if that field is empty or not yet available.
fn detect_dns_servers(app: &App) -> Vec<(String, bool)> {
    // Collect IPs actively used for DNS (port 53 connections)
    let active_dns: HashSet<IpAddr> = app
        .connections
        .iter()
        .filter(|c| c.remote_port == Some(53))
        .filter_map(|c| c.remote_addr)
        .collect();

    // Try app.dns_servers (system-configured DNS list) first.
    // This field is populated from `get_dns_servers()` on a background thread.
    if !app.dns_servers.is_empty() {
        app.dns_servers
            .iter()
            .map(|ip| (ip.to_string(), active_dns.contains(ip)))
            .collect()
    } else if !active_dns.is_empty() {
        // Fallback: use whatever we see on port 53
        let mut servers: Vec<(String, bool)> = active_dns
            .iter()
            .map(|ip| (ip.to_string(), true))
            .collect();
        servers.sort_by(|a, b| a.0.cmp(&b.0));
        servers
    } else {
        vec![("DNS".to_string(), false)]
    }
}

// ─── Helper: detect local IP from connections ────────────────────────────────

fn detect_local_ip(app: &App) -> String {
    for conn in &app.connections {
        let ip = conn.local_addr;
        if !ip.is_loopback() && !ip.is_unspecified() {
            return ip.to_string();
        }
    }
    "127.0.0.1".to_string()
}

// ─── Helper: truncate string to max width ────────────────────────────────────

fn truncate_str(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else if max > 3 {
        // Find a valid char boundary at or before `max`
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    } else {
        ""
    }
}
