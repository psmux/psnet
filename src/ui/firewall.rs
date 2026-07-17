//! Firewall & Usage tab UI — app-centric block/allow management with bandwidth data.
//!
//! Shows apps that are currently making network connections (or were previously
//! blocked), with firewall status, bandwidth columns, and Enter for detail/action popup.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::utils::{format_bytes, format_speed};

pub fn draw_firewall(f: &mut Frame, area: Rect, app: &App) {
    let apps = app.firewall_app_list_filtered();
    let blocked_count = apps.iter().filter(|(_, b, _)| *b).count();

    let fw = &app.firewall_manager;
    let filter_info = if app.filter_editing {
        format!(" [filter: {}_]", fw.filter_text)
    } else if fw.filter_text.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", fw.filter_text)
    };

    let mut title_spans = vec![
        Span::styled(
            " Firewall & Usage ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} apps ", apps.len()),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
        Span::styled(
            format!(" {} blocked ", blocked_count),
            Style::default()
                .fg(if blocked_count > 0 { Color::Rgb(255, 120, 80) } else { Color::Rgb(70, 90, 120) }),
        ),
    ];
    if !filter_info.is_empty() {
        title_spans.push(Span::styled(filter_info, Style::default().fg(Color::Yellow)));
    }

    let outer_block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(12, 16, 28)));
    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Firewall status strip
            Constraint::Length(4),  // Data plan summary
            Constraint::Min(6),    // App list with bandwidth columns
        ])
        .split(inner);

    draw_firewall_status(f, chunks[0], app);
    draw_data_plan_summary(f, chunks[1], app);
    draw_firewall_apps(f, chunks[2], app, &apps);
}

fn draw_firewall_status(f: &mut Frame, area: Rect, app: &App) {
    let fw = &app.firewall_manager;

    let status_str = if fw.enabled { "ACTIVE" } else { "DISABLED" };
    let status_color = if fw.enabled { Color::Rgb(80, 200, 120) } else { Color::Rgb(255, 80, 80) };

    let mode_color = match fw.mode {
        crate::types::FirewallMode::Normal => Color::Rgb(80, 180, 255),
        crate::types::FirewallMode::AskToConnect => Color::Rgb(255, 200, 60),
        crate::types::FirewallMode::Lockdown => Color::Rgb(255, 80, 80),
    };

    let pending_str = if fw.mode == crate::types::FirewallMode::AskToConnect && !fw.pending_apps.is_empty() {
        format!("  |  {} pending: {}", fw.pending_apps.len(),
            fw.pending_apps.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
    } else {
        String::new()
    };

    let (policy_label, policy_color) = if fw.default_deny {
        ("DENY-ALL", Color::Rgb(255, 100, 80))
    } else {
        ("ALLOW-ALL", Color::Rgb(80, 200, 120))
    };

    let line = Line::from(vec![
        Span::styled("  Shield: ", Style::default().fg(Color::Rgb(120, 140, 170))),
        Span::styled(status_str, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::styled("  |  Policy: ", Style::default().fg(Color::Rgb(80, 100, 130))),
        Span::styled(policy_label, Style::default().fg(policy_color).add_modifier(Modifier::BOLD)),
        Span::styled("  |  Mode: ", Style::default().fg(Color::Rgb(80, 100, 130))),
        Span::styled(fw.mode.label(), Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  |  {} blocked", fw.blocked_apps.len()),
            Style::default().fg(Color::Rgb(90, 110, 140)),
        ),
        Span::styled(pending_str, Style::default().fg(Color::Rgb(255, 200, 60))),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_data_plan_summary(f: &mut Frame, area: Rect, app: &App) {
    let (today_down, today_up) = app.usage_tracker.today_usage();
    let (month_down, month_up) = app.usage_tracker.month_usage();
    let (used, limit, pct) = app.usage_tracker.plan_status();

    let plan_info = if limit > 0 {
        let gauge_width = 20u16;
        let filled = ((pct as f64 / 100.0) * gauge_width as f64).round() as u16;
        let empty = gauge_width.saturating_sub(filled);
        let gauge_color = if pct > 90 { Color::Red } else if pct > 70 { Color::Yellow } else { Color::Rgb(50, 200, 120) };

        vec![
            Line::from(vec![
                Span::styled("  Data Plan: ", Style::default().fg(Color::Rgb(120, 140, 170))),
                Span::styled(
                    format!("{} / {} ", format_bytes(used), format_bytes(limit)),
                    Style::default().fg(Color::Rgb(180, 200, 230)).add_modifier(Modifier::BOLD),
                ),
                Span::styled("\u{2588}".repeat(filled as usize), Style::default().fg(gauge_color)),
                Span::styled("\u{2591}".repeat(empty as usize), Style::default().fg(Color::Rgb(30, 40, 55))),
                Span::styled(format!(" {}%", pct), Style::default().fg(gauge_color)),
            ]),
            Line::from(vec![
                Span::styled("  Today: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("\u{25bc}{} \u{25b2}{}", format_bytes(today_down), format_bytes(today_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
                Span::styled("  \u{2502}  Month: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("\u{25bc}{} \u{25b2}{}", format_bytes(month_down), format_bytes(month_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("  No data plan configured", Style::default().fg(Color::Rgb(80, 100, 130))),
            ]),
            Line::from(vec![
                Span::styled("  Today: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("\u{25bc}{} \u{25b2}{}", format_bytes(today_down), format_bytes(today_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
                Span::styled("  \u{2502}  Month: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("\u{25bc}{} \u{25b2}{}", format_bytes(month_down), format_bytes(month_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
            ]),
        ]
    };

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(plan_info).block(block), area);
}

fn draw_firewall_apps(
    f: &mut Frame,
    area: Rect,
    app: &App,
    apps: &[(String, bool, usize)],
) {
    let total = apps.len();
    let visible_height = area.height.saturating_sub(5) as usize;
    let selected = if total > 0 {
        app.firewall_manager.scroll_offset.min(total - 1)
    } else {
        0
    };

    // Build display items — insert separator between active and inactive groups
    enum DisplayItem<'a> {
        App(usize, &'a (String, bool, usize)),
        Separator(&'static str),
    }

    let display_items: Vec<DisplayItem> = if total == 0 {
        Vec::new()
    } else {
        let active_count = apps.iter().filter(|(_, _, c)| *c > 0).count();
        let inactive_count = apps.iter().filter(|(_, _, c)| *c == 0).count();
        let mut items = Vec::new();
        if active_count > 0 {
            for (idx, app_entry) in apps.iter().enumerate().filter(|(_, (_, _, c))| *c > 0) {
                items.push(DisplayItem::App(idx, app_entry));
            }
        }
        if inactive_count > 0 && active_count > 0 {
            items.push(DisplayItem::Separator("\u{2500}\u{2500}\u{2500} Inactive / Not Currently Connected \u{2500}\u{2500}\u{2500}"));
        }
        for (idx, app_entry) in apps.iter().enumerate().filter(|(_, (_, _, c))| *c == 0) {
            items.push(DisplayItem::App(idx, app_entry));
        }
        items
    };
    let display_total = display_items.len();

    // Viewport follows selection
    let selected_display_idx = display_items.iter().position(|item| {
        matches!(item, DisplayItem::App(idx, _) if *idx == selected)
    }).unwrap_or(0);

    let viewport_start = if display_total <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected_display_idx <= half {
            0
        } else if selected_display_idx >= display_total.saturating_sub(half) {
            display_total.saturating_sub(visible_height)
        } else {
            selected_display_idx.saturating_sub(half)
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    let sort_col = app.bandwidth_tracker.sort_column;
    let sort_asc = app.bandwidth_tracker.sort_ascending;
    let si = |col: usize| -> &str {
        if sort_col == col { if sort_asc { " \u{25b2}" } else { " \u{25bc}" } } else { "" }
    };

    let header = Row::new(vec![
        Cell::from(Span::styled("Status", hdr_style)),
        Cell::from(Span::styled(format!("Application{}", si(4)), hdr_style)),
        Cell::from(Span::styled(format!("Conns{}", si(3)), hdr_style)),
        Cell::from(Span::styled(format!("\u{2193} Down{}", si(1)), hdr_style)),
        Cell::from(Span::styled(format!("\u{2191} Up{}", si(2)), hdr_style)),
        Cell::from(Span::styled(format!("Total{}", si(0)), hdr_style)),
        Cell::from(Span::styled("Speed", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = if display_total == 0 {
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from(Span::styled(
                "  No apps detected yet. Apps appear here when they make network connections.",
                Style::default().fg(Color::Rgb(80, 100, 140)),
            )),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])
        .style(Style::default().bg(Color::Rgb(12, 16, 28)))]
    } else {
        display_items
            .iter()
            .enumerate()
            .skip(viewport_start)
            .take(visible_height)
            .map(|(_display_idx, item)| match item {
                DisplayItem::Separator(label) => Row::new(vec![
                    Cell::from(""),
                    Cell::from(Span::styled(
                        *label,
                        Style::default().fg(Color::Rgb(60, 80, 110)),
                    )),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ])
                .style(Style::default().bg(Color::Rgb(8, 10, 20))),

                DisplayItem::App(idx, (name, _is_blocked, conn_count)) => {
                    let is_selected = *idx == selected;

                    let (status_str, eff_blocked) = app.firewall_manager.effective_status(name);
                    let status_color = match status_str {
                        "DENY" => Color::Rgb(255, 80, 80),
                        "DROP" => Color::Rgb(255, 140, 40),
                        "ALLOW" => Color::Rgb(80, 200, 255),
                        "BLOCKED" => Color::Rgb(255, 80, 80),
                        _ => Color::Rgb(80, 200, 120), // ALLOWED
                    };

                    let prefix = if is_selected { "\u{25b6} " } else { "  " };
                    let display_name = format!("{}{}", prefix, truncate_str(name, 30));

                    let conn_str = if *conn_count > 0 {
                        conn_count.to_string()
                    } else {
                        "-".to_string()
                    };

                    // Look up bandwidth data
                    let key = name.to_lowercase();
                    let bw = app.bandwidth_tracker.apps.get(&key);

                    let (dl_str, ul_str, total_str) = if let Some(bw) = bw {
                        (
                            format_bytes(bw.download_bytes),
                            format_bytes(bw.upload_bytes),
                            format_bytes(bw.total_bytes()),
                        )
                    } else {
                        ("-".to_string(), "-".to_string(), "-".to_string())
                    };

                    let (speed_str, speed_color) = if let Some(bw) = bw {
                        let sd = bw.smooth_down();
                        let su = bw.smooth_up();
                        if sd + su > 0.5 {
                            let c = if sd + su > 100_000.0 {
                                Color::Rgb(80, 220, 160)
                            } else if sd + su > 1000.0 {
                                Color::Rgb(100, 160, 200)
                            } else {
                                Color::Rgb(70, 120, 100)
                            };
                            (format!("\u{25bc}{} \u{25b2}{}", format_speed(sd), format_speed(su)), c)
                        } else {
                            ("idle".to_string(), Color::Rgb(50, 60, 75))
                        }
                    } else {
                        ("-".to_string(), Color::Rgb(50, 60, 75))
                    };

                    let row_bg = if is_selected {
                        Color::Rgb(25, 45, 85)
                    } else if eff_blocked {
                        Color::Rgb(22, 10, 10)
                    } else {
                        Color::Rgb(12, 16, 28)
                    };

                    Row::new(vec![
                        Cell::from(Span::styled(
                            status_str,
                            Style::default()
                                .fg(status_color)
                                .add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(Span::styled(
                            display_name,
                            Style::default().fg(if eff_blocked {
                                Color::Rgb(200, 130, 130)
                            } else {
                                Color::Rgb(160, 200, 160)
                            }),
                        )),
                        Cell::from(Span::styled(
                            conn_str,
                            Style::default().fg(Color::Rgb(120, 150, 190)),
                        )),
                        Cell::from(Span::styled(
                            dl_str,
                            Style::default().fg(Color::Rgb(80, 180, 255)),
                        )),
                        Cell::from(Span::styled(
                            ul_str,
                            Style::default().fg(Color::Rgb(180, 120, 255)),
                        )),
                        Cell::from(Span::styled(
                            total_str,
                            Style::default().fg(Color::Rgb(170, 185, 210)).add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(Span::styled(
                            speed_str,
                            Style::default().fg(speed_color),
                        )),
                    ])
                    .style(Style::default().bg(row_bg))
                }
            })
            .collect()
    };

    // Bottom hint
    let hint_line = if let Some((name, _, _)) = apps.get(selected) {
        Line::from(vec![
            Span::styled(
                " Enter ",
                Style::default()
                    .fg(Color::Rgb(255, 200, 80))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Detail/Action ", Style::default().fg(Color::Rgb(140, 170, 210))),
            Span::styled(truncate_str(name, 20), Style::default().fg(Color::Rgb(160, 180, 220))),
            Span::styled(
                "  |  1-4:sort  f:filter  r:refresh  x:reset  e:export",
                Style::default().fg(Color::Rgb(55, 70, 100)),
            ),
        ])
    } else {
        Line::from(Span::styled(
            "  Apps will appear here when they make network connections",
            Style::default().fg(Color::Rgb(60, 80, 110)),
        ))
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),    // Status
            Constraint::Min(16),     // Application
            Constraint::Length(6),   // Connections
            Constraint::Length(10),  // Download
            Constraint::Length(10),  // Upload
            Constraint::Length(10),  // Total
            Constraint::Length(22),  // Speed
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title_bottom(hint_line)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28))),
    );

    f.render_widget(table, area);

    // Scrollbar
    if display_total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state =
            ScrollbarState::new(display_total.saturating_sub(visible_height)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let end = s.char_indices()
            .nth(max_len.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}\u{2026}", &s[..end])
    } else {
        s.to_string()
    }
}
