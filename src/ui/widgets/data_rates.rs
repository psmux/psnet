//! Data Rates KPI widget — per-app live speed mini-sparklines with rates.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::utils::format_speed;

/// Draw top active apps with their live data rates.
pub fn draw_data_rates(f: &mut Frame, area: Rect, app: &App) {
    let bg = Color::Rgb(8, 12, 24);

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " Live Rates ",
                Style::default()
                    .fg(Color::Rgb(100, 220, 200))
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 1 || inner.width < 15 {
        return;
    }

    // Get apps sorted by current speed (sum of smooth down + up)
    let mut apps: Vec<(&String, &crate::types::AppBandwidth)> =
        app.bandwidth_tracker.apps.iter()
            .filter(|(_, bw)| bw.smooth_down() > 0.0 || bw.smooth_up() > 0.0 || bw.active_connections > 0)
            .collect();

    apps.sort_by(|a, b| {
        let speed_a = a.1.smooth_down() + a.1.smooth_up();
        let speed_b = b.1.smooth_down() + b.1.smooth_up();
        speed_b.partial_cmp(&speed_a).unwrap_or(std::cmp::Ordering::Equal)
    });

    let max_rows = inner.height as usize;
    let max_speed = apps.iter()
        .map(|(_, bw)| bw.smooth_down() + bw.smooth_up())
        .fold(0.0f64, f64::max)
        .max(1.0);

    let mut lines: Vec<Line<'static>> = Vec::new();

    if apps.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No active apps",
            Style::default().fg(Color::Rgb(50, 65, 90)),
        )));
    }

    let name_budget = 12.min(inner.width.saturating_sub(24) as usize);
    let bar_budget = inner.width.saturating_sub(name_budget as u16 + 22) as usize;

    for (_, (name, bw)) in apps.iter().take(max_rows).enumerate() {
        let down = bw.smooth_down();
        let up = bw.smooth_up();
        let total = down + up;

        // Truncate name
        let display_name: String = if name.chars().count() > name_budget {
            format!("{}…", name.chars().take(name_budget.saturating_sub(1)).collect::<String>())
        } else {
            format!("{:<width$}", name, width = name_budget)
        };

        // Mini speed bar
        let bar_len = if bar_budget > 0 {
            ((total / max_speed) * bar_budget as f64).ceil() as usize
        } else {
            0
        };

        let speed_color = if total > 100_000.0 {
            Color::Rgb(80, 255, 160)
        } else if total > 10_000.0 {
            Color::Rgb(80, 200, 120)
        } else {
            Color::Rgb(60, 140, 100)
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!(" {}", display_name),
                Style::default().fg(Color::Rgb(160, 175, 200)),
            ),
            Span::styled(" ▼", Style::default().fg(Color::Rgb(60, 120, 180))),
            Span::styled(
                format!("{:>8}", format_speed(down)),
                Style::default().fg(Color::Rgb(80, 170, 230)),
            ),
            Span::styled(" ▲", Style::default().fg(Color::Rgb(120, 70, 180))),
            Span::styled(
                format!("{:>8} ", format_speed(up)),
                Style::default().fg(Color::Rgb(170, 120, 240)),
            ),
            Span::styled(
                "█".repeat(bar_len.min(bar_budget)),
                Style::default().fg(speed_color),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(bg));
    f.render_widget(paragraph, inner);
}
