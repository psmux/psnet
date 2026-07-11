use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub struct BarEntry {
    pub label: String,
    pub value: u64,
    pub color: Color,
}

/// Draw a horizontal bar chart showing top items.
pub fn draw_bar_chart(f: &mut Frame, area: Rect, title: &str, entries: &[BarEntry]) {
    let inner_width = area.width.saturating_sub(2) as usize;
    let inner_height = area.height.saturating_sub(2) as usize;

    let max_val = entries.iter().map(|e| e.value).max().unwrap_or(1).max(1);
    let label_width = 14; // truncate app names to this
    let value_width = 9;  // e.g. "123.4 MB "
    let bar_width = inner_width.saturating_sub(label_width + value_width + 3);

    let lines: Vec<Line> = entries.iter().take(inner_height).map(|entry| {
        let char_count = entry.label.chars().count();
        let name = if char_count > label_width {
            let truncated: String = entry.label.chars().take(label_width - 1).collect();
            format!("{}…", truncated)
        } else {
            format!("{:width$}", entry.label, width = label_width)
        };

        let filled = (entry.value as f64 / max_val as f64 * bar_width as f64) as usize;
        let bar = format!("{}{}", "█".repeat(filled), "░".repeat(bar_width.saturating_sub(filled)));
        let val_str = fmt_bytes_short(entry.value);

        Line::from(vec![
            Span::styled(name, Style::default().fg(Color::Rgb(130, 200, 140))),
            Span::styled(" ", Style::default()),
            Span::styled(bar, Style::default().fg(entry.color)),
            Span::styled(format!(" {}", val_str), Style::default().fg(Color::Rgb(100, 120, 150))),
        ])
    }).collect();

    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", title),
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn fmt_bytes_short(b: u64) -> String {
    if b >= 1_073_741_824 { format!("{:.1} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
    else if b >= 1024 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{} B", b) }
}
