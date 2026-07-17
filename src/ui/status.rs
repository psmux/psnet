use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::types::BottomTab;

/// Tab menu — rendered above the tab content area.
pub fn draw_tab_menu(f: &mut Frame, area: Rect, app: &App) {
    let tabs = [
        BottomTab::Dashboard,
        BottomTab::Connections,
        BottomTab::Servers,
        BottomTab::Packets,
        BottomTab::Topology,
        BottomTab::Alerts,
        BottomTab::Firewall,
        BottomTab::Devices,
        BottomTab::Networks,
    ];
    let mut tab_spans: Vec<Span<'static>> = Vec::new();
    for (i, tab) in tabs.iter().enumerate() {
        if i > 0 {
            tab_spans.push(Span::styled(" │ ", Style::default().fg(Color::Rgb(40, 55, 80))));
        }
        let label = format!(" {} {} ", i + 1, tab.label());
        if *tab == app.bottom_tab {
            tab_spans.push(Span::styled(
                label,
                Style::default()
                    .fg(Color::Rgb(255, 220, 120))
                    .bg(Color::Rgb(30, 42, 70))
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            tab_spans.push(Span::styled(
                label,
                Style::default().fg(Color::Rgb(80, 100, 135)),
            ));
        }
    }
    let tab_line = Paragraph::new(Line::from(tab_spans))
        .style(Style::default().bg(Color::Rgb(18, 25, 45)));
    f.render_widget(tab_line, area);
}

/// Key hints — rendered at the very bottom of the screen.
pub fn draw_key_hints(f: &mut Frame, area: Rect, app: &App) {
    // If popup is open, show dismiss hint only
    if app.detail_popup.is_some() {
        let spans = vec![
            Span::styled(
                " Enter / Esc ",
                Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(Modifier::BOLD),
            ),
            Span::styled("Close detail  ", Style::default().fg(Color::Rgb(95, 108, 135))),
        ];
        let paragraph = Paragraph::new(Line::from(spans))
            .style(Style::default().bg(Color::Rgb(20, 28, 50)));
        f.render_widget(paragraph, area);
        return;
    }

    // While the filter query is being edited, every printable key is typed into
    // the query, so the normal key hints do not apply.
    if app.filter_editing {
        let mut spans = Vec::new();
        for s in [
            key_span("Type", "to filter"),
            key_span("Enter", "Done"),
            key_span("Esc", "Clear"),
            key_span("Backspace", "Delete"),
            key_span("Tab", "Switch"),
        ] {
            spans.extend(s);
        }
        let paragraph = Paragraph::new(Line::from(spans))
            .style(Style::default().bg(Color::Rgb(20, 28, 50)));
        f.render_widget(paragraph, area);
        return;
    }

    let incognito_label = format!("Incognito:{}", if app.incognito { "ON" } else { "OFF" });
    let common_keys = vec![
        key_span("q", "Quit"),
        key_span("Tab", "Switch"),
        key_span("\u{2191}\u{2193}", "Select"),
        key_span("Enter", "Detail"),
        key_span("i", &incognito_label),
    ];

    let tab_keys = match app.bottom_tab {
        BottomTab::Dashboard => vec![
            key_span("1-4", "Time Range"),
        ],
        BottomTab::Connections => vec![
            key_span("1-5", "Sort"),
            key_span("b", "Block"),
            key_span("l", &format!("Listen:{}", if app.show_listen { "ON" } else { "OFF" })),
            key_span("x", &format!("{}", if app.hide_localhost_conn { "Show Local" } else { "Hide Local" })),
            key_span("f", "Filter"),
            key_span("Esc", "Clear"),
        ],
        BottomTab::Servers => vec![
            key_span("s", "Scan"),
            key_span("o", "Open"),
            key_span("y", "Copy"),
            key_span("p", "Folder"),
            key_span("\u{2190}", "Collapse"),
            key_span("\u{2192}", "Expand"),
            key_span("1-3", "Sort"),
        ],
        BottomTab::Alerts => vec![
            key_span("\u{2190}\u{2192}", "Pane"),
            key_span("\u{2191}\u{2193}", "Scroll"),
            key_span("Enter", "Detail"),
            key_span("r", "Mark Read"),
            key_span("c", "Clear All"),
            key_span("z", &format!("{}", if app.alert_engine.is_snoozed() { "Unsnooze" } else { "Snooze 5m" })),
        ],
        BottomTab::Firewall => vec![
            key_span("Enter", "Detail"),
            key_span("d", &format!("Policy:{}", if app.firewall_manager.default_deny { "Deny-All" } else { "Allow-All" })),
            key_span("1-4", "Sort"),
            key_span("r", "Refresh"),
            key_span("e", "Export"),
            key_span("f", "Filter"),
            key_span("x", "Reset All"),
            key_span("Esc", "Clear"),
        ],
        BottomTab::Devices => vec![
            key_span("s", "Scan Now"),
            key_span("r", "Rename"),
            key_span("o", &format!("Offline:{}", if app.hide_offline_devices { "Hidden" } else { "Shown" })),
        ],
        BottomTab::Networks => vec![
            key_span("s", "Scan Now"),
            key_span("b", &format!("{}", if app.bluetooth_expanded { "Collapse BT" } else { "Expand BT" })),
        ],
        BottomTab::Packets => vec![
            key_span("Space", &format!("{}", if app.packets_paused { "Resume" } else { "Pause" })),
            key_span("d", "Detail"),
            key_span("c", "Clear"),
            key_span("f", "Filter"),
            key_span("Esc", "Clear"),
        ],
        BottomTab::Topology => vec![
            key_span("\u{2191}\u{2193}", "Navigate"),
        ],
    };

    let mut spans = Vec::new();
    for s in common_keys {
        spans.extend(s);
    }
    spans.push(Span::styled(" │ ", Style::default().fg(Color::Rgb(40, 55, 80))));
    for s in tab_keys {
        spans.extend(s);
    }

    let paragraph = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(Color::Rgb(20, 28, 50)));
    f.render_widget(paragraph, area);
}

fn key_span(key: &str, desc: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {} ", key),
            Style::default()
                .fg(Color::Rgb(255, 200, 80))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} ", desc),
            Style::default().fg(Color::Rgb(95, 108, 135)),
        ),
    ]
}
