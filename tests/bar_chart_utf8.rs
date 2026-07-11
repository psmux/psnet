// Regression tests for issue #4: UTF-8 handling in the bar chart widget.
// Includes the real source file so the actual production code is exercised.
#[path = "../src/ui/widgets/bar_chart.rs"]
mod bar_chart;

use bar_chart::{draw_bar_chart, BarEntry};
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;

fn render(entries: Vec<BarEntry>) -> Vec<String> {
    let backend = TestBackend::new(60, 10);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| draw_bar_chart(f, f.area(), "Top Apps", &entries))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect()
}

/// A Cyrillic label whose byte length (26) exceeds label_width (14) forces the
/// truncation branch; slicing at byte 13 lands mid character and must not panic.
#[test]
fn multibyte_label_does_not_panic() {
    let entries = vec![BarEntry {
        label: "ЯндексБраузер".to_string(), // 13 chars, 26 bytes
        value: 1_500_000,
        color: Color::Cyan,
    }];
    let rows = render(entries);
    assert!(rows[1].contains("ЯндексБраузер"), "13 char name fits in 14 cols and must not be truncated, got row: {:?}", rows[1]);
}

/// Names longer than 14 characters must be truncated by characters, not bytes.
#[test]
fn multibyte_label_truncates_by_chars() {
    let entries = vec![BarEntry {
        label: "ОченьДлинноеИмяПриложения".to_string(), // 25 chars
        value: 900_000,
        color: Color::Cyan,
    }];
    let rows = render(entries);
    assert!(
        rows[1].contains("ОченьДлинноеИ…"),
        "expected 13 chars + ellipsis, got row: {:?}",
        rows[1]
    );
}

/// A short Cyrillic name and a short ASCII name must produce bars starting in
/// the same column, otherwise the chart columns are misaligned.
#[test]
fn multibyte_label_pads_to_same_column_as_ascii() {
    let entries = vec![
        BarEntry {
            label: "chrome".to_string(),
            value: 2_000_000,
            color: Color::Cyan,
        },
        BarEntry {
            label: "Яндекс".to_string(),
            value: 1_000_000,
            color: Color::Cyan,
        },
    ];
    let rows = render(entries);
    let bar_col_ascii = rows[1].chars().position(|c| c == '█' || c == '░');
    let bar_col_cyr = rows[2].chars().position(|c| c == '█' || c == '░');
    assert_eq!(
        bar_col_ascii, bar_col_cyr,
        "bars misaligned: ascii row {:?} vs cyrillic row {:?}",
        rows[1], rows[2]
    );
}
