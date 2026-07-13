// Reproduction for issue #7: Topology tab alignment overflowing / "overscan"
// over time. We include the REAL src/ui/topology.rs and render it into a
// TestBackend with shim crate::{app,types,utils} modules that provide exactly
// the App surface topology.rs touches. This exercises the real geometry code so
// the buffer dump is ground truth for what a user sees.

use std::net::{IpAddr, Ipv4Addr};

use ratatui::backend::TestBackend;
use ratatui::Terminal;

// ── Shim: crate::types ────────────────────────────────────────────────────────
mod types {
    #[derive(Clone)]
    pub enum ConnProto {
        Tcp,
        Udp,
    }
    #[derive(Clone, PartialEq)]
    pub enum TcpState {
        Established,
        #[allow(dead_code)]
        Other,
    }
    pub struct Connection {
        pub remote_addr: Option<std::net::IpAddr>,
        pub remote_port: Option<u16>,
        pub local_addr: std::net::IpAddr,
        pub proto: ConnProto,
        pub state: Option<TcpState>,
        pub process_name: String,
    }
}

// ── Shim: crate::utils ────────────────────────────────────────────────────────
mod utils {
    pub fn format_speed(v: f64) -> String {
        format!("{:.1} KB/s", v / 1024.0)
    }
}

// ── Shim: crate::app ──────────────────────────────────────────────────────────
mod app {
    use std::collections::HashMap;
    use std::net::IpAddr;

    pub struct GeoInfo {
        pub code: String,
        pub name: String,
        pub flag: String,
    }
    pub struct GeoIpResolver;
    impl GeoIpResolver {
        // Mirror real behaviour: private / link-local IPs have no GeoIP (no
        // flag), public IPs resolve to a country with a flag emoji.
        pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
            let is_private = match ip {
                IpAddr::V4(v) => {
                    let o = v.octets();
                    o[0] == 10
                        || o[0] == 192 && o[1] == 168
                        || o[0] == 172 && (16..=31).contains(&o[1])
                        || o[0] == 169 && o[1] == 254
                        || v.is_loopback()
                }
                _ => false,
            };
            if is_private {
                return None;
            }
            Some(GeoInfo {
                code: "US".to_string(),
                name: "United States".to_string(),
                flag: "\u{1F1FA}\u{1F1F8}".to_string(),
            })
        }
    }
    pub struct DnsCache {
        pub map: HashMap<IpAddr, Option<String>>,
    }
    impl DnsCache {
        pub fn get(&self, ip: &IpAddr) -> Option<&Option<String>> {
            self.map.get(ip)
        }
    }
    pub struct Device {
        pub custom_name: Option<String>,
        pub hostname: Option<String>,
        pub vendor: Option<String>,
        pub mac: String,
        pub is_online: bool,
        pub ip: IpAddr,
    }
    pub struct NetworkScanner {
        pub devices: Vec<Device>,
        pub gateway: Option<IpAddr>,
        pub local_ip: Option<IpAddr>,
    }
    pub struct FirewallManager {
        pub enabled: bool,
    }
    pub struct App {
        pub connections: Vec<crate::types::Connection>,
        pub dns_cache: DnsCache,
        pub geoip: GeoIpResolver,
        pub dns_servers: Vec<IpAddr>,
        pub network_scanner: NetworkScanner,
        pub firewall_manager: FirewallManager,
        pub interface_name: String,
        pub current_down_speed: f64,
        pub current_up_speed: f64,
        pub topology_scroll: usize,
    }
}

#[path = "../src/ui/topology.rs"]
mod topology;

use app::{App, Device, DnsCache, FirewallManager, GeoIpResolver, NetworkScanner};
use types::{ConnProto, Connection, TcpState};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Return the rendered buffer as rows of per-cell symbols (skip cells = "").
fn render_cells(width: u16, height: u16, app: &App) -> Vec<Vec<String>> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| topology::draw_topology(f, f.area(), app))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect()
        })
        .collect()
}

fn is_regional_indicator(c: char) -> bool {
    (0x1F1E6..=0x1F1FF).contains(&(c as u32))
}

/// Columns a rendered row occupies in an embedded vt100 terminal (like psmux)
/// that counts EACH Regional Indicator (U+1F1E6..=U+1F1FF) as width 2. ratatui
/// lays a flag pair into one symbol cell plus one continuation cell (2 columns
/// total), and its output stream emits nothing for the continuation cell. The
/// embedded parser instead advances 2 columns per indicator = 4 for the pair,
/// so each flag adds 2 columns beyond what ratatui budgeted.
fn embedded_row_cols(row: &[String], ratatui_width: usize) -> usize {
    let flags: usize = row
        .iter()
        .flat_map(|s| s.chars())
        .filter(|c| is_regional_indicator(*c))
        .count()
        / 2; // two indicators per flag
    ratatui_width + 2 * flags
}

/// Regression guard for issue #7. Topology node titles previously embedded a
/// country flag emoji (Regional Indicator pair). ratatui lays it out as 2
/// columns, but an embedded vt100 terminal (psmux) counts each indicator as
/// W=2, so every flagged node row rendered 2 columns too wide and spilled past
/// the panel border. As more public hosts appeared over a session, more rows
/// overflowed — the reported "overscan / alignment overflowing" that worsened
/// over time. The fix drops the flag and keeps the ASCII country code.
///
/// Before the fix, public-IP title rows measured `width + 2` here and this test
/// failed on the `fits` assertion. After the fix, every title row fits exactly.
#[test]
fn node_titles_have_no_flag_and_fit_embedded_terminal() {
    // Mix like the screenshot: private IPs (no geo) first, public IPs (geo).
    let specs: &[(IpAddr, usize, &str)] = &[
        (v4(192, 168, 0, 10), 24, "[Kernel]"),
        (v4(169, 254, 1, 1), 12, "[Kernel]"),
        (v4(172, 22, 5, 5), 12, "[Kernel]"),
        (v4(8, 136, 1, 1), 8, "[Kernel]"),
        (v4(136, 92, 1, 1), 6, "firefox.exe"),
        (v4(216, 239, 1, 1), 4, "GoogleDriveFS.exe"),
    ];
    let app = build_app(specs, 4);
    let width: usize = 150;
    let cells = render_cells(width as u16, 48, &app);

    let mut title_rows = 0;
    let mut public_rows = 0; // rows that still carry a country code
    for (y, row) in cells.iter().enumerate() {
        // A remote-node title row has a box top-left corner in the right pane
        // (cell column > 40), distinct from the left-column boxes at column ~1.
        let is_title = row
            .iter()
            .enumerate()
            .any(|(x, s)| x > 40 && s == "\u{250C}");
        if !is_title {
            continue;
        }
        title_rows += 1;
        let joined: String = row.concat();

        // (1) No Regional Indicators anywhere in a node title row.
        assert!(
            !joined.chars().any(is_regional_indicator),
            "row {y} still contains a flag emoji (Regional Indicator): {:?}",
            joined.trim_end()
        );

        // (2) The row fits the panel exactly in the embedded-terminal model.
        let embedded = embedded_row_cols(row, width);
        assert_eq!(
            embedded, width,
            "row {y} overflows embedded terminal by {} cols: {:?}",
            embedded as isize - width as isize,
            joined.trim_end()
        );

        // Country code is still displayed for public hosts.
        if joined.contains(" US ") || joined.contains(" US\u{2500}") || joined.contains("US ") {
            public_rows += 1;
        }
    }

    assert!(title_rows >= 4, "expected several node rows, got {title_rows}");
    assert!(
        public_rows >= 1,
        "expected public-IP nodes to still show the ASCII country code"
    );
    println!("{title_rows} node title rows, all flag-free and fitting; {public_rows} show country code");
}

/// Measure how ratatui budgets cells for the country flag emoji used in node
/// titles. On a real terminal a flag draws as 2 columns; if ratatui reserves a
/// different number of columns, everything after the flag is misaligned.
#[test]
fn flag_emoji_cell_budget() {
    use ratatui::text::{Line, Span};
    use ratatui::widgets::Paragraph;

    let title = " 8.8.0.90 \u{1F1FA}\u{1F1F8} US ---";
    let line_w = ratatui::text::Line::from(title).width();
    println!("ratatui Line::width of {:?} = {}", title, line_w);

    let backend = TestBackend::new(30, 1);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| {
            f.render_widget(
                Paragraph::new(vec![Line::from(Span::raw(title))]),
                f.area(),
            );
        })
        .unwrap();
    let buf = terminal.backend().buffer().clone();
    print!("cells: ");
    for x in 0..buf.area.width {
        let s = buf[(x, 0)].symbol();
        print!("[{}]", if s.is_empty() { "SKIP" } else { s });
    }
    println!();
    // Compare against what a real terminal does: flag = 2 columns. If ratatui
    // width != 2 for the flag, the title line is mis-budgeted.
    let flag = "\u{1F1FA}\u{1F1F8}";
    println!(
        "ratatui width(flag) = {}  (real terminals render it as 2 columns)",
        Line::from(flag).width()
    );
}

/// Build an App with `remote_specs` = list of (remote_ip, conn_count, process).
/// Each spec produces `conn_count` TCP connections to that IP so the topology
/// aggregator sees the intended per-node connection count.
fn build_app(remote_specs: &[(IpAddr, usize, &str)], lan_devices: usize) -> App {
    let local = v4(192, 168, 1, 50);
    let mut connections = Vec::new();
    for (ip, count, proc) in remote_specs {
        for _ in 0..*count {
            connections.push(Connection {
                remote_addr: Some(*ip),
                remote_port: Some(443),
                local_addr: local,
                proto: ConnProto::Tcp,
                state: Some(TcpState::Established),
                process_name: proc.to_string(),
            });
        }
    }

    let devices = (0..lan_devices)
        .map(|i| Device {
            custom_name: None,
            hostname: Some(format!("device-{i}")),
            vendor: None,
            mac: format!("00:11:22:33:44:{:02x}", i),
            is_online: true,
            ip: v4(192, 168, 1, 100 + i as u8),
        })
        .collect();

    App {
        connections,
        dns_cache: DnsCache {
            map: std::collections::HashMap::new(),
        },
        geoip: GeoIpResolver,
        dns_servers: vec![v4(192, 168, 1, 1)],
        network_scanner: NetworkScanner {
            devices,
            gateway: Some(v4(192, 168, 1, 1)),
            local_ip: Some(local),
        },
        firewall_manager: FirewallManager { enabled: true },
        interface_name: "WiFi".to_string(),
        current_down_speed: 4798.0 * 1024.0,
        current_up_speed: 33.7 * 1024.0,
        topology_scroll: 0,
    }
}

fn dump(width: u16, height: u16, app: &App) -> Vec<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| topology::draw_topology(f, f.area(), app))
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

/// Render a screenshot-like scenario: ~10 remote nodes sorted by conn_count,
/// tall panel. Print the buffer so we can SEE any overflow/overlap.
#[test]
fn dump_topology_screenshot_scenario() {
    let specs = [
        (v4(192, 168, 0, 10), 24, "[Kernel]"),
        (v4(169, 254, 1, 1), 12, "[Kernel]"),
        (v4(169, 254, 1, 2), 12, "[Kernel]"),
        (v4(172, 22, 5, 5), 12, "[Kernel]"),
        (v4(142, 250, 1, 1), 4, "GoogleDriveFS.exe"),
        (v4(216, 239, 1, 1), 4, "GoogleDriveFS.exe"),
        (v4(8, 136, 1, 1), 4, "[Kernel]"),
        (v4(136, 92, 1, 1), 3, "[Kernel]"),
        (v4(34, 120, 1, 1), 3, "firefox.exe"),
        (v4(35, 190, 1, 1), 2, "firefox.exe"),
    ];
    let app = build_app(&specs, 10);
    let rows = dump(150, 48, &app);
    println!("\n===== TOPOLOGY 150x48 ({} nodes) =====", specs.len());
    for (i, r) in rows.iter().enumerate() {
        println!("{:2}|{}", i, r.trim_end());
    }
    assert!(!rows.is_empty());
}
