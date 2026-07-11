use sysinfo::Networks;

/// Aggregate received/sent bytes across all network interfaces.
/// Returns (total_recv, total_sent, most_active_interface_name).
pub fn get_network_bytes(networks: &Networks) -> (u64, u64, String) {
    let ifaces: Vec<(String, u64, u64)> = networks
        .iter()
        .map(|(name, data)| (name.clone(), data.total_received(), data.total_transmitted()))
        .collect();
    aggregate_interface_bytes(&ifaces)
}

/// Sum interface counters, skipping NDIS filter driver shadow rows.
///
/// On Windows, lightweight filter drivers (e.g. "Wi-Fi-Native WiFi Filter
/// Driver-0000", "Ethernet-QoS Packet Scheduler-0000") appear as separate
/// interfaces whose counters mirror the underlying physical adapter. Summing
/// them double counts every byte. A row is a shadow if its name extends
/// another interface's name ("<base>-...") and its counters match that base.
pub fn aggregate_interface_bytes(ifaces: &[(String, u64, u64)]) -> (u64, u64, String) {
    let mut total_recv: u64 = 0;
    let mut total_sent: u64 = 0;
    let mut iface_name = String::from("No Interface");
    let mut best_traffic: u64 = 0;

    for (name, r, s) in ifaces {
        let is_shadow = ifaces.iter().any(|(base, br, bs)| {
            base != name
                && name.starts_with(base.as_str())
                && name[base.len()..].starts_with('-')
                && br == r
                && bs == s
        });
        if is_shadow {
            continue;
        }
        total_recv += r;
        total_sent += s;
        if r + s > best_traffic {
            best_traffic = r + s;
            iface_name = name.clone();
        }
    }
    (total_recv, total_sent, iface_name)
}
