use std::collections::HashSet;

/// Sum interface byte counters, keeping only real internet uplinks.
///
/// psnet's traffic totals come from summing per-interface counters. A real
/// Windows machine's interface table is full of adapters whose counters either
/// mirror or are internal to the physical uplink: NDIS filter driver shadow
/// rows, Hyper-V / WSL `vEthernet` switches, NAT adapters, VPN tunnels. Summing
/// them inflates every total many times over (issue #6).
///
/// When `uplinks` is provided it is the OS's list of adapters that are up and
/// own a default gateway (see `uplink::uplink_interface_names`) — the only
/// locale-independent, structural signal that separates a genuine uplink from a
/// virtual overlay, since virtual switches, NAT and loopback adapters have no
/// gateway. We count only those.
///
/// When the OS query is unavailable (`None`, e.g. it failed or a non-Windows
/// build) we fall back to the narrower heuristic of skipping only NDIS filter
/// driver shadow rows by their naming convention, rather than losing all
/// totals.
///
/// Returns (total_recv, total_sent, most_active_counted_interface_name).
pub fn aggregate_interface_bytes(
    ifaces: &[(String, u64, u64)],
    uplinks: Option<&HashSet<String>>,
) -> (u64, u64, String) {
    let mut total_recv: u64 = 0;
    let mut total_sent: u64 = 0;
    let mut iface_name = String::from("No Interface");
    let mut best_traffic: u64 = 0;

    for (name, r, s) in ifaces {
        let counted = match uplinks {
            Some(set) => set.contains(name),
            None => !is_filter_shadow(name, ifaces),
        };
        if !counted {
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

/// True if `name` is an NDIS filter driver shadow row over another adapter in
/// the table, i.e. it carries the "<base adapter>-<filter name>-NNNN" naming
/// convention and a matching base adapter exists. Comparing counters instead is
/// racy: the two rows are sampled at slightly different instants, and a single
/// missed skip injects the adapter's whole lifetime counter into one tick's
/// delta.
fn is_filter_shadow(name: &str, ifaces: &[(String, u64, u64)]) -> bool {
    has_filter_instance_suffix(name)
        && ifaces.iter().any(|(base, _, _)| {
            base != name && name.starts_with(base.as_str()) && name[base.len()..].starts_with('-')
        })
}

/// True if the name ends in "-NNNN" (four or more digits), the instance
/// suffix NDIS appends to filter driver rows.
fn has_filter_instance_suffix(name: &str) -> bool {
    match name.rsplit_once('-') {
        Some((_, tail)) => tail.len() >= 4 && tail.chars().all(|c| c.is_ascii_digit()),
        None => false,
    }
}
