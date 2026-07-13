// Regression tests for issue #6: network totals inflated because the interface
// table contains adapters that mirror or are internal to the physical uplink
// (NDIS filter driver shadow rows, Hyper-V / WSL vEthernet switches, NAT and
// VPN adapters). The real fix counts only adapters the OS reports as up with a
// default gateway; the name-based shadow skip remains a fallback for when that
// OS query is unavailable.
#[path = "../src/network/speed.rs"]
mod speed;

use speed::aggregate_interface_bytes;
use std::collections::HashSet;

fn uplinks(names: &[&str]) -> HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Primary path: OS-provided uplink set (up adapters that own a default gateway)
// ---------------------------------------------------------------------------

/// Real interface table captured on Windows 11. Only "Wi-Fi" owns a default
/// gateway; the vEthernet (Hyper-V / WSL / NAT) switches and the filter driver
/// shadow do not. Previously all of these were summed, inflating the total
/// many times over. Now only the real uplink is counted.
#[test]
fn only_gateway_uplink_is_counted() {
    let ifaces = vec![
        ("vEthernet (nat)".to_string(), 178_641_887u64, 4_948_670_886u64),
        ("vEthernet (Default Switch)".to_string(), 0, 471_341),
        ("vEthernet (WSL (Hyper-V firewall))".to_string(), 19_912, 483_290),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 53_691_547, 459_906_686),
        ("Wi-Fi".to_string(), 53_691_547, 459_906_686),
    ];
    let up = uplinks(&["Wi-Fi"]);
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, Some(&up));
    assert_eq!(recv, 53_691_547, "only the Wi-Fi uplink recv should count");
    assert_eq!(sent, 459_906_686, "only the Wi-Fi uplink sent should count");
    assert_eq!(iface, "Wi-Fi");
}

/// A machine with two genuine NICs, both with gateways, counts both.
#[test]
fn multiple_gateway_uplinks_all_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Wi-Fi".to_string(), 500, 300),
        ("vEthernet (WSL)".to_string(), 9_000_000, 9_000_000),
    ];
    let up = uplinks(&["Ethernet", "Wi-Fi"]);
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, Some(&up));
    assert_eq!(recv, 1_500);
    assert_eq!(sent, 2_300);
    assert_eq!(iface, "Ethernet");
}

/// An empty uplink set never occurs at runtime (`uplink_interface_names`
/// returns `None` instead), but guard the behavior: nothing counted.
#[test]
fn empty_uplink_set_counts_nothing() {
    let ifaces = vec![("Wi-Fi".to_string(), 500u64, 300u64)];
    let up: HashSet<String> = HashSet::new();
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, Some(&up));
    assert_eq!(recv, 0);
    assert_eq!(sent, 0);
    assert_eq!(iface, "No Interface");
}

// ---------------------------------------------------------------------------
// Fallback path: OS query unavailable (`None`) -> skip only filter shadow rows
// ---------------------------------------------------------------------------

/// The "Native WiFi Filter Driver" row duplicates the Wi-Fi adapter byte for
/// byte. Under the fallback it must not be double counted (other real/virtual
/// adapters are still summed, since without gateway data we cannot tell them
/// apart).
#[test]
fn fallback_filter_driver_shadow_row_is_not_double_counted() {
    let ifaces = vec![
        ("vEthernet (nat)".to_string(), 175_425_087u64, 4_947_922_843u64),
        ("vEthernet (Default Switch)".to_string(), 0, 143_600),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 12_165_914_220, 14_636_879_690),
        ("vEthernet (WSL (Hyper-V firewall))".to_string(), 17_842, 155_549),
        ("Wi-Fi".to_string(), 12_165_914_220, 14_636_879_690),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 175_425_087 + 17_842 + 12_165_914_220, "Wi-Fi bytes counted twice");
    assert_eq!(sent, 4_947_922_843 + 143_600 + 155_549 + 14_636_879_690, "Wi-Fi bytes counted twice");
    assert_eq!(iface, "Wi-Fi");
}

/// Distinct adapters with different counters must all be counted.
#[test]
fn fallback_independent_adapters_all_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Wi-Fi".to_string(), 500, 300),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 1_500);
    assert_eq!(sent, 2_300);
    assert_eq!(iface, "Ethernet");
}

/// A short numeric suffix is not the NDIS "-NNNN" filter instance pattern,
/// so an adapter named like this must still be counted.
#[test]
fn fallback_short_numeric_suffix_still_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Ethernet-2".to_string(), 700, 800),
    ];
    let (recv, sent, _) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 1_700);
    assert_eq!(sent, 2_800);
}

/// Shadow rows are sampled at a slightly different instant than the base
/// adapter, so their counters can drift a few bytes apart within one refresh.
/// They must STILL be skipped: a single missed skip injects the adapter's
/// whole lifetime counter into one tick's delta (seen live as an 11 GB spike).
#[test]
fn fallback_shadow_row_with_drifted_counters_still_skipped() {
    let ifaces = vec![
        ("Wi-Fi".to_string(), 12_165_914_220u64, 14_636_879_690u64),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 12_165_915_733, 14_636_880_101),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 12_165_914_220);
    assert_eq!(sent, 14_636_879_690);
    assert_eq!(iface, "Wi-Fi");
}

/// A filter suffix row only counts as a shadow when a matching base adapter
/// actually exists in the table.
#[test]
fn fallback_suffix_without_matching_base_still_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Tunnel-0001".to_string(), 700, 800),
    ];
    let (recv, sent, _) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 1_700);
    assert_eq!(sent, 2_800);
}

/// Two shadow filter rows over the same adapter are both skipped.
#[test]
fn fallback_multiple_shadow_rows_all_skipped() {
    let ifaces = vec![
        ("Wi-Fi".to_string(), 42u64, 24u64),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 42, 24),
        ("Wi-Fi-QoS Packet Scheduler-0000".to_string(), 42, 24),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces, None);
    assert_eq!(recv, 42);
    assert_eq!(sent, 24);
    assert_eq!(iface, "Wi-Fi");
}
