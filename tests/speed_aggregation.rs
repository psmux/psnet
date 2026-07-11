// Regression tests for issue #6: network totals double counted because
// NDIS filter driver shadow interfaces mirror the physical adapter counters.
#[path = "../src/network/speed.rs"]
mod speed;

use speed::aggregate_interface_bytes;

/// Real interface table captured on Windows 11: the "Native WiFi Filter
/// Driver" row duplicates the Wi-Fi adapter byte for byte, which previously
/// made every total exactly 2x.
#[test]
fn filter_driver_shadow_row_is_not_double_counted() {
    let ifaces = vec![
        ("vEthernet (nat)".to_string(), 175_425_087u64, 4_947_922_843u64),
        ("vEthernet (Default Switch)".to_string(), 0, 143_600),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 12_165_914_220, 14_636_879_690),
        ("vEthernet (WSL (Hyper-V firewall))".to_string(), 17_842, 155_549),
        ("Wi-Fi".to_string(), 12_165_914_220, 14_636_879_690),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 175_425_087 + 17_842 + 12_165_914_220, "Wi-Fi bytes counted twice");
    assert_eq!(sent, 4_947_922_843 + 143_600 + 155_549 + 14_636_879_690, "Wi-Fi bytes counted twice");
    assert_eq!(iface, "Wi-Fi");
}

/// Distinct adapters with different counters must all be counted.
#[test]
fn independent_adapters_all_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Wi-Fi".to_string(), 500, 300),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 1_500);
    assert_eq!(sent, 2_300);
    assert_eq!(iface, "Ethernet");
}

/// A short numeric suffix is not the NDIS "-NNNN" filter instance pattern,
/// so an adapter named like this must still be counted.
#[test]
fn short_numeric_suffix_still_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Ethernet-2".to_string(), 700, 800),
    ];
    let (recv, sent, _) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 1_700);
    assert_eq!(sent, 2_800);
}

/// Shadow rows are sampled at a slightly different instant than the base
/// adapter, so their counters can drift a few bytes apart within one refresh.
/// They must STILL be skipped: a single missed skip injects the adapter's
/// whole lifetime counter into one tick's delta (seen live as an 11 GB spike).
#[test]
fn shadow_row_with_drifted_counters_still_skipped() {
    let ifaces = vec![
        ("Wi-Fi".to_string(), 12_165_914_220u64, 14_636_879_690u64),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 12_165_915_733, 14_636_880_101),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 12_165_914_220);
    assert_eq!(sent, 14_636_879_690);
    assert_eq!(iface, "Wi-Fi");
}

/// A filter suffix row only counts as a shadow when a matching base adapter
/// actually exists in the table.
#[test]
fn suffix_without_matching_base_still_counted() {
    let ifaces = vec![
        ("Ethernet".to_string(), 1_000u64, 2_000u64),
        ("Tunnel-0001".to_string(), 700, 800),
    ];
    let (recv, sent, _) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 1_700);
    assert_eq!(sent, 2_800);
}

/// Two shadow filter rows over the same adapter are both skipped.
#[test]
fn multiple_shadow_rows_all_skipped() {
    let ifaces = vec![
        ("Wi-Fi".to_string(), 42u64, 24u64),
        ("Wi-Fi-Native WiFi Filter Driver-0000".to_string(), 42, 24),
        ("Wi-Fi-QoS Packet Scheduler-0000".to_string(), 42, 24),
    ];
    let (recv, sent, iface) = aggregate_interface_bytes(&ifaces);
    assert_eq!(recv, 42);
    assert_eq!(sent, 24);
    assert_eq!(iface, "Wi-Fi");
}
