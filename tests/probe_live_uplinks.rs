// Live diagnostic (ignored by default): prints the OS uplink set and the
// sysinfo interface names side by side so adapter naming mismatches are
// visible when debugging traffic totals (issue #6).
// Run: cargo test --test probe_live_uplinks -- --ignored --nocapture

mod network {
    #[path = "../../src/network/speed.rs"]
    pub mod speed;
    #[path = "../../src/network/uplink.rs"]
    pub mod uplink;
}

use sysinfo::Networks;

#[test]
#[ignore]
fn probe_live_uplinks() {
    let uplinks = network::uplink::uplink_interface_names();
    println!("UPLINK SET: {:?}", uplinks);

    let networks = Networks::new_with_refreshed_list();
    for (name, data) in networks.iter() {
        let counted = uplinks
            .as_ref()
            .map(|set| set.contains(name))
            .unwrap_or(true);
        println!(
            "IFACE: {:?} recv={} sent={} counted={}",
            name,
            data.total_received(),
            data.total_transmitted(),
            counted
        );
    }
}
