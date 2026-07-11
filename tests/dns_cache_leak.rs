// Regression test for issue #5: read_dns_cache_api leaked the entire
// DnsGetCacheDataTable linked list (entries + name strings) on every call.
// Called every 2 seconds, this compounded to gigabytes over long sessions.
#[path = "../src/network/dns.rs"]
mod dns;

/// Hammer the cache reader and assert the process heap stays flat. With the
/// leak present, 300 calls retained tens of MB (each call leaks the whole
/// cache table); fixed, growth stays within normal allocator noise.
#[test]
fn repeated_cache_reads_do_not_grow_memory() {
    // Warm up: first call pays one-time allocator/dnsapi setup costs.
    for _ in 0..10 {
        let _ = dns::read_dns_cache_api();
    }

    let before = private_bytes();
    for _ in 0..300 {
        let _ = dns::read_dns_cache_api();
    }
    let after = private_bytes();

    let growth_mb = (after.saturating_sub(before)) as f64 / 1_048_576.0;
    assert!(
        growth_mb < 8.0,
        "read_dns_cache_api retained {:.1} MB over 300 calls - the DNS cache table is leaking again",
        growth_mb
    );
}

/// Current process private (committed) bytes via GetProcessMemoryInfo.
fn private_bytes() -> u64 {
    #[repr(C)]
    struct ProcessMemoryCountersEx {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
        private_usage: usize,
    }

    #[link(name = "psapi")]
    extern "system" {
        fn GetProcessMemoryInfo(
            process: *mut std::ffi::c_void,
            counters: *mut ProcessMemoryCountersEx,
            cb: u32,
        ) -> i32;
    }
    extern "system" {
        fn GetCurrentProcess() -> *mut std::ffi::c_void;
    }

    unsafe {
        let mut c: ProcessMemoryCountersEx = std::mem::zeroed();
        c.cb = std::mem::size_of::<ProcessMemoryCountersEx>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0 {
            c.private_usage as u64
        } else {
            0
        }
    }
}
