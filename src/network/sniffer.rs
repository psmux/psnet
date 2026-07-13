//! Raw socket packet sniffer for Windows.
//!
//! Captures IP packets using a raw socket with SIO_RCVALL,
//! extracts printable ASCII snippets from TCP/UDP payloads,
//! and stores them in a thread-safe ring buffer for the UI.
//!
//! Requires Administrator privileges to function.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::Local;

use crate::types::{ConnProto, PacketDirection, PacketSnippet};

// ─── Winsock2 FFI ────────────────────────────────────────────────────────────

const AF_INET: i32 = 2;
const SOCK_RAW: i32 = 3;
const IPPROTO_IP: i32 = 0;
const SIO_RCVALL: u32 = 0x98000001;
const RCVALL_ON: u32 = 1;
const INVALID_SOCKET: usize = !0;
const SOCKET_ERROR: i32 = -1;

#[repr(C)]
#[allow(non_snake_case, non_camel_case_types)]
struct WSADATA {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [u8; 257],
    szSystemStatus: [u8; 129],
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: *mut u8,
}

#[repr(C)]
#[allow(non_snake_case)]
struct SOCKADDR_IN {
    sin_family: i16,
    sin_port: u16,
    sin_addr: u32, // in_addr as raw u32
    sin_zero: [u8; 8],
}

#[link(name = "ws2_32")]
extern "system" {
    fn WSAStartup(wVersionRequested: u16, lpWSAData: *mut WSADATA) -> i32;
    fn socket(af: i32, type_: i32, protocol: i32) -> usize;
    fn bind(s: usize, addr: *const SOCKADDR_IN, namelen: i32) -> i32;
    fn WSAIoctl(
        s: usize,
        dwIoControlCode: u32,
        lpvInBuffer: *const u32,
        cbInBuffer: u32,
        lpvOutBuffer: *mut u8,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut u8,
        lpCompletionRoutine: *mut u8,
    ) -> i32;
    fn recv(s: usize, buf: *mut u8, len: i32, flags: i32) -> i32;
    fn closesocket(s: usize) -> i32;
    fn WSACleanup() -> i32;
    fn gethostname(name: *mut u8, namelen: i32) -> i32;
    fn getaddrinfo(
        pNodeName: *const u8,
        pServiceName: *const u8,
        pHints: *const ADDRINFO,
        ppResult: *mut *mut ADDRINFO,
    ) -> i32;
    fn freeaddrinfo(pAddrInfo: *mut ADDRINFO);
}

#[repr(C)]
#[allow(non_snake_case)]
struct ADDRINFO {
    ai_flags: i32,
    ai_family: i32,
    ai_socktype: i32,
    ai_protocol: i32,
    ai_addrlen: usize,
    ai_canonname: *mut u8,
    ai_addr: *mut SOCKADDR_IN,
    ai_next: *mut ADDRINFO,
}

// ─── Sniffer state ───────────────────────────────────────────────────────────

/// Thread-safe packet snippet buffer.
pub struct PacketSniffer {
    pub snippets: Arc<Mutex<VecDeque<PacketSnippet>>>,
    pub max_snippets: usize,
    pub active: Arc<AtomicBool>,
    pub error_msg: Arc<Mutex<Option<String>>>,
    handle: Option<thread::JoinHandle<()>>,
    /// Total packets ever added (for drain_new tracking).
    total_added: Arc<AtomicUsize>,
    /// How many packets we've consumed for traffic events.
    consumed_count: usize,
}

impl PacketSniffer {
    pub fn new(max_snippets: usize) -> Self {
        Self {
            snippets: Arc::new(Mutex::new(VecDeque::with_capacity(max_snippets))),
            max_snippets,
            active: Arc::new(AtomicBool::new(false)),
            error_msg: Arc::new(Mutex::new(None)),
            handle: None,
            total_added: Arc::new(AtomicUsize::new(0)),
            consumed_count: 0,
        }
    }

    /// Start the sniffer on a background thread. No-op if already running.
    pub fn start(&mut self) {
        if self.active.load(Ordering::Relaxed) {
            return;
        }
        self.active.store(true, Ordering::Relaxed);

        let snippets = Arc::clone(&self.snippets);
        let active = Arc::clone(&self.active);
        let error_msg = Arc::clone(&self.error_msg);
        let max = self.max_snippets;
        let total_added = Arc::clone(&self.total_added);

        self.handle = Some(thread::spawn(move || {
            sniffer_thread(snippets, active, error_msg, max, total_added);
        }));
    }

    /// Stop the sniffer.
    pub fn stop(&mut self) {
        self.active.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// Get new packets added since the last call to drain_new.
    pub fn drain_new(&mut self) -> Vec<PacketSnippet> {
        let total = self.total_added.load(Ordering::Relaxed);
        if total <= self.consumed_count {
            return Vec::new();
        }
        let new_count = total - self.consumed_count;
        self.consumed_count = total;

        if let Ok(lock) = self.snippets.lock() {
            // Pre-allocate and clone only the new tail — minimizes lock hold time
            let len = lock.len();
            let skip = len.saturating_sub(new_count);
            let mut result = Vec::with_capacity(new_count);
            for pkt in lock.iter().skip(skip) {
                result.push(pkt.clone());
            }
            result
        } else {
            Vec::new()
        }
    }

    /// Get recent snippets for display.
    pub fn recent(&self, count: usize) -> Vec<PacketSnippet> {
        if let Ok(lock) = self.snippets.lock() {
            lock.iter().rev().take(count).cloned().collect::<Vec<_>>().into_iter().rev().collect()
        } else {
            Vec::new()
        }
    }

    /// Get the error message if sniffer failed to start.
    pub fn get_error(&self) -> Option<String> {
        self.error_msg.lock().ok().and_then(|e| e.clone())
    }
}

impl Drop for PacketSniffer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─── Background thread ──────────────────────────────────────────────────────

fn sniffer_thread(
    snippets: Arc<Mutex<VecDeque<PacketSnippet>>>,
    active: Arc<AtomicBool>,
    error_msg: Arc<Mutex<Option<String>>>,
    max_snippets: usize,
    total_added: Arc<AtomicUsize>,
) {
    unsafe {
        // Initialize Winsock
        let mut wsa_data: WSADATA = std::mem::zeroed();
        if WSAStartup(0x0202, &mut wsa_data) != 0 {
            set_error(&error_msg, "WSAStartup failed");
            active.store(false, Ordering::Relaxed);
            return;
        }

        // Get local IP. Prefer the gateway-owning uplink adapter: that is the
        // wire all internet traffic (including NAT-forwarded WSL/VM flows)
        // actually crosses. Hostname resolution can return a Hyper-V/WSL or
        // VPN adapter first, which would capture only that virtual switch.
        let local_ip = match crate::network::uplink::uplink_ipv4().or_else(|| get_local_ipv4()) {
            Some(ip) => ip,
            None => {
                set_error(&error_msg, "Could not determine local IP");
                WSACleanup();
                active.store(false, Ordering::Relaxed);
                return;
            }
        };

        // Create raw socket
        let sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if sock == INVALID_SOCKET {
            set_error(&error_msg, "Raw socket creation failed (run as Administrator)");
            WSACleanup();
            active.store(false, Ordering::Relaxed);
            return;
        }

        // Bind to local IP
        let addr = SOCKADDR_IN {
            sin_family: AF_INET as i16,
            sin_port: 0,
            sin_addr: local_ip,
            sin_zero: [0; 8],
        };
        if bind(sock, &addr as *const _, std::mem::size_of::<SOCKADDR_IN>() as i32) == SOCKET_ERROR
        {
            set_error(&error_msg, "Socket bind failed");
            closesocket(sock);
            WSACleanup();
            active.store(false, Ordering::Relaxed);
            return;
        }

        // Enable SIO_RCVALL (promiscuous mode)
        let opt_val: u32 = RCVALL_ON;
        let mut bytes_returned: u32 = 0;
        if WSAIoctl(
            sock,
            SIO_RCVALL,
            &opt_val as *const u32,
            4,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == SOCKET_ERROR
        {
            set_error(
                &error_msg,
                "SIO_RCVALL failed (requires Administrator privileges)",
            );
            closesocket(sock);
            WSACleanup();
            active.store(false, Ordering::Relaxed);
            return;
        }

        // Clear any previous error — we're live
        if let Ok(mut e) = error_msg.lock() {
            *e = None;
        }

        // ── Capture loop ──
        let mut buf = vec![0u8; 65535];

        while active.load(Ordering::Relaxed) {
            // Use a timeout approach: set socket recv timeout so we can check `active`
            // For simplicity, just recv (blocking) with large buffer.
            // The thread will be stopped when active=false and Drop closes the socket.
            let len = recv(sock, buf.as_mut_ptr(), buf.len() as i32, 0);
            if len <= 0 || !active.load(Ordering::Relaxed) {
                break;
            }
            let pkt = &buf[..len as usize];

            if let Some(snippet) = parse_packet(pkt, local_ip) {
                if let Ok(mut lock) = snippets.lock() {
                    lock.push_back(snippet);
                    total_added.fetch_add(1, Ordering::Relaxed);
                    while lock.len() > max_snippets {
                        lock.pop_front();
                    }
                }
            }
        }

        closesocket(sock);
        WSACleanup();
    }

    active.store(false, Ordering::Relaxed);
}

// ─── Packet parsing ──────────────────────────────────────────────────────────

fn parse_packet(pkt: &[u8], local_ip: u32) -> Option<PacketSnippet> {
    if pkt.len() < 20 {
        return None; // Too small for IP header
    }

    // IP header
    let version = (pkt[0] >> 4) & 0xF;
    if version != 4 {
        return None; // Only IPv4
    }
    let ihl = (pkt[0] & 0xF) as usize * 4;
    if pkt.len() < ihl {
        return None;
    }

    let protocol = pkt[9];
    let src_ip_bytes: [u8; 4] = [pkt[12], pkt[13], pkt[14], pkt[15]];
    let dst_ip_bytes: [u8; 4] = [pkt[16], pkt[17], pkt[18], pkt[19]];
    let src_ip = Ipv4Addr::from(src_ip_bytes);
    let dst_ip = Ipv4Addr::from(dst_ip_bytes);

    // Skip loopback
    if src_ip.is_loopback() && dst_ip.is_loopback() {
        return None;
    }

    // Extract additional IP header fields
    let ttl = pkt[8];
    let ip_total_len = u16::from_be_bytes([pkt[2], pkt[3]]);
    let ip_id = u16::from_be_bytes([pkt[4], pkt[5]]);

    let (src_port, dst_port, payload_offset, tcp_flags, tcp_seq, tcp_ack_num, tcp_window) = match protocol {
        6 => {
            // TCP
            if pkt.len() < ihl + 20 {
                return None;
            }
            let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            let tcp_hdr_len = ((pkt[ihl + 12] >> 4) & 0xF) as usize * 4;
            let flags = pkt[ihl + 13];
            let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
            let ack = u32::from_be_bytes([pkt[ihl + 8], pkt[ihl + 9], pkt[ihl + 10], pkt[ihl + 11]]);
            let win = u16::from_be_bytes([pkt[ihl + 14], pkt[ihl + 15]]);
            (sp, dp, ihl + tcp_hdr_len, flags, seq, ack, win)
        }
        17 => {
            // UDP
            if pkt.len() < ihl + 8 {
                return None;
            }
            let sp = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dp = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            (sp, dp, ihl + 8, 0u8, 0u32, 0u32, 0u16)
        }
        _ => return None, // Skip ICMP, IGMP, etc.
    };

    // Extract payload and snippet
    let has_payload = payload_offset < pkt.len() && pkt.len() > payload_offset;
    let payload = if has_payload { &pkt[payload_offset..] } else { &[] as &[u8] };
    let payload_size = payload.len();

    // Extract printable ASCII snippet (up to 200 chars)
    let snippet = if !payload.is_empty() {
        extract_best_snippet(payload, 200)
    } else {
        String::new()
    };

    // For TCP: show SYN, FIN, RST packets even without readable payload.
    // Skip pure ACK-only packets without payload (too noisy).
    if snippet.is_empty() {
        if protocol == 6 {
            let is_syn = tcp_flags & 0x02 != 0;
            let is_fin = tcp_flags & 0x01 != 0;
            let is_rst = tcp_flags & 0x04 != 0;
            if !is_syn && !is_fin && !is_rst {
                return None; // Pure ACK or PSH without readable payload — skip
            }
        } else {
            // UDP with no readable payload
            if payload.is_empty() {
                return None;
            }
        }
    }

    // Extract raw payload bytes (up to 256 bytes) for hex dump
    let raw_payload = if payload_offset < pkt.len() {
        pkt[payload_offset..pkt.len().min(payload_offset + 256)].to_vec()
    } else {
        Vec::new()
    };

    // Determine direction
    let src_raw = u32::from_ne_bytes(src_ip_bytes);
    let direction = if src_raw == local_ip {
        PacketDirection::Outbound
    } else {
        PacketDirection::Inbound
    };

    Some(PacketSnippet {
        timestamp: Local::now().time(),
        direction,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol: if protocol == 6 {
            ConnProto::Tcp
        } else {
            ConnProto::Udp
        },
        snippet,
        payload_size,
        ttl,
        ip_total_len,
        ip_id,
        tcp_flags,
        tcp_seq,
        tcp_ack_num,
        tcp_window,
        raw_payload,
    })
}

/// Find the most readable substring in the payload.
/// Scans for runs of printable ASCII, picks the longest/most readable one,
/// and only returns it if it looks like actual human-readable text.
fn extract_best_snippet(data: &[u8], max_len: usize) -> String {
    // First: find all runs of printable ASCII (including common whitespace)
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        let is_text = (byte >= 0x20 && byte <= 0x7E)
            || byte == b'\r'
            || byte == b'\n'
            || byte == b'\t';
        match (is_text, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(start)) => {
                if i - start >= 6 {
                    runs.push((start, i));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = run_start {
        if data.len() - start >= 6 {
            runs.push((start, data.len()));
        }
    }

    if runs.is_empty() {
        return String::new();
    }

    // Score each run: prefer longer runs with more word-like characters
    let best_run = runs.iter().max_by_key(|(start, end)| {
        let slice = &data[*start..*end];
        let len = slice.len();
        let text_chars = slice.iter().filter(|&&b| {
            b.is_ascii_alphanumeric() || b == b' ' || b == b'/' || b == b':'
                || b == b'.' || b == b',' || b == b'-' || b == b'='
                || b == b'\n' || b == b'\r'
        }).count();
        let ratio = (text_chars * 100) / len.max(1);
        len * ratio
    });

    let (start, end) = match best_run {
        Some(r) => *r,
        None => return String::new(),
    };

    let slice = &data[start..end];

    // Check readability: at least 40% should be alphanumeric/space/common punct
    let text_chars = slice.iter().filter(|&&b| {
        b.is_ascii_alphanumeric() || b == b' ' || b == b'/' || b == b':'
            || b == b'.' || b == b',' || b == b'-' || b == b'=' || b == b'_'
            || b == b'?' || b == b'&' || b == b'"' || b == b'\''
            || b == b'{' || b == b'}' || b == b'[' || b == b']'
            || b == b'\n' || b == b'\r'
    }).count();
    let ratio = (text_chars * 100) / slice.len().max(1);
    if ratio < 40 {
        return String::new();
    }

    // Format the snippet: convert to clean display string
    let mut result = String::with_capacity(max_len);
    let mut last_was_ws = false;

    for &byte in slice.iter() {
        if result.len() >= max_len {
            break;
        }
        if byte >= 0x20 && byte <= 0x7E {
            result.push(byte as char);
            last_was_ws = false;
        } else if byte == b'\r' || byte == b'\n' || byte == b'\t' {
            if !last_was_ws {
                result.push_str(" | ");
                last_was_ws = true;
            }
        }
    }

    // Trim trailing separators
    let trimmed = result.trim_end_matches(" | ").trim();
    trimmed.to_string()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn set_error(error_msg: &Arc<Mutex<Option<String>>>, msg: &str) {
    if let Ok(mut e) = error_msg.lock() {
        *e = Some(msg.to_string());
    }
}

/// Get the local IPv4 address (non-loopback) as a raw u32 in network byte order.
unsafe fn get_local_ipv4() -> Option<u32> {
    let mut hostname = [0u8; 256];
    if gethostname(hostname.as_mut_ptr(), 256) != 0 {
        return None;
    }

    let mut hints: ADDRINFO = std::mem::zeroed();
    hints.ai_family = AF_INET as i32;
    hints.ai_socktype = 1; // SOCK_STREAM

    let mut result: *mut ADDRINFO = std::ptr::null_mut();
    if getaddrinfo(
        hostname.as_ptr(),
        std::ptr::null(),
        &hints as *const _,
        &mut result,
    ) != 0
    {
        return None;
    }

    let mut ip: Option<u32> = None;
    let mut current = result;
    while !current.is_null() {
        let info = &*current;
        if info.ai_family == AF_INET as i32 && !info.ai_addr.is_null() {
            let addr = &*info.ai_addr;
            let raw_ip = addr.sin_addr;
            let bytes = raw_ip.to_ne_bytes();
            let v4 = Ipv4Addr::from(bytes);
            if !v4.is_loopback() && !v4.is_unspecified() {
                ip = Some(raw_ip);
                break;
            }
        }
        current = info.ai_next;
    }

    freeaddrinfo(result);
    ip
}
