// stats.rs
//
// FR5 – Statistics aggregation
//   • Bytes sent / received per process
//   • Total NIC bandwidth over time (for the live plot)
//   • Active connection / process count
//
// Architecture:
//   The capture thread creates `PacketEvent` values and sends them over an
//   mpsc channel.  The GUI thread drains that channel every repaint and calls
//   `Aggregator::ingest` for each event.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::capture::{Packet, Protocol};
use crate::process::ProcessInfo;

// ─── packet event ─────────────────────────────────────────────────────────────

/// Enriched packet produced by the capture thread.
pub struct PacketEvent {
    pub packet:      Packet,
    pub process:     Option<ProcessInfo>,
    /// `true`  → src IP is the local side (outbound traffic)
    /// `false` → dst IP is the local side (inbound traffic)
    pub is_outbound: bool,
}

// ─── per-process statistics ───────────────────────────────────────────────────

/// Sliding-window size for the per-process bandwidth estimate.
const BW_WINDOW_SECS: f64 = 5.0;

#[derive(Clone, Debug)]
pub struct ProcessStats {
    pub pid:           u32,
    pub name:          String,
    pub username:      String,
    pub bytes_sent:    u64,
    pub bytes_recv:    u64,
    pub packet_count:  u64,
    /// Current bandwidth in bytes/second (sliding-window average).
    pub bandwidth_bps: f64,
    // Internal: (instant, byte_count) pairs in the sliding window.
    window: VecDeque<(Instant, u64)>,
}

impl ProcessStats {
    fn new(info: &ProcessInfo) -> Self {
        ProcessStats {
            pid:           info.pid,
            name:          info.name.clone(),
            username:      info.username.clone(),
            bytes_sent:    0,
            bytes_recv:    0,
            packet_count:  0,
            bandwidth_bps: 0.0,
            window:        VecDeque::new(),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_recv
    }

    fn add_bytes(&mut self, bytes: u64, now: Instant) {
        self.window.push_back((now, bytes));
        // Evict samples older than the window.
        while let Some(&(t, _)) = self.window.front() {
            if now.duration_since(t).as_secs_f64() > BW_WINDOW_SECS {
                self.window.pop_front();
            } else {
                break;
            }
        }
        let total: u64 = self.window.iter().map(|(_, b)| *b).sum();
        self.bandwidth_bps = total as f64 / BW_WINDOW_SECS;
    }
}

// ─── per-remote-host statistics ───────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct HostStats {
    pub addr:         String,
    pub bytes:        u64,
    pub packet_count: u64,
}

// ─── aggregator ───────────────────────────────────────────────────────────────

/// Central store for all live statistics.
///
/// Wrapped in `Arc<Mutex<>>` so the capture thread can produce events while
/// the GUI thread reads a consistent snapshot.
pub struct Aggregator {
    /// Per-process statistics keyed by PID.
    pub processes:         HashMap<u32, ProcessStats>,
    /// Per-remote-IP statistics keyed by IPv4 address (network byte order).
    pub hosts:             HashMap<u32, HostStats>,
    /// Circular buffer of `[elapsed_seconds, bytes_per_second]` samples –
    /// one entry per second, up to 120 seconds of history.
    pub bandwidth_history: VecDeque<[f64; 2]>,
    /// Most-recently measured NIC bandwidth (bytes/s).
    pub current_bps:       f64,
    pub total_bytes:       u64,
    pub total_packets:     u64,

    // ── internal ──────────────────────────────────────────────────────────────
    start:           Instant,
    last_tick:       Instant,
    bytes_this_tick: u64,
}

impl Default for Aggregator {
    fn default() -> Self {
        let now = Instant::now();
        Aggregator {
            processes:         HashMap::new(),
            hosts:             HashMap::new(),
            bandwidth_history: VecDeque::with_capacity(120),
            current_bps:       0.0,
            total_bytes:       0,
            total_packets:     0,
            start:             now,
            last_tick:         now,
            bytes_this_tick:   0,
        }
    }
}

impl Aggregator {
    /// Process one packet event, updating all statistics.
    pub fn ingest(&mut self, ev: PacketEvent) {
        let now   = Instant::now();
        let bytes = ev.packet.size_bytes as u64;

        self.total_bytes        += bytes;
        self.total_packets      += 1;
        self.bytes_this_tick    += bytes;

        // ── 1-second NIC bandwidth tick ───────────────────────────────────────
        let tick_s = now.duration_since(self.last_tick).as_secs_f64();
        if tick_s >= 0.2 {
            let bps = self.bytes_this_tick as f64 / tick_s;
            self.current_bps        = bps;
            self.bytes_this_tick    = 0;
            self.last_tick          = now;

            let elapsed = now.duration_since(self.start).as_secs_f64();
            self.bandwidth_history.push_back([elapsed, bps]);
            if self.bandwidth_history.len() > 120 {
                self.bandwidth_history.pop_front();
            }
        }

        // ── per-process accounting ────────────────────────────────────────────
        if let Some(ref info) = ev.process {
            let entry = self.processes
                .entry(info.pid)
                .or_insert_with(|| ProcessStats::new(info));

            if ev.is_outbound { entry.bytes_sent += bytes; }
            else              { entry.bytes_recv += bytes; }
            entry.packet_count += 1;
            entry.add_bytes(bytes, now);
        }

        // ── per-remote-host accounting ────────────────────────────────────────
        let remote_ip = if ev.is_outbound {
            ev.packet.dst_ip
        } else {
            ev.packet.src_ip
        };
        let host = self.hosts.entry(remote_ip).or_insert_with(|| HostStats {
            addr:         Ipv4Addr::from(remote_ip).to_string(),
            bytes:        0,
            packet_count: 0,
        });
        host.bytes        += bytes;
        host.packet_count += 1;
    }

    // ── FR7: sorted process views ─────────────────────────────────────────────

    /// Return up to `n` processes sorted by current bandwidth (highest first).
    pub fn top_processes_by_bandwidth(&self, n: usize) -> Vec<&ProcessStats> {
        let mut v: Vec<&ProcessStats> = self.processes.values().collect();
        v.sort_by(|a, b| {
            b.bandwidth_bps
                .partial_cmp(&a.bandwidth_bps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        v.truncate(n);
        v
    }

    /// Return up to `n` remote hosts sorted by total bytes (highest first).
    pub fn top_hosts_by_bytes(&self, n: usize) -> Vec<&HostStats> {
        let mut v: Vec<&HostStats> = self.hosts.values().collect();
        v.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        v.truncate(n);
        v
    }

    /// Number of distinct processes seen so far (approximation for FR5).
    pub fn active_process_count(&self) -> usize {
        self.processes.len()
    }
}
