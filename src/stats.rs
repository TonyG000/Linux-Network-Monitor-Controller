use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::Instant;

use crate::capture::{Packet, Protocol};
use crate::process::ProcessInfo;

//  packet event 
// packet produced by the capture thread.
pub struct PacketEvent {
    pub packet:      Packet,
    pub process:     Option<ProcessInfo>,

    pub is_outbound: bool,
    // true  = src IP is the local side (packet is going out)
    // false = dst IP is the local side (packet is coming in)
}

//  per-process statistics 
// Sliding-window size for the per-process bandwidth estimate.
const BW_WINDOW_SECS: f64 = 5.0;

#[derive(Clone, Debug)]
pub struct ProcessStats {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub username: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packet_count:  u64,

    // Current bandwidth in bytes/second (sliding-window average).
    pub bandwidth_bps: f64,

    // Internal: (instant, byte_count) pairs in the sliding window.
    window: VecDeque<(Instant, u64)>,
}

impl ProcessStats {
    fn new(info: &ProcessInfo) -> Self {
        ProcessStats {
            pid: info.pid,
            uid: info.uid,
            name: info.name.clone(),
            username: info.username.clone(),
            bytes_sent: 0,
            bytes_recv: 0,
            packet_count:  0,
            bandwidth_bps: 0.0,
            window: VecDeque::new(),
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

//  per-remote-host statistics 
#[derive(Clone, Debug)]
pub struct HostStats {
    pub addr:         String,
    pub bytes:        u64,
    pub packet_count: u64,
}

// CONNECTION DETAILS
// ConnectionKey uniquely identifies one logical connection.
// packets belong to the same connection if all five fields match.
// Derives Hash + Eq so it can be used as a HashMap key.

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey { //map key
    pub protocol: u8,   // 6 = TCP, 17 = UDP
    pub local_ip: u32,
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,
}

// Live statistics for a single connection
// ConnectionRecord holds everything the detail panel needs for one connection.
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub key: ConnectionKey,
    pub proc_name: String, // Resolved process name
    pub pid: u32,
    pub username: String,
    pub protocol: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets: u64,
    pub last_seen: Instant, // Timestamp of last seen packet 
}

impl ConnectionRecord {
    fn new(key: &ConnectionKey, process: Option<&ProcessInfo>) -> Self {
        // Build the protocol string from the raw IP protocol number
        let proto_str = match key.protocol {
            6  => "TCP".to_string(),
            17 => "UDP".to_string(),
            n  => format!("IP/{}", n),
        };
        ConnectionRecord {
            key: key.clone(),
            proc_name: process.map(|p| p.name.clone()).unwrap_or_else(|| "–".into()),
            pid: process.map(|p| p.pid).unwrap_or(0),
            username: process.map(|p| p.username.clone()).unwrap_or_else(|| "–".into()),
            protocol: proto_str,
            remote_addr: Ipv4Addr::from(key.remote_ip).to_string(),
            remote_port: key.remote_port,
            local_port: key.local_port,
            bytes_sent: 0,
            bytes_recv: 0,
            packets: 0,
            last_seen: Instant::now(),
        }
    }
}

// FR8: Traffic Direction

pub type BwSample = [f64; 3];
// [0] elapsed seconds since capture started
// [1] outbound bytes/second at this moment
// [2] inbound  bytes/second at this moment


// aggregator 
// Maximum number of distinct connections to keep in memory.
const MAX_CONNECTIONS: usize = 1000;

// Central store for all live statistics.
// Wrapped in `Arc<Mutex<>>` so the capture thread can produce events while
// the GUI thread reads a consistent snapshot.
pub struct Aggregator {
    pub processes: HashMap<u32, ProcessStats>,
    pub hosts: HashMap<u32, HostStats>,
    pub bandwidth_history: VecDeque<BwSample>,
    pub current_bps: f64,
    pub current_out_bps: f64,
    pub current_in_bps: f64,
    pub total_bytes: u64,
    pub total_packets: u64,

    pub connections: HashMap<ConnectionKey, ConnectionRecord>, // for per connectoin records
    connection_order: VecDeque<ConnectionKey>,

    start: Instant,
    last_tick: Instant,
    bytes_out_tick: u64,
    bytes_in_tick: u64,
}

impl Default for Aggregator {
    fn default() -> Self {
        let now = Instant::now();
        Aggregator {
            processes: HashMap::new(),
            hosts: HashMap::new(),
            bandwidth_history: VecDeque::with_capacity(120),
            current_bps: 0.0,
            current_out_bps: 0.0,
            current_in_bps: 0.0,
            total_bytes: 0,
            total_packets: 0,
            connections: HashMap::new(),
            connection_order: VecDeque::new(),
            start: now,
            last_tick: now,
            bytes_out_tick: 0,
            bytes_in_tick: 0,
        }
    }
}

impl Aggregator {
    // Process one packet event, updating all statistics.
    pub fn ingest(&mut self, ev: PacketEvent) {
        let now = Instant::now();
        let bytes = ev.packet.size_bytes as u64;

        self.total_bytes += bytes;
        self.total_packets += 1;

        if ev.is_outbound { //count bytes per direction
            self.bytes_out_tick += bytes;
        } 
        else {
            self.bytes_in_tick += bytes;
        }

        //  1-second NIC bandwidth tick 
        let tick_s = now.duration_since(self.last_tick).as_secs_f64();

        if tick_s >= 0.2 {
            let out_bps = self.bytes_out_tick as f64 / tick_s;
            let in_bps = self.bytes_in_tick  as f64 / tick_s;

            self.current_out_bps = out_bps;
            self.current_in_bps = in_bps;
            self.current_bps = out_bps + in_bps;
            self.bytes_out_tick = 0;
            self.bytes_in_tick = 0;
            self.last_tick = now;

            let elapsed = now.duration_since(self.start).as_secs_f64();
            self.bandwidth_history.push_back([elapsed, out_bps, in_bps]);
            if self.bandwidth_history.len() > 120 {
                self.bandwidth_history.pop_front();
            }
        }

        //  per-process accounting 
        if let Some(ref info) = ev.process {
            let entry = self.processes
                .entry(info.pid)
                .or_insert_with(|| ProcessStats::new(info));

            if ev.is_outbound { entry.bytes_sent += bytes; }
            else { entry.bytes_recv += bytes; }
            entry.packet_count += 1;
            entry.add_bytes(bytes, now);
        }

        //  per-remote-host accounting 
        let remote_ip = if ev.is_outbound {
            ev.packet.dst_ip
        } else {
            ev.packet.src_ip
        };

        let host = self.hosts.entry(remote_ip).or_insert_with(|| HostStats {
            addr: Ipv4Addr::from(remote_ip).to_string(),
            bytes: 0,
            packet_count: 0,
        });

        host.bytes += bytes;
        host.packet_count += 1;



        // per connection accounting
        let (local_ip, local_port, remote_ip2, remote_port) = if ev.is_outbound {
            (ev.packet.src_ip, ev.packet.src_port, ev.packet.dst_ip, ev.packet.dst_port)
        } 
        else {
            (ev.packet.dst_ip, ev.packet.dst_port, ev.packet.src_ip, ev.packet.src_port)
        };
 
        let proto_byte = match ev.packet.protocol {
            crate::capture::Protocol::Tcp => 6u8,
            crate::capture::Protocol::Udp => 17u8,
            crate::capture::Protocol::Other(n) => n,
        };
 
        let key = ConnectionKey {
            protocol: proto_byte,
            local_ip,
            local_port,
            remote_ip: remote_ip2,
            remote_port,
        };
 
        if !self.connections.contains_key(&key) {
            // remove oldest entry if at capacity
            if self.connection_order.len() >= MAX_CONNECTIONS {
                if let Some(old_key) = self.connection_order.pop_front() {
                    self.connections.remove(&old_key);
                }
            }

            let record = ConnectionRecord::new(&key, ev.process.as_ref());
            self.connections.insert(key.clone(), record);
            self.connection_order.push_back(key.clone());
        }
 
        if let Some(rec) = self.connections.get_mut(&key) {
            if ev.is_outbound { 
                rec.bytes_sent += bytes; 
            }

            else { 
                rec.bytes_recv += bytes; 
            }

            rec.packets += 1;
            rec.last_seen = now;

            // Update process info if we didn't have it before
            if rec.pid == 0 {
                if let Some(ref info) = ev.process {
                    rec.proc_name = info.name.clone();
                    rec.pid       = info.pid;
                    rec.username  = info.username.clone();
                }
            }
        }
    }


    // Return up to n processes sorted by current bandwidth (highest first).
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

    // Return up to n remote hosts sorted by total bytes (highest first).
    pub fn top_hosts_by_bytes(&self, n: usize) -> Vec<&HostStats> {
        let mut v: Vec<&HostStats> = self.hosts.values().collect();
        v.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        v.truncate(n);
        v
    }

    // return connections for a specific PID, sorted by total bytes descendingly
    pub fn connections_for_pid(&self, pid: u32) -> Vec<&ConnectionRecord> {
        let mut v: Vec<&ConnectionRecord> = self.connections.values()
            .filter(|r| r.pid == pid)
            .collect();

        v.sort_by(|a, b| {
            (b.bytes_sent + b.bytes_recv).cmp(&(a.bytes_sent + a.bytes_recv))
        });
        v
    }

    // return all connections sorted by total bytes descendingly, capped at n connections
    pub fn top_connections(&self, n: usize) -> Vec<&ConnectionRecord> {
        let mut v: Vec<&ConnectionRecord> = self.connections.values().collect();

        v.sort_by(|a, b| {
            (b.bytes_sent + b.bytes_recv).cmp(&(a.bytes_sent + a.bytes_recv))
        });
        v.truncate(n);
        v
    }


    // Number of distinct processes seen so far (approximation for FR5).
    pub fn active_process_count(&self) -> usize {
        self.processes.len()
    }
}
