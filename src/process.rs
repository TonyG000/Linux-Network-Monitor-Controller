use std::fs;
use std::str::FromStr;
use std::collections::HashMap;
use std::time::{Instant, Duration};

use crate::capture::Protocol;

//  types 

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid:      u32,
    pub name:     String,
    pub uid:      u32,
    pub username: String,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
struct CacheKey {
    protocol: Protocol,
    src_ip:   u32,
    src_port: u16,
    dst_ip:   u32,
    dst_port: u16,
}

pub struct ProcessResolver {
    // connection -> (info, is_outbound, timestamp)
    conn_cache: HashMap<CacheKey, (ProcessInfo, bool, Instant)>,
    // inode -> (pid, timestamp)
    inode_cache: HashMap<u64, (u32, Instant)>,
    // pid -> (uid, name, timestamp)
    proc_cache: HashMap<u32, (u32, String, Instant)>,
    // uid -> username
    user_cache: HashMap<u32, String>,

    last_cleanup: Instant,
}

const CACHE_TTL: Duration = Duration::from_secs(30);
const CONN_CACHE_MAX: usize = 2000;
const INODE_CACHE_MAX: usize = 1000;
const PROC_CACHE_MAX: usize = 500;

//  /proc/net formatting 

// Format an IP+port pair the same way the Linux kernel writes it in
// /proc/net/tcp and /proc/net/udp.
fn format_socket_addr(ip: u32, port: u16) -> String {
    let bytes      = ip.to_be_bytes();
    let kernel_ip  = u32::from_ne_bytes(bytes);
    format!("{:08X}:{:04X}", kernel_ip, port)
}

//  /proc/net lookup 
fn find_socket_inode(proto_file: &str, local: &str, remote: &str) -> Option<u64> {
    let contents = fs::read_to_string(proto_file).ok()?;

    // Many daemons (NTP, DNS, DHCP…) bind to 0.0.0.0 rather than a specific
    // interface IP.  Build a wildcard version of the local address so we can
    // match "00000000:<port>" as a fallback.
    let local_port   = local.split(':').nth(1).unwrap_or("");
    let any_ip_local = format!("00000000:{}", local_port);

    for line in contents.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 { continue; }

        let local_addr = parts[1];
        let rem_addr = parts[2];
        let inode_str = parts[9];

        let matches =
            // Exact 4-tuple
            (local_addr == local && rem_addr == remote)
            // Remote not connected (UDP common case)
            || (local_addr == local && rem_addr == "00000000:0000")
            // Socket bound to 0.0.0.0 (matches any local interface IP)
            || (local_addr == any_ip_local && rem_addr == remote)
            || (local_addr == any_ip_local && rem_addr == "00000000:0000");

        if matches {
            if let Ok(inode) = u64::from_str(inode_str) {
                return Some(inode);
            }
        }
    }
    None
}

//  PID lookup by socket inode 
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let target  = format!("socket:[{}]", inode);
    let entries = fs::read_dir("/proc").ok()?;

    for entry in entries.filter_map(Result::ok) {
        let file_name = entry.file_name();
        let pid_str   = file_name.to_string_lossy();
        if let Ok(pid) = u32::from_str(&pid_str) {
            let fd_dir = entry.path().join("fd");
            if let Ok(fds) = fs::read_dir(fd_dir) {
                for fd_entry in fds.filter_map(Result::ok) {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        if link.to_string_lossy() == target {
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

//  process metadata 
fn get_process_uid_and_name(pid: u32) -> Option<(u32, String)> {
    let path     = format!("/proc/{}/status", pid);
    let contents = fs::read_to_string(path).ok()?;

    let mut name = String::from("unknown");
    let mut uid  = None;

    for line in contents.lines() {
        if line.starts_with("Name:") {
            if let Some(n) = line.split_whitespace().nth(1) {
                name = n.to_string();
            }
        } else if line.starts_with("Uid:") {
            if let Some(u_str) = line.split_whitespace().nth(1) {
                if let Ok(u) = u32::from_str(u_str) {
                    uid = Some(u);
                }
            }
        }
    }
    uid.map(|u| (u, name))
}

fn uid_to_username(target_uid: u32) -> String {
    if let Ok(contents) = fs::read_to_string("/etc/passwd") {
        for line in contents.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(u) = u32::from_str(parts[2]) {
                    if u == target_uid {
                        return parts[0].to_string();
                    }
                }
            }
        }
    }
    target_uid.to_string()
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            conn_cache:   HashMap::new(),
            inode_cache:  HashMap::new(),
            proc_cache:   HashMap::new(),
            user_cache:   HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub fn resolve_with_direction(
        &mut self,
        protocol: Protocol,
        src_ip: u32, src_port: u16,
        dst_ip: u32, dst_port: u16,
    ) -> Option<(ProcessInfo, bool)> {
        self.maybe_cleanup();

        let key = CacheKey { protocol, src_ip, src_port, dst_ip, dst_port };

        // 1. Check connection cache
        if let Some((info, dir, ts)) = self.conn_cache.get(&key) {
            if ts.elapsed() < CACHE_TTL {
                return Some((info.clone(), *dir));
            }
        }

        // 2. Perform resolution
        let res = self.resolve_internal(protocol, src_ip, src_port, dst_ip, dst_port);

        // 3. Update cache
        if let Some((ref info, dir)) = res {
            if self.conn_cache.len() >= CONN_CACHE_MAX {
                self.conn_cache.clear(); // Simple eviction
            }
            self.conn_cache.insert(key, (info.clone(), dir, Instant::now()));
        }

        res
    }

    fn resolve_internal(
        &mut self,
        protocol: Protocol,
        src_ip: u32, src_port: u16,
        dst_ip: u32, dst_port: u16,
    ) -> Option<(ProcessInfo, bool)> {
        let proto_file = match protocol {
            Protocol::Tcp => "/proc/net/tcp",
            Protocol::Udp => "/proc/net/udp",
            _ => return None,
        };

        let src_str = format_socket_addr(src_ip, src_port);
        let dst_str = format_socket_addr(dst_ip, dst_port);

        // Try src-as-local first (outbound)
        if let Some(info) = self.resolve_single(proto_file, &src_str, &dst_str) {
            return Some((info, true));
        }
        // Fallback: dst-as-local (inbound)
        if let Some(info) = self.resolve_single(proto_file, &dst_str, &src_str) {
            return Some((info, false));
        }

        None
    }

    fn resolve_single(&mut self, proto_file: &str, local: &str, remote: &str) -> Option<ProcessInfo> {
        let inode = find_socket_inode(proto_file, local, remote)?;

        // 1. Inode to PID
        let pid = if let Some(&(pid, ts)) = self.inode_cache.get(&inode) {
            if ts.elapsed() < CACHE_TTL { pid } else { self.find_and_cache_pid(inode)? }
        } else {
            self.find_and_cache_pid(inode)?
        };

        // 2. PID to Metadata
        let (uid, name) = if let Some((uid, name, ts)) = self.proc_cache.get(&pid) {
            if ts.elapsed() < CACHE_TTL { (*uid, name.clone()) } else { self.find_and_cache_proc(pid)? }
        } else {
            self.find_and_cache_proc(pid)?
        };

        // 3. UID to Username
        let username = self.user_cache.entry(uid)
            .or_insert_with(|| uid_to_username(uid))
            .clone();

        Some(ProcessInfo { pid, name, uid, username })
    }

    fn find_and_cache_pid(&mut self, inode: u64) -> Option<u32> {
        let pid = find_pid_by_inode(inode)?;
        if self.inode_cache.len() >= INODE_CACHE_MAX { self.inode_cache.clear(); }
        self.inode_cache.insert(inode, (pid, Instant::now()));
        Some(pid)
    }

    fn find_and_cache_proc(&mut self, pid: u32) -> Option<(u32, String)> {
        let res = get_process_uid_and_name(pid)?;
        if self.proc_cache.len() >= PROC_CACHE_MAX { self.proc_cache.clear(); }
        self.proc_cache.insert(pid, (res.0, res.1.clone(), Instant::now()));
        Some(res)
    }

    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() > Duration::from_secs(60) {
            let now = Instant::now();
            self.conn_cache.retain(|_, (_, _, ts)| now.duration_since(*ts) < CACHE_TTL);
            self.inode_cache.retain(|_, (_, ts)| now.duration_since(*ts) < CACHE_TTL);
            self.proc_cache.retain(|_, (_, _, ts)| now.duration_since(*ts) < CACHE_TTL);
            self.last_cleanup = now;
        }
    }
}

// Keep the old API for backward compatibility if needed, 
// but it will be stateless and slower. 
// For NFR3, the main capture loop should use ProcessResolver.

pub fn find_process_with_direction(
    protocol: Protocol,
    src_ip: u32, src_port: u16,
    dst_ip: u32, dst_port: u16,
) -> Option<(ProcessInfo, bool)> {
    let mut resolver = ProcessResolver::new();
    resolver.resolve_with_direction(protocol, src_ip, src_port, dst_ip, dst_port)
}

pub fn find_process(
    protocol: Protocol,
    src_ip:   u32, src_port: u16,
    dst_ip:   u32, dst_port: u16,
) -> Option<ProcessInfo> {
    find_process_with_direction(protocol, src_ip, src_port, dst_ip, dst_port)
        .map(|(info, _)| info)
}