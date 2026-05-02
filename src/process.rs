// process.rs  (FR3, FR4)
//
// Resolves which local process owns a given TCP/UDP socket by walking
//   /proc/net/{tcp,udp}  →  socket inode
//   /proc/*/fd/*         →  PID
//   /proc/<pid>/status   →  UID + process name
//   /etc/passwd          →  username
//
// The new `find_process_with_direction` variant additionally reports whether
// the src or dst address was found as the local side, enabling FR5 to
// distinguish bytes-sent from bytes-received.

use std::fs;
use std::str::FromStr;

use crate::capture::Protocol;

// ─── types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid:      u32,
    pub name:     String,
    pub uid:      u32,
    pub username: String,
}

// ─── /proc/net formatting ─────────────────────────────────────────────────────

/// Format an IP+port pair the same way the Linux kernel writes it in
/// /proc/net/tcp and /proc/net/udp.
fn format_socket_addr(ip: u32, port: u16) -> String {
    // Packets arrive with the IP in network byte order stored as a big-endian
    // u32.  The kernel dumps __be32 with printf("%08X"), which is native-endian
    // on little-endian hosts (i.e. byte-swapped from network order).
    let bytes      = ip.to_be_bytes();
    let kernel_ip  = u32::from_ne_bytes(bytes);
    format!("{:08X}:{:04X}", kernel_ip, port)
}

// ─── /proc/net lookup ────────────────────────────────────────────────────────

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
        let rem_addr   = parts[2];
        let inode_str  = parts[9];

        let matches =
            // Exact 4-tuple
            (local_addr == local          && rem_addr == remote)
            // Remote not connected (UDP common case)
            || (local_addr == local          && rem_addr == "00000000:0000")
            // Socket bound to 0.0.0.0 (matches any local interface IP)
            || (local_addr == any_ip_local   && rem_addr == remote)
            || (local_addr == any_ip_local   && rem_addr == "00000000:0000");

        if matches {
            if let Ok(inode) = u64::from_str(inode_str) {
                return Some(inode);
            }
        }
    }
    None
}

// ─── PID lookup by socket inode ──────────────────────────────────────────────

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

// ─── process metadata ────────────────────────────────────────────────────────

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

// ─── internal resolve helper ─────────────────────────────────────────────────

fn resolve(proto_file: &str, local: &str, remote: &str) -> Option<ProcessInfo> {
    let inode = find_socket_inode(proto_file, local, remote)?;
    let pid   = find_pid_by_inode(inode)?;
    let (uid, name) = get_process_uid_and_name(pid)?;
    let username    = uid_to_username(uid);
    Some(ProcessInfo { pid, name, uid, username })
}

// ─── public API ──────────────────────────────────────────────────────────────

/// Locate the process that owns the given TCP/UDP socket (FR3, FR4).
///
/// Returns `None` if the socket cannot be matched to any local process.
pub fn find_process(
    protocol: Protocol,
    src_ip:   u32, src_port: u16,
    dst_ip:   u32, dst_port: u16,
) -> Option<ProcessInfo> {
    find_process_with_direction(protocol, src_ip, src_port, dst_ip, dst_port)
        .map(|(info, _)| info)
}

/// Like `find_process` but also returns the traffic direction:
///   `true`  → src is the local endpoint (packet is outbound / sent)
///   `false` → dst is the local endpoint (packet is inbound  / received)
///
/// Used by FR5 to distinguish bytes-sent from bytes-received per process.
pub fn find_process_with_direction(
    protocol: Protocol,
    src_ip:   u32, src_port: u16,
    dst_ip:   u32, dst_port: u16,
) -> Option<(ProcessInfo, bool)> {
    let proto_file = match protocol {
        Protocol::Tcp   => "/proc/net/tcp",
        Protocol::Udp   => "/proc/net/udp",
        _               => return None,
    };
    let src_str = format_socket_addr(src_ip, src_port);
    let dst_str = format_socket_addr(dst_ip, dst_port);

    // Try src-as-local first (outbound packet).
    if let Some(info) = resolve(proto_file, &src_str, &dst_str) {
        return Some((info, true));
    }
    // Fallback: dst-as-local (inbound packet).
    if let Some(info) = resolve(proto_file, &dst_str, &src_str) {
        return Some((info, false));
    }
    None
}