use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::capture::Protocol;

// Process Information we track
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub uid: u32,
    pub username: String,
}

/// Helper: replicate how Linux displays IP in /proc/net/{tcp,udp}
/// IP in packet header: e.g. 127.0.0.1 is 0x7F000001 (big endian u32)
fn format_socket_addr(ip: u32, port: u16) -> String {
    // libpcap `src_ip` was parsed via `u32::from_be_bytes(ip)`.
    // We convert it back to bytes, then read it natively as if it was a __be32 dumped by printf.
    let bytes = ip.to_be_bytes();
    let kernel_ip = u32::from_ne_bytes(bytes);
    format!("{:08X}:{:04X}", kernel_ip, port)
}

/// Parse /proc/net/tcp (or udp) and find the inode of the matching socket
fn find_socket_inode(proto_file: &str, target_local: &str, target_remote: &str) -> Option<u64> {
    let contents = fs::read_to_string(proto_file).ok()?;
    // Format:
    // sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
    //  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 21674 ...
    for line in contents.lines().skip(1) { // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        // IPv4 lines typically have 12+ parts, let's just make sure we have up to inode
        if parts.len() < 10 { continue; }
        
        let local_addr = parts[1];
        let rem_addr = parts[2];
        let inode_str = parts[9];
        
        // Match both exact connection, or wildcard remote (e.g. listening socket 00000000:0000)
        let exact_match = local_addr == target_local && rem_addr == target_remote;
        let wildcard_match = local_addr == target_local && rem_addr == "00000000:0000";

        if exact_match || wildcard_match {
            if let Ok(inode) = u64::from_str(inode_str) {
                return Some(inode);
            }
        }
    }
    None
}

/// Scan /proc/*/fd/* to find the PID that owns the given socket inode
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let target = format!("socket:[{}]", inode);
    
    let entries = fs::read_dir("/proc").ok()?;
    for entry in entries.filter_map(Result::ok) {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
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

/// Read /proc/<pid>/status to extract Real UID and process Name
fn get_process_uid_and_name(pid: u32) -> Option<(u32, String)> {
    let path = format!("/proc/{}/status", pid);
    let contents = fs::read_to_string(path).ok()?;
    
    let mut name = String::from("unknown");
    let mut uid = None;

    for line in contents.lines() {
        if line.starts_with("Name:") {
            if let Some(n) = line.split_whitespace().nth(1) {
                name = n.to_string();
            }
        } else if line.starts_with("Uid:") {
            // Uid:    <Real>    <Effective> ...
            if let Some(u_str) = line.split_whitespace().nth(1) {
                if let Ok(u) = u32::from_str(u_str) {
                    uid = Some(u);
                }
            }
        }
    }

    uid.map(|u| (u, name))
}

/// Map UID to Username using /etc/passwd
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

/// Locate network process owner using IPv4 routing tuples
pub fn find_process(protocol: Protocol, src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Option<ProcessInfo> {
    let proto_file = match protocol {
        Protocol::Tcp => "/proc/net/tcp",
        Protocol::Udp => "/proc/net/udp",
        _ => return None,
    };

    let src_str = format_socket_addr(src_ip, src_port);
    let dst_str = format_socket_addr(dst_ip, dst_port);

    // Since we sniff the wire, we don't know which IP represents our local machine.
    // So we first assume the Source IP belongs to the local machine:
    let mut inode = find_socket_inode(proto_file, &src_str, &dst_str);

    // If not found, assume the Destination IP belongs to the local machine:
    if inode.is_none() {
        inode = find_socket_inode(proto_file, &dst_str, &src_str);
    }

    if let Some(i) = inode {
        if let Some(pid) = find_pid_by_inode(i) {
            if let Some((uid, name)) = get_process_uid_and_name(pid) {
                let username = uid_to_username(uid);
                return Some(ProcessInfo {
                    pid,
                    name,
                    uid,
                    username,
                });
            }
        }
    }

    None
}
