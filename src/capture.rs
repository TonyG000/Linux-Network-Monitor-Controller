// capture.rs
//
// FR1  – Real-time packet capture on one or more Linux NICs via libpcap.
// FR2  – Extract src/dst IP, src/dst port, protocol, and packet size from
//         every captured IPv4 frame.
// FR14 – Enumerate available interfaces so the caller can choose one at runtime.

use pcap::{Capture, Device};

// ─── types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Other(u8),
}

/// Every IPv4 packet the capture layer delivers to the caller.
/// IP addresses are big-endian u32 (network byte order).
/// Ports are host byte order.
#[derive(Debug, Clone)]
pub struct Packet {
    pub src_ip:     u32,
    pub dst_ip:     u32,
    pub src_port:   u16,
    pub dst_port:   u16,
    pub protocol:   Protocol,
    pub size_bytes: usize,
}

// ─── datalink / EtherType constants ──────────────────────────────────────────

const DLT_EN10MB:     i32 = 1;   // standard Ethernet
const DLT_LINUX_SLL:  i32 = 113; // Linux cooked-capture ("any" interface)
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETH_HDR_LEN:    usize = 14;
const SLL_HDR_LEN:    usize = 16;
const IPPROTO_TCP:    u8 = 6;
const IPPROTO_UDP:    u8 = 17;

// ─── packet parsing (FR2) ─────────────────────────────────────────────────────

fn parse(data: &[u8], datalink: i32) -> Option<Packet> {
    // Locate start of the IPv4 header based on the link-layer type
    let ip_offset = match datalink {
        DLT_EN10MB => {
            if data.len() < ETH_HDR_LEN { return None; }
            let etype = u16::from_be_bytes([data[12], data[13]]);
            if etype != ETHERTYPE_IPV4 { return None; }
            ETH_HDR_LEN
        }
        DLT_LINUX_SLL => {
            if data.len() < SLL_HDR_LEN { return None; }
            let etype = u16::from_be_bytes([data[14], data[15]]);
            if etype != ETHERTYPE_IPV4 { return None; }
            SLL_HDR_LEN
        }
        _ => return None,
    };

    let ip = &data[ip_offset..];
    if ip.len() < 20 { return None; }

    let version = ip[0] >> 4;
    if version != 4 { return None; }

    let ihl_bytes  = ((ip[0] & 0x0F) as usize) * 4;
    let size_bytes = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let proto_byte = ip[9];
    let src_ip     = u32::from_be_bytes([ip[12], ip[13], ip[14], ip[15]]);
    let dst_ip     = u32::from_be_bytes([ip[16], ip[17], ip[18], ip[19]]);

    if ip.len() < ihl_bytes { return None; }
    let transport = &ip[ihl_bytes..];

    let (protocol, src_port, dst_port) = match proto_byte {
        IPPROTO_TCP => {
            if transport.len() < 20 { return None; }
            let sp = u16::from_be_bytes([transport[0], transport[1]]);
            let dp = u16::from_be_bytes([transport[2], transport[3]]);
            (Protocol::Tcp, sp, dp)
        }
        IPPROTO_UDP => {
            if transport.len() < 8 { return None; }
            let sp = u16::from_be_bytes([transport[0], transport[1]]);
            let dp = u16::from_be_bytes([transport[2], transport[3]]);
            (Protocol::Udp, sp, dp)
        }
        other => (Protocol::Other(other), 0, 0),
    };

    Some(Packet { src_ip, dst_ip, src_port, dst_port, protocol, size_bytes })
}

// ─── CaptureEngine ───────────────────────────────────────────────────────────

pub struct CaptureEngine {
    iface: String,
}

impl CaptureEngine {
    /// Open and validate a capture handle on `iface` (FR1).
    /// Returns an error if the interface does not exist or privileges are missing.
    pub fn new(iface: &str) -> Result<Self, pcap::Error> {
        // Probe once to surface any permission / interface errors early
        let _ = Capture::from_device(iface)?
            .promisc(false)
            .snaplen(65536)
            .timeout(100)
            .open()?;
        Ok(CaptureEngine { iface: iface.to_owned() })
    }

    /// Blocking capture loop (FR1).
    /// Parses each frame and calls `on_packet` with the result (FR2).
    /// Returns only on an unrecoverable pcap error; Ctrl+C terminates the
    /// process via the default SIGINT handler.
    pub fn run(&self, mut on_packet: impl FnMut(Packet)) -> Result<(), pcap::Error> {
        let mut cap = Capture::from_device(self.iface.as_str())?
            .promisc(false)
            .snaplen(65536)
            .timeout(100)
            .open()?;

        let datalink = cap.get_datalink().0;

        loop {
            match cap.next_packet() {
                Ok(raw) => {
                    if let Some(pkt) = parse(raw.data, datalink) {
                        on_packet(pkt);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// FR14 – list every network interface available on this machine.
    pub fn list_interfaces() -> Result<Vec<String>, pcap::Error> {
        Ok(Device::list()?.into_iter().map(|d| d.name).collect())
    }
}
