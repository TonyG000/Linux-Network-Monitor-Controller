mod capture;
mod process;

use std::net::Ipv4Addr;

use capture::{CaptureEngine, Protocol};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // FR14 – interface selection
    let iface = match args.get(1) {
        Some(i) => i.clone(),
        None => {
            eprintln!("Usage: netmonitor <interface>\n");
            eprintln!("Available interfaces:");
            match CaptureEngine::list_interfaces() {
                Ok(list) => list.iter().for_each(|i| eprintln!("  {i}")),
                Err(e)   => eprintln!("  (error: {e})"),
            }
            std::process::exit(1);
        }
    };

    let engine = match CaptureEngine::new(&iface) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Cannot open '{iface}': {e}");
            eprintln!("Hint: run as root (sudo) or grant CAP_NET_RAW.");
            std::process::exit(1);
        }
    };

    println!("Capturing on '{iface}' — Ctrl+C to stop\n");
    println!("{:<22} {:<22} {:<6} {:>7} {}", "SRC", "DST", "PROTO", "BYTES", "PROCESS");
    println!("{}", "─".repeat(80));

    // FR1 + FR2 – capture loop; Ctrl+C (SIGINT) terminates the process naturally
    let result = engine.run(|pkt| {
        let src   = format!("{}:{}", Ipv4Addr::from(pkt.src_ip), pkt.src_port);
        let dst   = format!("{}:{}", Ipv4Addr::from(pkt.dst_ip), pkt.dst_port);
        let proto = match pkt.protocol {
            Protocol::Tcp      => "TCP".to_string(),
            Protocol::Udp      => "UDP".to_string(),
            Protocol::Other(n) => format!("#{n}"),
        };
        let process_info = process::find_process(
            pkt.protocol,
            pkt.src_ip,
            pkt.src_port,
            pkt.dst_ip,
            pkt.dst_port,
        );

        let process_str = match process_info {
            Some(info) => format!("{}/{} ({})", info.pid, info.username, info.name),
            None => "-".to_string(),
        };

        println!("{src:<22} {dst:<22} {proto:<6} {:>7} {}", pkt.size_bytes, process_str);
    });

    if let Err(e) = result {
        eprintln!("\nCapture error: {e}");
    }
}
