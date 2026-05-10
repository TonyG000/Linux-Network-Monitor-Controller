mod capture;
mod process;
mod stats;
mod gui;
mod control;
mod logger;

use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;

use eframe::egui;

use capture::{CaptureEngine, Protocol};
use stats::{Aggregator, PacketEvent};
use gui::App;
use control::TrafficController;
use logger::SessionLogger;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    //interface selection 
    let iface = match args.get(1) {
        Some(i) => i.clone(),
        None => {
            eprintln!("Usage: afashtak <interface>\n");
            eprintln!("Available interfaces:");
            match CaptureEngine::list_interfaces() {
                Ok(list) => list.iter().for_each(|i| eprintln!("  {i}")),
                Err(e)   => eprintln!("  (error listing interfaces: {e})"),
            }
            std::process::exit(1);
        }
    };

    let engine = match CaptureEngine::new(&iface) {
        Ok(e)  => e,
        Err(e) => {
            eprintln!("Cannot open '{iface}': {e}");
            eprintln!("Hint: run as root (sudo) or grant CAP_NET_RAW.");
            std::process::exit(1);
        }
    };

    println!("Capturing on '{iface}' — Ctrl+C to stop\n");
    println!("{:<22} {:<22} {:<6} {:>7} {}", "SRC", "DST", "PROTO", "BYTES", "PROCESS");
    println!("{}", "─".repeat(80));

    // shared state 
    // Bounded channel: if the GUI thread falls behind, try_send silently drops
    // the excess rather than allowing unbounded memory growth.
    let (tx, rx)   = mpsc::sync_channel::<PacketEvent>(16_384);
    let aggregator = Arc::new(Mutex::new(Aggregator::default()));
    let controller = Arc::new(Mutex::new(TrafficController::new()));
    let session_logger = Arc::new(Mutex::new(SessionLogger::new()));

    //  capture thread
    thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let mut resolver = process::ProcessResolver::new();
            let _ = engine.run(|pkt| {
                std::thread::sleep(std::time::Duration::from_millis(2));
                // FR3 + FR4 + NFR3: resolve process and direction with caching
                let (process, is_outbound) = resolver.resolve_with_direction(
                    pkt.protocol,
                    pkt.src_ip, pkt.src_port,
                    pkt.dst_ip, pkt.dst_port,
                ).map(|(info, dir)| (Some(info), dir))
                 .unwrap_or((None, false));

                // Non-blocking send; silently drop on backpressure.
                if let Err(e) = tx.send(PacketEvent { packet: pkt, process, is_outbound }) {
                    eprintln!("Channel send failed: {:?}", e);
                }
            });
        })
        .expect("failed to spawn capture thread");

    //  GUI 
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AFASHTAK: Linux Network Monitor and Controller")
            .with_inner_size([1_260.0, 760.0])
            .with_min_inner_size([900.0, 500.0]),
        ..Default::default()
    };

    let agg_clone   = Arc::clone(&aggregator);
    let iface_clone = iface.clone();
    let ctrl_clone = Arc::clone(&controller);
    let logger_clone = Arc::clone(&session_logger);

    eframe::run_native(
        "Afashtak",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(App::new(cc, agg_clone, rx, iface_clone, ctrl_clone, logger_clone,)))
        }),
    )
    .unwrap_or_else(|e| eprintln!("GUI error: {e:?}"));

    controller.lock().unwrap().unblock_all();

     let logger = session_logger.lock().unwrap();
    if !logger.connections.is_empty() {
        eprintln!(
            "Session ended. {} connection records in log (use Export in GUI before exit to save)",
            logger.connections.len()
        );
    }
}
