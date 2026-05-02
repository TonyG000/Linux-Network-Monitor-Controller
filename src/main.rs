// main.rs
//
// Entry point.  Wires the three layers together:
//
//   ┌─────────────────────┐   PacketEvent    ┌──────────────────────────────┐
//   │  capture thread     │ ──────────────►  │  GUI thread (main)           │
//   │  CaptureEngine::run │  sync_channel    │  Aggregator::ingest + egui   │
//   └─────────────────────┘                  └──────────────────────────────┘
//
// FR1  – real-time capture  (capture.rs)
// FR2  – header extraction  (capture.rs)
// FR3  – process resolution (process.rs)
// FR4  – user resolution    (process.rs)
// FR5  – statistics         (stats.rs)
// FR6  – live dashboard     (gui.rs)
// FR7  – process ranking    (gui.rs)
// FR14 – interface selector (this file)

mod capture;
mod process;
mod stats;
mod gui;

use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use std::thread;

use eframe::egui;

use capture::{CaptureEngine, Protocol};
use process::find_process_with_direction;
use stats::{Aggregator, PacketEvent};
use gui::NetMonApp;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // ── FR14: interface selection ─────────────────────────────────────────────
    let iface = match args.get(1) {
        Some(i) => i.clone(),
        None => {
            eprintln!("Usage: netmonitor <interface>\n");
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

    // ── shared state ─────────────────────────────────────────────────────────
    // Bounded channel: if the GUI thread falls behind, try_send silently drops
    // the excess rather than allowing unbounded memory growth.
    let (tx, rx)   = mpsc::sync_channel::<PacketEvent>(16_384);
    let aggregator = Arc::new(Mutex::new(Aggregator::default()));

    // ── capture thread ────────────────────────────────────────────────────────
    thread::Builder::new()
        .name("capture".into())
        .spawn(move || {
            let _ = engine.run(|pkt| {
                std::thread::sleep(std::time::Duration::from_millis(2));
                // FR3 + FR4: resolve process and direction
                let (process, is_outbound) = find_process_with_direction(
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

    // ── GUI (must run on the main thread) ─────────────────────────────────────
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NetMonitor — Live Dashboard")
            .with_inner_size([1_260.0, 760.0])
            .with_min_inner_size([900.0, 500.0]),
        ..Default::default()
    };

    let agg_clone   = Arc::clone(&aggregator);
    let iface_clone = iface.clone();

    eframe::run_native(
        "NetMonitor",
        native_options,
        Box::new(move |cc| {
            Ok(Box::new(NetMonApp::new(cc, agg_clone, rx, iface_clone)))
        }),
    )
    .unwrap_or_else(|e| eprintln!("GUI error: {e:?}"));
}
