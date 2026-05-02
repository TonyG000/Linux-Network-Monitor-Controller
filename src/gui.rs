// gui.rs
//
// FR6 – Live dashboard: bandwidth plot, top-process panel, top-host panel.
// FR7 – Process ranking sorted by bandwidth, with inline bandwidth bars.
//
// Aesthetic: industrial / terminal-monitor.
//   Dark panel background, high-density monospace data, green-on-dark
//   sparkline, gold/silver/bronze rank highlights.

use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText, Visuals};
use egui_plot::{Line, Plot, PlotPoints};

use crate::stats::{Aggregator, PacketEvent};

const GREEN:    Color32 = Color32::from_rgb(72,  199, 116);
const CYAN:     Color32 = Color32::from_rgb(80,  200, 200);
const YELLOW:   Color32 = Color32::from_rgb(255, 196, 68);
const BLUE_OUT: Color32 = Color32::from_rgb(100, 180, 255);
const ORG_IN:   Color32 = Color32::from_rgb(255, 155, 80);
const DIM:      Color32 = Color32::from_rgb(110, 110, 120);
const PANEL_BG: Color32 = Color32::from_rgb(16,  18,  24);
const CARD_BG:  Color32 = Color32::from_rgb(22,  25,  33);

struct ProcRow {
    pid:     u32,
    name:    String,
    user:    String,
    bw_bps:  f64,
    sent:    u64,
    recv:    u64,
    bw_frac: f32,   // 0–1 relative to the top process
}

struct HostRow {
    addr:    String,
    bytes:   u64,
    packets: u64,
    frac:    f32,   // 0–1 relative to top host
}

struct Snapshot {
    total_bytes:   u64,
    total_packets: u64,
    current_bps:   f64,
    active_procs:  usize,
    bw_history:    Vec<[f64; 2]>,
    processes:     Vec<ProcRow>,
    hosts:         Vec<HostRow>,
}

fn snapshot(agg: &Aggregator) -> Snapshot {
    let procs_raw = agg.top_processes_by_bandwidth(20);
    let max_bw    = procs_raw.first().map(|p| p.bandwidth_bps).unwrap_or(1.0).max(1.0);
    let processes = procs_raw.iter().map(|p| ProcRow {
        pid:     p.pid,
        name:    p.name.clone(),
        user:    p.username.clone(),
        bw_bps:  p.bandwidth_bps,
        sent:    p.bytes_sent,
        recv:    p.bytes_recv,
        bw_frac: (p.bandwidth_bps / max_bw).clamp(0.0, 1.0) as f32,
    }).collect();

    let hosts_raw = agg.top_hosts_by_bytes(20);
    let max_bytes = hosts_raw.first().map(|h| h.bytes).unwrap_or(1).max(1);
    let hosts = hosts_raw.iter().map(|h| HostRow {
        addr:    h.addr.clone(),
        bytes:   h.bytes,
        packets: h.packet_count,
        frac:    (h.bytes as f32 / max_bytes as f32).clamp(0.0, 1.0),
    }).collect();

    Snapshot {
        total_bytes:   agg.total_bytes,
        total_packets: agg.total_packets,
        current_bps:   agg.current_bps,
        active_procs:  agg.active_process_count(),
        bw_history:    agg.bandwidth_history.iter().copied().collect(),
        processes,
        hosts,
    }
}


pub struct NetMonApp {
    aggregator:    Arc<Mutex<Aggregator>>,
    rx:            Receiver<PacketEvent>,
    iface:         String,
    start:         Instant,
    /// false → can't read /proc/<pid>/fd, process column will always be empty
    proc_perm_ok:  bool,
}

impl NetMonApp {
    pub fn new(
        cc:         &eframe::CreationContext<'_>,
        aggregator: Arc<Mutex<Aggregator>>,
        rx:         Receiver<PacketEvent>,
        iface:      String,
    ) -> Self {
        // Terminal-monitor dark theme
        let mut vis          = Visuals::dark();
        vis.panel_fill       = PANEL_BG;
        vis.window_fill      = CARD_BG;
        vis.extreme_bg_color = Color32::from_rgb(10, 11, 15);
        vis.widgets.noninteractive.bg_fill = CARD_BG;
        cc.egui_ctx.set_visuals(vis);

        // Check whether we can read other processes' fd directories.
        // /proc/1 (init/systemd) is always owned by root, so reading its fd/
        // dir is a reliable proxy for "do we have root/CAP_SYS_PTRACE?".
        let proc_perm_ok = std::fs::read_dir("/proc/1/fd").is_ok();

        Self { aggregator, rx, iface, start: Instant::now(), proc_perm_ok }
    }
}

impl eframe::App for NetMonApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ── drain channel (cap at 8 k to stay responsive) ────────────────────
        {
            let mut agg = self.aggregator.lock().unwrap();
            for ev in self.rx.try_iter().take(8_192) {
                agg.ingest(ev);
            }
        }
        // Repaint at ~2 Hz even when idle
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        let snap   = snapshot(&*self.aggregator.lock().unwrap());
        let uptime = self.start.elapsed().as_secs();

        // ── header bar ───────────────────────────────────────────────────────
        egui::TopBottomPanel::top("hdr")
            .frame(egui::Frame::none().fill(Color32::from_rgb(10, 55, 35)))
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("⬡ NETMONITOR")
                            .strong()
                            .color(GREEN)
                            .size(17.0),
                    );
                    ui.separator();
                    ui.label(RichText::new(format!("if: {}", self.iface)).color(CYAN).monospace());
                    ui.separator();
                    ui.label(RichText::new(format!("▲ {}/s", fmt_bytes(snap.current_bps as u64))).color(GREEN).strong());
                    ui.separator();
                    ui.label(RichText::new(format!("total  {}", fmt_bytes(snap.total_bytes))).color(YELLOW));
                    ui.separator();
                    ui.label(RichText::new(format!("pkts  {}", snap.total_packets)).color(DIM));
                    ui.separator();
                    ui.label(RichText::new(format!("procs  {}", snap.active_procs)).color(CYAN));
                    ui.separator();
                    ui.label(RichText::new(format!("up  {}s", uptime)).color(DIM));
                });
                ui.add_space(6.0);
            });

        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::none().fill(Color32::from_rgb(10, 18, 12)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("● LIVE").color(GREEN).small());
                    ui.label(RichText::new("  Ctrl+C in terminal to exit").color(DIM).small());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(format!(
                                "peak  {}/s",
                                fmt_bytes(
                                    snap.bw_history.iter().map(|p| p[1] as u64).max().unwrap_or(0)
                                )
                            ))
                            .color(DIM)
                            .small(),
                        );
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(PANEL_BG).inner_margin(egui::Margin::same(10.0)))
            .show(ctx, |ui| {
                // FR6: bandwidth sparkline 
                section_header(ui, "BANDWIDTH  (bytes / second)");

                let pts = PlotPoints::new(snap.bw_history.clone());
                Plot::new("bw")
                    .height(155.0)
                    .show_axes([true, true])
                    .x_axis_label("elapsed (s)")
                    .y_axis_label("bytes / s")
                    .include_y(0.0)
                    .set_margin_fraction(egui::Vec2::new(0.0, 0.12))
                    .show(ui, |pu| {
                        pu.line(
                            Line::new(pts)
                                .color(GREEN)
                                .width(1.8)
                                .name("B/s")
                                .fill(0.0),
                        );
                    });

                // Measure remaining height BEFORE splitting columns so both
                // scroll areas get the same explicit max_height.
                let table_h = ui.available_height() - 8.0;

                ui.columns(2, |cols| {
                    // Left: FR7 process ranking 
                    {
                        let ui = &mut cols[0];
                        section_header(ui, "TOP PROCESSES  (by bandwidth)");

                        egui::ScrollArea::vertical()
                            .id_source("procs")
                            .max_height(table_h)
                            .show(ui, |ui| {
                                if snap.processes.is_empty() {
                                    ui.add_space(12.0);
                                    if !self.proc_perm_ok {
                                        // ── permission warning ────────────────
                                        let warn_frame = egui::Frame::none()
                                            .fill(Color32::from_rgb(80, 30, 10))
                                            .inner_margin(egui::Margin::same(10.0))
                                            .rounding(egui::Rounding::same(4.0));
                                        warn_frame.show(ui, |ui| {
                                            ui.label(
                                                RichText::new("⚠  Missing permissions")
                                                    .color(YELLOW)
                                                    .strong(),
                                            );
                                            ui.add_space(4.0);
                                            ui.label(
                                                RichText::new(
                                                    "Process resolution requires reading\n\
                                                     /proc/<pid>/fd/ symlinks, which are\n\
                                                     restricted to root on Linux."
                                                )
                                                .color(DIM)
                                                .small(),
                                            );
                                            ui.add_space(6.0);
                                            ui.label(RichText::new("Fix — restart as root:").color(DIM).small());
                                            ui.add_space(2.0);
                                            let iface = self.iface.clone();
                                            ui.label(
                                                RichText::new(format!("  sudo ./netmonitor {iface}"))
                                                    .color(GREEN)
                                                    .monospace(),
                                            );
                                        });
                                    } else {
                                        ui.label(
                                            RichText::new("Waiting for resolvable traffic…")
                                                .color(DIM),
                                        );
                                        ui.add_space(4.0);
                                        ui.label(
                                            RichText::new(
                                                "Permissions OK. Traffic is arriving but\n\
                                                 no matching sockets found in /proc/net/tcp\n\
                                                 or /proc/net/udp yet."
                                            )
                                            .color(DIM)
                                            .small(),
                                        );
                                    }
                                    ui.add_space(4.0);
                                } else {
                                    egui::Grid::new("pg")
                                        .num_columns(6)
                                        .spacing([6.0, 3.0])
                                        .striped(true)
                                        .show(ui, |ui| {
                                            for h in &["#", "PID", "PROCESS", "USER", "B/S", "↑SENT / ↓RECV"] {
                                                ui.label(RichText::new(*h).color(DIM).small().strong());
                                            }
                                            ui.end_row();

                                            for (rank, row) in snap.processes.iter().enumerate() {
                                                let name_col = rank_color(rank);
                                                ui.label(RichText::new(format!("{}", rank + 1)).color(name_col).small().strong());
                                                ui.label(RichText::new(row.pid.to_string()).color(DIM).small().monospace());
                                                ui.label(RichText::new(&row.name).color(name_col).monospace());
                                                ui.label(RichText::new(&row.user).color(DIM).small());
                                                ui.vertical(|ui| {
                                                    ui.label(RichText::new(format!("{}/s", fmt_bytes(row.bw_bps as u64))).color(GREEN).small().monospace());
                                                    ui.add(
                                                        egui::ProgressBar::new(row.bw_frac)
                                                            .desired_width(90.0)
                                                            .fill(Color32::from_rgb(40, 160, 80)),
                                                    );
                                                });
                                                ui.vertical(|ui| {
                                                    ui.label(RichText::new(fmt_bytes(row.sent)).color(BLUE_OUT).small().monospace());
                                                    ui.label(RichText::new(fmt_bytes(row.recv)).color(ORG_IN).small().monospace());
                                                });
                                                ui.end_row();
                                            }
                                        });
                                }
                            });
                    }

                    // Right: FR6 top remote hosts
                    {
                        let ui = &mut cols[1];
                        section_header(ui, "TOP REMOTE HOSTS  (by volume)");

                        egui::ScrollArea::vertical()
                            .id_source("hosts")
                            .max_height(table_h)
                            .show(ui, |ui| {
                                egui::Grid::new("hg")
                                    .num_columns(4)
                                    .spacing([6.0, 3.0])
                                    .striped(true)
                                    .show(ui, |ui| {
                                        for h in &["#", "IP ADDRESS", "BYTES", "PKTS"] {
                                            ui.label(RichText::new(*h).color(DIM).small().strong());
                                        }
                                        ui.end_row();

                                        for (i, row) in snap.hosts.iter().enumerate() {
                                            ui.label(RichText::new(format!("{}", i + 1)).color(DIM).small());
                                            ui.label(RichText::new(&row.addr).color(YELLOW).monospace().small());
                                            ui.vertical(|ui| {
                                                ui.label(RichText::new(fmt_bytes(row.bytes)).color(YELLOW).small().monospace());
                                                ui.add(
                                                    egui::ProgressBar::new(row.frac)
                                                        .desired_width(90.0)
                                                        .fill(Color32::from_rgb(180, 140, 30)),
                                                );
                                            });
                                            ui.label(RichText::new(row.packets.to_string()).color(DIM).small().monospace());
                                            ui.end_row();
                                        }

                                        if snap.hosts.is_empty() {
                                            ui.label(RichText::new("waiting for traffic…").color(DIM).small());
                                            ui.end_row();
                                        }
                                    });
                            });
                    }
                });
            });
    }
}

//helpers

fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.add_space(2.0);
    ui.label(RichText::new(text).color(CYAN).small().strong());
    ui.separator();
    ui.add_space(2.0);
}

fn fmt_bytes(b: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;
    match b {
        b if b >= GB => format!("{:.2} GB", b as f64 / GB as f64),
        b if b >= MB => format!("{:.1} MB", b as f64 / MB as f64),
        b if b >= KB => format!("{:.1} KB", b as f64 / KB as f64),
        b            => format!("{b} B"),
    }
}

fn rank_color(rank: usize) -> Color32 {
    match rank {
        0 => Color32::from_rgb(255, 215, 0),   // gold
        1 => Color32::from_rgb(192, 192, 192), // silver
        2 => Color32::from_rgb(205, 127, 50),  // bronze
        _ => Color32::WHITE,
    }
}