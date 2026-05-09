use std::sync::{Arc, Mutex};
use std::sync::mpsc::Receiver;
use std::time::Instant;

use eframe::egui::{self, Color32, RichText, Visuals};
use egui_plot::{Line, Plot, PlotPoints};

use crate::control::TrafficController;
use crate::stats::{Aggregator, ConnectionRecord, PacketEvent};

use crate::logger::SessionLogger;

const GREEN: Color32 = Color32::from_rgb(72,  199, 116);
const CYAN: Color32 = Color32::from_rgb(80,  200, 200);
const YELLOW: Color32 = Color32::from_rgb(255, 196, 68);
const BLUE_OUT: Color32 = Color32::from_rgb(100, 180, 255);
const ORG_IN: Color32 = Color32::from_rgb(255, 155, 80);
const DIM: Color32 = Color32::from_rgb(110, 110, 120);
const PANEL_BG: Color32 = Color32::from_rgb(15, 8, 26);
const CARD_BG: Color32 = Color32::from_rgb(31, 22, 46);
const RED_DIM: Color32 = Color32::from_rgb(200, 80,  60);

const DONUT_COLORS: &[Color32] = &[
    Color32::from_rgb(100, 136, 221), // blue
    Color32::from_rgb(72,  199, 116), // green
    Color32::from_rgb(255, 196, 68),  // yellow
    Color32::from_rgb(80,  200, 200), // cyan
    Color32::from_rgb(200, 120, 220), // purple
    Color32::from_rgb(255, 140, 80),  // orange
    Color32::from_rgb(120, 200, 160), // mint
    Color32::from_rgb(200, 80,  100), // red-pink
];

struct ProcRow {
    pid: u32,
    uid: u32,
    name: String,
    user: String,
    bw_bps: f64,
    sent: u64,
    recv: u64,
    bw_frac: f32,
}

struct HostRow {
    addr: String,
    bytes: u64,
    packets: u64,
    frac: f32, 
}


//one connection for the detail panel.
struct ConnRow {
    pid: u32,
    proc_name: String,
    username: String,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
    local_port: u16,
    bytes_sent: u64,
    bytes_recv: u64,
    packets: u64,
    age_secs: u64,
}

struct Snapshot {
    total_bytes: u64,
    total_packets: u64,
    current_bps: f64,
    current_out_bps: f64,
    current_in_bps: f64,
    active_procs: usize,
    bw_history_out: Vec<[f64; 2]>,
    bw_history_in: Vec<[f64; 2]>,
    processes: Vec<ProcRow>,
    hosts: Vec<HostRow>,
    top_conns: Vec<ConnRow>,

    peak_out_bps: f64,
    peak_in_bps: f64,
    total_sent: u64,
    total_recv: u64,
    tcp_bytes: u64,
    udp_bytes: u64,
}

fn conn_row_from(r: &ConnectionRecord) -> ConnRow {
    ConnRow {
        pid: r.pid,
        proc_name: r.proc_name.clone(),
        username: r.username.clone(),
        protocol: r.protocol.clone(),
        remote_addr: r.remote_addr.clone(),
        remote_port: r.remote_port,
        local_port: r.local_port,
        bytes_sent: r.bytes_sent,
        bytes_recv: r.bytes_recv,
        packets: r.packets,
        age_secs: r.last_seen.elapsed().as_secs(),
    }
}

fn snapshot(agg: &Aggregator) -> Snapshot {
    let procs_raw = agg.top_processes_by_bandwidth(20);
    let max_bw    = procs_raw.first().map(|p| p.bandwidth_bps).unwrap_or(1.0).max(1.0);
    let processes = procs_raw.iter().map(|p| ProcRow {
        pid: p.pid,
        uid: p.uid,
        name: p.name.clone(),
        user: p.username.clone(),
        bw_bps: p.bandwidth_bps,
        sent: p.bytes_sent,
        recv: p.bytes_recv,
        bw_frac: (p.bandwidth_bps / max_bw).clamp(0.0, 1.0) as f32,
    }).collect();

    let hosts_raw = agg.top_hosts_by_bytes(20);
    let max_bytes = hosts_raw.first().map(|h| h.bytes).unwrap_or(1).max(1);
    let hosts = hosts_raw.iter().map(|h| HostRow {
        addr: h.addr.clone(),
        bytes: h.bytes,
        packets: h.packet_count,
        frac: (h.bytes as f32 / max_bytes as f32).clamp(0.0, 1.0),
    }).collect();


    //split history into two separate point sets for the two plot lines
    let bw_history_out: Vec<[f64; 2]> = agg.bandwidth_history.iter()
        .map(|s| [s[0], s[1]]).collect();
    
    let bw_history_in: Vec<[f64; 2]>  = agg.bandwidth_history.iter()
        .map(|s| [s[0], s[2]]).collect();

    let peak_out_bps = bw_history_out.iter().map(|p| p[1]).fold(0.0_f64, f64::max);

    let peak_in_bps  = bw_history_in.iter().map(|p| p[1]).fold(0.0_f64, f64::max);
 
    //global top-connections snapshot
    let top_conns = agg.top_connections(50)
        .iter()
        .map(|r| conn_row_from(r))
        .collect();

    // totals for sent/recv
    let total_sent: u64 = procs_raw.iter().map(|p| p.bytes_sent).sum();
    let total_recv: u64 = procs_raw.iter().map(|p| p.bytes_recv).sum();

    // by protocol
    let all_conns = agg.top_connections(1000);

    let tcp_bytes: u64 = all_conns.iter().filter(|c| c.protocol == "TCP")
        .map(|c| c.bytes_sent + c.bytes_recv).sum();

    let udp_bytes: u64 = all_conns.iter().filter(|c| c.protocol == "UDP")
        .map(|c| c.bytes_sent + c.bytes_recv).sum();

    Snapshot {
        total_bytes: agg.total_bytes,
        total_packets: agg.total_packets,
        current_bps: agg.current_bps,
        current_out_bps: agg.current_out_bps,
        current_in_bps: agg.current_in_bps,
        active_procs: agg.active_process_count(),
        bw_history_out,
        bw_history_in,
        processes,
        hosts,
        top_conns,

        peak_out_bps,
        peak_in_bps,
        total_sent,
        total_recv,
        tcp_bytes,
        udp_bytes,
    }
}


#[derive(PartialEq, Clone, Copy)]
enum LeftTab {
    Summary,
    Processes,
}


#[derive(PartialEq, Clone, Copy)]
enum RightTab {
    Hosts,
    Connections,
}

#[derive(Default)]
struct ExportModal {
    open: bool,
    path_buf: String,       
    format: ExportFormat,
    status: Option<String>,
    status_ok: bool,
}
 
#[derive(PartialEq, Clone, Copy, Default)]
enum ExportFormat { #[default] Csv, Json }
 
// Log viewer state
#[derive(Default)]
struct LogViewer {
    open: bool,
}

pub struct App {
    aggregator: Arc<Mutex<Aggregator>>,
    rx: Receiver<PacketEvent>,
    iface: String,
    start: Instant,

    proc_perm_ok: bool,

    selected_pid: Option<u32>,
    right_tab: RightTab,
    controller: Arc<Mutex<TrafficController>>,
    auto_follow: bool,

    left_tab: LeftTab,

    filter_proc: String,
    filter_user: String,
    filter_proto: Option<String>,

    session_logger: Arc<Mutex<SessionLogger>>,
    export_modal: ExportModal,
    log_viewer: LogViewer,
    snapshot_count: usize,
}

impl App {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        aggregator: Arc<Mutex<Aggregator>>,
        rx: Receiver<PacketEvent>,
        iface: String,
        controller: Arc<Mutex<TrafficController>>,
        session_logger: Arc<Mutex<SessionLogger>>,
        

    ) -> Self {
        let mut vis = Visuals::dark();
        vis.panel_fill = PANEL_BG;
        vis.window_fill = CARD_BG;
        vis.extreme_bg_color = Color32::from_rgb(8, 5, 18);
        vis.widgets.noninteractive.bg_fill = CARD_BG;
        cc.egui_ctx.set_visuals(vis);

        // Check whether we can read other processes' fd directories.
        // /proc/1 (init/systemd) is always owned by root, so reading its fd/
        // dir is a reliable proxy for "do we have root/CAP_SYS_PTRACE?".
        let proc_perm_ok = std::fs::read_dir("/proc/1/fd").is_ok();

        let export_modal = ExportModal {
            path_buf: "./session.csv".to_string(),
            ..Default::default()
        };

        Self { 
            aggregator, 
            rx, 
            iface, 
            start: Instant::now(), 
            proc_perm_ok,
            selected_pid: None,
            right_tab: RightTab::Connections, 
            controller,
            auto_follow: true,

            left_tab:  LeftTab::Summary,

            filter_proc: String::new(),
            filter_user: String::new(),
            filter_proto: None,

            session_logger,
            export_modal,
            log_viewer: LogViewer::default(),
            snapshot_count: 0,
        }
    }



    // Take a snapshot of current connections into the session log.
    fn take_snapshot(&mut self) {
        let agg = self.aggregator.lock().unwrap();
        let records = agg.top_connections(1000);

        let mut logger = self.session_logger.lock().unwrap();
        logger.snapshot_connections(&records);
        self.snapshot_count += 1;
    }
 
    // Sync summary stats into the logger before export.
    fn sync_logger_summary(&self, snap: &Snapshot) {
        let mut logger = self.session_logger.lock().unwrap();
        logger.update_summary(
            snap.total_bytes,
            snap.total_packets,
            snap.peak_out_bps,
            snap.peak_in_bps,
            &self.iface,
        );
    }

}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // drain channel (cap at 8 k to stay responsive)
        {
            let mut agg = self.aggregator.lock().unwrap();
            for ev in self.rx.try_iter().take(8_192) {
                agg.ingest(ev);
            }
        }
        // Repaint at 2 Hz even when idle
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        let snap   = snapshot(&*self.aggregator.lock().unwrap());

        // if a PID is selected, pull its connections from the aggregator
        let detail_conns: Vec<ConnRow> = if let Some(pid) = self.selected_pid {
            self.aggregator.lock().unwrap()
                .connections_for_pid(pid)
                .iter()
                .map(|r| conn_row_from(r))
                .collect()
        } 

        else {
            Vec::new()
        };

        let uptime = self.start.elapsed().as_secs();
        let log_count = self.session_logger.lock().unwrap().connections.len();

        // header bar
        egui::TopBottomPanel::top("hdr")
            .frame(egui::Frame::none().fill(Color32::from_rgb(47, 25, 84)))
            .show(ctx, |ui| {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("AFASHTAK")
                            .strong()
                            .color(GREEN)
                            .size(17.0),
                    );
                    ui.separator();
                    ui.label(RichText::new(format!("if: {}", self.iface)).color(CYAN).monospace());
                    ui.separator();

                    ui.label(RichText::new(format!("⬆  {}/s", fmt_bytes(snap.current_out_bps as u64))).color(BLUE_OUT).strong());
                    ui.label(RichText::new("⬇").color(ORG_IN));
                    ui.label(RichText::new(format!("{}/s", fmt_bytes(snap.current_in_bps as u64))).color(ORG_IN).strong());

                    ui.separator();
                    ui.label(RichText::new(format!("total  {}", fmt_bytes(snap.total_bytes))).color(YELLOW));
                    ui.separator();
                    ui.label(RichText::new(format!("pkts  {}", snap.total_packets)).color(DIM));
                    ui.separator();
                    ui.label(RichText::new(format!("procs  {}", snap.active_procs)).color(CYAN));
                    ui.separator();
                    ui.label(RichText::new(format!("up  {}s", uptime)).color(DIM));
                    
                    // let ctrl = self.controller.lock().unwrap();
                    // let blocked = ctrl.blocked_list();
                    // if !blocked.is_empty() {
                    //     ui.separator();
                    //     ui.label(
                    //         RichText::new(format!("🚫 {} blocked", blocked.len()))
                    //             .color(Color32::from_rgb(255, 100, 80))
                    //             .small()
                    //             .strong(),
                    //     );
                    // }

                    let blocked_len = {
                    let ctrl = self.controller.lock().unwrap();
                    ctrl.blocked_list().len()
                    };

                    if blocked_len > 0 {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("🚫 {} blocked", blocked_len))
                                .color(Color32::from_rgb(255, 100, 80))
                                .small()
                                .strong(),
                        );
                    }
                    
                    ui.add_space(6.0);

                    let snap_label = format!("Snapshot ({})", self.snapshot_count);
                    if ui.add(
                        egui::Button::new(RichText::new(&snap_label).color(GREEN).small().strong())
                            .fill(Color32::from_rgb(35, 20, 55))
                    ).on_hover_text("Capture current connections into the session log").clicked() {
                        self.take_snapshot();
                    }

                    ui.add_space(4.0);

                    // Log viewer toggle
                    let log_label = format!("Log ({})", log_count);
                    let log_col   = if log_count > 0 { YELLOW } else { DIM };
                    if ui.add(
                        egui::Button::new(RichText::new(&log_label).color(log_col).small())
                            .fill(Color32::from_rgb(35, 20, 55))
                    ).on_hover_text("View session log entries").clicked() {
                        self.log_viewer.open = !self.log_viewer.open;
                    }

                    ui.add_space(4.0);

                    if ui.add(
                        egui::Button::new(RichText::new("Export").color(CYAN).small())
                            .fill(Color32::from_rgb(35, 20, 55))
                    ).on_hover_text("Export session log to CSV or JSON").clicked() {
                        self.export_modal.open = true;
                    }

                    });
                
            ui.add_space(6.0);

        });

        egui::TopBottomPanel::bottom("status")
            .frame(egui::Frame::none().fill(Color32::from_rgb(12, 8, 22)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(RichText::new("LIVE").color(GREEN).small());
                    ui.label(RichText::new("  Ctrl+C in terminal to exit").color(DIM).small());

                    if self.selected_pid.is_some() {
                        ui.separator();
                        ui.label(
                            RichText::new("ESC or click header to deselect process")
                                .color(YELLOW).small(),
                        );
                    }

                    // Show log record count in status bar
                    if log_count > 0 {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("{} log records -- {} snapshots", log_count, self.snapshot_count))
                                .color(DIM).small(),
                        );
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(8.0);

                        let peak_out = snap.bw_history_out.iter().map(|p| p[1] as u64).max().unwrap_or(0);
                        let peak_in  = snap.bw_history_in.iter().map(|p| p[1] as u64).max().unwrap_or(0);

                        ui.label(
                            RichText::new(format!(
                                "peak ⬆ {}/s  ⬇{}/s",
                                fmt_bytes(peak_out),
                                fmt_bytes(peak_in),
                            ))
                            .color(DIM).small(),
                        );
                    });
                });
            });


        // ESC clears process selection (FR9)
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.selected_pid = None;
        }


        // Export modal window
        if self.export_modal.open {
            let mut open = true;
            egui::Window::new("Export Session Log")
                .collapsible(false)
                .resizable(false)
                .default_width(420.0)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .open(&mut open)
                .show(ctx, |ui| {
                    draw_export_modal(ui, &mut self.export_modal, &self.session_logger, log_count);
                });
            if !open { self.export_modal.open = false; }
        }
 
        // Log viewer window
        if self.log_viewer.open {
            let mut open = true;
            egui::Window::new(format!("Session Log — {} records", log_count))
                .collapsible(true)
                .resizable(true)
                .default_width(820.0)
                .default_height(400.0)
                .open(&mut open)
                .show(ctx, |ui| {
                    draw_log_viewer(ui, &self.session_logger);
                });
            if !open { self.log_viewer.open = false; }
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(PANEL_BG).inner_margin(egui::Margin::same(10.0)))
            .show(ctx, |ui| {
                
                section_header(ui, "BANDWIDTH  (bytes / second)  ⬆outbound   ⬇inbound");

                let pts_out = PlotPoints::new(snap.bw_history_out.clone());
                let pts_in  = PlotPoints::new(snap.bw_history_in.clone());

                let latest_x = snap.bw_history_out.last().map(|p| p[0]).unwrap_or(0.0);

                // Recenter button shown when auto_follow is off
                ui.horizontal(|ui| {
                    if !self.auto_follow {
                        if ui.button(
                            RichText::new("⟳ Re-center").color(YELLOW).small().strong()
                        ).clicked() {
                            self.auto_follow = true;
                        }
                    } 
                    else {
                        ui.label(RichText::new("● LIVE").color(GREEN).small());
                    }
                });

                if self.auto_follow {
                    egui_plot::PlotMemory::load(ctx, egui::Id::new("bw"))
                        .map(|mut mem| {
                            mem.auto_bounds = egui::Vec2b::new(true, true);
                            mem.store(ctx, egui::Id::new("bw"));
                        });
                }

                let mut plot = Plot::new("bw")
                    .height(140.0)
                    .show_axes([true, true])
                    .x_axis_label("elapsed (s)")
                    .y_axis_label("bytes / s")
                    .include_y(0.0)
                    .set_margin_fraction(egui::Vec2::new(0.0, 0.12));

                // When re-centering, nuke the saved pan/zoom state completely
                if self.auto_follow {
                    plot = plot.reset();
                }

                let plot_response = plot.show(ui, |pu| {
                    pu.line(Line::new(pts_out).color(BLUE_OUT).width(1.8).name("⬆ Out B/s"));
                    pu.line(Line::new(pts_in).color(ORG_IN).width(1.8).name("⬇ In B/s").fill(0.0));
                });

                if plot_response.response.dragged()
                    || (plot_response.response.hovered() && ui.input(|i| i.raw_scroll_delta.length() > 0.0))
                {
                    self.auto_follow = false;
                }

                let table_h = ui.available_height() - 8.0;

                let total_w = ui.available_width();
                let left_w  = (total_w * 0.55).floor(); 
                let right_w = total_w - left_w - 8.0;

                ui.horizontal_top(|ui| {

                    // LEFT PANEL
                    ui.allocate_ui_with_layout(
                        egui::Vec2::new(left_w, table_h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.horizontal(|ui| {
                                let sum_sel  = self.left_tab == LeftTab::Summary;
                                let proc_sel = self.left_tab == LeftTab::Processes;

                                if ui.add(egui::SelectableLabel::new(
                                    sum_sel,
                                    RichText::new("SUMMARY")
                                        .color(if sum_sel { CYAN } else { DIM }).small().strong(),
                                )).clicked() {
                                    self.left_tab = LeftTab::Summary;
                                }

                                ui.label(RichText::new("|").color(DIM).small());

                                let proc_label = if let Some(pid) = self.selected_pid {
                                    format!("PROCESSES  (pid {} selected)", pid)
                                } else {
                                    "PROCESSES  (click to inspect)".to_string()
                                };

                                let proc_resp = ui.add(egui::SelectableLabel::new(
                                    proc_sel,
                                    RichText::new(&proc_label)
                                        .color(if proc_sel { CYAN } else { DIM }).small().strong(),
                                ));
                                if proc_resp.clicked() {
                                    self.left_tab = LeftTab::Processes;
                                }
                                if proc_resp.clicked() && proc_sel {
                                    self.selected_pid = None;
                                }
                            });

                            ui.separator();
                            ui.add_space(2.0);

                            egui::ScrollArea::vertical()
                                .id_source("left_panel")
                                .max_height(table_h)
                                .show(ui, |ui| {
                                    match self.left_tab {
                                        LeftTab::Summary => {
                                            draw_summary(ui, &snap, self.controller.lock().unwrap().blocked_list().len());
                                        }
                                        LeftTab::Processes => {
                                            draw_processes(ui, &snap, &mut self.selected_pid, &mut self.right_tab,
                                                &self.iface, self.proc_perm_ok, &self.controller);
                                        }
                                    }
                                });
                        },
                    );

                    ui.add_space(8.0); // space between panels

                    //  RIGHT PANEL
                    ui.allocate_ui_with_layout(
                        egui::Vec2::new(right_w, table_h),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.horizontal(|ui| {
                                let hosts_sel = self.right_tab == RightTab::Hosts;
                                let conn_sel  = self.right_tab == RightTab::Connections;

                                if ui.add(egui::SelectableLabel::new(
                                    hosts_sel,
                                    RichText::new("TOP REMOTE HOSTS").color(if hosts_sel { CYAN } else { DIM }).small().strong(),
                                )).clicked() {
                                    self.right_tab = RightTab::Hosts;
                                }

                                ui.label(RichText::new("|").color(DIM).small());

                                let conn_label = if let Some(pid) = self.selected_pid {
                                    format!("CONNECTIONS  (pid {})", pid)
                                } else {
                                    "CONNECTIONS  (all)".to_string()
                                };

                                if ui.add(egui::SelectableLabel::new(
                                    conn_sel,
                                    RichText::new(&conn_label).color(if conn_sel { CYAN } else { DIM }).small().strong(),
                                )).clicked() {
                                    self.right_tab = RightTab::Connections;
                                }
                            });

                            ui.separator();
                            ui.add_space(2.0);

                            ui.separator();
                            ui.add_space(2.0);

                            // Filter bar for the Connections tab
                            if self.right_tab == RightTab::Connections {
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(28, 20, 42))
                                    .inner_margin(egui::Margin::symmetric(6.0, 4.0))
                                    .rounding(egui::Rounding::same(4.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            //  Process filter 
                                            ui.label(RichText::new("proc").color(DIM).small());
                                            let pe = egui::TextEdit::singleline(&mut self.filter_proc)
                                                .desired_width(90.0)
                                                .hint_text("filter…")
                                                .font(egui::TextStyle::Monospace);
                                            ui.add(pe);

                                            ui.add_space(6.0);

                                            //  User filter 
                                            ui.label(RichText::new("user").color(DIM).small());
                                            let ue = egui::TextEdit::singleline(&mut self.filter_user)
                                                .desired_width(80.0)
                                                .hint_text("filter…")
                                                .font(egui::TextStyle::Monospace);
                                            ui.add(ue);

                                            ui.add_space(6.0);

                                            //  Protocol toggle buttons 
                                            for proto in &["ALL", "TCP", "UDP"] {
                                                let active = match *proto {
                                                    "ALL" => self.filter_proto.is_none(),
                                                    p     => self.filter_proto.as_deref() == Some(p),
                                                };
                                                let col = if active { CYAN } else { DIM };
                                                if ui.add(
                                                    egui::SelectableLabel::new(
                                                        active,
                                                        RichText::new(*proto).color(col).small().strong(),
                                                    )
                                                ).clicked() {
                                                    self.filter_proto = match *proto {
                                                        "ALL" => None,
                                                        p     => Some(p.to_string()),
                                                    };
                                                }
                                            }

                                            //  Clear button (only when a filter is active) 
                                            let any_active = !self.filter_proc.is_empty()
                                                || !self.filter_user.is_empty()
                                                || self.filter_proto.is_some();

                                            if any_active {
                                                ui.add_space(4.0);
                                                if ui.add(
                                                    egui::Button::new(
                                                        RichText::new("clear").color(RED_DIM).small()
                                                    ).frame(false)
                                                ).clicked() {
                                                    self.filter_proc.clear();
                                                    self.filter_user.clear();
                                                    self.filter_proto = None;
                                                }
                                            }
                                        });
                                    });

                                ui.add_space(3.0);
                            }

                            egui::ScrollArea::vertical()
                                .id_source("right_panel")
                                .max_height(table_h - 28.0)
                                .show(ui, |ui| {
                                    match self.right_tab {
                                        RightTab::Hosts => draw_hosts_table(ui, &snap.hosts),

                                        RightTab::Connections => {
                                            // pick raw slice (per-pid or global)
                                            let raw: &[ConnRow] = if self.selected_pid.is_some() {
                                                &detail_conns
                                            } else {
                                                &snap.top_conns
                                            };

                                            // apply filters
                                            let filtered = apply_conn_filters(
                                                raw,
                                                &self.filter_proc.clone(),
                                                &self.filter_user.clone(),
                                                &self.filter_proto.clone(),
                                            );

                                            // show match count when a filter is active
                                            let any_active = !self.filter_proc.is_empty()
                                                || !self.filter_user.is_empty()
                                                || self.filter_proto.is_some();

                                            if any_active {
                                                ui.label(
                                                    RichText::new(format!(
                                                        "{} / {} connections",
                                                        filtered.len(), raw.len()
                                                    ))
                                                    .color(DIM).small(),
                                                );
                                                ui.add_space(2.0);
                                            }

                                            draw_connections_table(ui, &filtered);
                                        }
                                    }
                                });
                        },
                    );
                });

                    
            });
        }
    }


//helpers
fn draw_summary(ui: &mut egui::Ui, snap: &Snapshot, blocked_count: usize) {
    let card_bg   = Color32::from_rgb(31, 22, 46);
    let card_dark = Color32::from_rgb(20, 14, 34);
    let full_w    = ui.available_width();

    // Stat cards 2 by 2 grid
    ui.columns(2, |cols| {
        stat_card(&mut cols[0], card_bg, "CURRENT BANDWIDTH",
            &format!("{}/s", fmt_bytes(snap.current_bps as u64)), GREEN,
            &format!("⬆ {}/s  ⬇ {}/s",
                fmt_bytes(snap.current_out_bps as u64),
                fmt_bytes(snap.current_in_bps as u64)));

        stat_card(&mut cols[1], card_bg, "TOTAL TRANSFERRED",
            &fmt_bytes(snap.total_bytes), YELLOW,
            &format!("{} packets", snap.total_packets));
    });

    ui.add_space(4.0);

    ui.columns(2, |cols| {
        stat_card(&mut cols[0], card_bg, "ACTIVE PROCESSES",
            &snap.active_procs.to_string(), CYAN,
            "using network now");

        let (blocked_val, blocked_col) = if blocked_count > 0 {
            (blocked_count.to_string(), RED_DIM)
        } else {
            ("0".to_string(), DIM)
        };
        stat_card(&mut cols[1], card_bg, "BLOCKED",
            &blocked_val, blocked_col,
            "processes blocked");
    });

    ui.add_space(8.0);

    // donut 
    sub_section_header(ui, "BANDWIDTH SHARE BY PROCESS");

    if snap.processes.is_empty() {
        ui.label(RichText::new("No process data yet…").color(DIM).small());
    } else {
        let total_bw: f64 = snap.processes.iter().map(|p| p.bw_bps).sum::<f64>().max(1.0);
        let show_n = snap.processes.len().min(7);

        // Use painter to draw the donut
        
        let donut_size = (full_w * 0.42).min(160.0); // slightly smaller so legend fits

        let (rect, _) = ui.allocate_exact_size(
            egui::Vec2::new(full_w, donut_size + 8.0),
            egui::Sense::hover(),
        );
        let painter = ui.painter();

        let legend_w  = 110.0_f32;   // reserved width for the legend on the right
        let donut_area_w = full_w - legend_w;
        let center = egui::Pos2::new(
            rect.min.x + donut_area_w / 2.0,  // horizontally centered in the donut area
            rect.center().y,
        );

        let r_outer = donut_size / 2.0;
        let r_inner = r_outer * 0.56;
        let gap_rad = 0.025_f32;

        // background ring
        painter.circle_stroke(
            center, r_outer,
            egui::Stroke::new(r_outer - r_inner, Color32::from_rgb(32, 22, 50)),
        );

        let mut start_angle: f32 = -std::f32::consts::FRAC_PI_2;

        for (i, proc) in snap.processes[..show_n].iter().enumerate() {
            let frac   = (proc.bw_bps / total_bw) as f32;
            let sweep  = frac * std::f32::consts::TAU - gap_rad * 2.0;
            if sweep <= 0.0 { continue; }

            let color  = DONUT_COLORS[i % DONUT_COLORS.len()];
            let mid_r  = (r_outer + r_inner) / 2.0;
            let steps  = ((sweep * mid_r) as usize).max(6);

            // draw arc as thick polyline segments
            let mut pts: Vec<egui::Pos2> = Vec::with_capacity(steps + 1);
            for s in 0..=steps {
                let a = start_angle + gap_rad + sweep * (s as f32 / steps as f32);
                pts.push(egui::Pos2::new(
                    center.x + mid_r * a.cos(),
                    center.y + mid_r * a.sin(),
                ));
            }
            let thickness = r_outer - r_inner - 1.0;
            painter.add(egui::Shape::line(pts, egui::Stroke::new(thickness, color)));

            start_angle += frac * std::f32::consts::TAU;
        }

        // center label
        painter.text(
            center,
            egui::Align2::CENTER_CENTER,
            fmt_bytes(snap.current_bps as u64),
            egui::FontId::proportional(11.0),
            CYAN,
        );
        painter.text(
            egui::Pos2::new(center.x, center.y + 13.0),
            egui::Align2::CENTER_CENTER,
            "/s",
            egui::FontId::proportional(9.0),
            DIM,
        );

        // legend to the right of donut
        let legend_x = rect.min.x + donut_area_w + 4.0;
        let mut ly   = rect.min.y + 6.0;
        for (i, proc) in snap.processes[..show_n].iter().enumerate() {
            let color = DONUT_COLORS[i % DONUT_COLORS.len()];
            let pct   = (proc.bw_bps / total_bw * 100.0) as u32;

            // color square
            painter.rect_filled(
                egui::Rect::from_min_size(egui::Pos2::new(legend_x, ly + 1.0), egui::Vec2::splat(9.0)),
                2.0,
                color,
            );
            // process name
            painter.text(
                egui::Pos2::new(legend_x + 13.0, ly + 5.0),
                egui::Align2::LEFT_CENTER,
                format!("{} {}%", truncate(&proc.name, 12), pct),
                egui::FontId::monospace(10.0),
                Color32::from_rgb(180, 185, 200),
            );
            ly += 18.0;
        }

        // "other" if processes were cut off
        if snap.processes.len() > show_n {
            let other_bw: f64 = snap.processes[show_n..].iter().map(|p| p.bw_bps).sum();
            let pct = (other_bw / total_bw * 100.0) as u32;
            if pct > 0 {
                painter.rect_filled(
                    egui::Rect::from_min_size(egui::Pos2::new(legend_x, ly + 1.0), egui::Vec2::splat(9.0)),
                    2.0,
                    DIM,
                );
                painter.text(
                    egui::Pos2::new(legend_x + 13.0, ly + 5.0),
                    egui::Align2::LEFT_CENTER,
                    format!("other {}%", pct),
                    egui::FontId::monospace(10.0),
                    DIM,
                );
            }
        }
    }

    ui.add_space(6.0);

    //  Direction split
    sub_section_header(ui, "DIRECTION SPLIT");

    let dir_total = (snap.total_sent + snap.total_recv).max(1) as f32;
    let out_frac  = snap.total_sent as f32 / dir_total;
    let in_frac   = snap.total_recv as f32 / dir_total;

    direction_bar(ui, "⬆", BLUE_OUT, out_frac, &fmt_bytes(snap.total_sent));
    ui.add_space(2.0);
    direction_bar(ui, "⬇", ORG_IN,   in_frac,  &fmt_bytes(snap.total_recv));

    ui.add_space(8.0);

    // Protocol breakdown
    sub_section_header(ui, "PROTOCOL BREAKDOWN");

    let proto_total = (snap.tcp_bytes + snap.udp_bytes).max(1) as f32;
    let tcp_frac    = snap.tcp_bytes as f32 / proto_total;
    let udp_frac    = snap.udp_bytes as f32 / proto_total;

    protocol_bar(ui, card_dark, "TCP", CYAN,   tcp_frac);
    ui.add_space(2.0);
    protocol_bar(ui, card_dark, "UDP", YELLOW, udp_frac);

    ui.add_space(8.0);

    // Session peaks
    sub_section_header(ui, "SESSION PEAKS");

    let peak_frame = egui::Frame::none()
        .fill(card_bg)
        .inner_margin(egui::Margin::same(8.0))
        .rounding(egui::Rounding::same(5.0));

    peak_frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            let col_w = (ui.available_width() - 16.0) / 3.0;

            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.label(RichText::new("PEAK ⬆ OUT").color(DIM).size(9.0));
                ui.label(RichText::new(format!("{}/s", fmt_bytes(snap.peak_out_bps as u64)))
                    .color(BLUE_OUT).monospace().size(12.0));
            });

            ui.separator();

            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.label(RichText::new("PEAK ⬇ IN").color(DIM).size(9.0));
                ui.label(RichText::new(format!("{}/s", fmt_bytes(snap.peak_in_bps as u64)))
                    .color(ORG_IN).monospace().size(12.0));
            });

            ui.separator();

            ui.vertical(|ui| {
                ui.set_width(col_w);
                ui.label(RichText::new("PEAK TOTAL").color(DIM).size(9.0));
                ui.label(RichText::new(
                    format!("{}/s", fmt_bytes((snap.peak_out_bps + snap.peak_in_bps) as u64)))
                    .color(GREEN).monospace().size(12.0));
            });
        });
    });

    ui.add_space(4.0);
}


// helper functions fr draw summary
fn stat_card(ui: &mut egui::Ui, bg: Color32, label: &str, value: &str, value_color: Color32, sub: &str) {
    let frame = egui::Frame::none()
        .fill(bg)
        .inner_margin(egui::Margin::symmetric(10.0, 8.0))
        .rounding(egui::Rounding::same(6.0));

    frame.show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(label).color(DIM).size(9.0));
        ui.add_space(2.0);
        ui.label(RichText::new(value).color(value_color).size(18.0).strong().monospace());
        ui.label(RichText::new(sub).color(DIM).size(10.0));
    });
}

fn sub_section_header(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).color(CYAN).size(9.0).strong());
    ui.add_space(4.0);
}

fn direction_bar(ui: &mut egui::Ui, icon: &str, color: Color32, frac: f32, label: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).color(color).size(12.0));
        ui.add(
            egui::ProgressBar::new(frac)
                .desired_width(ui.available_width() - 80.0)
                .fill(color),
        );
        ui.label(RichText::new(label).color(color).small().monospace());
    });
}

fn protocol_bar(ui: &mut egui::Ui, badge_bg: Color32, name: &str, color: Color32, frac: f32) {
    ui.horizontal(|ui| {
        // badge
        let badge_frame = egui::Frame::none()
            .fill(badge_bg)
            .inner_margin(egui::Margin::symmetric(6.0, 2.0))
            .rounding(egui::Rounding::same(3.0));
        badge_frame.show(ui, |ui| {
            ui.label(RichText::new(name).color(color).size(9.0).strong().monospace());
        });

        ui.add(
            egui::ProgressBar::new(frac)
                .desired_width(ui.available_width() - 46.0)
                .fill(color.linear_multiply(0.6)),
        );
        ui.label(RichText::new(format!("{:.0}%", frac * 100.0)).color(DIM).small());
    });
}

fn draw_processes(
    ui:           &mut egui::Ui,
    snap:         &Snapshot,
    selected_pid: &mut Option<u32>,
    right_tab:    &mut RightTab,
    iface:        &str,
    proc_perm_ok: bool,
    controller:   &Arc<Mutex<TrafficController>>,
) {
    if snap.processes.is_empty() {
        ui.add_space(12.0);
        if !proc_perm_ok {
            let warn_frame = egui::Frame::none()
                .fill(Color32::from_rgb(80, 30, 10))
                .inner_margin(egui::Margin::same(10.0))
                .rounding(egui::Rounding::same(4.0));

            warn_frame.show(ui, |ui| {
                ui.label(RichText::new("⚠  Missing permissions").color(YELLOW).strong());
                ui.add_space(4.0);
                ui.label(RichText::new(
                    "Process resolution requires reading\n\
                     /proc/<pid>/fd/ symlinks, which are\n\
                     restricted to root on Linux."
                ).color(DIM).small());
                ui.add_space(6.0);
                ui.label(RichText::new("Fix — restart as root:").color(DIM).small());
                ui.add_space(2.0);
                ui.label(RichText::new(format!("  sudo ./afashtak {iface}")).color(GREEN).monospace());
            });
        } else {
            ui.label(RichText::new("Waiting for resolvable traffic…").color(DIM));
            ui.add_space(4.0);
            ui.label(RichText::new(
                "Permissions OK. Traffic is arriving but\n\
                 no matching sockets found in /proc/net/tcp\n\
                 or /proc/net/udp yet."
            ).color(DIM).small());
        }
        ui.add_space(4.0);
        return;
    }

    egui::Grid::new("pg")
        .num_columns(7)
        .spacing([6.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            for h in &["#", "PID", "PROCESS", "USER", "B/S", "↑ SENT / ↓ RECV", "ACTION"] {
                ui.label(RichText::new(*h).color(DIM).small().strong());
            }
            ui.end_row();

            for (rank, row) in snap.processes.iter().enumerate() {
                let is_sel   = *selected_pid == Some(row.pid);
                let name_col = if is_sel { YELLOW } else { rank_color(rank) };
                let mut ctrl = controller.lock().unwrap();
                let blocked  = ctrl.is_blocked(row.pid);

                let r = ui.add(
                    egui::Label::new(
                        RichText::new(format!("{}", rank + 1)).color(name_col).small().strong()
                    ).sense(egui::Sense::click()),
                );
                if r.clicked() {
                    *selected_pid = Some(row.pid);
                    *right_tab    = RightTab::Connections;
                }

                ui.label(RichText::new(row.pid.to_string()).color(DIM).small().monospace());

                let rn = ui.add(
                    egui::Label::new(RichText::new(&row.name).color(name_col).monospace())
                        .sense(egui::Sense::click()),
                );
                if rn.clicked() {
                    *selected_pid = Some(row.pid);
                    *right_tab    = RightTab::Connections;
                }
                if rn.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }

                ui.label(RichText::new(&row.user).color(DIM).small());

                ui.vertical(|ui| {
                    ui.label(RichText::new(format!("{}/s", fmt_bytes(row.bw_bps as u64)))
                        .color(GREEN).small().monospace());
                    ui.add(
                        egui::ProgressBar::new(row.bw_frac)
                            .desired_width(90.0)
                            .fill(Color32::from_rgb(120, 60, 180)),
                    );
                });

                ui.vertical(|ui| {
                    ui.label(RichText::new(fmt_bytes(row.sent)).color(BLUE_OUT).small().monospace());
                    ui.label(RichText::new(fmt_bytes(row.recv)).color(ORG_IN).small().monospace());
                });

                let (label, color) = if blocked {
                    ("UNBLOCK", Color32::from_rgb(255, 100, 80))
                } else {
                    ("BLOCK",   Color32::from_rgb(255, 196, 68))
                };

                if ui.add(
                    egui::Button::new(RichText::new(label).small().color(color))
                        .min_size(egui::Vec2::new(60.0, 16.0))
                ).clicked() {
                    if blocked {
                        if let Err(e) = ctrl.unblock(row.pid) {
                            eprintln!("unblock failed: {e}");
                        }
                    } else {
                        if let Err(e) = ctrl.block(row.pid, row.uid, &row.name) {
                            eprintln!("block failed: {e}");
                        }
                    }
                }

                ui.end_row();
            }
        });
}


fn draw_connections_table(ui: &mut egui::Ui, rows: &[&ConnRow]) {
    if rows.is_empty() {
        ui.add_space(12.0);
        ui.label(RichText::new("No connections match.").color(DIM).small());
        return;
    }
 
    egui::Grid::new("cg")
        .num_columns(8)
        .spacing([6.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            for h in &["PROTO", "PROCESS", "USER", "REMOTE", "PORT", "↑SENT", "↓RECV", "AGE"] {
                ui.label(RichText::new(*h).color(DIM).small().strong());
            }
            ui.end_row();
 
            for row in rows {
                // Protocol badge with colour coding
                let proto_col = match row.protocol.as_str() {
                    "TCP" => CYAN,
                    "UDP" => YELLOW,
                    _ => DIM,
                };

                ui.label(RichText::new(&row.protocol).color(proto_col).small().monospace());
 
                // Process name + PID
                let proc_display = if row.pid > 0 {
                    format!("{}\n({})", row.proc_name, row.pid)
                } else {
                    row.proc_name.clone()
                };

                ui.label(RichText::new(proc_display).color(GREEN).small().monospace());
 
                ui.label(RichText::new(&row.username).color(DIM).small());
 
                // Remote address
                ui.label(RichText::new(&row.remote_addr).color(YELLOW).small().monospace());
 
                // Ports: local → remote
                ui.label(
                    RichText::new(format!("{}→{}", row.local_port, row.remote_port))
                        .color(DIM).small().monospace()
                );
 
                // sent/recv with direction colours
                ui.label(RichText::new(fmt_bytes(row.bytes_sent)).color(BLUE_OUT).small().monospace());
                ui.label(RichText::new(fmt_bytes(row.bytes_recv)).color(ORG_IN).small().monospace());
 
                // Age: colour shifts red if stale (>10 s since last packet)
                let age_col = if row.age_secs > 10 { RED_DIM } else { DIM };
                ui.label(RichText::new(format!("{}s", row.age_secs)).color(age_col).small().monospace());
 
                ui.end_row();
            }
        });
}


fn draw_hosts_table(ui: &mut egui::Ui, hosts: &[HostRow]) {
    egui::Grid::new("hg")
        .num_columns(4)
        .spacing([6.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            for h in &["#", "IP ADDRESS", "BYTES", "PKTS"] {
                ui.label(RichText::new(*h).color(DIM).small().strong());
            }
            ui.end_row();
 
            for (i, row) in hosts.iter().enumerate() {
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
 
            if hosts.is_empty() {
                ui.label(RichText::new("waiting for traffic…").color(DIM).small());
                ui.end_row();
            }
        });
}

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

fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        format!("{}…", &s[..s.char_indices().nth(max_chars - 1).map(|(i,_)| i).unwrap_or(s.len())])
    }
}

// for filtration
fn apply_conn_filters<'a>(
    rows:   &'a [ConnRow],
    proc:   &str,
    user:   &str,
    proto:  &Option<String>,
) -> Vec<&'a ConnRow> {
    let proc_lc  = proc.to_lowercase();
    let user_lc  = user.to_lowercase();

    rows.iter().filter(|r| {
        // process name substring match (case-insensitive)
        (proc_lc.is_empty()  || r.proc_name.to_lowercase().contains(&proc_lc))
        // user substring match (case-insensitive)
        && (user_lc.is_empty() || r.username.to_lowercase().contains(&user_lc))
        // protocol exact match, or None = show all
        && proto.as_deref().map_or(true, |p| r.protocol == p)
    }).collect()
}


fn draw_export_modal(
    ui: &mut egui::Ui,
    modal: &mut ExportModal,
    logger: &Arc<Mutex<SessionLogger>>,
    log_count: usize,
) {
    let has_data = log_count > 0;
 
    egui::Frame::none()
        .fill(CARD_BG)
        .inner_margin(egui::Margin::same(12.0))
        .rounding(egui::Rounding::same(6.0))
        .show(ui, |ui| {
            ui.label(RichText::new("SESSION LOG EXPORT").color(CYAN).strong());
            ui.add_space(6.0);
 
            // Record count
            if has_data {
                ui.label(
                    RichText::new(format!("📋 {} connection records ready to export.", log_count))
                        .color(GREEN).small(),
                );
            } else {
                ui.label(
                    RichText::new("⚠  No records in log yet. Press  ● Snapshot  first.")
                        .color(YELLOW).small(),
                );
            }
 
            ui.add_space(8.0);
 
            // Format selector
            ui.label(RichText::new("Format").color(DIM).small());
            ui.horizontal(|ui| {
                if ui.add(egui::SelectableLabel::new(
                    modal.format == ExportFormat::Csv,
                    RichText::new("CSV").color(if modal.format == ExportFormat::Csv { CYAN } else { DIM }).monospace(),
                )).clicked() {
                    modal.format = ExportFormat::Csv;
                    // update extension in path
                    if let Some(s) = modal.path_buf.strip_suffix(".json") {
                        modal.path_buf = format!("{}.csv", s);
                    }
                }
                if ui.add(egui::SelectableLabel::new(
                    modal.format == ExportFormat::Json,
                    RichText::new("JSON").color(if modal.format == ExportFormat::Json { CYAN } else { DIM }).monospace(),
                )).clicked() {
                    modal.format = ExportFormat::Json;
                    if let Some(s) = modal.path_buf.strip_suffix(".csv") {
                        modal.path_buf = format!("{}.json", s);
                    }
                }
            });
 
            ui.add_space(6.0);
 
            // Path input
            ui.label(RichText::new("Output path").color(DIM).small());
            ui.add(
                egui::TextEdit::singleline(&mut modal.path_buf)
                    .desired_width(380.0)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("./peeknet_session.csv"),
            );
 
            ui.add_space(8.0);
 
            ui.horizontal(|ui| {
                // Export button
                let export_btn = ui.add_enabled(
                    has_data && !modal.path_buf.trim().is_empty(),
                    egui::Button::new(RichText::new("Export").color(Color32::BLACK).strong())
                        .fill(GREEN),
                );
 
                if export_btn.clicked() {
                    let path = std::path::Path::new(modal.path_buf.trim());
                    let lg   = logger.lock().unwrap();
                    let result = match modal.format {
                        ExportFormat::Csv  => lg.export_csv(path),
                        ExportFormat::Json => lg.export_json(path),
                    };
                    match result {
                        Ok(()) => {
                            modal.status    = Some(format!("✓ Exported to {}", path.display()));
                            modal.status_ok = true;
                        }
                        Err(e) => {
                            modal.status    = Some(format!("✗ Error: {e}"));
                            modal.status_ok = false;
                        }
                    }
                }
 
                ui.add_space(8.0);
 
                // Clear log button
                if ui.add_enabled(
                    has_data,
                    egui::Button::new(RichText::new("Clear log").color(RED_DIM).small())
                ).clicked() {
                    logger.lock().unwrap().clear();
                    modal.status    = Some("Log cleared.".to_string());
                    modal.status_ok = true;
                }
            });
 
            // Status line
            if let Some(ref msg) = modal.status {
                ui.add_space(6.0);
                let col = if modal.status_ok { GREEN } else { RED_DIM };
                ui.label(RichText::new(msg).color(col).small().monospace());
            }
        });
}
 
// Log viewer window
 
fn draw_log_viewer(ui: &mut egui::Ui, logger: &Arc<Mutex<SessionLogger>>) {
    let lg = logger.lock().unwrap();
 
    if lg.connections.is_empty() {
        ui.add_space(12.0);
        ui.label(RichText::new("No records yet. press Snapshot  in the header bar.").color(DIM));
        return;
    }
 
    // Summary bar at top of viewer
    if let Some(ref s) = lg.summary {
        egui::Frame::none()
            .fill(Color32::from_rgb(22, 14, 36))
            .inner_margin(egui::Margin::symmetric(8.0, 5.0))
            .rounding(egui::Rounding::same(4.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("if: {}", s.iface)).color(CYAN).small().monospace());
                    ui.separator();
                    ui.label(RichText::new(format!("duration: {}s", s.duration_secs)).color(DIM).small());
                    ui.separator();
                    ui.label(RichText::new(format!("total: {}", fmt_bytes(s.total_bytes))).color(YELLOW).small());
                    ui.separator();
                    ui.label(RichText::new(format!("pkts: {}", s.total_packets)).color(DIM).small());
                    ui.separator();
                    ui.label(RichText::new(format!("peak ⬆ {}/s", fmt_bytes(s.peak_out_bps as u64))).color(BLUE_OUT).small());
                    ui.label(RichText::new(format!("⬇ {}/s", fmt_bytes(s.peak_in_bps as u64))).color(ORG_IN).small());
                });
            });
        ui.add_space(4.0);
    }
 
    egui::ScrollArea::vertical()
        .max_height(340.0)
        .show(ui, |ui| {
            egui::Grid::new("log_grid")
                .num_columns(9)
                .spacing([6.0, 3.0])
                .striped(true)
                .show(ui, |ui| {
                    for h in &["TIME", "PROCESS", "PID", "USER", "PROTO", "REMOTE", "PORT", "↑SENT", "↓RECV"] {
                        ui.label(RichText::new(*h).color(DIM).small().strong());
                    }
                    ui.end_row();
 
                    for c in lg.connections.iter() {
                        // Format unix timestamp as HH:MM:SS
                        let ts = format_unix_time(c.timestamp);
                        ui.label(RichText::new(&ts).color(DIM).small().monospace());
 
                        ui.label(RichText::new(&c.proc_name).color(GREEN).small().monospace());
                        ui.label(RichText::new(c.pid.to_string()).color(DIM).small().monospace());
                        ui.label(RichText::new(&c.username).color(DIM).small());
 
                        let proto_col = match c.protocol.as_str() {
                            "TCP" => CYAN,
                            "UDP" => YELLOW,
                            _ => DIM,
                        };
                        ui.label(RichText::new(&c.protocol).color(proto_col).small().monospace());
                        ui.label(RichText::new(&c.remote_addr).color(YELLOW).small().monospace());
                        ui.label(RichText::new(format!(":{}", c.remote_port)).color(DIM).small().monospace());
                        ui.label(RichText::new(fmt_bytes(c.bytes_sent)).color(BLUE_OUT).small().monospace());
                        ui.label(RichText::new(fmt_bytes(c.bytes_recv)).color(ORG_IN).small().monospace());
                        ui.end_row();
                    }
                });
        });
}
 
// Format a unix timestamp as a simple HH:MM:SS string
fn format_unix_time(unix: u64) -> String {
    let secs_in_day = unix % 86400;
    let h = secs_in_day / 3600;
    let m = (secs_in_day % 3600) / 60;
    let s = secs_in_day % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}