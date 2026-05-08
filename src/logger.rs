use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::stats::ConnectionRecord;

#[derive(Debug, Clone)]
pub struct LoggedConnection {
    pub timestamp: u64, 
    pub proc_name: String,
    pub pid: u32,
    pub username: String,
    pub protocol: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets: u64,
}

impl LoggedConnection {
    fn from_record(r: &ConnectionRecord) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        LoggedConnection {
            timestamp,
            proc_name: r.proc_name.clone(),
            pid: r.pid,
            username: r.username.clone(),
            protocol: r.protocol.clone(),
            remote_addr: r.remote_addr.clone(),
            remote_port: r.remote_port,
            local_port: r.local_port,
            bytes_sent: r.bytes_sent,
            bytes_recv: r.bytes_recv,
            packets: r.packets,
        }
    }
}

//  Session summary written once on export
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub start_unix:    u64,
    pub duration_secs: u64,
    pub total_bytes:   u64,
    pub total_packets: u64,
    pub peak_out_bps:  f64,
    pub peak_in_bps:   f64,
    pub iface:         String,
}

//  Logger
pub struct SessionLogger {
    pub connections: Vec<LoggedConnection>,
    pub summary: Option<SessionSummary>,
    start_unix: u64,
}

impl SessionLogger {
    pub fn new() -> Self {
        let start_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        SessionLogger {
            connections: Vec::new(),
            summary:     None,
            start_unix,
        }
    }

    // Snapshot all current connections from the aggregator into the log.
    // call this  from the GUI 
    pub fn snapshot_connections(&mut self, records: &[&ConnectionRecord]) {
        for r in records {
            // Avoid logging unknown/empty entries
            if r.pid == 0 && r.proc_name == "–" { continue; }
            self.connections.push(LoggedConnection::from_record(r));
        }
    }

    // Update the session summary (call before export)
    pub fn update_summary(
        &mut self,
        total_bytes:   u64,
        total_packets: u64,
        peak_out_bps:  f64,
        peak_in_bps:   f64,
        iface:         &str,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.summary = Some(SessionSummary {
            start_unix: self.start_unix,
            duration_secs: now.saturating_sub(self.start_unix),
            total_bytes,
            total_packets,
            peak_out_bps,
            peak_in_bps,
            iface: iface.to_string(),
        });
    }

    pub fn clear(&mut self) {
        self.connections.clear();
        self.summary = None;
        self.start_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    //  Export 
    pub fn export_csv(&self, path: &Path) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);

        // summary block at the top as comments
        if let Some(ref s) = self.summary {
            writeln!(w, "# Peeknet session export")?;
            writeln!(w, "# interface:     {}", s.iface)?;
            writeln!(w, "# start (unix):  {}", s.start_unix)?;
            writeln!(w, "# duration:      {}s", s.duration_secs)?;
            writeln!(w, "# total bytes:   {}", s.total_bytes)?;
            writeln!(w, "# total packets: {}", s.total_packets)?;
            writeln!(w, "# peak out bps:  {:.0}", s.peak_out_bps)?;
            writeln!(w, "# peak in bps:   {:.0}", s.peak_in_bps)?;
            writeln!(w, "#")?;
        }

        // header row
        writeln!(w, "timestamp,process,pid,user,protocol,remote_addr,remote_port,local_port,bytes_sent,bytes_recv,packets")?;

        for c in &self.connections {
            writeln!(
                w,
                "{},{},{},{},{},{},{},{},{},{},{}",
                c.timestamp,
                c.proc_name,
                c.pid,
                c.username,
                c.protocol,
                c.remote_addr,
                c.remote_port,
                c.local_port,
                c.bytes_sent,
                c.bytes_recv,
                c.packets,
            )?;
        }

        w.flush()
    }

    pub fn export_json(&self, path: &Path) -> std::io::Result<()> {
        let file = File::create(path)?;
        let mut w = BufWriter::new(file);

        writeln!(w, "{{")?;

        // summary object
        if let Some(ref s) = self.summary {
            writeln!(w, "  \"summary\": {{")?;
            writeln!(w, "    \"interface\": \"{}\",",     s.iface)?;
            writeln!(w, "    \"start_unix\": {},",        s.start_unix)?;
            writeln!(w, "    \"duration_secs\": {},",     s.duration_secs)?;
            writeln!(w, "    \"total_bytes\": {},",       s.total_bytes)?;
            writeln!(w, "    \"total_packets\": {},",     s.total_packets)?;
            writeln!(w, "    \"peak_out_bps\": {:.0},",   s.peak_out_bps)?;
            writeln!(w, "    \"peak_in_bps\": {:.0}",     s.peak_in_bps)?;
            writeln!(w, "  }},")?;
        }

        // connections array
        writeln!(w, "  \"connections\": [")?;
        let last = self.connections.len().saturating_sub(1);
        for (i, c) in self.connections.iter().enumerate() {
            let comma = if i < last { "," } else { "" };
            writeln!(w, "    {{")?;
            writeln!(w, "      \"timestamp\": {},",      c.timestamp)?;
            writeln!(w, "      \"process\": \"{}\",",    c.proc_name)?;
            writeln!(w, "      \"pid\": {},",             c.pid)?;
            writeln!(w, "      \"user\": \"{}\",",       c.username)?;
            writeln!(w, "      \"protocol\": \"{}\",",   c.protocol)?;
            writeln!(w, "      \"remote_addr\": \"{}\",",c.remote_addr)?;
            writeln!(w, "      \"remote_port\": {},",    c.remote_port)?;
            writeln!(w, "      \"local_port\": {},",     c.local_port)?;
            writeln!(w, "      \"bytes_sent\": {},",     c.bytes_sent)?;
            writeln!(w, "      \"bytes_recv\": {},",     c.bytes_recv)?;
            writeln!(w, "      \"packets\": {}",         c.packets)?;
            writeln!(w, "    }}{}", comma)?;
        }
        writeln!(w, "  ]")?;
        writeln!(w, "}}")?;

        w.flush()
    }
}