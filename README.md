# AFASHTAK

> Real-time network monitoring and traffic control for Linux.

---

## Overview

**AFASHTAK** is a system-level network monitor written in Rust. It captures live traffic on any Linux interface, resolves packets to the owning process and user, and presents a live egui dashboard with the ability to block or unblock outbound traffic per process on the fly.

---

## Features

- Live packet capture via libpcap
- Maps sockets → PID → user by walking `/proc`
- Per-process bandwidth, bytes sent/received, and packet counts
- Inbound / outbound split with scrolling bandwidth plot
- Click any process to inspect its active connections
- Block / unblock outbound traffic via iptables (requires root)

---

## Requirements

- **OS:** Linux
- **Privileges:** Must run as root (`sudo`)
- **Rust:** stable, 2021 edition or later

```toml
[dependencies]
pcap = "2.2"
eframe = { version = "0.28", default-features = true }
egui_plot = "0.28"
```

---

## Usage

```bash
git clone https://github.com/TonyG000/Linux-Network-Monitor-Controller.git
cd Linux-Network-Monitor-Controller

# List available interfaces
sudo cargo run

# Capture on a specific interface
sudo cargo run eth0
sudo cargo run wlan0
sudo cargo run any
```

---

## Dashboard

| Area | Description |
|---|---|
| **Header** | Live bandwidth, total bytes, packet count, active processes |
| **Bandwidth plot** | Scrolling in/out graph — drag to pan, scroll to zoom, click Re-center to go live |
| **Summary tab** | Bandwidth donut, direction split, protocol breakdown, session peaks |
| **Processes tab** | Ranked by bandwidth; click a row to filter connections to that PID |
| **Connections tab** | Active connections with protocol, remote addr, ports, bytes, age |
| **Hosts tab** | Top remote IPs by total bytes |

- Press **ESC** or click the panel header to deselect a process.
- **BLOCK / UNBLOCK** inserts or removes an `iptables OUTPUT DROP` rule for the process's UID.
- Use **Snapshot** to capture the current connections into the session log, then **Export** to CSV or JSON.

---

## Notes

- Running without `sudo` will fail at the libpcap step and disable traffic blocking.
- The GUI shows a permission warning if `/proc/<pid>/fd/` cannot be read.
- Use interface `any` to capture across all interfaces simultaneously.

---
## Authors
- Habiba Elsayed
- Mahinour Abdelgawad
- Omar Leithy
- Tony Gerges

*Built as a course project for CSCE3401: Operating Systems, Spring 2026 at The American University in Cairo*