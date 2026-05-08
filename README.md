# Linux Network Monitor & Controller

> A real-time network monitoring and traffic control tool for Linux, built to fill the gaps left by existing tools like Nethogs, Iftop, Wireshark, and Sniffnet.

---

## Overview

**Linux Network Monitor & Controller** is a system-level network monitoring application written in Rust. It captures live traffic on any Linux network interface, resolves packets to the owning process and user, and presents a real-time egui dashboard with the ability to block or unblock outbound traffic for individual processes on the fly.

---

## Features

| Feature | Description |
|---|---|
| **FR1** Real-time capture | Live packet capture on any Linux NIC via libpcap |
| **FR2** Header extraction | Extracts src/dst IP, src/dst port, protocol, and size from every IPv4 frame |
| **FR3** Process resolution | Maps each socket to the owning PID by walking `/proc/net/{tcp,udp}` and `/proc/*/fd/` |
| **FR4** User resolution | Resolves the UID of each process to a human-readable username via `/etc/passwd` |
| **FR5** Statistics aggregation | Tracks bytes sent/received, packet counts, and sliding-window bandwidth per process |
| **FR6** Live dashboard | Real-time egui GUI with bandwidth plot, top-process panel, and top-host panel |
| **FR7** Process ranking | Processes sorted by current bandwidth with inline progress bars |
| **FR8** Traffic direction | Bandwidth history and per-process stats split into inbound and outbound |
| **FR9** Connection detail view | Click any process row to inspect its active connections with port, byte, and age info |
| **FR10** Traffic control | Block / unblock outbound traffic for any process via iptables (requires root) |
| **FR14** Interface selector | Enumerates available NICs at startup; user selects one as a CLI argument |

---

### Module Summary

| File | Responsibility |
|---|---|
| `main.rs` | Entry point; wires capture thread, aggregator, GUI, and traffic controller |
| `capture.rs` | libpcap wrapper; Ethernet/SLL frame parsing; `Packet` type |
| `process.rs` | `/proc` walking to resolve sockets → PID → UID → username |
| `stats.rs` | `Aggregator`, `ProcessStats`, `ConnectionRecord`, bandwidth history |
| `gui.rs` | egui/eframe dashboard; process table; connection detail panel |
| `control.rs` | iptables-based outbound traffic blocking per UID |

---

## Requirements

- **OS**: Linux (uses `/proc/net/tcp`, `/proc/net/udp`, `/proc/*/fd/`)
- **Privileges**: Must be run as `root` (sudo)
- **Rust toolchain**: stable, 2021 edition or later

### Cargo dependencies

```toml
[dependencies]
pcap = "2.2"
eframe = { version = "0.28", default-features = true}
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
sudo cargo run any # all interfaces
```

> **Note:** Running without `sudo` will fail at the libpcap open step and at any traffic-blocking action. The GUI will also display a permission warning if `/proc/<pid>/fd/` cannot be read.

---

## Dashboard

```
┌── NETMONITOR  if: any  ⬆ 1.2 MB/s  ⬇ 340 KB/s  total 4.8 GB  procs 12  up 47s ──┐
│                                                                                       │
│  BANDWIDTH (bytes / second)  ⬆ outbound  ⬇ inbound                                  │
│  [════════════════════════════════ live plot ══════════════════════════════════════]  │
│                                                                                       │
│  TOP PROCESSES (by bandwidth)     │  TOP REMOTE HOSTS  |  CONNECTIONS (all)          │
│  #  PID   PROCESS   USER  B/S     │  #  IP ADDRESS      BYTES   PKTS                 │
│  1  1234  firefox   alice 900KB/s │  1  142.250.x.x   ████ 2.1 GB                   │
│  2  5678  curl      root  120KB/s │  2  93.184.x.x    ██   400 MB                   │
│  ...                [BLOCK]       │  ...                                              │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

- **Click a process row** to filter the Connections panel to that PID only. Press `ESC` or click the panel header to deselect.
- **BLOCK / UNBLOCK** buttons insert or remove an `iptables OUTPUT DROP` rule scoped to the process's UID.
- **Drag or scroll** the bandwidth plot to pan/zoom; click **Re-center** to return to live tracking.

---