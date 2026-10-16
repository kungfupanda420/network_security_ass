# Adaptive Network Intrusion Detection & Honeypot System

**Course:** CS4031E Network Security  
**Institution:** NIT Calicut  

A custom-built, real-time Network Intrusion Detection System (NIDS) and Intrusion Prevention System (IPS) written in C for Linux environments. The system actively sniffs network traffic using raw sockets, identifies reconnaissance phases (port scans and stealth scans), and mitigates threats dynamically using a tiered response mechanism via Netfilter/IPTables.

## Features

* **Real-Time Packet Sniffing:** Bypasses standard OS network stacks using `SOCK_RAW` to capture TCP packets directly from the wire.
* **Stateful Threat Tracking:** Tracks connection states and unique port access per IP within rolling time windows (15 seconds) to identify aggressive probing.
* **Stealth Scan Classification:** Analyzes TCP flags to classify advanced Nmap scans (SYN, FIN, NULL, XMAS).
* **Adaptive Tiered Defense:**
  * **Tier 1 (Low Risk - 5 ports):** Silently logs the suspicious activity.
  * **Tier 2 (Medium Risk - 15 ports):** Transparently redirects the attacker to internal honeypots using NAT `PREROUTING`.
  * **Tier 3 (High Risk - 30+ ports):** Implements a kernel-level `DROP` via IPTables to permanently lock out the attacker.
* **Integrated Multi-Threaded Honeypots:** Runs lightweight, fake SSH (2222), FTP (2121), and HTTP (8080) services on background `pthreads` to trap redirected attackers and log their interaction payloads.
* **Live Threat Dashboard:** A Python Flask web interface that asynchronously polls an SQLite database to visualize attack origins, targeted ports, and real-time defense actions.

## Project Structure

```text
├── build/                  # Compiled C object files and the final binary
├── dashboard/              # Flask Web Dashboard (Module 7)
│   ├── app.py              # Flask backend API
│   └── templates/          # Jinja2 HTML templates (Dashboard, Threat Intel, Logs)
├── database/               # SQLite database storage
│   └── schema.sql          # Database initialization schema
├── scripts/                # Bash automation scripts
│   ├── cleanup_iptables.sh # Flushes rules post-testing
│   ├── run_detector.sh     # Master build and launch script
│   └── setup_iptables.sh   # Establishes clean firewall baselines
└── src/                    # C Engine Source Code
    ├── capture/            # Raw socket initialization and packet processing
    ├── detection/          # IP tracking, scan classification, and state logic
    ├── honeypot/           # Fake SSH, FTP, and HTTP pthread services
    ├── logging/            # SQLite interface and event formatting
    ├── response/           # IPTables execution and tiered response routing
    └── main.c              # Engine entry point and thread management
```

## Prerequisites

This system requires a Linux environment (Ubuntu recommended) with root privileges for raw socket and Netfilter access.

```bash
# Install C compiler and SQLite development libraries
sudo apt update
sudo apt install build-essential libsqlite3-dev

# Install Python requirements for the dashboard
sudo apt install python3-flask
```

## Installation & Usage

1. **Clone the repository and make scripts executable:**
   ```bash
   chmod +x scripts/*.sh
   ```

2. **Launch the Core Defense Engine:**
   This script automatically compiles the C code, cleans the firewall state, initializes the database, and starts the raw socket listener and honeypot threads.
   ```bash
   sudo ./scripts/run_detector.sh
   ```

3. **Launch the Live Dashboard (Open a new terminal):**
   ```bash
   cd dashboard
   sudo python3 app.py
   ```
   Navigate to `http://localhost:5000` in your web browser to view the live dashboard.

## Testing the System

You can test the system's defenses from a secondary device (e.g., a mobile phone running Termux or another laptop on the same network). Replace `192.168.x.x` with your host machine's IP.

**Trigger Tier 1 (Log):**
```bash
nmap -p 1-5 -T4 192.168.x.x
```
**Trigger Tier 2 (Honeypot Redirect):**
```bash
nmap -p 1-15,21,22 -T4 192.168.x.x
```
*(After reaching Tier 2, try running `ssh root@192.168.x.x` — you will be silently routed to the fake SSH trap).*

**Trigger Tier 3 (Firewall Drop):**
```bash
nmap -p 1-50 -T4 192.168.x.x
```

## Resetting the Environment

After an IP is blocked at Tier 3, all further communication from that IP is dropped by the kernel. To reset the firewall state and clear the blocks for subsequent tests:
```bash
sudo ./scripts/cleanup_iptables.sh
```
