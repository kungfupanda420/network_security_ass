#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Run with sudo: sudo ./scripts/start_all.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

mkdir -p database logs
chmod +x scripts/*.sh

# Detect active LAN interface and IP
LAN_IFACE=$(ip route | awk '/default/ {print $5; exit}')
HOST_IP=$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
HOST_IP=${HOST_IP:-127.0.0.1}

# 1. Refresh IPTables silently
./scripts/reset_iptables.sh >/dev/null 2>&1

# 2. Start Python Flask dashboard silently in the background
python3 "$ROOT_DIR/dashboard/app.py" > "$ROOT_DIR/logs/dashboard.log" 2>&1 &
FLASK_PID=$!

cleanup() {
    pkill -P "$FLASK_PID" >/dev/null 2>&1
    kill "$FLASK_PID" >/dev/null 2>&1
    "$ROOT_DIR/scripts/reset_iptables.sh" >/dev/null 2>&1
    exit 0
}
trap cleanup INT TERM EXIT

# 3. Print ONLY the IP and Dashboard link first
echo "Host IP   : $HOST_IP"
echo "Dashboard : http://$HOST_IP:5000"
echo "----------------------------------------------------------"

# 4. Run detector and stream ONLY its logs (also saved to logs/detector.log)
export HOST_IP
export LAN_IFACE
export QUIET_SETUP=1
./scripts/run_detector.sh 2>&1 | tee -a "$ROOT_DIR/logs/detector.log"