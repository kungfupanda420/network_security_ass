#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  echo "Error: You must run the Defense Engine as root (sudo)."
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 1

mkdir -p database logs

# Generate SSH honeypot key once if missing
if [ ! -f "logs/honeypot_rsa_key" ]; then
    ssh-keygen -t rsa -b 2048 -f logs/honeypot_rsa_key -N "" -q
fi

# Auto-detect LAN IP if not passed by start_all.sh
if [ -z "$HOST_IP" ]; then
    LAN_IFACE=$(ip route | awk '/default/ {print $5; exit}')
    HOST_IP=$(ip -4 addr show "$LAN_IFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
fi

# Compile silently unless an error occurs
BUILD_LOG=$(make clean 2>&1 && make 2>&1)
if [ $? -ne 0 ]; then
    echo "[-] Compilation failed:"
    echo "$BUILD_LOG"
    exit 1
fi

# Apply clean firewall baseline silently
chmod +x scripts/setup_iptables.sh
./scripts/setup_iptables.sh >/dev/null 2>&1

export HOST_IP
export LAN_IFACE

# Stream live defense engine logs unbuffered
stdbuf -oL -eL ./build/defense_engine