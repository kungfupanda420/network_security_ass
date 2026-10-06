#!/bin/bash

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run this script as root (sudo)."
  exit 1
fi

echo "[*] Configuring baseline IPTables rules for Defense Engine..."

# 1. Flush all existing rules in the filter and nat tables
iptables -t filter -F
iptables -t filter -X
iptables -t nat -F
iptables -t nat -X

# 2. Set default policies to ACCEPT (so normal traffic flows freely)
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# 3. Allow established and related connections (keeps existing SSH sessions alive)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 4. Allow all local loopback traffic
iptables -A INPUT -i lo -j ACCEPT

echo "[+] IPTables successfully reset to clean baseline!"
echo "[+] Ready to launch the Defense Engine."