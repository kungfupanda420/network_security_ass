#!/bin/bash

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Error: You must run the Defense Engine as root (sudo)."
  exit 1
fi

echo "=========================================================="
echo "  Adaptive Network Intrusion Detection & Honeypot System  "
echo "=========================================================="
echo ""

# 1. Ensure we are in the project root directory
SCRIPT_DIR=$(dirname "$0")
cd "$SCRIPT_DIR/.." || exit

# 2. Prepare the database directory
mkdir -p database logs

# 3. Compile the C project
echo "[*] Compiling the C engine..."
make

if [ $? -ne 0 ]; then
    echo "[-] Compilation failed! Please check the C code."
    exit 1
fi

# 4. Run the IPTables setup script to ensure a clean state
echo "[*] Applying clean firewall baseline..."
./scripts/setup_iptables.sh

# 5. Execute the compiled binary
echo "[*] Starting the Defense Engine and Fake Honeypot Services..."
echo "----------------------------------------------------------"
./build/defense_engine