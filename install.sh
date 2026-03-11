#!/bin/bash

# TraceFlow Secure Installation Script
# This script compiles TraceFlow and sets the necessary Linux capabilities
# for the privileged helper binary.

set -e

echo "--- Building TraceFlow (Release) ---"
cargo build --release

BIN_PATH="target/release/traceflow"
HELPER_PATH="target/release/traceflow-helper"
DEST_DIR="/usr/local/bin"

echo "--- Installing to $DEST_DIR (requires sudo) ---"
sudo cp "$BIN_PATH" "$DEST_DIR/traceflow"
sudo cp "$HELPER_PATH" "$DEST_DIR/traceflow-helper"

echo "--- Setting Linux Capabilities for Helper ---"
# cap_net_raw: For raw socket sniffing and ICMP traceroute
# cap_net_admin: For promiscuous mode and ARP/NDP scanning
sudo setcap cap_net_raw,cap_net_admin=eip "$DEST_DIR/traceflow-helper"

echo ""
echo "Success! You can now run TraceFlow by simply typing: traceflow"
echo "The UI runs as your normal user, while the helper handles privileged networking."
