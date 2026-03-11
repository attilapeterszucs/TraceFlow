#!/bin/bash

# TraceFlow Secure Installation Script
# This script compiles TraceFlow and sets the necessary Linux capabilities
# so it can be run without sudo.

set -e

echo "--- Building TraceFlow (Release) ---"
cargo build --release

BINARY_PATH="target/release/traceflow"
DEST_PATH="/usr/local/bin/traceflow"

echo "--- Installing to $DEST_PATH (requires sudo) ---"
sudo cp "$BINARY_PATH" "$DEST_PATH"

echo "--- Setting Linux Capabilities ---"
# cap_net_raw: For raw socket sniffing and ICMP traceroute
# cap_net_admin: For promiscuous mode and ARP scanning
sudo setcap cap_net_raw,cap_net_admin=eip "$DEST_PATH"

echo ""
echo "Success! You can now run TraceFlow by simply typing: traceflow"
echo "Note: No sudo is required anymore."
