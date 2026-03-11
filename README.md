# TraceFlow: Terminal Internet Map 🛰️

Created by **Attila Peter Szucs**

TraceFlow is a high-performance, real-time Terminal User Interface (TUI) application designed to visualize and audit your machine's network traffic. Unlike traditional sniffers that present raw data, TraceFlow constructs a dynamic "map" of your connectivity—from the hardware on your local desk to the servers on the other side of the planet.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Language](https://img.shields.io/badge/language-Rust-orange.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

---

## 🌟 Features

### 1. Global Visualization
*   **High-Res Braille Map:** Utilizes Unicode Braille patterns to achieve 8x higher geographic resolution than standard ASCII.
*   **Real-Time Geo-Mapping:** Automatically projects destination IPs onto a world map using Latitude/Longitude coordinates.
*   **Directional Flow:** Animated pulses show data moving in real-time (`>>>` for uploads, `<<<` for downloads).

### 2. Deep Infrastructure Discovery
*   **Active Traceroute Engine:** Automatically discovers the full path of every connection (ISP hops, CDNs, backbone nodes).
*   **Latency Heatmaps:** Color-coded RTT (Round-Trip Time) metrics highlighting network congestion (Green <50ms, Yellow 50-150ms, Red >150ms).
*   **ASN & Org Identification:** Identifies the legal entity owning the remote server (e.g., "Google LLC", "Cloudflare").
*   **TLS SNI Sniffing:** Peeks at encrypted handshakes to identify website names (e.g., `discord.com`) even behind generic IPs.

### 3. Local System Integration
*   **Process Mapping:** Scans `/proc` to identify which local application (Firefox, Spotify, etc.) is responsible for a connection.
*   **LAN Topology:** A dedicated "Local Mode" that performs ARP scanning to map all devices on your current subnet (Printers, IoT, Phones).
*   **Hardware Fingerprinting:** Identifies the manufacturer of local devices via MAC OUI lookups (e.g., Apple, Tesla, Hewlett-Packard).

### 4. Security & Auditing
*   **Heuristic Alert Engine:** Persistent sidebar feed logging risks like cleartext passwords (HTTP/FTP), Tor relays, and VPN tunnels.
*   **Hex Dump Inspection:** One-key deep dive into the first 256 bytes of any packet for payload analysis.
*   **BPF Filtering:** Dynamic search bar to isolate traffic by protocol, port, or host.

---

## 🛠️ How It Works

TraceFlow operates using a **Privilege-Separated Architecture**:

1.  **The Sniffer:** A high-speed background thread uses `libpnet` to capture raw frames directly from the network interface.
2.  **The Resolver:** Asynchronous workers perform reverse DNS lookups, GeoIP coordinate fetches, and ASN identification without blocking the UI.
3.  **The Engine:** A stateful manager correlates incoming packets with Linux system inodes to find owning PIDs and process names.
4.  **The TUI:** Built with `Ratatui`, the interface renders at 20FPS, calculating dynamic layouts and Braille dot-density on the fly.

---

## 🚀 Installation

TraceFlow is written in Rust and requires `libpcap` development headers.

### Prerequisites (Arch Linux)
```bash
sudo pacman -S libpcap rustup
```

### Automatic Secure Install
The included `install.sh` script compiles the application and applies Linux **Capabilities**. This allows you to run TraceFlow **without sudo**, which is the most secure way to handle raw network data.

```bash
git clone https://github.com/your-repo/TraceFlow.git
cd TraceFlow
chmod +x install.sh
./install.sh
```

---

## 🎮 Controls

| Key | Action |
| :--- | :--- |
| **`Q`** | Quit application |
| **`L`** | Toggle View (World Map vs. Local LAN Topology) |
| **`P`** | **Pause/Resume** the traffic stream (Freeze for inspection) |
| **`I`** | Switch Network Interface (Popup Menu) |
| **`/`** | Open Filter Bar (e.g., type `tcp`, `port 443`, or `host 8.8.8.8`) |
| **`C`** | Clear map and traffic history |
| **`↑ / ↓`** | Navigate through the Traffic Sidebar |
| **`Enter`** | **Deep Inspect** selected connection (Hex Dump + Stats) |
| **`Esc`** | Close any active popup or menu |

---

## ⚖️ License
This project is licensed under the MIT License. Use it responsibly for network diagnostics and security auditing.
