# Looker - Native Rust Proxy Harvester, Local Gateway & Multi-Slot MEGA Downloader

> A self-contained Windows & Linux desktop app that scrapes and validates thousands of public proxies in the background and uses them to bypass MEGA transfer quota walls automatically.

[![Release](https://img.shields.io/github/v/release/x7ssss/looker?color=emerald)](https://github.com/x7ssss/looker/releases/latest)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Platform: Windows & Linux](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20(x64)-informational.svg)](https://github.com/x7ssss/looker/releases/latest)
[![Rust: 1.80+](https://img.shields.io/badge/Rust-1.80+-orange.svg)](https://www.rust-lang.org)

---

## Installation

Prebuilt standalone binaries and packages for Windows and Linux (x64) are available on the official releases page:

🔗 **[Download Latest Release (GitHub)](https://github.com/x7ssss/looker/releases/latest)**

### Windows (x64)
- 📥 **[Looker-Setup-x64.exe](https://github.com/x7ssss/looker/releases/latest)**
- Single native setup installer powered by Rust and Windows WebView2. No Java Runtime Environment (JRE), Python runtime, or manual proxy list juggling required. Simply run the installer and launch Looker.

### Linux (x64)
- 📥 **[Looker-Linux-x64.AppImage](https://github.com/x7ssss/looker/releases/latest)** or **[Looker-Linux-x64.deb](https://github.com/x7ssss/looker/releases/latest)**
- Compatible with Wayland and X11 desktop environments via native XDG Desktop Portal (`xdg-portal`).
- Requires WebKit2GTK 4.1 (`libwebkit2gtk-4.1-0`) on Debian/Ubuntu/Arch systems (`sudo apt install libwebkit2gtk-4.1-0`).
- To run the AppImage:
  ```bash
  chmod +x Looker-Linux-x64.AppImage
  ./Looker-Linux-x64.AppImage
  ```
- Or install the Debian package:
  ```bash
  sudo dpkg -i Looker-Linux-x64.deb
  ```

---

## Key Capabilities

- **Autonomous Proxy Engine:** Automatically pulls candidates from 52 verified public proxy feeds, validates up to 500 sockets concurrently with low-overhead TCP handshakes, seeds surviving nodes from previous sessions on boot, and exposes live local feeds (`http://127.0.0.1:8080/all.txt`, `socks5.txt`, `socks4.txt`, `http.txt`) for external tools.
- **Passive 509 Failover & Force Proxy Modes:** By default (Passive Mode), downloads stream directly over your primary connection at full ISP line speed. The instant MEGA returns an HTTP 509 bandwidth quota limit, Looker seamlessly fails active and remaining chunk workers over to verified rotating proxy nodes with per-IP cooldown tracking. Force Proxy mode routes all chunks through proxy nodes from byte zero.
- **In-Flight Decryption & Integrity Checks:** Streams and decrypts AES-128-CTR chunks directly into sparse destination files on disk without creating temporary chunk fragments. Supports optional cryptographic CBC-MAC checksum condensation to verify byte integrity against file keys on completion.
- **Interactive Folder Pruning & Persistent Queue:** Inspects modern (`/folder/{id}#{key}`) and legacy (`#F!{id}!{key}`) folder links, presenting an interactive folder hierarchy to selectively keep or remove specific files and subdirectories before downloading. All queue states, progress, and paused tasks survive application restarts.

---

## Troubleshooting Stalled Transfers

If a download or chunk worker appears to stall:

1. **Initial Proxy Validation Sweep:** When launching Looker fresh without cached proxies, allow 30–60 seconds for the background validation sweep to finish testing public sources and populate a pool of healthy SOCKS5 and HTTP proxies. You can monitor pool progress in the **Proxy Pool** tab or top status bar.
2. **Lowering Proxy Validation Concurrency:** On consumer-grade routers, testing 500 sockets simultaneously can saturate local NAT state tables. If your internet connection stutters during scrapes, reduce the checker concurrency in Settings.
3. **Windows Firewall Outbound Rules:** Ensure Looker has permission to establish outbound connections on non-standard ports (such as `1080`, `8080`, `3128`, `8888`), which public SOCKS/HTTP proxies utilize.
4. **Live Debug Console (Ctrl+Shift+D):** Press `Ctrl+Shift+D` (or choose **Debug -> Toggle Live Console** in the top bar) to open the built-in terminal drawer. This displays live chunk allocation, storage URL renewals (`gfs`), proxy cooldown events, and stall watchdog retries in real time. You can export logs directly via the **Save Debug Log** button.

---

## Build from Source

### Prerequisites
- [Rust 1.80+](https://rustup.rs/) (stable toolchain)
- Microsoft Visual C++ (MSVC) Build Tools

### Building
```powershell
# Clone repository
git clone https://github.com/x7ssss/looker.git
cd looker

# Run complete workspace test suite
cargo test --workspace

# Build optimized release CLI binaries (looker-proxy, looker-down)
cargo build --release

# Build native desktop application and NSIS installer
cd crates/looker-app
cargo install tauri-cli --version "^2.0.0" --locked
cargo tauri build --bundles nsis
```

The resulting standalone executable and setup wizard will be generated in `target/release/bundle/nsis/`.

---

## Disclaimer

Looker is an independent open-source network utility created for research, testing, and backup purposes. It is provided "as is" under the GNU General Public License v3.0 (GPL-3.0) without warranties of any kind. Looker is not affiliated with, endorsed by, or associated with MEGA Limited or any of its subsidiaries. Users are solely responsible for complying with MEGA's Terms of Service and applicable local laws in their jurisdiction.

---

## License

Copyright (C) 2026 x7ssss. Distributed under the [GNU General Public License v3.0](LICENSE).
