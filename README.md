<div align="center">

# Looker: High-Speed Rotating Proxy Infrastructure & Native MEGA Engine

**Next-generation, zero-install rotating proxy daemon and ultra-fast, quota-bypassing MEGA.nz downloader engineered in 100% memory-safe, clean-room Rust.**

[![Rust 1.80+](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Zero-Copy Architecture](https://img.shields.io/badge/Zero--Copy-MaxMind%20%26%20Raw%20Sockets-success.svg)](#critical-system-invariants)

</div>

---

## ⚡ The Consumption Gap: Why Looker?

Existing proxy scrapers (such as `monosans/proxy-scraper-checker`) do a fine job of dumping static lists of thousands of raw IP addresses into text files (`http.txt`, `socks5.txt`). However, **static lists leave a massive consumption gap**:

```
[ Scraper Dumps Text File ] ──> ??? (Manual configuration, dead IP failures, stalled downloads) ──> Application
```

Applications and tools cannot consume a text file of 5,000 raw proxies without building their own connection pools, health checkers, protocol negotiation, and failover handlers. Looker bridges this gap by turning public proxies into a **living, local, transparent gateway daemon**.

| Feature | Legacy Scrapers (e.g. `monosans/proxy-scraper-checker`) | **Looker (`looker-proxy` + `looker-gateway`)** |
| :--- | :--- | :--- |
| **Output Model** | Static text dumps (`http.txt`, `socks5.txt`) | **Live local rotating HTTP CONNECT gateway at `127.0.0.1:8080`** |
| **Application Integration** | Requires custom proxy rotation logic in every client tool | **Zero-config: `ALL_PROXY=http://127.0.0.1:8080 curl/looker-down`** |
| **In-Flight Failover** | None: dead proxy causes connection drop in client | **Pre-Commit Retry Rule: Gateway retries 3–5 proxies before sending `200 OK`** |
| **Protocol Support** | Separate checks for HTTP, SOCKS4, SOCKS5 | **Unified multi-protocol proxy pool with protocol auto-negotiation** |
| **GeoIP & ASN Resolution** | Often slow web API queries or missing | **Zero-copy memory-mapped offline MaxMind GeoLite2 resolver** |
| **Circuit Breakers** | None: dead proxies are retried repeatedly until re-scraped | **Lock-free atomic circuit breakers with exponential backoff** |
| **Latency Tracking** | Snapshot ping at scan time | **Dynamic Exponential Moving Average (EMA) latency ranking** |

---

## 🚀 Native Performance: looker-down vs. Legacy Java Downloaders

Legacy tools such as **MegaBasterd** pioneered proxy-based quota bypassing for MEGA.nz, but they suffer from severe JVM bottlenecks:

- **JVM Bloat & Heavy RAM Footprint:** Java downloaders frequently consume 500 MB – 2 GB of memory, causing garbage collection pauses and high CPU load during intensive parallel transfers.
- **GUI Lockups & Freezes:** Swing/JavaFX graphical interfaces frequently become unresponsive under high I/O throughput.
- **Memory Leaks during Long Runs:** Complex object graphs and chunk buffers degrade system performance over multi-gigabyte transfers.
- **Dependency Overhead:** Requires installing and configuring a full Java Runtime Environment (JRE).

### The Looker Solution (`looker-down`)
- **Zero-Install Single Binary:** Compiled to a tiny native binary with no runtime dependencies.
- **Negligible Footprint:** Operates smoothly under 20–30 MB of RAM with zero garbage collection overhead.
- **Native Cryptographic Acceleration:** Uses hardware-accelerated AES-NI instructions for AES-128-CTR stream decryption and chunk CBC-MAC integrity verification.
- **Non-Blocking Async I/O:** Powered by Tokio and asynchronous raw TCP pipelines for wire-speed network saturation.

---

## 🏛️ System Architecture

```
                       +---------------------------------------+
                       |        Public Proxy Feeds             |
                       |  (ProxyScrape, Monosans, TheSpeedX..) |
                       +-------------------+-------------------+
                                           |
                                    looker-scraper
                        (Async fetch, regex, bogon filter)
                                           |
                                           v
+------------------+              +------------------+
| looker-geo       | ---------->  | looker-pool      | <------- looker-protocol
| (MaxMind mmdb    |   (Geo/ASN)  | (Registry, CB,   |  (Raw SOCKS4/5/HTTP probe)
|  zero-copy mmap) |              |  latency ranking)|
+------------------+              +--------+---------+
                                           |
                                           v
                                  looker-gateway
                      (127.0.0.1:8080, Pre-Commit Retry Engine)
                                           ^
                                           |  (HTTP CONNECT tunnels)
                                           |
                                  looker-down CLI
                           (Parallel chunk downloader)
                                           |
                                           v
                                     looker-mega
                        (Key derivation, AES-CTR, CBC-MAC)
```

---

## 🛠️ Workspace Crates

| Crate | Path | Description |
| :--- | :--- | :--- |
| **`looker-protocol`** | [`crates/looker-protocol`](file:///crates/looker-protocol) | Raw byte-level SOCKS4/5 & HTTP CONNECT handshakes on `TcpStream`. |
| **`looker-geo`** | [`crates/looker-geo`](file:///crates/looker-geo) | Zero-copy offline MaxMind GeoLite2 reader via `memmap2`. |
| **`looker-scraper`** | [`crates/looker-scraper`](file:///crates/looker-scraper) | Async public proxy collector, multi-format extractor, bogon filter. |
| **`looker-pool`** | [`crates/looker-pool`](file:///crates/looker-pool) | Thread-safe proxy registry, atomic circuit breakers, latency ranking. |
| **`looker-gateway`** | [`crates/looker-gateway`](file:///crates/looker-gateway) | Local `127.0.0.1:8080` rotating proxy listener with pre-commit retries. |
| **`looker-mega`** | [`crates/looker-mega`](file:///crates/looker-mega) | MEGA.nz API client, key derivation, AES-128-CTR decryption, CBC-MAC. |
| **`looker-proxy`** | [`crates/looker-proxy`](file:///crates/looker-proxy) | Daemon & CLI binary: scraper + pool + gateway + file exporter. |
| **`looker-down`** | [`crates/looker-down`](file:///crates/looker-down) | Native CLI downloader: parallel chunking through local gateway. |

---

## 🚦 Quickstart Guide

### 1. Build from Source
Ensure you have a recent Rust toolchain installed (1.80+):
```bash
git clone https://github.com/looker-rs/looker.git
cd looker
cargo build --release
```

### 2. Start the Rotating Proxy Gateway Daemon
Launch the background proxy aggregator, embedded web dashboard, and gateway listener on `127.0.0.1:8080`:
```bash
./target/release/looker-proxy daemon --bind 127.0.0.1:8080 --scrape-interval 300
```

- **Web Dashboard:** Open [`http://127.0.0.1:8080/ui`](http://127.0.0.1:8080/ui) in any browser for live pool metrics, latency graphs, node health, and one-click downloader commands.
- **Live Proxy Feed:** [`http://127.0.0.1:8080/live.txt`](http://127.0.0.1:8080/live.txt)
- **JSON Pool Stats:** [`http://127.0.0.1:8080/status`](http://127.0.0.1:8080/status)

Verify the proxy gateway via command-line:
```bash
curl -x http://127.0.0.1:8080 https://api.ipify.org
```

### 3. Download Files & Entire Public Folders from MEGA
Download any public MEGA file or entire folder tree at wire speed through the rotating gateway:
```bash
# Download a single file:
./target/release/looker-down "https://mega.nz/file/xxxx#yyyy" -o output.bin --workers 16

# Download a complete folder tree (recursively recreates directory structure):
./target/release/looker-down "https://mega.nz/folder/xxxx#yyyy" -o ./downloads/ --workers 16
```

---

## 🔒 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
