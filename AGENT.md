# Looker Permanent AI Agent Context (`AGENT.md`)

> **MANDATORY SESSION BOOTSTRAP INSTRUCTION:**
> At the start of **every** development session:
> 1. Read `AGENT.md` first to restore all architectural invariants, crate maps, and crypto rules into working memory.
> 2. Run `git status` to verify repository working tree state.
> 3. Inspect the **Development Roadmap & Task Checklist** below.
> 4. Select and execute the next unfinished phase or task without deviating from the core invariants.

---

## 1. Project Mission & High-Level Architecture

**Looker** is a high-performance, clean-room Rust ecosystem uniting two core components:
1. **`looker-proxy` (Rotating Proxy Gateway Daemon):** A zero-install, autonomous proxy daemon that scrapes raw public proxies, tests and validates them with low-overhead raw TCP handshakes, filters bogons, annotates with zero-copy MaxMind GeoIP/ASN, ranks proxies in a thread-safe latency-aware pool, and exposes a transparent local HTTP forward/CONNECT proxy at `127.0.0.1:8080` featuring **in-flight pre-commit retries**.
2. **`looker-down` (Wire-Speed Native MEGA Downloader):** A lightweight, multi-threaded CLI download engine that fetches large files from MEGA.nz via parallel chunking routed through the local `looker-proxy` gateway. It bypasses IP transfer quotas by distributing chunks across distinct outbound proxies, decrypting streams on-the-fly with AES-128-CTR and verifying file integrity with MEGA's condensated chunk CBC-MAC scheme.

```
                      +---------------------------------------+
                      |       Public Proxy Sources            |
                      |  (ProxyScrape, Monosans, TheSpeedX..) |
                      +-------------------+-------------------+
                                          |
                                    looker-scraper
                        (Async fetch, regex, bogon filter)
                                          |
                                          v
+------------------+             +------------------+
| looker-geo       | ----------> | looker-pool      | <------- looker-protocol
| (MaxMind mmdb    |  (Geo/ASN)  | (Registry, CB,   |  (Raw SOCKS4/5/HTTP probe)
|  zero-copy mmap) |             |  latency ranking)|
+------------------+             +--------+---------+
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

## 2. Critical System Invariants

### Invariant 1: Zero-Allocation / Low-Overhead Raw Socket Handshakes
- Handshakes (`crates/looker-protocol`) operate strictly on raw byte streams (`tokio::net::TcpStream` or types implementing `AsyncRead + AsyncWrite + Unpin`).
- **Forbidden:** Heavy HTTP clients (e.g., `reqwest`) or dynamic runtime allocations for proxy health probing and SOCKS/CONNECT handshakes.
- Handshakes must parse replies byte-by-byte or in small stack buffers.
- When parsing `HTTP CONNECT` upstream responses, **never** over-read bytes past `\r\n\r\n`, ensuring client-server payload bytes are preserved uncorrupted for bidirectional copying.
- For SOCKS5, the reply parser must strictly consume variable-length bound addresses (`0x01` IPv4 4B + 2B, `0x03` Domain 1B len + NB + 2B, `0x04` IPv6 16B + 2B).

### Invariant 2: The Pre-Commit Retry Rule (`looker-gateway`)
- When a client sends `CONNECT authority HTTP/1.1` to `looker-gateway`:
  1. The gateway acquires healthy proxy candidates from `looker-pool`.
  2. The gateway connects to the proxy and completes upstream `handshake_socks5`, `handshake_socks4`, or `handshake_http_connect`.
  3. **CRITICAL:** If upstream TCP connection or handshake fails, the gateway records the failure against that proxy in the pool and immediately retries with the next candidate (up to 3–5 attempts).
  4. Only **AFTER** upstream handshake succeeds does the gateway emit `HTTP/1.1 200 Connection Established\r\n\r\n` to the client.
  5. Once the 200 response is committed, the connection becomes an opaque bidirectional pipe (`tokio::io::copy_bidirectional`). Retries are impossible after commit.

### Invariant 3: AES-128-CTR Nonce & Counter Math (`looker-mega`)
- MEGA uses AES-128-CTR with a custom 128-bit counter vector:
  - High 64 bits: `Nonce64` (`[k4, k5]` big-endian words).
  - Low 64 bits: `BE64(block_index)` where `block_index = pos / 16`.
- **CRITICAL:** Only the lower 64 bits increment as blocks advance.
- The 128-bit AES key is derived as:
  ```rust
  aes_key[0] = k[0] ^ k[4];
  aes_key[1] = k[1] ^ k[5];
  aes_key[2] = k[2] ^ k[6];
  aes_key[3] = k[3] ^ k[7];
  ```

### Invariant 4: Chunk CBC-MAC Integrity & Condensation (`looker-mega`)
- Each logical chunk CBC-MAC is initialized with:
  ```rust
  let mut c = [nonce[0], nonce[1], nonce[0], nonce[1]]; // 16 bytes: Nonce64 || Nonce64
  ```
- For each 16-byte block $M_c$:
  $$C_{new} = \text{AES-ECB-Encrypt}(K_{aes}, C_{old} \oplus M_c)$$
- Partial trailing blocks ($< 16$ bytes) are padded with trailing zeros to 16 bytes before encryption.
- After all chunks are downloaded, file condensation folds all chunk MACs:
  - Initialize file MAC accumulation block $F = 0^{16}$.
  - For each chunk MAC $C_i$:
    $$F = \text{AES-ECB-Encrypt}(K_{aes}, F \oplus C_i)$$
  - Condensate $F = [f_0, f_1, f_2, f_3]$ (four 32-bit big-endian words) into two 32-bit words:
    ```rust
    let mac_w0 = f[0] ^ f[1];
    let mac_w1 = f[2] ^ f[3];
    ```
  - Verify that `mac_w0 == k[6]` and `mac_w1 == k[7]`.

### Invariant 5: Storage Node Fetching Strategy
- Storage URLs returned by MEGA API (`g` action) support path-based range slicing:
  `{storage_url}/{START}-{END}` where `START` and `END` are byte offsets.
- As a defensive fallback, standard HTTP `Range: bytes={START}-{END}` header is supported.
- Chunk sizing follows the official MEGA schedule:
  - Chunks 0..7: $(i + 1) \times 131072$ bytes (128 KiB, 256 KiB, ..., 1024 KiB).
  - Chunk 8+: Fixed at 1,048,576 bytes (1 MiB).
  - The final chunk is clamped to remaining file size.

### Invariant 6: Socket Buffer & Low-Latency Tuning
- All tunnel and client connections configure underlying OS sockets via `socket2`:
  - `TCP_NODELAY = true` (disable Nagle algorithm).
  - Send buffer: 16 KiB (`SO_SNDBUF = 16384`).
  - Receive buffer: 16 KiB (`SO_RCVBUF = 16384`).
  - TCP keepalive enabled (interval: 30s).

---

## 3. Full Crate Map & Responsibility Boundaries

| Crate | Purpose & Scope | Key Types & Public API |
| :--- | :--- | :--- |
| `crates/looker-protocol` | Wire-level proxy handshakes on raw sockets without allocations. | `ProxyProto`, `TargetAddr`, `handshake_socks5`, `handshake_socks4`, `handshake_http_connect`, `ProbeResult` |
| `crates/looker-geo` | Zero-copy offline IP geolocation and ASN identification via memory-mapped MaxMind `.mmdb`. | `GeoResolver`, `GeoInfo`, `Country`, `AsnInfo` |
| `crates/looker-scraper` | Public proxy scraper, multi-format candidate extractor, and bogon filter. | `ProxyScraper`, `SourceConfig`, `extract_candidates`, `is_bogon`, `CandidateProxy` |
| `crates/looker-pool` | Concurrent proxy registry with atomic circuit breakers and latency ranking. | `ProxyPool`, `ProxyItem`, `PoolStats`, `CircuitBreakerState`, `SelectionStrategy` |
| `crates/looker-gateway` | Transparent local HTTP CONNECT proxy listener at `127.0.0.1:8080` with in-flight pre-commit retries. | `ProxyGateway`, `GatewayConfig`, `run_gateway` |
| `crates/looker-mega` | MEGA.nz API client, link parsing, key derivation, AES-128-CTR decryption, CBC-MAC verification. | `MegaLink`, `MegaKey`, `MegaClient`, `ChunkIterator`, `ChunkInfo`, `MegaCbcMac` |
| `crates/looker-proxy` | Standalone CLI binary & background daemon orchestrating scraper, pool, gateway, and file exporter. | `main.rs`, CLI args: `daemon`, `scrape`, `check`, `export` |
| `crates/looker-down` | Native high-speed downloader CLI routing multi-threaded chunk streams through `looker-proxy`. | `main.rs`, CLI args: `<URL> -o <FILE> -c <CONCURRENCY> --gateway <PROXY>` |

---

## 4. Development Roadmap & Task Checklist

### Phase 1: Core Protocols & Cryptographic Primitives
- [x] Workspace `Cargo.toml` manifest & workspace dependencies configured.
- [x] Repository `AGENT.md` persistent context & `README.md` documentation.
- [x] `looker-protocol`: SOCKS5 handshake (IPv4, Domain, IPv6 + reply drain).
- [x] `looker-protocol`: SOCKS4 / SOCKS4a handshake (Domain + IPv4).
- [x] `looker-protocol`: HTTP CONNECT client handshake without header over-read.
- [x] `looker-geo`: Memory-mapped `GeoLite2-City` and `GeoLite2-ASN` zero-copy resolver.
- [x] `looker-mega`: Public link parser (v1 `#` and v2 `file/` formats).
- [x] `looker-mega`: 32-byte key derivation (AES key, Nonce64, MAC verification words).
- [x] `looker-mega`: AES-128-CBC attribute decryption (`MEGA` magic + JSON extraction).
- [x] `looker-mega`: Dynamic chunk schedule iterator (128 KiB to 1 MiB cap).
- [x] `looker-mega`: AES-128-CTR keystream & chunk CBC-MAC condensation.

### Phase 2: Active Validation Pipeline & Live Gateway Daemon
- [x] `looker-scraper`: `collect_all` concurrent harvester across `DEFAULT_SOURCES` with strict 10s timeouts and bogon drops.
- [x] `looker-scraper`: `ProxyChecker` bounded validation pipeline (500 max in-flight sockets via `Arc<Semaphore>`).
- [x] `looker-scraper`: Direct IP leak baselining and 3-tier anonymity classification (`Transparent`, `Anonymous`, `Elite`).
- [x] `looker-scraper`: Synchronous MaxMind GeoIP/ASN enrichment via `GeoResolver`.
- [x] `looker-pool`: Dynamic registration via `add_or_update(CheckedProxy)`.
- [x] `looker-pool`: Active circuit breaking (quarantines nodes after >= 2 failures) and lock-free selection.
- [x] `looker-pool`: Live proxy text exporter (`export_live_text`) and JSON pool stats (`PoolStats`).
- [x] `looker-gateway`: Pre-Commit Retry Rule (up to 4 upstream handshakes before committing `200 OK`).
- [x] `looker-gateway`: Integrated `GET /live.txt` (plain text proxy feed) and `GET /status` (JSON stats).
- [x] `looker-gateway`: Integration test suite (`retry_rule_test.rs`) verifying transparent retry and local endpoints.
- [x] `looker-proxy`: Background daemon orchestrating 15-minute re-harvest, validation, quarantine re-checks, and gateway.
- [x] `looker-proxy`: One-shot `scrape` command dumping verified proxies to `out/proxies.txt` and `out/proxies.json`.

### Phase 3: The Native MEGA Downloader Engine (looker-mega & looker-down)
- [x] `looker-mega`: `MegaClient::resolve_file` resolving handles via `https://g.api.mega.co.nz/cs` with quota detection (`EOVERQUOTA -17`, `ENOENT -9`, `EBLOCKED -16`).
- [x] `looker-mega`: Zero-IV AES-128-CBC attribute block decryption verifying `MEGA` magic prefix and extracting file metadata.
- [x] `looker-mega`: 32-byte key derivation ($k_0 \dots k_7$), `Nonce64 || BE64(pos / 16)` CTR keystream math with lower 64-bit incrementation.
- [x] `looker-mega`: `ChunkIterator` generating exact chunk schedule (128 KiB to 896 KiB linear scaling for chunks 0..7, 1 MiB fixed for chunk 8+).
- [x] `looker-mega`: `compute_chunk_mac` and `FileMacAccumulator` with 64-bit condensation folding `[(c0^c1), (c2^c3)]` verifying against `[k6, k7]`.
- [x] `looker-mega`: Integration unit test suite (`crypto_tests.rs`) covering key derivation vectors, arbitrary CTR offset decryption, CBC attribute decryption, and MAC folding.
- [x] `looker-down`: Sparse file allocation (`set_len`) on disk with zero temporary chunk files.
- [x] `looker-down`: Parallel chunk worker pool with MPSC queue, per-chunk 30s timeout, HTTP 509 / -17 quota detection, and automatic backoff/re-queueing through rotating gateway.
- [x] `looker-down`: Direct-to-offset sparse disk writing (`seek` + `write_all`) with in-flight AES-128-CTR decryption and CBC-MAC computation.
- [x] `looker-down`: Multi-progress `indicatif` UI rendering instantaneous transfer speed, ETA, chunk completion counters, and active proxy gateway indicators.
- [x] `looker-down`: Standalone CLI supporting `--output`, `--concurrency`, `--gateway`, and `--direct`.

### Phase 4: Public Folder Engine & Modern Dashboard Integration
- [x] `looker-mega`: Support parsing modern public folder URLs (`/folder/{id}#{key}`), subfile URLs (`/folder/{id}#{key}/file/{file_id}`), and legacy folder URLs (`/#F!{id}!{key}`).
- [x] `looker-mega`: 16-byte folder share key parser from Base64URL (`parse_folder_share_key`).
- [x] `looker-mega`: `MegaClient::fetch_folder_tree` querying `POST https://g.api.mega.co.nz/cs?id={seq}&n={folder_id}` with `[{"a":"f","c":1,"r":1,"ca":1}]`.
- [x] `looker-mega`: Node key unwrapping via AES-128-ECB (`unwrap_node_key`): 16-byte attribute keys for folders (`t = 1`), 32-byte keys for files (`t = 0`) folded into 16-byte AES key, 8-byte nonce, and expected MAC words.
- [x] `looker-mega`: Hierarchical folder tree parsing (`parse_folder_tree`) reconstructing nested directories and relative disk paths (`MegaFolderTree`, `MegaFolderNode`).
- [x] `looker-mega`: `MegaClient::get_folder_file_url` querying storage URL with `[{"a":"g","g":1,"n":"{handle}","ssl":2}]` (clean-room invariant: NEVER passing `"v":2`).
- [x] `looker-down`: Recursive batch folder download engine: pre-creates directory hierarchy, resolves URLs for each file node, runs downloads through parallel worker pool with sparse allocation, AES-128-CTR decryption, and CBC-MAC checksum validation.
- [x] `looker-gateway`: Embedded dark-mode single-page dashboard using `rust-embed` (`#[folder = "ui/dist"]`) served on `GET /ui`, `GET /ui/*`, and `GET /`.
- [x] `looker-gateway`: Real-time pool status polling (`GET /status`), proxy snapshot feed (`GET /api/proxies`), raw text export (`GET /live.txt`), and quick looker-down command generator.
- [x] Integration test suites: `crates/looker-mega/tests/folder_tests.rs` (link parsing, share key decoding, ECB unwrapping, path hierarchy) and `crates/looker-gateway/tests/retry_rule_test.rs` (UI & API routes).

### Phase 5: Production Hardening, Memory Optimization, and Cross-Platform CI/CD Matrix
- [x] Memory allocator optimization: Configured `mimalloc::MiMalloc` as `#[global_allocator]` in `looker-proxy` and `looker-down` to eliminate heap fragmentation under rapid concurrent socket recycling.
- [x] Graceful OS signal handling: Clean Ctrl-C / SIGINT shutdown using `tokio_util::sync::CancellationToken` across `looker-proxy` and `looker-down`.
- [x] `looker-proxy`: 3-second grace window for in-flight gateway tunnels via `tokio_util::task::TaskTracker` before hard aborting, and automatic export of healthy proxies to `out/proxies_last_shutdown.txt`.
- [x] `looker-down`: Safe interruption handling flushing in-memory chunks to disk without corrupting files, persisting session state to `.looker-resume`, and transparent resumption on subsequent runs.
- [x] Browser auto-launch: Added `--open` flag to `looker-proxy daemon` using `opener` to open `http://127.0.0.1:8080/ui` upon listener startup with headless fallback.
- [x] Production binary profile tuning in root `Cargo.toml`: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.
- [x] Cross-platform GitHub Actions release matrix (`.github/workflows/release.yml`): Windows (`x86_64-pc-windows-msvc`), static Linux musl (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` via `cross`), macOS Intel & Apple Silicon (`x86_64-apple-darwin`, `aarch64-apple-darwin`), SHA-256 checksums, and automated GitHub Releases.

### Phase 6: 52 Production Sources, Real-Time Streaming Architecture, and Premium UI Overhaul
- [x] `looker-scraper`: Ingestion of all 52 verified public endpoints from monosans/proxy-scraper-checker (21 HTTP, 8 SOCKS4, 23 SOCKS5) with concurrency of 24.
- [x] `looker-scraper`: Replaced batch waiting in `ProxyChecker` with `check_all_streaming` (concurrency 512, connect timeout 5.0s, total timeout 10.0s, target `ipv4.icanhazip.com:443`).
- [x] `looker-pool`: Real-time streaming proxy insertion (`add_or_update`) as candidate nodes survive verification without blocking on full batch completion.
- [x] `looker-pool`: Real-time tracking of top-10 lowest-latency surviving proxies (`fastest: Arc<RwLock<Vec<CheckedProxy>>>`).
- [x] `looker-gateway`: Live REST APIs:
  - `GET /api/status`: Real-time stats (`total_candidates`, `checked_count`, `working_count`, `quarantined_count`, `avg_latency_ms`, `is_scraping`).
  - `GET /api/fastest`: Top 10 fastest verified proxies with protocol tags and latency.
  - `GET /api/proxies`: Healthy proxy registry list supporting `?limit=N`.
  - `GET /live.txt`: Plain-text proxy stream.
- [x] `looker-gateway`: High-end dark theme dashboard at `http://127.0.0.1:8080/ui` with auto-refreshing metrics, live progress bar, realtime fastest nodes list, and searchable proxy table.

### Phase 7: Strict Protocol Segregation Across Exports, Gateway Endpoints, and Dashboard
- [x] `looker-pool`: Protocol-segregated exports via `ProxyPool::export_by_proto` returning raw `host:port\n` for a specific protocol (healthy nodes only).
- [x] `looker-pool`: Added `HealthyByProto` tracking per-protocol counts (`http`, `socks4`, `socks5`) in `PoolStats` and `ApiStatus`.
- [x] `looker-pool`: Added `ProxyPool::healthy_checked(&self) -> Vec<CheckedProxy>` and `ProxyItem::to_checked(&self) -> CheckedProxy`.
- [x] `looker-gateway`: Dedicated protocol feeds:
  - `GET /http.txt`: Raw `host:port\n` lines of healthy HTTP proxies.
  - `GET /socks4.txt`: Raw `host:port\n` lines of healthy SOCKS4 proxies.
  - `GET /socks5.txt`: Raw `host:port\n` lines of healthy SOCKS5 proxies.
  - `GET /all.txt` & `GET /live.txt` (alias): `proto://host:port\n` lines of all healthy proxies.
  - `GET /api/status`: Rich status including `healthy_by_proto: { http: usize, socks4: usize, socks5: usize }`.
- [x] `looker-proxy`: Structured disk output hierarchy matching production specifications on shutdown and on `looker-proxy scrape`:
  ```
  out/
  ├── proxies.json
  └── proxies/
      ├── all.txt
      ├── http.txt
      ├── socks4.txt
      └── socks5.txt
  ```
- [x] `looker-gateway/ui`: Modern protocol navigation with interactive pill filters (`[ All ] [ SOCKS5 ] [ SOCKS4 ] [ HTTP ]`) showing live counts, direct table filtering, header export badges (`all.txt`, `socks5.txt`, `socks4.txt`, `http.txt`), and per-protocol status breakdown.

### Phase 8: Proxy Filter Bugfix, Server-Side Pagination, and Web-Based MEGA Downloader UI
- [x] `looker-pool`: Extended `ProxyPool::api_proxies` to support `proto_filter: Option<ProxyProto>`, filtering healthy nodes before limit and latency sorting.
- [x] `looker-gateway`: Added server-side protocol query parameter `?proto=socks5|socks4|http|all` to `GET /api/proxies` with case-insensitive parsing.
- [x] `looker-gateway`: Implemented `DownloadManager` (`crates/looker-gateway/src/download.rs`) tracking background tasks, in-flight progress, dynamic transfer speed (MB/s), ETA calculation, and cancellation via `CancellationToken`.
- [x] `looker-gateway`: Exposed complete MEGA REST API suite:
  - `POST /api/mega/inspect`: Accepts `{ "url": "..." }`, resolves single file metadata or recursive folder tree via `looker-mega::fetch_folder_tree`.
  - `POST /api/mega/download`: Accepts `{ "url": "...", "selected_handles": [...], "output_dir": "..." }`, spawns background multi-worker chunk download tasks routing through local gateway with fallback.
  - `GET /api/mega/tasks`: Returns active and completed download jobs with real-time transfer metrics.
  - `POST /api/mega/tasks/:id/cancel`: Cancels running download tasks.
- [x] `looker-gateway/ui`: Upgraded dashboard with complete MEGA Downloader Studio:
  - URL input with animated loading spinner.
  - Interactive file selection card with checkboxes, path and size badges, "Select All" / "Deselect All", and dynamic selection summary.
  - Output directory selector (`./downloads`).
  - Active download task cards with animated progress bar, real-time speed, ETA, status pills, and cancellation controls.
  - Server-side protocol filtering on tab clicks (`/api/proxies?proto=...`).

### Phase 9: Native Desktop Shell & NSIS Setup Wizard (Tauri v2)
- [x] `looker-app`: Created native desktop application crate with Tauri v2 (`crates/looker-app`) wrapping the Looker gateway daemon, pool engine, and embedded UI into a native Windows window (WebView2).
- [x] `looker-app/tauri.conf.json`: Configured window properties (1280x800, min 900x600, centered, dark theme), icon assets (`icon.ico`, `icon.png`, `32x32`, `128x128`, `128x128@2x`), and NSIS installer target (`bundle.targets: ["nsis"]`).
- [x] `looker-app/src/main.rs`:
  - Suppressed console window in release builds with `#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]`.
  - Integrated `mimalloc` as global memory allocator.
  - Spawns background scraper & validation engine and local gateway server on `127.0.0.1:8080` using `tauri::async_runtime::spawn`.
  - Implemented window close interception (`WindowEvent::CloseRequested` -> `prevent_close()` and `window.hide()`) so closing the window minimizes to tray without dropping background proxy services or downloads.
  - Configured Windows system tray with context menu items: "Show Looker", "Open live.txt", and "Quit Looker" (with graceful proxy pool persistence to `out/proxies_last_shutdown.txt`).
  - Left-clicking system tray icon restores and focuses main window.
- [x] CI/CD Workflow (`.github/workflows/release.yml`):
  - Updated Windows release matrix to install Tauri CLI and build the NSIS installer via `cargo tauri build --target x86_64-pc-windows-msvc --bundles nsis`.
  - Packages standalone NSIS installer as `Looker-Setup-x64.exe` (and `Looker_x64-setup.exe`) in `dist/` alongside portable zip archives and SHA-256 checksums.

### Phase 10: MEGA Subfolder Deep-Link Parsing, Download Category & Folder Picker, and Tauri External Window Routing
- [x] `looker-mega`: Extended `MegaLink` parser to support subfolder and file deep-links:
  - `/folder/{root_id}#{key}/folder/{sub_folder_id}` -> `sub_folder_id: Some(sub_id)`.
  - `/folder/{root_id}#{key}/file/{target_file_id}` -> `target_file_id: Some(file_id)`.
  - Extracts 22-character Base64 share key cleanly without errors.
- [x] `looker-mega`: Implemented `MegaFolderTree::apply_scope`:
  - When `sub_folder_id` is present: scopes returned nodes to `target_h` and all recursive descendants whose parent chain reaches `target_h`. Recomputes relative paths so `target_h` acts as the download root.
  - When `target_file_id` is present: scopes to that single file node.
  - Integration tests in `crates/looker-mega/tests/folder_tests.rs`: verified `test_subfolder_deep_link_parsing` and `test_folder_tree_subfolder_and_file_scoping`.
- [x] `looker-gateway`: Safe default download directory resolution via `resolve_default_download_dir()` using `dirs::download_dir().join("Looker")`, falling back to `./downloads`.
- [x] `looker-gateway`: System REST API endpoints:
  - `GET /api/system/default-dir`: Returns JSON `{ "base_dir": "..." }`.
  - `POST /api/system/pick-folder`: Native folder selection dialog via `rfd::AsyncFileDialog::new().pick_folder().await`, returning `{ "path": "<selected_path>" }`.
  - `GET /favicon.ico`: Returns `204 No Content` to eliminate 405 console errors.
  - `POST /api/mega/download`: Recursively ensures output directory exists before worker allocation.
- [x] `looker-gateway/ui`: Upgraded MEGA Downloader UI:
  - Added `<link rel="icon" href="data:," />` in `<head>`.
  - Download category pills: `General` (`<base_dir>`), `Media & Video` (`<base_dir>/Media`), `Software & ISOs` (`<base_dir>/Software`), `Games` (`<base_dir>/Games`), `Archives` (`<base_dir>/Archives`).
  - Destination path input with real OS path + `Browse...` button connecting to `POST /api/system/pick-folder`.
- [x] `looker-app`: Configured programmatic `WebviewWindowBuilder` with `.on_new_window(|url, _features| { let _ = opener::open(url.as_str()); NewWindowResponse::Deny })` so `target="_blank"` links (`all.txt`, `socks5.txt`, etc.) open in the user's default browser instead of broken Webview2 popup windows.
- [x] `looker-down`: Integrated `link.is_folder_scope()` to automatically handle subfolders and folder file deep-links through the scoped tree batch download pipeline.

### Phase 11: MEGA Client HTTPS/TLS Hardening, Direct Metadata Routing, and Full Error Chain Reporting
- [x] `looker-mega/Cargo.toml`: Explicitly configured `reqwest` with `features = ["json", "rustls-tls", "socks", "stream"]` and updated workspace dependencies to eliminate TLS root issues.
- [x] `looker-mega/error.rs`: Upgraded `MegaError::Http` formatting with `format_error_chain(&dyn Error)` walking the complete `std::error::Error::source()` hierarchy and joining causes with `: `, ensuring root cause errors (such as TCP connection resets or certificate rejections) are never swallowed into a bare `"error sending request for url"`.
- [x] `looker-mega/api.rs`: Dual-client architecture in `MegaClient`:
  - **Direct HTTPS Client (`direct_http`)**: Dedicated direct connection with `rustls-tls`, 10s connect timeout, 20s total timeout, and explicit User-Agent for all metadata and control server API calls (`resolve_file`, `fetch_folder_tree`, `get_folder_file_url` to `https://g.api.mega.co.nz/cs`). Metadata queries bypass the public proxy gateway to eliminate inspection drops.
  - **Gateway Client (`gateway_http`)**: Optional proxy-routed client (`http://127.0.0.1:8080`) used by `chunk_client()` for high-throughput quota-bypassing payload transfers from `gfs*.userstorage.mega.co.nz`.
  - **Automated Retry & Fallback (`post_api`)**: Transient retry logic (up to 2 retries with 500ms backoff) on `g.api.mega.co.nz/cs` with automatic fallback to gateway proxy if direct access is blocked (e.g. ISP censorship).
- [x] `looker-gateway`: Wired direct metadata resolution in `POST /api/mega/inspect` and `POST /api/mega/download` via `MegaClient::new(Some(&gateway_url))`.
- [x] Integration tests: Added `test_mega_error_chain_formatting` and `test_mega_client_direct_and_gateway_routing` in `crates/looker-mega/tests/crypto_tests.rs`.

### Phase 12: Warm-Boot Proxy Seeding, Hard 3-Strike Eviction, and Periodic Clean Exports
- [x] `looker-pool`:
  - Added cumulative lifetime failure tracking (`total_failures: AtomicU32` in `ProxyItem` and `total_failures: u32` in `ProxySnapshot`).
  - Implemented Hard 3-Strike Eviction: When a proxy reaches 3 total failures in `record_failure` or `record_failure_by_addr`, it is permanently removed from the registry (`self.remove_item`) and fastest cache.
  - Implemented `ProxyPool::handle_check_failure`: If a quarantined proxy fails background re-verification, it is immediately evicted with zero retry delay.
  - Implemented `ProxyPool::prune_dead(&self) -> usize` removing all nodes with `total_failures >= 3`.
  - Implemented `export_disk_hierarchy` and `ProxyPool::export_to_dir(&self, out_dir: &Path)` synchronizing clean survivor-only dumps to disk:
    * `out/proxies.json` (structured JSON with latency and geo)
    * `out/proxies/all.txt` (`proto://host:port`)
    * `out/proxies/http.txt`, `socks4.txt`, `socks5.txt` (raw `host:port`)
- [x] `looker-scraper`:
  - Implemented `load_warm_boot_candidates<P: AsRef<Path>>(path: P) -> Vec<CandidateProxy>` reading previously saved survivors from `out/proxies.json`.
  - In `check_all_streaming`: checks surviving candidates and invokes `pool.handle_check_failure` on failed probes, followed by `pool.prune_dead()`.
- [x] `looker-proxy` & `looker-app`:
  - Priority Warm-Boot Seeding: On daemon/app startup, checks `out/proxies.json` and priority-verifies cached survivors through the streaming pipeline before fresh 52-source harvest, guaranteeing operational rotating proxies within 1-2 seconds of launch.
  - Periodic Clean Disk Sync: Automatically updates `out/proxies.json` and `out/proxies/*.txt` after every validation cycle (and on graceful shutdown/quit), eliminating dead proxy clutter.
- [x] Unit & Integration Tests:
  - Verified `test_hard_3_strike_eviction` in `looker-pool` (asserts registry proxy count decrements to 0 after 3 strikes).
  - Verified `test_quarantine_failed_reverification_eviction` in `looker-pool`.
  - Verified `test_export_to_dir_clean_sync` in `looker-pool`.
  - Verified `test_load_warm_boot_candidates` in `looker-scraper`.
  - Full workspace test suite passes with 34 green unit and integration tests.

### Phase 13: MegaBasterd Feature Parity (Interactive Folder Tree with Keep/Remove Selection, Legacy #F! Link Support, Persistent Batch Queue, Smart 509 Proxy Cooldowns, and Live Worker Controls)
- [x] Reference Audit & Clean-Room Extraction:
  - Audited MegaBasterd reference repository (`Download.java`, `ChunkDownloader.java`, `SmartMegaProxyManager.java`, `FolderLinkDialog.java`).
  - Extracted constants: 509 quota proxy ban window (`now + 60 minutes`, clamped between 10s and 3600s), legacy `#F!{id}@{sub_id}!{key}` subfolder syntax, and Keep/Remove selection algorithms.
  - Verified zero Java code left behind with full deletion of `temp_megabasterd`.
- [x] `looker-mega`:
  - Extended `MegaLink` parser to support legacy MegaBasterd link formats:
    * `#F!{id}!{key}` and `#F!{id}@{sub_id}!{key}` (parses `root_id = "{id}"`, `sub_folder_id = Some("{sub_id}")`, `key = "{key}"`, `is_folder = true`).
    * `#!{id}!{key}` legacy single file format.
    * Added `MegaLink::root_id(&self) -> &str` helper accessor.
  - Unit tests in `crates/looker-mega/src/link.rs` and `crates/looker-mega/tests/folder_tests.rs`: verified `test_legacy_megabasterd_subfolder_link_parsing`.
- [x] `looker-pool`:
  - Added `mega_cooldown_until: parking_lot::RwLock<Option<Instant>>` to `ProxyItem`.
  - Added `is_mega_cooldown(&self) -> bool`, `mark_mega_509_cooldown(&self, cooldown: Duration)`, `clear_mega_cooldown(&self)`, and `mega_cooldown_remaining_secs(&self) -> Option<u64>`.
  - When hitting HTTP 509 or `-17`: proxy is marked on MEGA cooldown for 60 minutes without incrementing general failure strikes or evicting from general HTTP/SOCKS routing.
  - Implemented `ProxyPool::get_mega_healthy_candidates(&self, max_candidates: usize)`: prioritizes healthy proxies that are not in MEGA cooldown.
  - Unit test in `crates/looker-pool/src/pool.rs`: verified `test_mega_509_cooldown_does_not_evict_from_general_pool`.
- [x] `looker-down`:
  - Added `--mode <passive|force_proxy>` flag (default `passive`).
  - Implemented dual-client worker architecture: direct host connection (`direct_http`) and rotating proxy gateway client (`proxy_http`).
  - Passive Mode: Chunks download at full host ISP speed until HTTP 509 or `-17` occurs, then automatically and seamlessly switches active and remaining chunk workers to the rotating proxy gateway without losing completed chunk data.
  - Force Proxy Mode: Chunks route through rotating gateway from byte 0.
- [x] `looker-gateway`:
  - Disk Space Pre-Check: Implemented `check_available_disk_space(&path, needed_bytes)` using Windows API `GetDiskFreeSpaceExW` to verify free space before allocating downloads; returns clear error if `total_selected_bytes > free_space`.
  - Live Worker & Engine Config (`GET /api/mega/config` & `POST /api/mega/config`):
    * `routing_mode`: "passive" vs "force_proxy"
    * `workers_per_file`: 1 to 24 (default 6)
    * `max_concurrent_files`: 1 to 5 (default 2)
    * `speed_limit_mbps`: live token-bucket `RateLimiter` (0 = unlimited)
  - Persistent Batch Queue:
    * Persists full queue state to `%LOCALAPPDATA%\looker\queue.json` on task creation, pause, progress, and completion.
    * On gateway startup, incomplete tasks reload in `TaskStatus::Paused` state, surviving application restarts.
    * Implemented pause/resume with chunk bitmap tracking (`POST /api/mega/tasks/:id/pause` flushes file buffers and saves chunk bitmap; `POST /api/mega/tasks/:id/resume` resumes remaining incomplete chunks).
    * Implemented `DELETE /api/mega/tasks/:id` removing tasks from memory and `queue.json`.
    * Implemented `POST /api/mega/tasks/:id/open-folder` opening destination directories in OS Explorer via `opener`.
  - Integration tests in `crates/looker-gateway/tests/retry_rule_test.rs`: verified `test_disk_space_and_config_validation` and live config endpoints.
- [x] `looker-gateway/ui/dist/index.html`:
  - Interactive Folder Link Modal (matching MegaBasterd's `FolderLink` workflow):
    * Collapsible nested directory/file tree showing folder names, filenames, and formatted sizes (`formatBytes`).
    * Multi-selection support: individual checkboxes, row click, `Ctrl+Click` (toggle), and `Shift+Click` (range selection).
    * Live search & extension filter (`.mp4`, keyword) with `Select All` and `Deselect All`.
    * Explicit **`KEEP THIS`** (Keep Selected) button removing all unselected/unhighlighted items.
    * Explicit **`REMOVE THIS`** (Remove Selected) button removing all selected items and their descendant subtrees.
    * Prominent live counter in modal header (`Selected: 14.20 GB (X / Y files)`) updating immediately.
    * Download category pills (`General`, `Media & Video`, `Software & ISOs`, `Games`, `Archives`) and native directory picker (`Browse...`) directly inside modal.
  - Multi-Link Inspector & Settings Bar:
    * Multi-line textarea supporting single or multiple newline-separated MEGA URLs.
    * Compact live settings bar: Routing Mode toggle, workers count, max concurrent files, and speed cap.
  - Transfer Queue UI:
    * Displays active queue items with Title, Category badge, Routing badge (`Passive Direct` vs `Proxy Gateway`), Active Workers count, Speed, ETA, and progress bar.
    * Action buttons: `[ Pause ]`, `[ Resume ]`, `[ Cancel ]`, `[ Open Folder ]`, and `[ Delete ]`.
- [x] Full workspace verification: 37 tests green across all crates, `cargo check -p looker-app` clean.

### Phase 14: Power-User Settings Suite (Clipboard Monitor, Slot Proxy Rotation, Stall Watchdog, Automation Hooks, and Settings Import/Export)
- [x] `looker-gateway` Settings Schema & REST Endpoints:
  - Created strongly typed `AppSettings` struct persisted to `%LOCALAPPDATA%\looker\settings.json` with 18 fields:
    * `default_download_dir`: OS `Downloads/Looker` fallback.
    * `temp_chunk_dir`: Option<String> optional staging directory for `.part` files before moving to final destination.
    * `max_parallel_downloads`: 1..=10 (default 3).
    * `slots_per_file`: 1..=24 (default 6).
    * `speed_limit_kbps`: u64 (0 = unlimited).
    * `verify_cbc_mac`: bool (default true - verifies in-flight and on-disk chunk condensation against expected `[k6, k7]`).
    * `clipboard_monitor`: bool (default false).
    * `auto_accept_folders`: bool (default false - auto-queues immediately without modal).
    * `freeze_before_start`: bool (default false - queues tasks in `Paused` state).
    * `routing_mode`: "passive" | "force_proxy" (default "passive").
    * `sticky_509_seconds`: u64 (default 3600 - holds proxy fallback for N seconds after host connection 509).
    * `proxy_selection_order`: "sequential" | "random" (default "sequential").
    * `reset_proxy_per_chunk`: bool (default true - acquires fresh proxy node per slot chunk so slots never stall on slow nodes).
    * `proxy_ban_seconds`: u64 (default 300 - cooldown duration on proxy error; 0 = permanent failure).
    * `stall_watchdog_seconds`: u64 (default 90 - streams chunk body with per-read timeout; drops stalled connection, cools down proxy, and retries chunk).
    * `upstream_proxy`: Option<String> for all outbound requests.
    * `cmd_on_509_limit`: Option<String> shell command executed on 509 limit (debounced once per 509 window).
    * `cmd_on_all_finished`: Option<String> shell command executed when active queue reaches 0 downloading tasks.
  - Exposed REST endpoints:
    * `GET /api/settings` -> returns current `AppSettings` JSON.
    * `POST /api/settings` -> validates, updates in-memory config, updates rate limiter, and saves `%LOCALAPPDATA%\looker\settings.json`.
    * `POST /api/settings/reset` -> restores factory defaults and persists.
- [x] `looker-pool` Proxy Selection Enhancements:
  - Implemented `ProxyPool::get_mega_healthy_candidates_ordered(&self, max_candidates: usize, order: &str) -> Vec<Arc<ProxyItem>>`:
    * `"sequential"`: ranks lowest latency first.
    * `"random"`: shuffles healthy non-509 nodes for even distribution.
- [x] `looker-gateway` Engine Integration:
  - Integrated `AppSettings` into `DownloadManager` with live synchronization to `DownloaderConfig` and `RateLimiter`.
  - Implemented sticky 509 timer tracking (`last_host_509_at`), routing chunks directly through proxies during sticky window.
  - Implemented per-chunk proxy rotation (`reset_proxy_per_chunk`) and slot candidate selection ordering.
  - Implemented stall watchdog streaming timeout (`stall_watchdog_seconds`) with `proxy_ban_seconds` cooldown and retry.
  - Implemented CBC-MAC integrity verification via `FileMacAccumulator` over on-disk chunk data.
  - Implemented temp chunk staging directory (`temp_chunk_dir`) with atomic rename/copy to target path upon successful validation.
  - Implemented shell command execution hooks via `tokio::process::Command` for 509 limits and queue completion.
- [x] `looker-gateway/ui/dist/index.html` Settings Drawer UI & Clipboard Monitor:
  - Added Settings gear button in top header bar next to gateway status pill.
  - Clean obsidian/emerald modal with 3 organized tabs:
    * Tab 1: **Downloads & Automation** (Folders, max files, slots, speed cap, CBC-MAC verify, clipboard monitor, auto-accept, freeze before start).
    * Tab 2: **SmartProxy & Routing** (Routing mode, selection order, reset per chunk, sticky 509 window, error ban time, stall watchdog, upstream proxy).
    * Tab 3: **Hooks & Backup** (Command on 509, command on all finished, Export JSON, Import JSON, Reset Defaults).
  - Clipboard Monitor: polls `navigator.clipboard.readText()` on window focus and interval for modern and legacy `mega.nz` URLs; auto-queues if `auto_accept_folders` is enabled, otherwise populates and opens the folder modal.
- [x] Full workspace verification: 40 tests green across all crates, `cargo check -p looker-app` clean.

### Phase 15: Chunk Stall Watchdog Fix, Live Rust Debug Console, and Complete Desktop UI/UX & Typography Overhaul
- [x] Strict Per-Read Stall Timeout on Chunk Streams (`looker-mega`, `looker-gateway`, `looker-down`):
  - Configured all HTTP/reqwest clients with explicit `connect_timeout(Duration::from_secs(8))` and `read_timeout(Duration::from_secs(15))` (or `stall_watchdog_seconds`).
  - Wrapped every `response.chunk().await` inside `tokio::time::timeout(watchdog_timeout, response.chunk())`.
  - When a chunk read times out or delivers 0 bytes within the watchdog window:
    * Immediately drop the stalled HTTP stream and close the underlying socket.
    * Logged detailed warning via `tracing::warn!` including file name, chunk index, byte offset, and stalled proxy endpoint.
    * Applied proxy cooldown ban (`proxy_ban_seconds`, default 300s) to mark the dead proxy so other workers skip it.
    * Re-queued the exact chunk onto a fresh proxy candidate without losing previously written chunks.
- [x] Automatic MEGA Temporary URL (`gfs`) Refresh & Speed Decay:
  - Implemented `refresh_file_download_url(folder_handle, file_handle)` in `looker-mega::api`.
  - When hitting HTTP 403, HTTP 509, or 3 consecutive chunk timeouts/errors, invalidates cached storage URL and queries `g.api.mega.co.nz/cs` (`a: "g"`) for a fresh storage URL.
  - Live download speed decays cleanly to `0.0 MB/s` within 2 seconds when no bytes arrive, avoiding frozen stale speed displays.
  - If all proxies in `ProxyPool` are temporarily on 509 cooldown or banned, logs `All proxies cooling down, waiting 10s before retrying...` and surfaces `cooling_down` status on the task row without spinning a tight CPU loop.
- [x] Decrypted Folder Title Preservation in Queue:
  - Updated `looker-mega::folder` to decrypt root node attributes using the folder share key directly when `unwrap_node_key` fails, exposing `tree.root_title()`.
  - Updated `POST /api/mega/download` and `start_download` to accept `title: Option<String>` and default to `tree.root_title()`, ensuring queue cards and destination directories preserve the decrypted name (e.g. `RRTVP017`) instead of `Folder_<id>`.
- [x] In-Memory Rust Tracing Buffer & Gateway Endpoints (`looker-gateway`, `looker-app`, `looker-proxy`):
  - Created `looker_gateway::logging`:
    * `DebugLogEntry`: `{ timestamp, level, target, message }`.
    * `LogBuffer`: thread-safe ring buffer (`Arc<RwLock<VecDeque<DebugLogEntry>>>`) capped at 2,000 entries.
    * `LogBufferLayer`: custom `tracing_subscriber::Layer` installed in `looker-app` and `looker-proxy`.
  - Endpoints:
    * `GET /api/debug/logs?limit=300` -> returns latest log entries as JSON.
    * `POST /api/debug/clear` -> clears in-memory log buffer.
    * `POST /api/system/open-devtools` -> triggers webview devtools in Tauri shell.
    * `POST /api/proxies/import` -> manually imports and registers proxy list into active pool.
  - Enabled `"devtools"` feature in `looker-app/Cargo.toml` and bound `F12` / `Ctrl+Shift+I` to open devtools even in release builds.
- [x] Non-Generic Desktop UI/UX & Typography Overhaul (`looker-gateway/ui/dist/index.html`):
  - Typography Scale: Replaced generic fonts with **Plus Jakarta Sans** (headings, buttons, UI) and **IBM Plex Mono** (endpoints, speeds, file sizes, logs).
  - Enforced strict minimum font size: `12px` (`text-xs`) metadata and `14px` (`text-sm`) standard text. Removed all microscopic `9px`, `10px`, `11px` text across the entire interface.
  - Applied `font-variant-numeric: tabular-nums` to all live counters, percentages, speeds, latencies, and timers.
  - Clean Desktop Architecture:
    * Palette: Canvas `#0c0d10`, Surface `#13151a`, Panel `#181b22`, subtle borders `rgba(255,255,255,0.07)`, primary text `#f1f3f5`, secondary text `#8b929e`, restrained emerald `#10b981`.
    * Compact Top Bar with app brand, live status (`Online · N proxies`), segmented view switcher tabs (**`Downloader`** and **`Proxy Pool`**), Settings button, Debug dropdown (`Toggle Live Console`, `Toggle DevTools`, `Save Debug Log`), and Export dropdown (`all.txt`, `socks5.txt`, `socks4.txt`, `http.txt`, `Import Proxies...`).
    * View 1 (Downloader Workspace): spacious URL textarea, prominent 44px `Inspect Links` button, Transfer Controls strip, spacious queue cards with decrypted titles, thick progress bars, live speeds, and control buttons.
    * View 2 (Proxy Pool Workspace): 4-card telemetry strip, Fastest Nodes list, and searchable protocol-filtered Surviving Proxy Pool table.
    * Slide-Up Live Debug Console (`Ctrl+Shift+D`): bottom terminal drawer polling `/api/debug/logs`, with level badges, keyword search, auto-scroll, Copy, and Clear.
- [x] Full workspace verification: 40 tests green across all crates, `cargo check -p looker-app` clean.

### Phase 16: Multi-File Folder Deadlock Fix, Task State Drop-Guard, and Decrypted Folder Naming
- [x] Multi-File Folder Deadlock Resolution (`looker-gateway`):
  - Fixed coordinator/worker channel coordination in `download_single_file`:
    * Separated chunk work queue from chunk result channel (`ChunkResult::Success`, `ChunkResult::Failed`).
    * Explicitly dropped coordinator-owned `Sender` instances (`work_tx`, `result_tx`) before awaiting `result_rx.recv().await`.
    * Deterministically terminated the collection loop as soon as `completed_chunks == total_chunks`, triggering `file_cancel.cancel()` to cleanly terminate idle worker tasks.
    * Eliminated all `tokio::sync::RwLock` and `Mutex` guard holding across `.await` points in `save_queue_from_tasks`, `open_task_folder`, `list_tasks`, and worker loops.
    * Ensured shared file handles (`tokio::fs::File`) are explicitly flushed (`f.flush().await`) and dropped at the end of each file before CBC-MAC verification and moving to subsequent files in folder downloads.
  - Added clear lifecycle tracing logs at every file boundary inside folder transfers:
    * `Starting file [X/N]: '<filename>' (<bytes> bytes, <chunks> chunks)`
    * `Fetching storage URL for '<filename>'...`
    * `Finalizing file '<filename>'...`
    * `Completed file [X/N]: '<filename>'`
    * `Folder transfer '<folder_name>' completed (N/N files)`
  - Added explicit error handling and error logging (`tracing::error!`) on storage URL resolution (`gfs`) and file transfers, cleanly transitioning tasks to `Failed` instead of silently hanging.
- [x] Task Execution Drop-Guard (`looker-gateway`):
  - Implemented `TaskDropGuard` wrapping the spawned background task in `spawn_task_worker`.
  - If a task future exits prematurely, encounters an unhandled error, or panics while in `TaskStatus::Downloading`, `TaskDropGuard` automatically catches it in `drop()`, transitions `task.status` to `TaskStatus::Failed`, resets `speed_mbps = 0.0`, `eta_seconds = 0`, and `active_workers = 0`, recording the error reason.
  - Exported `pub type DownloadStatus = TaskStatus;`.
- [x] Decrypted Folder Title & Filesystem Sanitization (`looker-mega` & `looker-gateway`):
  - Implemented `sanitize_folder_name` stripping Windows/cross-platform forbidden characters (`<>:"/\|?*` and control chars) and trimming trailing dots and whitespace.
  - Enhanced `looker-mega::folder::parse_folder_tree` to fall back to `folder_share_key` attribute decryption for folder nodes when `unwrap_node_key` yields an invalid attribute key, and set root folder relative path to empty `PathBuf` preventing duplicate nested directories.
  - Enhanced `MegaFolderTree::root_title()` to accurately detect decrypted root node names and top-level directory names.
  - Updated `POST /api/mega/inspect`, `POST /api/mega/download`, and `run_download_task` to prioritize and sanitize decrypted folder titles as both the task title and the target filesystem directory name instead of generic `Folder_<id>`.
- [x] Unit & Integration Tests:
  - Added `crates/looker-gateway/tests/folder_download_test.rs`:
    * `test_multi_file_folder_download_completion`: simulates multi-file folder download with 2 files (2 chunks each) over mock HTTP chunk server, verifying File #1 completes, File #2 starts and completes, decrypted contents match on disk, and the task transitions cleanly to `Completed`.
    * `test_task_drop_guard_failure_transition`: verifies drop guard transitions unexpectedly dropped tasks from `Downloading` to `Failed` with 0 speed and recorded error.
    * `test_task_drop_guard_clean_completion_preserves_status`: verifies completed tasks remain `Completed`.
    * `test_sanitize_folder_name`: tests invalid Windows character stripping and formatting.
- [x] Full workspace verification: 44 tests green across all crates, `cargo check -p looker-app` clean.

### Phase 17: Production Release Hardening & GitHub Launch (v0.1.0 - x7ssss)
- [x] UI Copy & Layout Cleanup:
  - Simplified window title in `crates/looker-app/src/main.rs`, `tauri.conf.json`, and `crates/looker-gateway/ui/dist/index.html` to simply "Looker".
  - Cleaned up Downloader view header: stripped "MEGA Downloader Studio", green "QUOTA-BYPASS ENGINE" badge, and long technical cipher subtitle; established clean, direct "MEGA Links" label above input.
  - Streamlined Settings modal header to "Settings" (removed "Power-User" prefix, "SUITE" badge, and subtitle).
  - Clarified settings field labels: "Verify file integrity", "Fastest first", "Command on 509 limit", and "Backup & Reset".
  - Replaced bottom footer bar with minimal: "Looker v0.1.0 · GPL-3.0 License · github.com/x7ssss/looker" linking to https://github.com/x7ssss/looker.
- [x] License & Cargo Workspace Metadata:
  - Created root `LICENSE` file containing GNU General Public License v3.0 (GPL-3.0) with `Copyright (C) 2026 x7ssss`.
  - Updated root `Cargo.toml` `[workspace.package]` with author `["x7ssss"]`, `license = "GPL-3.0-only"`, `repository = "https://github.com/x7ssss/looker"`, `homepage = "https://github.com/x7ssss/looker"`, and production description.
- [x] Production Hardening & CSRF Protection:
  - Removed `"devtools"` feature from release dependencies in `crates/looker-app/Cargo.toml`; scoped F12 WebView2 DevTools invocation strictly to debug builds (`#[cfg(debug_assertions)]`).
  - Preserved built-in Live Debug Console drawer (`Ctrl+Shift+D` and Debug dropdown) in production release builds for live chunk tracing and diagnostic log export.
  - Enforced strict `127.0.0.1` binding in `ProxyGateway` (never `0.0.0.0` or external network adapters).
  - Implemented CSRF / Cross-Origin middleware guard on all `/api/*` routes in `crates/looker-gateway/src/server.rs`, rejecting requests with external `Origin` or `Referer` headers (`403 Forbidden`) while permitting missing headers and local loopback/Tauri origins.
- [x] Original Production README.md:
  - Created sharp, production-ready, completely original `README.md` highlighting autonomous proxy harvesting across 52 feeds, passive 509 failover & force proxy modes, in-flight AES-128-CTR decryption, CBC-MAC validation, interactive folder pruning, persistent queue, and troubleshooting stalled transfers.
  - Included direct links to latest release installer (`Looker-Setup-x64.exe`), build-from-source guides, and GPL-3.0 licensing details.
- [x] GitHub Actions CI/CD Workflow (`.github/workflows/release.yml`):
  - Configured triggers on version tags (`v*`) and `workflow_dispatch`.
  - Added `cargo test --workspace` run on `windows-latest` prior to release artifact packaging.
  - Standardized Tauri CLI v2 installation and NSIS setup packaging as `Looker-Setup-x64.exe` for GitHub Releases via `softprops/action-gh-release`.
- [x] Full Workspace Verification:
  - 45 tests pass cleanly across all crates (including new `test_api_csrf_origin_guard_and_strict_bind`).
  - Production release build `cargo build --release -p looker-app` compiles cleanly without warnings or release devtools.
  - Project marked 100% production-ready for v0.1.0 public release.

---

## 5. Session Instructions for Future Agents
1. **Never violate any invariant listed in Section 2.**
2. When implementing new features, add appropriate unit tests in each crate.
3. Keep crate APIs strictly modular and cohesive according to Section 3.
4. Ensure `cargo check --workspace` and `cargo test --workspace` pass before concluding any session.
