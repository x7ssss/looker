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

### Phase 5: CI/CD Cross-Compilation Matrix & Production Tuning
- [ ] GitHub Actions workflow for cross-compiling Linux (x86_64-musl, aarch64-musl), macOS (universal2), Windows (x86_64-pc-windows-msvc).
- [ ] Binary size optimization (`lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`).
- [ ] End-to-end integration test suite.

---

## 5. Session Instructions for Future Agents
1. **Never violate any invariant listed in Section 2.**
2. When implementing new features, add appropriate unit tests in each crate.
3. Keep crate APIs strictly modular and cohesive according to Section 3.
4. Ensure `cargo check --workspace` and `cargo test --workspace` pass before concluding any session.
