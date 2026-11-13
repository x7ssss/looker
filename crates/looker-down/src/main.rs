use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use reqwest::{Client, Proxy, StatusCode};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use looker_mega::{
    compute_chunk_mac, decrypt_ctr, ChunkInfo, ChunkIterator, ChunkMac, FileMacAccumulator,
    FileMetadata, MegaClient, MegaError, MegaLink,
};

const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHUNK_RETRIES: usize = 8;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ChunkResumeRecord {
    pub index: usize,
    pub mac: ChunkMac,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ResumeMetadata {
    pub file_handle: String,
    pub total_size: u64,
    pub completed_chunks: Vec<ChunkResumeRecord>,
}

#[derive(Parser, Debug)]
#[command(name = "looker-down", version, about = "High-speed native multi-threaded MEGA downloader")]
struct Args {
    /// MEGA.nz public URL (single file or folder, e.g. https://mega.nz/folder/xxxx#yyyy or https://mega.nz/file/xxxx#yyyy)
    url: String,

    /// Destination output path or directory (defaults to remote file/folder name)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Maximum parallel chunk worker slots
    #[arg(short, long, default_value_t = 6)]
    concurrency: usize,

    /// Local rotating proxy gateway address
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    gateway: String,

    /// Bypass rotating proxy gateway and download directly via host IP
    #[arg(long)]
    direct: bool,

    /// Transfer routing mode: "passive" (direct ISP speed, auto-fallback to proxy on 509) or "force_proxy"
    #[arg(long, default_value = "passive")]
    mode: String,
}

#[derive(Debug, Clone)]
struct ChunkTask {
    info: ChunkInfo,
    attempt: usize,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "looker_down=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let link = MegaLink::parse(&args.url)?;

    let gateway_url = if args.direct {
        None
    } else {
        Some(args.gateway.as_str())
    };

    println!("============================================================");
    println!("     Looker Wire-Speed Native MEGA Downloader Engine        ");
    println!("============================================================");

    // 1. Probe local gateway if proxy routing is enabled
    let mut route_status = if let Some(gw) = gateway_url {
        format!("Routing via {} (connecting...)", gw)
    } else {
        "Direct host connection (proxy disabled)".to_string()
    };

    if let Some(gw) = gateway_url {
        let test_client = Client::builder()
            .timeout(Duration::from_millis(1500))
            .build()?;
        let status_url = format!("{}/status", gw.trim_end_matches('/'));
        if let Ok(resp) = test_client.get(&status_url).send().await {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    let healthy = val.get("healthy_proxies").and_then(|v| v.as_u64()).unwrap_or(0);
                    route_status = format!("Routing via {} [{} healthy proxies active]", gw, healthy);
                }
            }
        }
    }

    info!("{}", route_status);

    let mega = Arc::new(MegaClient::new(gateway_url));

    // Build HTTP clients for workers: direct connection and proxy gateway with per-read timeouts
    let direct_http = Arc::new(
        Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .read_timeout(Duration::from_secs(15))
            .timeout(CHUNK_TIMEOUT)
            .build()?,
    );
    let mut proxy_builder = Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .read_timeout(Duration::from_secs(15))
        .timeout(CHUNK_TIMEOUT);
    if let Ok(proxy) = Proxy::all(&args.gateway) {
        proxy_builder = proxy_builder.proxy(proxy);
    }
    let proxy_http = Arc::new(proxy_builder.build()?);

    let force_proxy = args.mode.eq_ignore_ascii_case("force_proxy") || args.mode.eq_ignore_ascii_case("force");
    let is_direct_only = args.direct;
    let use_proxy = Arc::new(std::sync::atomic::AtomicBool::new(force_proxy));

    if force_proxy {
        info!("Routing mode: FORCE PROXY (routing chunks through rotating gateway from byte 0)");
    } else if is_direct_only {
        info!("Routing mode: DIRECT ONLY (proxy disabled)");
    } else {
        info!("Routing mode: PASSIVE AUTO-FALLBACK (direct ISP speed, auto-switch to proxy on 509)");
    }

    if link.is_folder_scope() {
        // ============================================================
        // PUBLIC FOLDER BATCH DOWNLOAD
        // ============================================================
        info!("Resolving public folder tree via MEGA API...");
        let tree = mega.fetch_folder_tree(&link).await?;

        let folder_name = tree.root_title().unwrap_or_else(|| link.handle.clone());
        let base_out_dir = match args.output {
            Some(p) => p,
            None => PathBuf::from(&folder_name),
        };

        println!("Folder Handle : {}", tree.folder_handle);
        println!("Directories   : {} folders", tree.directories().len());
        println!("Files         : {} items", tree.files().len());
        println!(
            "Total Payload : {} bytes ({:.2} MB)",
            tree.total_bytes(),
            tree.total_bytes() as f64 / (1024.0 * 1024.0)
        );
        println!("Destination   : {}", base_out_dir.display());
        println!("Proxy Route   : {}", route_status);
        println!("============================================================");

        // Pre-create all subdirectories on disk
        tokio::fs::create_dir_all(&base_out_dir).await?;
        for dir in tree.directories() {
            let dir_path = base_out_dir.join(&dir.relative_path);
            tokio::fs::create_dir_all(&dir_path).await?;
        }

        let files = tree.files();
        let total_files = files.len();

        for (idx, file_node) in files.iter().enumerate() {
            println!(
                "\n[{}/{}] Downloading: {} ({:.2} MB)",
                idx + 1,
                total_files,
                file_node.relative_path.display(),
                file_node.size as f64 / (1024.0 * 1024.0)
            );

            let (download_url, _) = mega
                .get_folder_file_url(&link.handle, &file_node.handle)
                .await?;

            let target_path = base_out_dir.join(&file_node.relative_path);
            if let Some(parent) = target_path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            let file_key = file_node
                .key
                .clone()
                .ok_or_else(|| format!("Missing key for node {}", file_node.handle))?;

            let meta = FileMetadata {
                handle: file_node.handle.clone(),
                name: file_node.name.clone(),
                size: file_node.size,
                download_url,
                key: file_key,
            };

            download_file_pipeline(
                &meta,
                &target_path,
                Arc::clone(&mega),
                Some(&link.handle),
                Arc::clone(&direct_http),
                Arc::clone(&proxy_http),
                Arc::clone(&use_proxy),
                is_direct_only,
                args.concurrency,
                &route_status,
            ).await?;
        }

        println!("\n============================================================");
        println!(" Folder Download Complete: All {} files verified", total_files);
        println!(" Destination directory   : {}", base_out_dir.display());
        println!("============================================================");
    } else {
        // ============================================================
        // STANDALONE PUBLIC FILE DOWNLOAD
        // ============================================================
        info!("Resolving file metadata via MEGA API...");
        let meta = mega.resolve_file(&link).await?;

        let out_path = match args.output {
            Some(p) => {
                if p.is_dir() || p.to_string_lossy().ends_with('/') || p.to_string_lossy().ends_with('\\') {
                    p.join(&meta.name)
                } else {
                    p
                }
            }
            None => PathBuf::from(&meta.name),
        };

        if let Some(parent) = out_path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        println!("File Name   : {}", meta.name);
        println!("File Size   : {} bytes ({:.2} MB)", meta.size, meta.size as f64 / (1024.0 * 1024.0));
        println!("File Handle : {}", meta.handle);
        println!("Destination : {}", out_path.display());
        println!("Workers     : {} concurrent slots", args.concurrency);
        println!("Proxy Route : {}", route_status);
        println!("============================================================");

        download_file_pipeline(
            &meta,
            &out_path,
            Arc::clone(&mega),
            None,
            Arc::clone(&direct_http),
            Arc::clone(&proxy_http),
            Arc::clone(&use_proxy),
            is_direct_only,
            args.concurrency,
            &route_status,
        ).await?;

        println!("============================================================");
        println!(" File Download Complete : Verified");
        println!(" Destination file       : {}", out_path.display());
        println!("============================================================");
    }

    Ok(())
}

async fn download_file_pipeline(
    meta: &FileMetadata,
    out_path: &Path,
    mega: Arc<MegaClient>,
    folder_handle: Option<&str>,
    direct_http: Arc<Client>,
    proxy_http: Arc<Client>,
    use_proxy: Arc<std::sync::atomic::AtomicBool>,
    is_direct_only: bool,
    concurrency: usize,
    route_display: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resume_path = PathBuf::from(format!("{}.looker-resume", out_path.display()));

    // 1. Pre-allocate or open target sparse file on disk (Preserves resumed data)
    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(out_path)?;
    std_file.set_len(meta.size)?;
    drop(std_file);

    let shared_file = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(out_path)
            .await?,
    ));

    // 2. Initialize chunk scheduling
    let chunks: Vec<ChunkInfo> = ChunkIterator::new(meta.size).collect();
    let total_chunks = chunks.len();

    let chunk_macs = Arc::new(Mutex::new(vec![None::<ChunkMac>; total_chunks]));
    let completed_chunks = Arc::new(AtomicUsize::new(0));
    let active_workers = Arc::new(AtomicUsize::new(0));

    // 3. Inspect existing resume metadata
    let mut resumed_indices = HashSet::new();
    let mut resumed_bytes = 0u64;

    if resume_path.exists() {
        if let Ok(contents) = std::fs::read_to_string(&resume_path) {
            if let Ok(saved) = serde_json::from_str::<ResumeMetadata>(&contents) {
                if saved.file_handle == meta.handle && saved.total_size == meta.size {
                    let mut lock = chunk_macs.lock().await;
                    for rec in saved.completed_chunks {
                        if rec.index < total_chunks {
                            lock[rec.index] = Some(rec.mac);
                            resumed_indices.insert(rec.index);
                            resumed_bytes += chunks[rec.index].size;
                        }
                    }
                    info!(
                        "Resumed download session from {}: {}/{} chunks already complete",
                        resume_path.display(),
                        resumed_indices.len(),
                        total_chunks
                    );
                }
            }
        }
    }

    // 4. Setup indicatif MultiProgress UI
    let mp = MultiProgress::new();

    let pb_main = mp.add(ProgressBar::new(meta.size));
    pb_main.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb_main.inc(resumed_bytes);

    let pb_status = mp.add(ProgressBar::new(total_chunks as u64));
    pb_status.set_style(
        ProgressStyle::default_bar()
            .template("Status: {msg}")
            .unwrap(),
    );
    pb_status.set_message(format!(
        "Chunks {}/{} | Concurrency: {} | {}",
        resumed_indices.len(), total_chunks, concurrency, route_display
    ));

    // 5. Setup worker task queue & cancellation token
    let cancel_token = CancellationToken::new();
    let sig_token = cancel_token.clone();

    // Spawn signal listener for clean Ctrl-C shutdown
    let signal_handle = tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            sig_token.cancel();
        }
    });

    let (tx, rx) = mpsc::channel::<ChunkTask>(total_chunks + 32);
    for chunk in &chunks {
        if !resumed_indices.contains(&chunk.index) {
            tx.send(ChunkTask { info: *chunk, attempt: 0 }).await.unwrap();
        }
    }
    completed_chunks.store(resumed_indices.len(), Ordering::Relaxed);

    let mut worker_handles = Vec::with_capacity(concurrency);
    let rx = Arc::new(Mutex::new(rx));

    let current_storage_url = Arc::new(tokio::sync::RwLock::new(meta.download_url.clone()));
    let consecutive_errors = Arc::new(AtomicUsize::new(0));

    for _worker_id in 0..concurrency {
        let rx = Arc::clone(&rx);
        let tx = tx.clone();
        let direct_http = Arc::clone(&direct_http);
        let proxy_http = Arc::clone(&proxy_http);
        let use_proxy = Arc::clone(&use_proxy);
        let current_storage_url = Arc::clone(&current_storage_url);
        let consecutive_errors = Arc::clone(&consecutive_errors);
        let mega = Arc::clone(&mega);
        let folder_handle_opt = folder_handle.map(|s| s.to_string());
        let file_handle = meta.handle.clone();
        let file_name = meta.name.clone();
        let aes_key = meta.key.aes_key;
        let nonce = meta.key.nonce;
        let file = Arc::clone(&shared_file);
        let pb_main = pb_main.clone();
        let pb_status = pb_status.clone();
        let macs = Arc::clone(&chunk_macs);
        let completed = Arc::clone(&completed_chunks);
        let active = Arc::clone(&active_workers);
        let route_display = route_display.to_string();
        let worker_cancel = cancel_token.child_token();

        worker_handles.push(tokio::spawn(async move {
            loop {
                if worker_cancel.is_cancelled() {
                    break;
                }

                let task = tokio::select! {
                    _ = worker_cancel.cancelled() => break,
                    t = async {
                        let mut lock = rx.lock().await;
                        lock.recv().await
                    } => match t {
                        Some(item) => item,
                        None => break,
                    }
                };

                active.fetch_add(1, Ordering::Relaxed);
                let chunk = task.info;

                let http = if is_direct_only {
                    Arc::clone(&direct_http)
                } else if use_proxy.load(Ordering::Relaxed) {
                    Arc::clone(&proxy_http)
                } else {
                    Arc::clone(&direct_http)
                };

                let download_fut = async {
                    // INVARIANT 5: Storage Node Fetching
                    let current_url = current_storage_url.read().await.clone();
                    let range_path_url = format!("{}/{}", current_url, chunk.path_range());

                    let resp_res = http.get(&range_path_url).send().await;
                    let mut resp = match resp_res {
                        Ok(r) if r.status().is_success() => r,
                        Ok(r) if r.status() == StatusCode::FORBIDDEN => {
                            return Err(MegaError::ApiError(403));
                        }
                        Ok(r) if r.status() == StatusCode::from_u16(509).unwrap_or(StatusCode::TOO_MANY_REQUESTS) => {
                            return Err(MegaError::OverQuota);
                        }
                        _ => {
                            let range_val = format!("bytes={}-{}", chunk.offset, chunk.end_offset() - 1);
                            let r2 = http.get(&current_url)
                                .header("Range", range_val)
                                .send()
                                .await
                                .map_err(MegaError::Http)?;

                            if r2.status() == StatusCode::FORBIDDEN {
                                return Err(MegaError::ApiError(403));
                            }
                            if r2.status() == StatusCode::from_u16(509).unwrap_or(StatusCode::TOO_MANY_REQUESTS) {
                                return Err(MegaError::OverQuota);
                            }
                            if !r2.status().is_success() {
                                return Err(MegaError::Http(r2.error_for_status().unwrap_err()));
                            }
                            r2
                        }
                    };

                    // Strict Per-Read Stall Timeout on Chunk Streams
                    let mut plaintext = Vec::with_capacity(chunk.size as usize);
                    loop {
                        let chunk_read = tokio::time::timeout(Duration::from_secs(15), resp.chunk()).await;
                        match chunk_read {
                            Ok(Ok(Some(bytes))) => {
                                if bytes.is_empty() {
                                    drop(resp);
                                    return Err(MegaError::Io(std::io::Error::new(
                                        std::io::ErrorKind::TimedOut,
                                        "Stall watchdog: read delivered 0 bytes",
                                    )));
                                }
                                plaintext.extend_from_slice(&bytes);
                            }
                            Ok(Ok(None)) => break,
                            Ok(Err(e)) => {
                                drop(resp);
                                return Err(MegaError::Http(e));
                            }
                            Err(_) => {
                                drop(resp);
                                return Err(MegaError::Io(std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "Stall watchdog: per-read timeout exceeded",
                                )));
                            }
                        }
                    }

                    if plaintext.len() as u64 != chunk.size {
                        return Err(MegaError::SizeMismatch {
                            expected: chunk.size,
                            actual: plaintext.len() as u64,
                        });
                    }

                    // In-place AES-128-CTR decryption
                    decrypt_ctr(&aes_key, &nonce, chunk.offset, &mut plaintext);

                    // Compute chunk CBC-MAC
                    let mac = compute_chunk_mac(&aes_key, &nonce, &plaintext);

                    // Sparse file direct write to target file offset
                    {
                        let mut f = file.lock().await;
                        f.seek(SeekFrom::Start(chunk.offset)).await?;
                        f.write_all(&plaintext).await?;
                    }

                    Ok::<ChunkMac, MegaError>(mac)
                };

                let res = tokio::select! {
                    _ = worker_cancel.cancelled() => {
                        active.fetch_sub(1, Ordering::Relaxed);
                        break;
                    }
                    r = tokio::time::timeout(CHUNK_TIMEOUT, download_fut) => r,
                };

                active.fetch_sub(1, Ordering::Relaxed);

                match res {
                    Ok(Ok(mac)) => {
                        consecutive_errors.store(0, Ordering::Relaxed);
                        {
                            let mut lock = macs.lock().await;
                            lock[chunk.index] = Some(mac);
                        }

                        let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                        pb_main.inc(chunk.size);
                        pb_status.set_message(format!(
                            "Chunks {}/{} completed | Workers: {} active | {}",
                            done, total_chunks, active.load(Ordering::Relaxed), route_display
                        ));

                        if done == total_chunks {
                            break;
                        }
                    }
                    Ok(Err(MegaError::ApiError(403))) => {
                        warn!("HTTP 403 Forbidden on file '{}'; refreshing temporary download URL...", file_name);
                        if let Ok(new_url) = mega.refresh_file_download_url(folder_handle_opt.as_deref(), &file_handle).await {
                            *current_storage_url.write().await = new_url;
                            consecutive_errors.store(0, Ordering::Relaxed);
                        }
                        if task.attempt < MAX_CHUNK_RETRIES && !worker_cancel.is_cancelled() {
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        }
                    }
                    Ok(Err(MegaError::OverQuota)) => {
                        debug!("Chunk {} quota limit (HTTP 509). Backing off and retrying...", chunk.index);
                        if !is_direct_only && !use_proxy.load(Ordering::Relaxed) {
                            info!("Direct host connection hit MEGA 509 quota. Automatically switching to rotating proxy gateway!");
                            use_proxy.store(true, Ordering::SeqCst);
                        }
                        if let Ok(new_url) = mega.refresh_file_download_url(folder_handle_opt.as_deref(), &file_handle).await {
                            *current_storage_url.write().await = new_url;
                        }
                        tokio::time::sleep(Duration::from_millis(500 * (task.attempt + 1) as u64)).await;

                        if task.attempt < MAX_CHUNK_RETRIES && !worker_cancel.is_cancelled() {
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else if !worker_cancel.is_cancelled() {
                            error!("Chunk {} failed after {} quota retries", chunk.index, MAX_CHUNK_RETRIES);
                            return Err(MegaError::OverQuota);
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Chunk {} error on file '{}' (attempt {}): {}", chunk.index, file_name, task.attempt + 1, e);
                        let err_count = consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                        if err_count >= 3 {
                            warn!("3 consecutive errors on file '{}'; refreshing temporary download URL...", file_name);
                            if let Ok(new_url) = mega.refresh_file_download_url(folder_handle_opt.as_deref(), &file_handle).await {
                                *current_storage_url.write().await = new_url;
                                consecutive_errors.store(0, Ordering::Relaxed);
                            }
                        }
                        if task.attempt < MAX_CHUNK_RETRIES && !worker_cancel.is_cancelled() {
                            tokio::time::sleep(Duration::from_millis(250 * (task.attempt + 1) as u64)).await;
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else if !worker_cancel.is_cancelled() {
                            error!("Chunk {} permanently failed after {} retries: {}", chunk.index, MAX_CHUNK_RETRIES, e);
                            return Err(e);
                        }
                    }
                    Err(_) => {
                        warn!("Chunk stall timeout on file '{}', chunk #{}: dropping stalled stream", file_name, chunk.index);
                        let err_count = consecutive_errors.fetch_add(1, Ordering::Relaxed) + 1;
                        if err_count >= 3 {
                            warn!("3 consecutive timeouts on file '{}'; refreshing temporary download URL...", file_name);
                            if let Ok(new_url) = mega.refresh_file_download_url(folder_handle_opt.as_deref(), &file_handle).await {
                                *current_storage_url.write().await = new_url;
                                consecutive_errors.store(0, Ordering::Relaxed);
                            }
                        }
                        if task.attempt < MAX_CHUNK_RETRIES && !worker_cancel.is_cancelled() {
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else if !worker_cancel.is_cancelled() {
                            error!("Chunk {} permanently timed out after {} retries", chunk.index, MAX_CHUNK_RETRIES);
                            return Err(MegaError::ChunkDownloadFailed(MAX_CHUNK_RETRIES));
                        }
                    }
                }
            }

            Ok::<(), MegaError>(())
        }));
    }

    for h in worker_handles {
        let _ = h.await;
    }
    signal_handle.abort();

    // Check if interrupted via Ctrl-C
    if cancel_token.is_cancelled() {
        // 1. Flush file to disk
        {
            let mut f = shared_file.lock().await;
            let _ = f.flush().await;
        }

        // 2. Persist resume metadata
        let macs = chunk_macs.lock().await;
        let mut records = Vec::new();
        for (idx, mac_opt) in macs.iter().enumerate() {
            if let Some(mac) = mac_opt {
                records.push(ChunkResumeRecord {
                    index: idx,
                    mac: *mac,
                });
            }
        }

        let resume_meta = ResumeMetadata {
            file_handle: meta.handle.clone(),
            total_size: meta.size,
            completed_chunks: records,
        };

        if let Ok(json) = serde_json::to_string_pretty(&resume_meta) {
            let _ = std::fs::write(&resume_path, json);
            eprintln!("\n============================================================");
            eprintln!(" [INTERRUPTED] Download gracefully halted on Ctrl-C.");
            eprintln!(" [FLUSHED] In-memory chunks safely flushed to disk.");
            eprintln!(" [RESUME] Metadata saved to: {}", resume_path.display());
            eprintln!("============================================================");
        }

        return Err("Download interrupted by user (resume state saved)".into());
    }

    pb_main.finish_with_message("Transfer completed");
    pb_status.finish_with_message("Verifying CBC-MAC checksum...");

    // Validate CBC-MAC
    let mut accumulator = FileMacAccumulator::new(&meta.key.aes_key);
    let macs = chunk_macs.lock().await;

    for (idx, mac_opt) in macs.iter().enumerate() {
        let chunk_mac = mac_opt.ok_or_else(|| {
            format!("Missing chunk MAC for chunk index {}", idx)
        })?;
        accumulator.accumulate(&chunk_mac);
    }

    accumulator.verify(meta.key.expected_mac)?;

    // On complete verification, remove resume metadata file if present
    if resume_path.exists() {
        let _ = std::fs::remove_file(&resume_path);
    }

    Ok(())
}
