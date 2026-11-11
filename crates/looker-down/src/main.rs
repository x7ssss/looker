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
use tracing::{debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use looker_mega::{
    compute_chunk_mac, decrypt_ctr, ChunkInfo, ChunkIterator, ChunkMac, FileMacAccumulator,
    FileMetadata, MegaClient, MegaError, MegaLink,
};

const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHUNK_RETRIES: usize = 8;

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

    let mega = MegaClient::new(gateway_url);

    // Build HTTP client for workers
    let mut http_builder = Client::builder().timeout(CHUNK_TIMEOUT);
    if let Some(gw) = gateway_url {
        if let Ok(proxy) = Proxy::all(gw) {
            http_builder = http_builder.proxy(proxy);
        }
    }
    let http = Arc::new(http_builder.build()?);

    if link.is_folder() {
        // ============================================================
        // PUBLIC FOLDER BATCH DOWNLOAD
        // ============================================================
        info!("Resolving public folder tree via MEGA API...");
        let tree = mega.fetch_folder_tree(&link).await?;

        let base_out_dir = match args.output {
            Some(p) => p,
            None => PathBuf::from(&link.handle),
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

            download_file_pipeline(&meta, &target_path, Arc::clone(&http), args.concurrency, &route_status).await?;
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

        download_file_pipeline(&meta, &out_path, Arc::clone(&http), args.concurrency, &route_status).await?;

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
    http: Arc<Client>,
    concurrency: usize,
    route_display: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Pre-allocate target sparse file on disk (Zero intermediate temp files)
    let std_file = std::fs::File::create(out_path)?;
    std_file.set_len(meta.size)?;
    drop(std_file);

    let shared_file = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(out_path)
            .await?,
    ));

    // 2. Initialize chunk scheduling
    let chunks: Vec<ChunkInfo> = ChunkIterator::new(meta.size).collect();
    let total_chunks = chunks.len();

    // 3. Setup indicatif MultiProgress UI
    let mp = MultiProgress::new();

    let pb_main = mp.add(ProgressBar::new(meta.size));
    pb_main.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let pb_status = mp.add(ProgressBar::new(total_chunks as u64));
    pb_status.set_style(
        ProgressStyle::default_bar()
            .template("Status: {msg}")
            .unwrap(),
    );
    pb_status.set_message(format!(
        "Chunks 0/{} | Concurrency: {} | {}",
        total_chunks, concurrency, route_display
    ));

    // 4. Worker task queue channels
    let (tx, rx) = mpsc::channel::<ChunkTask>(total_chunks + 32);
    for chunk in chunks {
        tx.send(ChunkTask { info: chunk, attempt: 0 }).await.unwrap();
    }

    let chunk_macs = Arc::new(Mutex::new(vec![None::<ChunkMac>; total_chunks]));
    let completed_chunks = Arc::new(AtomicUsize::new(0));
    let active_workers = Arc::new(AtomicUsize::new(0));

    let mut worker_handles = Vec::with_capacity(concurrency);
    let rx = Arc::new(Mutex::new(rx));

    for _worker_id in 0..concurrency {
        let rx = Arc::clone(&rx);
        let tx = tx.clone();
        let http = Arc::clone(&http);
        let storage_url = meta.download_url.clone();
        let aes_key = meta.key.aes_key;
        let nonce = meta.key.nonce;
        let file = Arc::clone(&shared_file);
        let pb_main = pb_main.clone();
        let pb_status = pb_status.clone();
        let macs = Arc::clone(&chunk_macs);
        let completed = Arc::clone(&completed_chunks);
        let active = Arc::clone(&active_workers);
        let route_display = route_display.to_string();

        worker_handles.push(tokio::spawn(async move {
            loop {
                let task = {
                    let mut lock = rx.lock().await;
                    lock.recv().await
                };

                let task = match task {
                    Some(t) => t,
                    None => break,
                };

                active.fetch_add(1, Ordering::Relaxed);
                let chunk = task.info;

                let download_fut = async {
                    // INVARIANT 5: Storage Node Fetching
                    let range_path_url = format!("{}/{}", storage_url, chunk.path_range());

                    let resp_res = http.get(&range_path_url).send().await;
                    let resp = match resp_res {
                        Ok(r) if r.status().is_success() => r,
                        Ok(r) if r.status() == StatusCode::from_u16(509).unwrap_or(StatusCode::TOO_MANY_REQUESTS) => {
                            return Err(MegaError::OverQuota);
                        }
                        _ => {
                            let range_val = format!("bytes={}-{}", chunk.offset, chunk.end_offset() - 1);
                            let r2 = http.get(&storage_url)
                                .header("Range", range_val)
                                .send()
                                .await
                                .map_err(MegaError::Http)?;

                            if r2.status() == StatusCode::from_u16(509).unwrap_or(StatusCode::TOO_MANY_REQUESTS) {
                                return Err(MegaError::OverQuota);
                            }
                            if !r2.status().is_success() {
                                return Err(MegaError::Http(r2.error_for_status().unwrap_err()));
                            }
                            r2
                        }
                    };

                    let body_bytes = resp.bytes().await.map_err(MegaError::Http)?;
                    if body_bytes.len() as u64 != chunk.size {
                        return Err(MegaError::SizeMismatch {
                            expected: chunk.size,
                            actual: body_bytes.len() as u64,
                        });
                    }

                    let mut plaintext = body_bytes.to_vec();

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

                let res = tokio::time::timeout(CHUNK_TIMEOUT, download_fut).await;

                active.fetch_sub(1, Ordering::Relaxed);

                match res {
                    Ok(Ok(mac)) => {
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
                    Ok(Err(MegaError::OverQuota)) => {
                        debug!("Chunk {} quota limit (HTTP 509). Backing off and retrying...", chunk.index);
                        tokio::time::sleep(Duration::from_millis(500 * (task.attempt + 1) as u64)).await;

                        if task.attempt < MAX_CHUNK_RETRIES {
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else {
                            error!("Chunk {} failed after {} quota retries", chunk.index, MAX_CHUNK_RETRIES);
                            return Err(MegaError::OverQuota);
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("Chunk {} error (attempt {}): {}", chunk.index, task.attempt + 1, e);
                        if task.attempt < MAX_CHUNK_RETRIES {
                            tokio::time::sleep(Duration::from_millis(250 * (task.attempt + 1) as u64)).await;
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else {
                            error!("Chunk {} permanently failed after {} retries: {}", chunk.index, MAX_CHUNK_RETRIES, e);
                            return Err(e);
                        }
                    }
                    Err(_) => {
                        debug!("Chunk {} timed out (> {:?}) on attempt {}", chunk.index, CHUNK_TIMEOUT, task.attempt + 1);
                        if task.attempt < MAX_CHUNK_RETRIES {
                            let _ = tx.send(ChunkTask { info: chunk, attempt: task.attempt + 1 }).await;
                        } else {
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
        h.await??;
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
    Ok(())
}
