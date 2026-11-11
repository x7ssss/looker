use std::io::SeekFrom;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use tokio::io::AsyncSeekExt;
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use looker_mega::{
    decrypt_ctr, ChunkInfo, ChunkIterator, MegaCbcMac, MegaClient, MegaLink,
};

#[derive(Parser, Debug)]
#[command(name = "looker-down", version, about = "High-speed native multi-threaded MEGA downloader")]
struct Args {
    /// MEGA.nz public URL (e.g., https://mega.nz/file/xxxx#yyyy)
    url: String,

    /// Output file path (defaults to remote file name)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Concurrent chunk download workers
    #[arg(short, long, default_value_t = 8)]
    concurrency: usize,

    /// HTTP CONNECT proxy gateway (e.g. http://127.0.0.1:8080)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    gateway: String,

    /// Disable rotating proxy gateway and connect directly
    #[arg(long)]
    direct: bool,
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
    let gateway_opt = if args.direct {
        None
    } else {
        Some(args.gateway.as_str())
    };

    info!("Connecting to MEGA API (Gateway: {:?})...", gateway_opt);
    let mega = MegaClient::new(gateway_opt);
    let meta = mega.get_file_metadata(&link).await?;

    let out_path = args
        .output
        .unwrap_or_else(|| PathBuf::from(&meta.name));

    println!("============================================================");
    println!("File Name   : {}", meta.name);
    println!("File Size   : {} bytes ({:.2} MB)", meta.size, meta.size as f64 / (1024.0 * 1024.0));
    println!("Handle      : {}", meta.handle);
    println!("Output Path : {}", out_path.display());
    println!("Concurrency : {} workers", args.concurrency);
    println!("Proxy Route : {}", if args.direct { "Direct connection" } else { &args.gateway });
    println!("============================================================");

    // Pre-allocate destination file
    let file = std::fs::File::create(&out_path)?;
    file.set_len(meta.size)?;
    drop(file);

    let shared_file = Arc::new(tokio::sync::Mutex::new(
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(&out_path)
            .await?,
    ));

    let chunks: Vec<ChunkInfo> = ChunkIterator::new(meta.size).collect();
    let total_chunks = chunks.len();
    info!("File scheduled into {} dynamic chunks", total_chunks);

    let pb = ProgressBar::new(meta.size);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut http_builder = Client::builder()
        .timeout(Duration::from_secs(30));
    if let Some(gw) = gateway_opt {
        if let Ok(proxy) = reqwest::Proxy::all(gw) {
            http_builder = http_builder.proxy(proxy);
        }
    }
    let http = http_builder.build()?;

    let sem = Arc::new(Semaphore::new(args.concurrency));
    let downloaded_bytes = Arc::new(AtomicU64::new(0));
    let mac_tracker = Arc::new(Mutex::new(vec![[0u8; 16]; total_chunks]));

    let mut tasks = Vec::with_capacity(total_chunks);

    for chunk in chunks {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let http = http.clone();
        let storage_url = meta.download_url.clone();
        let aes_key = meta.key.aes_key;
        let nonce = meta.key.nonce;
        let file = Arc::clone(&shared_file);
        let pb = pb.clone();
        let d_bytes = Arc::clone(&downloaded_bytes);
        let macs = Arc::clone(&mac_tracker);

        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            // INVARIANT 5: Storage Node Fetching Strategy
            // Primary: path range /{START}-{END}. Fallback: HTTP Range header.
            let range_path_url = format!("{}/{}", storage_url, chunk.path_range());

            let resp = match http.get(&range_path_url).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => {
                    // Fallback to HTTP Range header
                    let range_header = format!("bytes={}-{}", chunk.offset, chunk.end_offset() - 1);
                    http.get(&storage_url)
                        .header("Range", range_header)
                        .send()
                        .await
                        .map_err(|e| format!("Chunk {} fetch failed: {}", chunk.index, e))?
                }
            };

            let mut chunk_bytes = resp
                .bytes()
                .await
                .map_err(|e| format!("Chunk {} body read error: {}", chunk.index, e))?
                .to_vec();

            if chunk_bytes.len() as u64 != chunk.size {
                return Err(format!(
                    "Chunk {} size mismatch: expected {}, got {}",
                    chunk.index,
                    chunk.size,
                    chunk_bytes.len()
                ));
            }

            // In-place AES-128-CTR decryption
            decrypt_ctr(&aes_key, &nonce, chunk.offset, &mut chunk_bytes);

            // Compute Chunk CBC-MAC
            let mac_engine = MegaCbcMac::new(&aes_key, &nonce);
            let chunk_mac = mac_engine.compute_chunk_mac(&chunk_bytes);

            // Write decrypted block into file at chunk offset
            {
                let mut f = file.lock().await;
                use tokio::io::AsyncWriteExt;
                f.seek(SeekFrom::Start(chunk.offset)).await.map_err(|e| e.to_string())?;
                f.write_all(&chunk_bytes).await.map_err(|e| e.to_string())?;
            }

            // Store chunk mac in order
            {
                let mut m = macs.lock().await;
                m[chunk.index] = chunk_mac;
            }

            d_bytes.fetch_add(chunk.size, Ordering::Relaxed);
            pb.inc(chunk.size);

            Ok::<(), String>(())
        }));
    }

    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                pb.finish_and_clear();
                error!("Download error: {}", e);
                return Err(e.into());
            }
            Err(e) => {
                pb.finish_and_clear();
                error!("Task panicked: {}", e);
                return Err(e.into());
            }
        }
    }

    pb.finish_with_message("Download completed. Verifying integrity...");

    // CBC-MAC Integrity Condensation & Verification
    let mut mac_verifier = MegaCbcMac::new(&meta.key.aes_key, &meta.key.nonce);
    let recorded_macs = mac_tracker.lock().await;
    for &chunk_mac in recorded_macs.iter() {
        mac_verifier.add_chunk_mac(chunk_mac);
    }

    match mac_verifier.verify_integrity(meta.key.expected_mac) {
        Ok(()) => {
            println!("MAC Integrity Check : PASSED [AES-ECB Condensation Verified]");
            println!("File successfully downloaded to: {}", out_path.display());
        }
        Err(e) => {
            println!("MAC Integrity Check : FAILED ({})", e);
            warn!("Downloaded file may be corrupted");
        }
    }

    Ok(())
}
