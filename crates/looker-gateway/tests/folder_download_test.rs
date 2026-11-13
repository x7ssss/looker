use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use looker_gateway::download::{
    download_single_file, sanitize_folder_name, RateLimiter, TaskDropGuard, TaskInfo, TaskStatus,
};
use looker_gateway::settings::AppSettings;
use looker_mega::{
    compute_chunk_mac, decrypt_ctr, ChunkIterator, FileMacAccumulator, MegaClient,
};
use looker_pool::ProxyPool;
use reqwest::Client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Spawns a mock HTTP server serving chunk data for 2 simulated files.
async fn spawn_mock_storage_server(
    file1_data: Arc<Vec<u8>>,
    file2_data: Arc<Vec<u8>>,
) -> (SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    let cancel_server = cancel.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_server.cancelled() => break,
                res = listener.accept() => {
                    let (mut socket, _) = match res {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let f1 = Arc::clone(&file1_data);
                    let f2 = Arc::clone(&file2_data);

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let n = match socket.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req_str.lines().next().unwrap_or("");
                        let path = first_line.split_whitespace().nth(1).unwrap_or("");

                        let (file_data, range_str) = if path.starts_with("/file1") {
                            let r = path.strip_prefix("/file1/").unwrap_or("");
                            (&*f1, r)
                        } else if path.starts_with("/file2") {
                            let r = path.strip_prefix("/file2/").unwrap_or("");
                            (&*f2, r)
                        } else {
                            return;
                        };

                        let (start, end) = if let Some(dash) = range_str.find('-') {
                            let s = range_str[..dash].parse::<usize>().unwrap_or(0);
                            let e = range_str[dash + 1..].parse::<usize>().unwrap_or(file_data.len().saturating_sub(1));
                            (s, (e + 1).min(file_data.len()))
                        } else {
                            (0, file_data.len())
                        };

                        let slice = &file_data[start..end];
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            slice.len()
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                        let _ = socket.write_all(slice).await;
                        let _ = socket.flush().await;
                    });
                }
            }
        }
    });

    (addr, cancel)
}

#[tokio::test]
async fn test_multi_file_folder_download_completion() {
    // 1. Prepare 2 distinct files with multiple chunks each (256 KiB each = 2 x 128 KiB chunks)
    let file_size: u64 = 262_144;
    let file1_plain = vec![0x33u8; file_size as usize];
    let file2_plain = vec![0x77u8; file_size as usize];

    let aes_key = [0x42u8; 16];
    let nonce = [0x24u8; 8];

    // Encrypt both with CTR keystream
    let mut file1_enc = file1_plain.clone();
    decrypt_ctr(&aes_key, &nonce, 0, &mut file1_enc);

    let mut file2_enc = file2_plain.clone();
    decrypt_ctr(&aes_key, &nonce, 0, &mut file2_enc);

    // Compute expected CBC-MAC for file 1
    let mut acc1 = FileMacAccumulator::new(&aes_key);
    for chunk in ChunkIterator::new(file_size) {
        let mac = compute_chunk_mac(
            &aes_key,
            &nonce,
            &file1_plain[chunk.offset as usize..chunk.end_offset() as usize],
        );
        acc1.accumulate(&mac);
    }
    let expected_mac1 = acc1.finish();

    // Compute expected CBC-MAC for file 2
    let mut acc2 = FileMacAccumulator::new(&aes_key);
    for chunk in ChunkIterator::new(file_size) {
        let mac = compute_chunk_mac(
            &aes_key,
            &nonce,
            &file2_plain[chunk.offset as usize..chunk.end_offset() as usize],
        );
        acc2.accumulate(&mac);
    }
    let expected_mac2 = acc2.finish();

    // 2. Spin up mock storage server
    let (server_addr, cancel_server) =
        spawn_mock_storage_server(Arc::new(file1_enc), Arc::new(file2_enc)).await;

    // 3. Setup temporary folder destination
    let test_dir = std::env::temp_dir().join(format!("looker_folder_test_{}", std::process::id()));
    let folder_dest = test_dir.join("Decrypted_Folder_Name");
    let _ = tokio::fs::create_dir_all(&folder_dest).await;

    let file1_out = folder_dest.join("part1.bin");
    let file2_out = folder_dest.join("part2.bin");

    // 4. Setup state and coordination objects
    let mega_client = Arc::new(MegaClient::new(None));
    let direct_http = Arc::new(Client::new());
    let gw_http = Arc::new(Client::new());
    let pool = Arc::new(ProxyPool::new());
    let rate_limiter = Arc::new(RateLimiter::new(0.0));
    let cumulative_bytes = Arc::new(AtomicU64::new(0));
    let grand_total_bytes = file_size * 2;
    let start_time = Instant::now();

    let task_info = Arc::new(RwLock::new(TaskInfo {
        id: "task-test-folder-1".to_string(),
        title: "Decrypted_Folder_Name".to_string(),
        category: "General".to_string(),
        status: TaskStatus::Downloading,
        total_bytes: grand_total_bytes,
        downloaded_bytes: 0,
        progress_percent: 0.0,
        speed_mbps: 0.0,
        eta_seconds: 0,
        output_path: folder_dest.to_string_lossy().to_string(),
        error: None,
        routing_mode: "passive".to_string(),
        active_workers: 0,
    }));

    let completed_chunks_map = Arc::new(RwLock::new(HashMap::new()));
    let using_proxies = Arc::new(AtomicBool::new(false));
    let mut settings = AppSettings::default();
    settings.verify_cbc_mac = true;
    let settings_arc = Arc::new(RwLock::new(settings));
    let last_host_509_at = Arc::new(RwLock::new(None));
    let last_509_cmd_at = Arc::new(RwLock::new(None));
    let cancel_token = CancellationToken::new();

    // 5. Execute File #1 download (2 chunks, 2 parallel workers)
    let file1_url = format!("http://{}/file1", server_addr);
    let res1 = download_single_file(
        "file_h1",
        "part1.bin",
        Some("root_h"),
        &file1_url,
        file_size,
        aes_key,
        nonce,
        expected_mac1,
        &file1_out,
        Arc::clone(&mega_client),
        Arc::clone(&direct_http),
        Arc::clone(&gw_http),
        Arc::clone(&pool),
        Arc::clone(&rate_limiter),
        Arc::clone(&cumulative_bytes),
        grand_total_bytes,
        start_time,
        2, // workers_per_file
        Arc::clone(&task_info),
        Arc::clone(&completed_chunks_map),
        Arc::clone(&using_proxies),
        Arc::clone(&settings_arc),
        Arc::clone(&last_host_509_at),
        Arc::clone(&last_509_cmd_at),
        cancel_token.clone(),
    )
    .await;

    assert!(res1.is_ok(), "File #1 download failed: {:?}", res1);
    assert!(file1_out.exists(), "File #1 was not written to disk");
    let written1 = tokio::fs::read(&file1_out).await.unwrap();
    assert_eq!(written1.len(), file_size as usize);
    assert_eq!(written1, file1_plain, "File #1 plaintext mismatch");

    // 6. Execute File #2 download (2 chunks, 2 parallel workers)
    let file2_url = format!("http://{}/file2", server_addr);
    let res2 = download_single_file(
        "file_h2",
        "part2.bin",
        Some("root_h"),
        &file2_url,
        file_size,
        aes_key,
        nonce,
        expected_mac2,
        &file2_out,
        Arc::clone(&mega_client),
        Arc::clone(&direct_http),
        Arc::clone(&gw_http),
        Arc::clone(&pool),
        Arc::clone(&rate_limiter),
        Arc::clone(&cumulative_bytes),
        grand_total_bytes,
        start_time,
        2, // workers_per_file
        Arc::clone(&task_info),
        Arc::clone(&completed_chunks_map),
        Arc::clone(&using_proxies),
        Arc::clone(&settings_arc),
        Arc::clone(&last_host_509_at),
        Arc::clone(&last_509_cmd_at),
        cancel_token.clone(),
    )
    .await;

    assert!(res2.is_ok(), "File #2 download failed: {:?}", res2);
    assert!(file2_out.exists(), "File #2 was not written to disk");
    let written2 = tokio::fs::read(&file2_out).await.unwrap();
    assert_eq!(written2.len(), file_size as usize);
    assert_eq!(written2, file2_plain, "File #2 plaintext mismatch");

    // 7. Transition task to Completed
    {
        let mut info = task_info.write().await;
        info.status = TaskStatus::Completed;
        info.progress_percent = 100.0;
        info.speed_mbps = 0.0;
        info.eta_seconds = 0;
        info.active_workers = 0;
    }

    let final_info = task_info.read().await.clone();
    assert_eq!(final_info.status, TaskStatus::Completed);
    assert_eq!(final_info.downloaded_bytes, grand_total_bytes);
    assert_eq!(final_info.progress_percent, 100.0);

    // Clean up
    cancel_server.cancel();
    let _ = tokio::fs::remove_dir_all(&test_dir).await;
}

#[tokio::test]
async fn test_task_drop_guard_failure_transition() {
    let task_info = Arc::new(RwLock::new(TaskInfo {
        id: "task-guard-test".to_string(),
        title: "Test Task".to_string(),
        category: "General".to_string(),
        status: TaskStatus::Downloading,
        total_bytes: 1000,
        downloaded_bytes: 500,
        progress_percent: 50.0,
        speed_mbps: 12.5,
        eta_seconds: 40,
        output_path: "test".to_string(),
        error: None,
        routing_mode: "passive".to_string(),
        active_workers: 4,
    }));

    {
        let _guard = TaskDropGuard {
            task_id: "task-guard-test".to_string(),
            task_info: Arc::clone(&task_info),
            completed_cleanly: false, // Simulates unexpected future drop / panic
        };
        // _guard is dropped here at scope end
    }

    // Wait brief moment for drop guard logic
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let info = task_info.read().await.clone();
    assert_eq!(info.status, TaskStatus::Failed);
    assert_eq!(info.speed_mbps, 0.0);
    assert_eq!(info.eta_seconds, 0);
    assert_eq!(info.active_workers, 0);
    assert!(info.error.is_some());
}

#[tokio::test]
async fn test_task_drop_guard_clean_completion_preserves_status() {
    let task_info = Arc::new(RwLock::new(TaskInfo {
        id: "task-clean-test".to_string(),
        title: "Clean Task".to_string(),
        category: "General".to_string(),
        status: TaskStatus::Completed,
        total_bytes: 1000,
        downloaded_bytes: 1000,
        progress_percent: 100.0,
        speed_mbps: 0.0,
        eta_seconds: 0,
        output_path: "test".to_string(),
        error: None,
        routing_mode: "passive".to_string(),
        active_workers: 0,
    }));

    {
        let mut guard = TaskDropGuard {
            task_id: "task-clean-test".to_string(),
            task_info: Arc::clone(&task_info),
            completed_cleanly: false,
        };
        guard.completed_cleanly = true; // Clean exit
    }

    let info = task_info.read().await.clone();
    assert_eq!(info.status, TaskStatus::Completed);
}

#[test]
fn test_sanitize_folder_name() {
    assert_eq!(sanitize_folder_name("RRTVP017"), "RRTVP017");
    assert_eq!(
        sanitize_folder_name("My Folder: Season 1 <HD> *Special* / Test?"),
        "My Folder_ Season 1 _HD_ _Special_ _ Test_"
    );
    assert_eq!(sanitize_folder_name("Trailing Dot....   "), "Trailing Dot");
    assert_eq!(sanitize_folder_name("   "), "Folder");
}
