use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use looker_mega::{
    compute_chunk_mac, decrypt_ctr, ChunkInfo, ChunkIterator, FolderNodeType,
    MegaClient, MegaError, MegaLink,
};

const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectNode {
    pub handle: String,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectResponse {
    #[serde(rename = "type")]
    pub target_type: String,
    pub title: String,
    pub total_size: u64,
    pub nodes: Vec<InspectNode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DownloadRequest {
    pub url: String,
    #[serde(default)]
    pub selected_handles: Vec<String>,
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
}

fn default_output_dir() -> String {
    "./downloads".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Downloading,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    pub title: String,
    pub status: TaskStatus,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub progress_percent: f64,
    pub speed_mbps: f64,
    pub eta_seconds: u64,
    pub output_path: String,
    pub error: Option<String>,
}

struct ActiveTask {
    info: Arc<RwLock<TaskInfo>>,
    cancel_token: CancellationToken,
}

pub struct DownloadManager {
    gateway_addr: String,
    tasks: Arc<RwLock<HashMap<String, ActiveTask>>>,
    next_id: AtomicUsize,
}

impl DownloadManager {
    pub fn new(gateway_addr: String) -> Self {
        Self {
            gateway_addr,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicUsize::new(1),
        }
    }

    /// Resolves single file metadata or entire folder tree from MEGA URL.
    pub async fn inspect(&self, url: &str) -> Result<InspectResponse, String> {
        let link = MegaLink::parse(url).map_err(|e| format!("Invalid MEGA URL: {}", e))?;
        let mega = MegaClient::new(Some(&format!("http://{}", self.gateway_addr)));

        if link.is_folder_scope() {
            let tree = mega
                .fetch_folder_tree(&link)
                .await
                .map_err(|e| format!("Failed to fetch folder tree: {}", e))?;

            // If it scoped to a single file node (e.g. /file/{id}):
            if tree.files().len() == 1 && tree.directories().is_empty() {
                let f = tree.files()[0];
                return Ok(InspectResponse {
                    target_type: "file".to_string(),
                    title: f.name.clone(),
                    total_size: f.size,
                    nodes: vec![InspectNode {
                        handle: f.handle.clone(),
                        name: f.name.clone(),
                        size: f.size,
                        is_dir: false,
                        path: format!("/{}", f.name),
                    }],
                });
            }

            let title = tree
                .directories()
                .iter()
                .find(|d| d.parent_handle.is_empty() || d.parent_handle == link.handle || d.handle == link.handle)
                .map(|d| d.name.clone())
                .unwrap_or_else(|| format!("Folder_{}", link.handle));

            let total_size = tree.total_bytes();

            let nodes = tree
                .nodes
                .iter()
                .map(|n| {
                    let formatted_path = format!(
                        "/{}",
                        n.relative_path
                            .to_string_lossy()
                            .replace('\\', "/")
                            .trim_start_matches('/')
                    );
                    InspectNode {
                        handle: n.handle.clone(),
                        name: n.name.clone(),
                        size: n.size,
                        is_dir: n.node_type == FolderNodeType::Folder,
                        path: formatted_path,
                    }
                })
                .collect();

            Ok(InspectResponse {
                target_type: "folder".to_string(),
                title,
                total_size,
                nodes,
            })
        } else {
            let meta = mega
                .resolve_file(&link)
                .await
                .map_err(|e| format!("Failed to resolve file: {}", e))?;

            Ok(InspectResponse {
                target_type: "file".to_string(),
                title: meta.name.clone(),
                total_size: meta.size,
                nodes: vec![InspectNode {
                    handle: meta.handle.clone(),
                    name: meta.name.clone(),
                    size: meta.size,
                    is_dir: false,
                    path: format!("/{}", meta.name),
                }],
            })
        }
    }

    /// Spawns an asynchronous download task in the background.
    pub async fn start_download(&self, mut req: DownloadRequest) -> Result<String, String> {
        let link = MegaLink::parse(&req.url).map_err(|e| format!("Invalid MEGA URL: {}", e))?;
        let task_id = format!("task-{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let cancel_token = CancellationToken::new();

        if req.output_dir.trim().is_empty() {
            req.output_dir = crate::resolve_default_download_dir()
                .to_string_lossy()
                .to_string();
        }

        let out_path = std::path::Path::new(&req.output_dir);
        tokio::fs::create_dir_all(out_path)
            .await
            .map_err(|e| format!("Failed to create output directory {}: {}", out_path.display(), e))?;

        let initial_title = if link.is_folder() {
            format!("MEGA Folder ({})", link.handle)
        } else {
            format!("MEGA File ({})", link.handle)
        };

        let task_info = Arc::new(RwLock::new(TaskInfo {
            id: task_id.clone(),
            title: initial_title,
            status: TaskStatus::Downloading,
            total_bytes: 0,
            downloaded_bytes: 0,
            progress_percent: 0.0,
            speed_mbps: 0.0,
            eta_seconds: 0,
            output_path: req.output_dir.clone(),
            error: None,
        }));

        {
            let mut tasks = self.tasks.write().await;
            tasks.insert(
                task_id.clone(),
                ActiveTask {
                    info: Arc::clone(&task_info),
                    cancel_token: cancel_token.clone(),
                },
            );
        }

        let gateway_addr = self.gateway_addr.clone();
        let task_id_clone = task_id.clone();
        let task_info_clone = Arc::clone(&task_info);
        let cancel_child = cancel_token.clone();

        tokio::spawn(async move {
            let run_res = run_download_task(
                link,
                req,
                gateway_addr,
                Arc::clone(&task_info_clone),
                cancel_child.clone(),
            )
            .await;

            let mut info = task_info_clone.write().await;
            if cancel_child.is_cancelled() {
                info.status = TaskStatus::Cancelled;
                info.speed_mbps = 0.0;
                info.eta_seconds = 0;
            } else {
                match run_res {
                    Ok(_) => {
                        info.status = TaskStatus::Completed;
                        info.progress_percent = 100.0;
                        info.speed_mbps = 0.0;
                        info.eta_seconds = 0;
                        info!("Download task {} completed successfully.", task_id_clone);
                    }
                    Err(e) => {
                        info.status = TaskStatus::Failed;
                        info.error = Some(e.clone());
                        info.speed_mbps = 0.0;
                        info.eta_seconds = 0;
                        error!("Download task {} failed: {}", task_id_clone, e);
                    }
                }
            }
        });

        Ok(task_id)
    }

    /// Lists all current download tasks.
    pub async fn list_tasks(&self) -> Vec<TaskInfo> {
        let tasks = self.tasks.read().await;
        let mut list = Vec::with_capacity(tasks.len());
        for active in tasks.values() {
            let info = active.info.read().await;
            list.push(info.clone());
        }
        list.sort_by(|a, b| b.id.cmp(&a.id));
        list
    }

    /// Cancels an active download task by ID.
    pub async fn cancel_task(&self, id: &str) -> bool {
        let tasks = self.tasks.read().await;
        if let Some(active) = tasks.get(id) {
            active.cancel_token.cancel();
            let mut info = active.info.write().await;
            info.status = TaskStatus::Cancelled;
            info.speed_mbps = 0.0;
            info.eta_seconds = 0;
            true
        } else {
            false
        }
    }
}

async fn build_http_client(gateway_addr: &str) -> Client {
    let gw_url = format!("http://{}", gateway_addr);
    if let Ok(proxy) = Proxy::all(&gw_url) {
        if let Ok(client) = Client::builder()
            .timeout(CHUNK_TIMEOUT)
            .proxy(proxy)
            .build()
        {
            return client;
        }
    }
    Client::builder()
        .timeout(CHUNK_TIMEOUT)
        .build()
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
struct ChunkTask {
    info: ChunkInfo,
}

async fn run_download_task(
    link: MegaLink,
    req: DownloadRequest,
    gateway_addr: String,
    task_info: Arc<RwLock<TaskInfo>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    let gw_url = format!("http://{}", gateway_addr);
    let mega = MegaClient::new(Some(&gw_url));
    let base_out = PathBuf::from(&req.output_dir);
    tokio::fs::create_dir_all(&base_out)
        .await
        .map_err(|e| format!("Failed to create output directory {}: {}", base_out.display(), e))?;

    let http = Arc::new(build_http_client(&gateway_addr).await);

    if link.is_folder_scope() {
        let tree = mega
            .fetch_folder_tree(&link)
            .await
            .map_err(|e| format!("Failed to fetch folder tree: {}", e))?;

        let folder_title = tree
            .directories()
            .iter()
            .find(|d| d.parent_handle.is_empty() || d.parent_handle == link.handle || d.handle == link.handle)
            .map(|d| d.name.clone())
            .unwrap_or_else(|| format!("Folder_{}", link.handle));

        let folder_dest = if tree.directories().is_empty() {
            base_out.clone()
        } else {
            base_out.join(&folder_title)
        };
        tokio::fs::create_dir_all(&folder_dest)
            .await
            .map_err(|e| format!("Failed to create folder {}: {}", folder_dest.display(), e))?;

        for d in tree.directories() {
            let dir_path = folder_dest.join(&d.relative_path);
            let _ = tokio::fs::create_dir_all(&dir_path).await;
        }

        let selected_set: HashSet<String> = req.selected_handles.into_iter().collect();
        let files: Vec<&looker_mega::MegaFolderNode> = tree
            .files()
            .into_iter()
            .filter(|f| selected_set.is_empty() || selected_set.contains(&f.handle))
            .collect();

        if files.is_empty() {
            return Err("No files selected for download".to_string());
        }

        let total_bytes: u64 = files.iter().map(|f| f.size).sum();

        {
            let mut info = task_info.write().await;
            info.title = folder_title;
            info.total_bytes = total_bytes;
            info.output_path = folder_dest.to_string_lossy().to_string();
        }

        let downloaded_so_far = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        for file_node in files {
            if cancel_token.is_cancelled() {
                return Ok(());
            }

            let (download_url, _) = mega
                .get_folder_file_url(&link.handle, &file_node.handle)
                .await
                .map_err(|e| format!("Failed to get URL for {}: {}", file_node.name, e))?;

            let target_path = folder_dest.join(&file_node.relative_path);
            if let Some(parent) = target_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let file_key = file_node
                .key
                .clone()
                .ok_or_else(|| format!("Missing key for {}", file_node.name))?;

            download_single_file(
                &download_url,
                file_node.size,
                file_key.aes_key,
                file_key.nonce,
                &target_path,
                Arc::clone(&http),
                Arc::clone(&downloaded_so_far),
                total_bytes,
                start_time,
                Arc::clone(&task_info),
                cancel_token.clone(),
            )
            .await?;
        }
    } else {
        let meta = mega
            .resolve_file(&link)
            .await
            .map_err(|e| format!("Failed to resolve file: {}", e))?;

        let target_path = base_out.join(&meta.name);

        {
            let mut info = task_info.write().await;
            info.title = meta.name.clone();
            info.total_bytes = meta.size;
            info.output_path = target_path.to_string_lossy().to_string();
        }

        let downloaded_so_far = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        download_single_file(
            &meta.download_url,
            meta.size,
            meta.key.aes_key,
            meta.key.nonce,
            &target_path,
            Arc::clone(&http),
            Arc::clone(&downloaded_so_far),
            meta.size,
            start_time,
            Arc::clone(&task_info),
            cancel_token,
        )
        .await?;
    }

    Ok(())
}

async fn download_single_file(
    storage_url: &str,
    file_size: u64,
    aes_key: [u8; 16],
    nonce: [u8; 8],
    out_path: &Path,
    http: Arc<Client>,
    cumulative_bytes: Arc<AtomicU64>,
    grand_total_bytes: u64,
    start_time: Instant,
    task_info: Arc<RwLock<TaskInfo>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    // 1. Pre-allocate sparse file
    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(out_path)
        .map_err(|e| format!("Cannot open {}: {}", out_path.display(), e))?;
    std_file
        .set_len(file_size)
        .map_err(|e| format!("Cannot pre-allocate {}: {}", out_path.display(), e))?;
    drop(std_file);

    let shared_file = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(out_path)
            .await
            .map_err(|e| format!("Async open failed: {}", e))?,
    ));

    let chunks: Vec<ChunkInfo> = ChunkIterator::new(file_size).collect();
    let total_chunks = chunks.len();

    let (tx, rx) = mpsc::channel::<ChunkTask>(total_chunks + 8);
    for chunk in &chunks {
        let _ = tx.send(ChunkTask { info: *chunk }).await;
    }

    let rx = Arc::new(Mutex::new(rx));
    let concurrency = 4.min(total_chunks).max(1);
    let mut handles = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let rx = Arc::clone(&rx);
        let http = Arc::clone(&http);
        let storage_url = storage_url.to_string();
        let file = Arc::clone(&shared_file);
        let cumulative = Arc::clone(&cumulative_bytes);
        let task_info = Arc::clone(&task_info);
        let cancel = cancel_token.clone();

        handles.push(tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }

                let task = tokio::select! {
                    _ = cancel.cancelled() => break,
                    t = async {
                        let mut lock = rx.lock().await;
                        lock.recv().await
                    } => match t {
                        Some(item) => item,
                        None => break,
                    }
                };

                let chunk = task.info;

                let download_fut = async {
                    let range_path_url = format!("{}/{}", storage_url, chunk.path_range());
                    let resp = match http.get(&range_path_url).send().await {
                        Ok(r) if r.status().is_success() => r,
                        _ => {
                            let range_val =
                                format!("bytes={}-{}", chunk.offset, chunk.end_offset() - 1);
                            http.get(&storage_url)
                                .header("Range", range_val)
                                .send()
                                .await
                                .map_err(MegaError::Http)?
                        }
                    };

                    if !resp.status().is_success() {
                        return Err(MegaError::Http(resp.error_for_status().unwrap_err()));
                    }

                    let body_bytes = resp.bytes().await.map_err(MegaError::Http)?;
                    let mut plaintext = body_bytes.to_vec();

                    decrypt_ctr(&aes_key, &nonce, chunk.offset, &mut plaintext);
                    let _mac = compute_chunk_mac(&aes_key, &nonce, &plaintext);

                    {
                        let mut f = file.lock().await;
                        f.seek(SeekFrom::Start(chunk.offset)).await?;
                        f.write_all(&plaintext).await?;
                    }

                    Ok::<(), MegaError>(())
                };

                let res = tokio::select! {
                    _ = cancel.cancelled() => break,
                    r = tokio::time::timeout(CHUNK_TIMEOUT, download_fut) => r,
                };

                match res {
                    Ok(Ok(())) => {
                        let current_cum = cumulative.fetch_add(chunk.size, Ordering::Relaxed) + chunk.size;
                        let elapsed = start_time.elapsed().as_secs_f64();
                        let speed_bps = if elapsed > 0.1 {
                            (current_cum as f64 / elapsed) as u64
                        } else {
                            0
                        };
                        let speed_mbps = (speed_bps as f64 / (1024.0 * 1024.0) * 10.0).round() / 10.0;
                        let remaining = grand_total_bytes.saturating_sub(current_cum);
                        let eta = if speed_bps > 0 { remaining / speed_bps } else { 0 };
                        let progress = if grand_total_bytes > 0 {
                            ((current_cum as f64 / grand_total_bytes as f64) * 1000.0).round() / 10.0
                        } else {
                            0.0
                        };

                        let mut info = task_info.write().await;
                        info.downloaded_bytes = current_cum;
                        info.progress_percent = progress.min(100.0);
                        info.speed_mbps = speed_mbps;
                        info.eta_seconds = eta;
                    }
                    _ => {
                        warn!("Chunk {} download error or timed out, retrying...", chunk.index);
                        // Re-queue
                        let _lock = rx.lock().await;
                    }
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    if cancel_token.is_cancelled() {
        return Err("Download cancelled by user".to_string());
    }

    Ok(())
}
