use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use looker_pool::{ProxyItem, ProxyPool};
use reqwest::{Client, Proxy, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock, Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use looker_mega::{
    compute_chunk_mac, decrypt_ctr, ChunkInfo, ChunkIterator, FileMacAccumulator, FolderNodeType,
    MegaClient, MegaError, MegaLink,
};
use crate::settings::AppSettings;

const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CHUNK_RETRIES: usize = 8;

// ============================================================
// DISK SPACE CHECKING (Cross-Platform / Windows FFI)
// ============================================================

#[cfg(windows)]
pub fn get_available_disk_space(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;

    // Resolve nearest existing ancestor path
    let mut current = path.to_path_buf();
    while !current.exists() {
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    let mut wide: Vec<u16> = current.as_os_str().encode_wide().collect();
    wide.push(0);

    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }

    let mut free_avail: u64 = 0;
    let mut total: u64 = 0;
    let mut total_free: u64 = 0;

    let res = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut free_avail,
            &mut total,
            &mut total_free,
        )
    };

    if res != 0 {
        Some(free_avail)
    } else {
        None
    }
}

#[cfg(not(windows))]
pub fn get_available_disk_space(_path: &Path) -> Option<u64> {
    None
}

pub fn check_available_disk_space(target_path: &Path, needed_bytes: u64) -> Result<(), String> {
    if let Some(free_space) = get_available_disk_space(target_path) {
        if needed_bytes > free_space {
            let needed_gb = needed_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let free_gb = free_space as f64 / (1024.0 * 1024.0 * 1024.0);
            return Err(format!(
                "Insufficient disk space: Selected files require {:.2} GB, but only {:.2} GB free on target drive.",
                needed_gb, free_gb
            ));
        }
    }
    Ok(())
}

// ============================================================
// RESUME STATE & BITMAP PERSISTENCE (.looker-resume)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    pub file_handle: String,
    pub total_size: u64,
    pub completed_chunk_indices: Vec<usize>,
    pub updated_at_epoch_secs: u64,
}

pub fn resume_file_path(target_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.looker-resume", target_path.display()))
}

pub fn load_resume_state(target_path: &Path, file_handle: &str, file_size: u64) -> Option<HashSet<usize>> {
    let p = resume_file_path(target_path);
    if p.exists() {
        if let Ok(content) = std::fs::read_to_string(&p) {
            if let Ok(state) = serde_json::from_str::<ResumeState>(&content) {
                if state.file_handle == file_handle && state.total_size == file_size {
                    return Some(state.completed_chunk_indices.into_iter().collect());
                }
            }
        }
    }
    None
}

pub fn save_resume_state(target_path: &Path, file_handle: &str, file_size: u64, completed: &[usize]) {
    let p = resume_file_path(target_path);
    let state = ResumeState {
        file_handle: file_handle.to_string(),
        total_size: file_size,
        completed_chunk_indices: completed.to_vec(),
        updated_at_epoch_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    if let Ok(json) = serde_json::to_string(&state) {
        let _ = std::fs::write(p, json);
    }
}

pub fn remove_resume_state(target_path: &Path) {
    let p = resume_file_path(target_path);
    let _ = std::fs::remove_file(p);
}

// ============================================================
// COLLISION-SAFE PATH GENERATION (Never Overwrite Files/Folders)
// ============================================================

pub fn resolve_unique_path(
    base_dir: &Path,
    name: &str,
    is_dir: bool,
    file_handle: Option<&str>,
    file_size: Option<u64>,
) -> PathBuf {
    let initial_path = base_dir.join(name);

    // If an existing file has an active matching .looker-resume file, resume it!
    if let (Some(handle), Some(size)) = (file_handle, file_size) {
        if initial_path.exists() && load_resume_state(&initial_path, handle, size).is_some() {
            return initial_path;
        }
    }

    if !initial_path.exists() {
        return initial_path;
    }

    if is_dir {
        let mut counter = 1;
        loop {
            let candidate_name = format!("{} ({})", name, counter);
            let candidate_path = base_dir.join(&candidate_name);
            if !candidate_path.exists() {
                return candidate_path;
            }
            counter += 1;
        }
    } else {
        let path_obj = Path::new(name);
        let stem = path_obj.file_stem().and_then(|s| s.to_str()).unwrap_or(name);
        let extension = path_obj.extension().and_then(|e| e.to_str());

        let mut counter = 1;
        loop {
            let candidate_name = match extension {
                Some(ext) => format!("{} ({}).{}", stem, counter, ext),
                None => format!("{} ({})", stem, counter),
            };
            let candidate_path = base_dir.join(&candidate_name);
            if let (Some(handle), Some(size)) = (file_handle, file_size) {
                if candidate_path.exists() && load_resume_state(&candidate_path, handle, size).is_some() {
                    return candidate_path;
                }
            }
            if !candidate_path.exists() {
                return candidate_path;
            }
            counter += 1;
        }
    }
}

// ============================================================
// ATOMIC CHUNK SCHEDULER (Duplicate-Free Work Distribution)
// ============================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkStatus {
    Pending,
    InFlight { active_workers: HashSet<usize>, attempt: usize },
    Completed,
    Failed,
}

#[derive(Debug)]
pub struct ChunkScheduler {
    chunks: Vec<ChunkInfo>,
    statuses: Vec<ChunkStatus>,
    completed_count: usize,
    total_size: u64,
}

impl ChunkScheduler {
    pub fn new(chunks: Vec<ChunkInfo>, file_size: u64, already_completed: &HashSet<usize>) -> Self {
        let total = chunks.len();
        let mut statuses = vec![ChunkStatus::Pending; total];
        let mut completed_count = 0;

        for &idx in already_completed {
            if idx < total {
                statuses[idx] = ChunkStatus::Completed;
                completed_count += 1;
            }
        }

        Self {
            chunks,
            statuses,
            completed_count,
            total_size: file_size,
        }
    }

    /// Atomically acquires the next pending chunk and marks it InFlight in a single lock acquisition.
    /// Guarantees that two workers can NEVER be assigned the same chunk concurrently!
    pub fn acquire_next_chunk(&mut self, worker_id: usize) -> Option<(ChunkInfo, usize)> {
        for (idx, status) in self.statuses.iter_mut().enumerate() {
            if *status == ChunkStatus::Pending {
                let mut active = HashSet::new();
                active.insert(worker_id);
                *status = ChunkStatus::InFlight { active_workers: active, attempt: 0 };
                return Some((self.chunks[idx], 0));
            }
        }
        None
    }

    /// When fewer than max_workers chunks remain at the end of a file, allow speculative tail retries
    /// on uncompleted in-flight chunks so one slow proxy cannot hold up file completion.
    pub fn acquire_speculative_tail_chunk(&mut self, worker_id: usize, max_workers: usize) -> Option<(ChunkInfo, usize)> {
        let remaining = self.chunks.len().saturating_sub(self.completed_count);
        if remaining == 0 || remaining >= max_workers {
            return None;
        }

        for (idx, status) in self.statuses.iter_mut().enumerate() {
            if let ChunkStatus::InFlight { active_workers, attempt } = status {
                if !active_workers.contains(&worker_id) && active_workers.len() < 2 {
                    active_workers.insert(worker_id);
                    *attempt += 1;
                    return Some((self.chunks[idx], *attempt));
                }
            }
        }
        None
    }

    /// Checks if a chunk is completed.
    pub fn is_completed(&self, index: usize) -> bool {
        if index < self.statuses.len() {
            self.statuses[index] == ChunkStatus::Completed
        } else {
            false
        }
    }

    /// Marks a chunk completed and increments the completion count.
    /// Returns true if newly transitioned to Completed, false if already Completed.
    pub fn mark_completed(&mut self, index: usize) -> bool {
        if index < self.statuses.len() {
            if self.statuses[index] != ChunkStatus::Completed {
                self.statuses[index] = ChunkStatus::Completed;
                self.completed_count += 1;
                return true;
            }
        }
        false
    }

    /// Marks a chunk for retry or marks it failed if max retries exceeded.
    pub fn mark_retry(&mut self, index: usize, max_retries: usize) -> Result<usize, ()> {
        self.mark_worker_retry(index, None, max_retries)
    }

    /// Marks a chunk for retry by a specific worker, preserving other in-flight workers.
    pub fn mark_worker_retry(&mut self, index: usize, worker_id: Option<usize>, max_retries: usize) -> Result<usize, ()> {
        if index < self.statuses.len() {
            if self.statuses[index] == ChunkStatus::Completed {
                return Ok(0);
            }
            if let ChunkStatus::InFlight { active_workers, attempt } = &mut self.statuses[index] {
                if let Some(w) = worker_id {
                    active_workers.remove(&w);
                    if !active_workers.is_empty() {
                        return Ok(*attempt);
                    }
                }
                let next_attempt = *attempt + 1;
                if next_attempt < max_retries {
                    self.statuses[index] = ChunkStatus::Pending;
                    Ok(next_attempt)
                } else {
                    self.statuses[index] = ChunkStatus::Failed;
                    Err(())
                }
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    pub fn completed_count(&self) -> usize {
        self.completed_count
    }

    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_all_completed(&self) -> bool {
        self.completed_count >= self.chunks.len()
    }

    pub fn active_in_flight(&self) -> usize {
        self.statuses
            .iter()
            .filter(|s| matches!(s, ChunkStatus::InFlight { .. }))
            .count()
    }

    pub fn completed_indices(&self) -> Vec<usize> {
        self.statuses
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if *s == ChunkStatus::Completed { Some(i) } else { None })
            .collect()
    }
}

// ============================================================
// RATE LIMITER & LIVE CONFIG
// ============================================================

pub struct RateLimiter {
    speed_limit_bytes_sec: AtomicU64,
    transferred_window_bytes: AtomicU64,
    window_start: parking_lot::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(speed_limit_mbps: f64) -> Self {
        let bytes_sec = (speed_limit_mbps * 1024.0 * 1024.0) as u64;
        Self {
            speed_limit_bytes_sec: AtomicU64::new(bytes_sec),
            transferred_window_bytes: AtomicU64::new(0),
            window_start: parking_lot::Mutex::new(Instant::now()),
        }
    }

    pub fn set_limit(&self, speed_limit_mbps: f64) {
        let bytes_sec = (speed_limit_mbps.max(0.0) * 1024.0 * 1024.0) as u64;
        self.speed_limit_bytes_sec.store(bytes_sec, Ordering::Relaxed);
    }

    pub async fn throttle(&self, bytes: usize) {
        let limit = self.speed_limit_bytes_sec.load(Ordering::Relaxed);
        if limit == 0 {
            return;
        }

        let sleep_duration = {
            let mut start_guard = self.window_start.lock();
            let elapsed = start_guard.elapsed();
            if elapsed >= Duration::from_millis(500) {
                *start_guard = Instant::now();
                self.transferred_window_bytes.store(bytes as u64, Ordering::Relaxed);
                None
            } else {
                let current = self.transferred_window_bytes.fetch_add(bytes as u64, Ordering::Relaxed) + bytes as u64;
                let window_secs = elapsed.as_secs_f64().max(0.001);
                let target_secs = current as f64 / limit as f64;
                if target_secs > window_secs {
                    let sleep_secs = target_secs - window_secs;
                    if sleep_secs > 0.005 && sleep_secs < 2.0 {
                        Some(Duration::from_secs_f64(sleep_secs))
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        if let Some(d) = sleep_duration {
            tokio::time::sleep(d).await;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloaderConfig {
    #[serde(default = "default_routing_mode")]
    pub routing_mode: String, // "passive" (default) or "force_proxy"
    #[serde(default = "default_workers")]
    pub workers_per_file: usize, // 1 to 24 (default 6)
    #[serde(default = "default_max_files")]
    pub max_concurrent_files: usize, // 1 to 5 (default 2)
    #[serde(default)]
    pub speed_limit_mbps: f64, // 0 = unlimited
}

fn default_routing_mode() -> String {
    "passive".to_string()
}
fn default_workers() -> usize {
    6
}
fn default_max_files() -> usize {
    2
}

impl Default for DownloaderConfig {
    fn default() -> Self {
        Self {
            routing_mode: default_routing_mode(),
            workers_per_file: default_workers(),
            max_concurrent_files: default_max_files(),
            speed_limit_mbps: 0.0,
        }
    }
}

impl DownloaderConfig {
    pub fn sanitize(&mut self) {
        if !self.routing_mode.eq_ignore_ascii_case("force_proxy") && !self.routing_mode.eq_ignore_ascii_case("force") {
            self.routing_mode = "passive".to_string();
        } else {
            self.routing_mode = "force_proxy".to_string();
        }
        self.workers_per_file = self.workers_per_file.clamp(1, 24);
        self.max_concurrent_files = self.max_concurrent_files.clamp(1, 5);
        if self.speed_limit_mbps < 0.0 {
            self.speed_limit_mbps = 0.0;
        }
    }
}

// ============================================================
// DATA TYPES & PERSISTENT QUEUE MODELS
// ============================================================

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
    #[serde(default = "default_category")]
    pub category: String,
    #[serde(default)]
    pub title: Option<String>,
}

fn default_output_dir() -> String {
    "./downloads".to_string()
}

fn default_category() -> String {
    "General".to_string()
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

pub type DownloadStatus = TaskStatus;

/// Sanitizes a folder title for Windows and cross-platform filesystem compatibility.
pub fn sanitize_folder_name(name: &str) -> String {
    let forbidden = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    let sanitized: String = name
        .chars()
        .map(|c| if forbidden.contains(&c) || c.is_control() { '_' } else { c })
        .collect();
    let trimmed = sanitized.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() {
        "Folder".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Completion / Drop Guard ensuring tasks never remain stuck in Downloading if their future stops running.
pub struct TaskDropGuard {
    pub task_id: String,
    pub task_info: Arc<RwLock<TaskInfo>>,
    pub completed_cleanly: bool,
}

impl Drop for TaskDropGuard {
    fn drop(&mut self) {
        if !self.completed_cleanly {
            let task_id = self.task_id.clone();
            if let Ok(mut info) = self.task_info.try_write() {
                if info.status == TaskStatus::Downloading {
                    info.status = TaskStatus::Failed;
                    if info.error.is_none() {
                        info.error = Some("Task terminated unexpectedly or panicked".to_string());
                    }
                    info.speed_mbps = 0.0;
                    info.eta_seconds = 0;
                    info.active_workers = 0;
                    warn!("TaskDropGuard transitioned task {} to Failed state", task_id);
                }
            } else {
                let task_info = Arc::clone(&self.task_info);
                tokio::spawn(async move {
                    let mut info = task_info.write().await;
                    if info.status == TaskStatus::Downloading {
                        info.status = TaskStatus::Failed;
                        if info.error.is_none() {
                            info.error = Some("Task terminated unexpectedly or panicked".to_string());
                        }
                        info.speed_mbps = 0.0;
                        info.eta_seconds = 0;
                        info.active_workers = 0;
                        warn!("TaskDropGuard (async fallback) transitioned task {} to Failed state", task_id);
                    }
                });
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    pub title: String,
    pub category: String,
    pub status: TaskStatus,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub progress_percent: f64,
    pub speed_mbps: f64,
    pub eta_seconds: u64,
    pub output_path: String,
    pub error: Option<String>,
    pub routing_mode: String,
    pub active_workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedTask {
    pub id: String,
    pub title: String,
    pub category: String,
    pub url: String,
    pub output_dir: String,
    pub selected_handles: Vec<String>,
    pub status: TaskStatus,
    pub total_bytes: u64,
    pub downloaded_bytes: u64,
    pub progress_percent: f64,
    pub output_path: String,
    pub error: Option<String>,
    #[serde(default)]
    pub completed_chunk_indices: HashMap<String, Vec<usize>>,
    pub routing_mode: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedQueue {
    pub tasks: Vec<PersistedTask>,
}

pub fn get_queue_file_path() -> PathBuf {
    if let Some(mut dir) = dirs::data_local_dir() {
        dir.push("looker");
        dir.push("queue.json");
        dir
    } else {
        PathBuf::from("queue.json")
    }
}

struct ActiveTask {
    info: Arc<RwLock<TaskInfo>>,
    cancel_token: parking_lot::Mutex<CancellationToken>,
    generation: AtomicU64,
    req: DownloadRequest,
    completed_chunks: Arc<RwLock<HashMap<String, HashSet<usize>>>>,
    using_proxies: Arc<AtomicBool>,
    created_at: u64,
}

fn spawn_shell_command(cmd: &str) {
    let cmd = cmd.to_string();
    tokio::spawn(async move {
        #[cfg(target_os = "windows")]
        let mut command = tokio::process::Command::new("cmd");
        #[cfg(target_os = "windows")]
        command.args(["/C", &cmd]);

        #[cfg(not(target_os = "windows"))]
        let mut command = tokio::process::Command::new("sh");
        #[cfg(not(target_os = "windows"))]
        command.args(["-c", &cmd]);

        match command.spawn() {
            Ok(mut child) => {
                let _ = child.wait().await;
            }
            Err(e) => {
                warn!("Failed to spawn shell command '{}': {}", cmd, e);
            }
        }
    });
}

async fn save_queue_from_tasks(tasks_lock: &Arc<RwLock<HashMap<String, Arc<ActiveTask>>>>) {
    let active_tasks: Vec<Arc<ActiveTask>> = {
        let tasks_map = tasks_lock.read().await;
        tasks_map.values().cloned().collect()
    };
    let mut persisted_tasks = Vec::with_capacity(active_tasks.len());

    for active in active_tasks {
        let info = active.info.read().await.clone();
        let chunks_guard = active.completed_chunks.read().await.clone();
        let mut chunk_indices = HashMap::new();
        for (h, set) in chunks_guard.iter() {
            chunk_indices.insert(h.clone(), set.iter().copied().collect::<Vec<usize>>());
        }

        persisted_tasks.push(PersistedTask {
            id: info.id.clone(),
            title: info.title.clone(),
            category: info.category.clone(),
            url: active.req.url.clone(),
            output_dir: active.req.output_dir.clone(),
            selected_handles: active.req.selected_handles.clone(),
            status: info.status,
            total_bytes: info.total_bytes,
            downloaded_bytes: info.downloaded_bytes,
            progress_percent: info.progress_percent,
            output_path: info.output_path.clone(),
            error: info.error.clone(),
            completed_chunk_indices: chunk_indices,
            routing_mode: info.routing_mode.clone(),
            created_at: active.created_at,
        });
    }

    let queue = PersistedQueue {
        tasks: persisted_tasks,
    };

    let path = get_queue_file_path();
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    if let Ok(json) = serde_json::to_string_pretty(&queue) {
        let _ = tokio::fs::write(&path, json).await;
    }
}

pub struct DownloadManager {
    gateway_addr: String,
    pool: Arc<ProxyPool>,
    config: Arc<RwLock<DownloaderConfig>>,
    settings: Arc<RwLock<AppSettings>>,
    rate_limiter: Arc<RateLimiter>,
    tasks: Arc<RwLock<HashMap<String, Arc<ActiveTask>>>>,
    next_id: AtomicUsize,
    last_host_509_at: Arc<RwLock<Option<Instant>>>,
    last_509_cmd_at: Arc<RwLock<Option<Instant>>>,
    persist_to_disk: bool,
}

impl DownloadManager {
    pub fn new(gateway_addr: String, pool: Arc<ProxyPool>) -> Self {
        let settings = AppSettings::load();
        Self::with_settings_and_persistence(gateway_addr, pool, settings, true)
    }

    pub fn new_ephemeral(gateway_addr: String, pool: Arc<ProxyPool>, settings: AppSettings) -> Self {
        Self::with_settings_and_persistence(gateway_addr, pool, settings, false)
    }

    fn with_settings_and_persistence(
        gateway_addr: String,
        pool: Arc<ProxyPool>,
        mut settings: AppSettings,
        persist_to_disk: bool,
    ) -> Self {
        settings.sanitize();
        let speed_mbps = settings.speed_limit_mbps.max(0.0);
        let rate_limiter = Arc::new(RateLimiter::new(speed_mbps));
        let config = DownloaderConfig {
            routing_mode: settings.routing_mode.clone(),
            workers_per_file: settings.slots_per_file,
            max_concurrent_files: settings.max_parallel_downloads,
            speed_limit_mbps: speed_mbps,
        };

        Self {
            gateway_addr,
            pool,
            config: Arc::new(RwLock::new(config)),
            settings: Arc::new(RwLock::new(settings)),
            rate_limiter,
            tasks: Arc::new(RwLock::new(HashMap::new())),
            next_id: AtomicUsize::new(1),
            last_host_509_at: Arc::new(RwLock::new(None)),
            last_509_cmd_at: Arc::new(RwLock::new(None)),
            persist_to_disk,
        }
    }

    /// Loads incomplete and completed tasks from `%LOCALAPPDATA%\looker\queue.json` on startup.
    /// Incomplete tasks are restored in a `Paused` state so downloads survive app restarts.
    pub async fn load_persisted_queue(&self) {
        let path = get_queue_file_path();
        if !path.exists() {
            return;
        }

        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read queue file {}: {}", path.display(), e);
                return;
            }
        };

        let queue: PersistedQueue = match serde_json::from_str(&content) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to parse queue file {}: {}", path.display(), e);
                return;
            }
        };

        let mut tasks_map = self.tasks.write().await;
        let mut max_seq = 0;

        for pt in queue.tasks {
            if let Some(num_str) = pt.id.strip_prefix("task-") {
                if let Ok(seq) = num_str.parse::<usize>() {
                    max_seq = max_seq.max(seq);
                }
            }

            // Restore in Paused state if it was downloading or paused
            let status = match pt.status {
                TaskStatus::Downloading | TaskStatus::Paused => TaskStatus::Paused,
                other => other,
            };

            let mut chunk_map = HashMap::new();
            for (handle, list) in pt.completed_chunk_indices {
                chunk_map.insert(handle, list.into_iter().collect::<HashSet<usize>>());
            }

            let task_info = Arc::new(RwLock::new(TaskInfo {
                id: pt.id.clone(),
                title: pt.title.clone(),
                category: pt.category.clone(),
                status,
                total_bytes: pt.total_bytes,
                downloaded_bytes: pt.downloaded_bytes,
                progress_percent: pt.progress_percent,
                speed_mbps: 0.0,
                eta_seconds: 0,
                output_path: pt.output_path.clone(),
                error: pt.error.clone(),
                routing_mode: pt.routing_mode.clone(),
                active_workers: 0,
            }));

            let is_force = pt.routing_mode.eq_ignore_ascii_case("force_proxy")
                || pt.routing_mode.eq_ignore_ascii_case("509_failover");
            let active = Arc::new(ActiveTask {
                info: task_info,
                cancel_token: parking_lot::Mutex::new(CancellationToken::new()),
                generation: AtomicU64::new(0),
                req: DownloadRequest {
                    url: pt.url,
                    selected_handles: pt.selected_handles,
                    output_dir: pt.output_dir,
                    category: pt.category,
                    title: Some(pt.title.clone()),
                },
                completed_chunks: Arc::new(RwLock::new(chunk_map)),
                using_proxies: Arc::new(AtomicBool::new(is_force)),
                created_at: pt.created_at,
            });

            tasks_map.insert(pt.id, active);
        }

        self.next_id.store(max_seq + 1, Ordering::Relaxed);
        info!("Loaded {} persistent download tasks from {}", tasks_map.len(), path.display());
    }

    /// Persists all current download tasks to disk.
    pub async fn save_queue(&self) {
        if self.persist_to_disk {
            save_queue_from_tasks(&self.tasks).await;
        }
    }

    /// Gets current application settings.
    pub async fn get_settings(&self) -> AppSettings {
        self.settings.read().await.clone()
    }

    /// Gets the last used download directory if configured.
    pub async fn get_last_used_download_dir(&self) -> Option<String> {
        let s = self.settings.read().await;
        s.last_used_download_dir.clone()
    }

    /// Updates application settings, enforces constraints, persists to disk, and applies rate limit.
    pub async fn update_settings(&self, mut new_settings: AppSettings) -> AppSettings {
        new_settings.sanitize();
        let speed_mbps = new_settings.speed_limit_mbps.max(0.0);
        self.rate_limiter.set_limit(speed_mbps);

        {
            let mut cfg = self.config.write().await;
            cfg.routing_mode = new_settings.routing_mode.clone();
            cfg.workers_per_file = new_settings.slots_per_file;
            cfg.max_concurrent_files = new_settings.max_parallel_downloads;
            cfg.speed_limit_mbps = speed_mbps;
        }

        if self.persist_to_disk {
            let _ = new_settings.save_async().await;
        }
        let mut s = self.settings.write().await;
        *s = new_settings.clone();
        new_settings
    }

    /// Resets application settings to factory defaults.
    pub async fn reset_settings(&self) -> AppSettings {
        let def = AppSettings::default();
        self.update_settings(def).await
    }

    /// Gets current live downloader configuration.
    pub async fn get_config(&self) -> DownloaderConfig {
        self.config.read().await.clone()
    }

    /// Updates live downloader configuration with bounds checking and applies rate limit.
    pub async fn update_config(&self, mut cfg: DownloaderConfig) -> DownloaderConfig {
        cfg.sanitize();
        self.rate_limiter.set_limit(cfg.speed_limit_mbps);
        {
            let mut current = self.config.write().await;
            *current = cfg.clone();
        }
        {
            let mut s = self.settings.write().await;
            s.routing_mode = cfg.routing_mode.clone();
            s.slots_per_file = cfg.workers_per_file;
            s.max_parallel_downloads = cfg.max_concurrent_files;
            s.speed_limit_mbps = cfg.speed_limit_mbps;
            if self.persist_to_disk {
                let _ = s.save_async().await;
            }
        }
        cfg
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
                .root_title()
                .map(|t| sanitize_folder_name(&t))
                .or_else(|| {
                    tree.directories()
                        .iter()
                        .find(|d| (d.parent_handle.is_empty() || d.handle == link.handle) && !d.name.is_empty() && d.name != link.handle)
                        .map(|d| sanitize_folder_name(&d.name))
                })
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

        let s = {
            let mut settings_guard = self.settings.write().await;
            if req.output_dir.trim().is_empty() || req.output_dir == "./downloads" {
                req.output_dir = settings_guard
                    .last_used_download_dir
                    .clone()
                    .unwrap_or_else(|| settings_guard.default_download_dir.clone());
            } else {
                settings_guard.last_used_download_dir = Some(req.output_dir.clone());
                if self.persist_to_disk {
                    let _ = settings_guard.save_async().await;
                }
            }
            settings_guard.clone()
        };

        let out_path = PathBuf::from(&req.output_dir);
        tokio::fs::create_dir_all(&out_path)
            .await
            .map_err(|e| format!("Failed to create output directory {}: {}", out_path.display(), e))?;

        let initial_title = if let Some(ref t) = req.title {
            let tr = t.trim();
            if !tr.is_empty() && !tr.starts_with("Folder_") && !tr.starts_with("MEGA Folder (") {
                sanitize_folder_name(tr)
            } else if link.is_folder() {
                format!("MEGA Folder ({})", link.handle)
            } else {
                format!("MEGA File ({})", link.handle)
            }
        } else if link.is_folder() {
            format!("MEGA Folder ({})", link.handle)
        } else {
            format!("MEGA File ({})", link.handle)
        };

        let is_force = s.routing_mode.eq_ignore_ascii_case("force_proxy");
        let using_proxies = Arc::new(AtomicBool::new(is_force));

        let category = if req.category.trim().is_empty() {
            "General".to_string()
        } else {
            req.category.clone()
        };

        let initial_status = if s.freeze_before_start {
            TaskStatus::Paused
        } else {
            TaskStatus::Downloading
        };

        let task_info = Arc::new(RwLock::new(TaskInfo {
            id: task_id.clone(),
            title: initial_title,
            category: category.clone(),
            status: initial_status,
            total_bytes: 0,
            downloaded_bytes: 0,
            progress_percent: 0.0,
            speed_mbps: 0.0,
            eta_seconds: 0,
            output_path: req.output_dir.clone(),
            error: None,
            routing_mode: s.routing_mode.clone(),
            active_workers: 0,
        }));

        let initial_gen = if s.freeze_before_start { 0 } else { 1 };
        let active_task = Arc::new(ActiveTask {
            info: Arc::clone(&task_info),
            cancel_token: parking_lot::Mutex::new(cancel_token.clone()),
            generation: AtomicU64::new(initial_gen),
            req: req.clone(),
            completed_chunks: Arc::new(RwLock::new(HashMap::new())),
            using_proxies: Arc::clone(&using_proxies),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });

        {
            let mut tasks = self.tasks.write().await;
            tasks.insert(task_id.clone(), Arc::clone(&active_task));
        }

        self.save_queue().await;

        if !s.freeze_before_start {
            self.spawn_task_worker(
                task_id.clone(),
                Arc::clone(&active_task),
                link,
                req,
                cancel_token,
                initial_gen,
            );
        }

        Ok(task_id)
    }

    fn spawn_task_worker(
        &self,
        task_id: String,
        active_task: Arc<ActiveTask>,
        link: MegaLink,
        req: DownloadRequest,
        cancel_token: CancellationToken,
        worker_gen: u64,
    ) {
        let gateway_addr = self.gateway_addr.clone();
        let pool = Arc::clone(&self.pool);
        let config_lock = Arc::clone(&self.config);
        let settings = Arc::clone(&self.settings);
        let last_host_509_at = Arc::clone(&self.last_host_509_at);
        let last_509_cmd_at = Arc::clone(&self.last_509_cmd_at);
        let tasks_map = Arc::clone(&self.tasks);
        let rate_limiter = Arc::clone(&self.rate_limiter);
        let task_info = Arc::clone(&active_task.info);
        let completed_chunks = Arc::clone(&active_task.completed_chunks);
        let using_proxies = Arc::clone(&active_task.using_proxies);
        let persist_to_disk = self.persist_to_disk;

        tokio::spawn(async move {
            let mut guard = TaskDropGuard {
                task_id: task_id.clone(),
                task_info: Arc::clone(&task_info),
                completed_cleanly: false,
            };

            let run_res = run_download_task(
                link,
                req,
                gateway_addr,
                pool,
                config_lock,
                Arc::clone(&settings),
                Arc::clone(&last_host_509_at),
                Arc::clone(&last_509_cmd_at),
                rate_limiter,
                Arc::clone(&task_info),
                completed_chunks,
                using_proxies,
                cancel_token.clone(),
            )
            .await;

            // If a newer resume generation superseded this worker, exit cleanly without overwriting state.
            if active_task.generation.load(Ordering::SeqCst) != worker_gen {
                guard.completed_cleanly = true;
                return;
            }

            {
                let mut info = task_info.write().await;
                if cancel_token.is_cancelled() {
                    if info.status != TaskStatus::Paused {
                        info.status = TaskStatus::Cancelled;
                    }
                    info.speed_mbps = 0.0;
                    info.eta_seconds = 0;
                    info.active_workers = 0;
                } else {
                    match run_res {
                        Ok(_) => {
                            info.status = TaskStatus::Completed;
                            info.progress_percent = 100.0;
                            info.speed_mbps = 0.0;
                            info.eta_seconds = 0;
                            info.active_workers = 0;
                            info!("Download task {} completed successfully.", task_id);
                        }
                        Err(e) => {
                            info.status = TaskStatus::Failed;
                            info.error = Some(e.clone());
                            info.speed_mbps = 0.0;
                            info.eta_seconds = 0;
                            info.active_workers = 0;
                            error!("Download task {} failed: {}", task_id, e);
                        }
                    }
                }
                guard.completed_cleanly = true;
            }

            // Persist updated queue state
            if persist_to_disk {
                save_queue_from_tasks(&tasks_map).await;
            }

            // Check if active queue has 0 remaining downloading tasks
            let active_remaining = {
                let map = tasks_map.read().await;
                let mut count = 0;
                for t in map.values() {
                    let st = t.info.read().await.status;
                    if st == TaskStatus::Downloading {
                        count += 1;
                    }
                }
                count
            };

            if active_remaining == 0 {
                let s = settings.read().await;
                if let Some(cmd) = &s.cmd_on_all_finished {
                    spawn_shell_command(cmd);
                }
            }
        });
    }

    /// Pauses an active download task, halts chunk workers, and flushes completed chunk bitmap.
    pub async fn pause_task(&self, id: &str) -> bool {
        let token_opt = {
            let tasks = self.tasks.read().await;
            if let Some(active) = tasks.get(id) {
                let mut info = active.info.write().await;
                if info.status == TaskStatus::Downloading {
                    info.status = TaskStatus::Paused;
                    info.speed_mbps = 0.0;
                    info.eta_seconds = 0;
                    info.active_workers = 0;
                    Some(active.cancel_token.lock().clone())
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(token) = token_opt {
            token.cancel();
            self.save_queue().await;
            true
        } else {
            false
        }
    }

    /// Resumes a paused, frozen, failed, or cancelled download task, fetching only remaining incomplete chunks.
    pub async fn resume_task(&self, id: &str) -> Result<bool, String> {
        let (active_task, link, req, new_token, worker_gen) = {
            let tasks = self.tasks.read().await;
            if let Some(active) = tasks.get(id) {
                let mut info = active.info.write().await;
                if info.status == TaskStatus::Downloading || info.status == TaskStatus::Completed {
                    return Ok(false);
                }

                let link = MegaLink::parse(&active.req.url).map_err(|e| format!("Invalid URL: {}", e))?;
                info.status = TaskStatus::Downloading;
                info.error = None;
                let new_token = CancellationToken::new();
                *active.cancel_token.lock() = new_token.clone();
                let worker_gen = active.generation.fetch_add(1, Ordering::SeqCst) + 1;
                (Arc::clone(active), link, active.req.clone(), new_token, worker_gen)
            } else {
                return Ok(false);
            }
        };

        self.spawn_task_worker(
            id.to_string(),
            Arc::clone(&active_task),
            link,
            req,
            new_token,
            worker_gen,
        );

        self.save_queue().await;
        Ok(true)
    }

    /// Pauses all currently downloading tasks atomically.
    pub async fn pause_all_tasks(&self) -> usize {
        let mut tokens = Vec::new();
        {
            let tasks = self.tasks.read().await;
            for active in tasks.values() {
                let mut info = active.info.write().await;
                if info.status == TaskStatus::Downloading {
                    info.status = TaskStatus::Paused;
                    info.speed_mbps = 0.0;
                    info.eta_seconds = 0;
                    info.active_workers = 0;
                    tokens.push(active.cancel_token.lock().clone());
                }
            }
        }
        let count = tokens.len();
        for token in tokens {
            token.cancel();
        }
        if count > 0 {
            self.save_queue().await;
        }
        count
    }

    /// Resumes all paused/frozen tasks in the queue.
    pub async fn resume_all_tasks(&self) -> usize {
        let mut to_spawn = Vec::new();
        {
            let tasks = self.tasks.read().await;
            for (id, active) in tasks.iter() {
                let mut info = active.info.write().await;
                if info.status == TaskStatus::Paused {
                    if let Ok(link) = MegaLink::parse(&active.req.url) {
                        info.status = TaskStatus::Downloading;
                        info.error = None;
                        let new_token = CancellationToken::new();
                        *active.cancel_token.lock() = new_token.clone();
                        let worker_gen = active.generation.fetch_add(1, Ordering::SeqCst) + 1;
                        to_spawn.push((
                            id.clone(),
                            Arc::clone(active),
                            link,
                            active.req.clone(),
                            new_token,
                            worker_gen,
                        ));
                    }
                }
            }
        }
        let count = to_spawn.len();
        for (id, active, link, req, new_token, worker_gen) in to_spawn {
            self.spawn_task_worker(id, active, link, req, new_token, worker_gen);
        }
        if count > 0 {
            self.save_queue().await;
        }
        count
    }

    /// Removes all completed tasks from the queue.
    pub async fn clear_completed_tasks(&self) -> usize {
        let completed_ids: Vec<String> = {
            let tasks = self.tasks.read().await;
            let mut ids = Vec::new();
            for (id, active) in tasks.iter() {
                if active.info.read().await.status == TaskStatus::Completed {
                    ids.push(id.clone());
                }
            }
            ids
        };
        if completed_ids.is_empty() {
            return 0;
        }
        let mut removed = 0;
        {
            let mut tasks = self.tasks.write().await;
            for id in completed_ids {
                if tasks.remove(&id).is_some() {
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            self.save_queue().await;
        }
        removed
    }

    /// Cancels an active download task by ID.
    pub async fn cancel_task(&self, id: &str) -> bool {
        let token_opt = {
            let tasks = self.tasks.read().await;
            if let Some(active) = tasks.get(id) {
                let mut info = active.info.write().await;
                info.status = TaskStatus::Cancelled;
                info.speed_mbps = 0.0;
                info.eta_seconds = 0;
                info.active_workers = 0;
                Some(active.cancel_token.lock().clone())
            } else {
                None
            }
        };

        if let Some(token) = token_opt {
            token.cancel();
            self.save_queue().await;
            true
        } else {
            false
        }
    }

    /// Removes a download task from memory and queue.json.
    /// Aborts in-flight workers immediately and cleans up incomplete .part files and resume sidecars.
    pub async fn delete_task(&self, id: &str) -> bool {
        let (token_opt, output_path, status) = {
            let mut tasks = self.tasks.write().await;
            if let Some(active) = tasks.remove(id) {
                let info = active.info.read().await.clone();
                (Some(active.cancel_token.lock().clone()), info.output_path, info.status)
            } else {
                (None, String::new(), TaskStatus::Cancelled)
            }
        };

        if let Some(token) = token_opt {
            token.cancel();
            self.save_queue().await;

            // If task was not completed, clean up .part files, .looker-resume, and incomplete files
            if status != TaskStatus::Completed && !output_path.is_empty() {
                let output_clone = output_path.clone();
                tokio::spawn(async move {
                    // Brief yield so cancelling workers drop Windows file handles cleanly
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    let path = PathBuf::from(&output_clone);
                    let resume_p = resume_file_path(&path);
                    let _ = tokio::fs::remove_file(&resume_p).await;

                    let part_path = PathBuf::from(format!("{}.part", output_clone));
                    let _ = tokio::fs::remove_file(&part_path).await;

                    if path.is_file() {
                        let _ = tokio::fs::remove_file(&path).await;
                    }
                });
            }
            true
        } else {
            false
        }
    }

    /// Opens output folder in native file explorer.
    pub async fn open_task_folder(&self, id: &str) -> Result<(), String> {
        let active = {
            let tasks = self.tasks.read().await;
            tasks.get(id).cloned()
        };
        let path_to_open = if let Some(active) = active {
            let info = active.info.read().await.clone();
            let path = PathBuf::from(&info.output_path);
            if path.is_file() {
                path.parent().unwrap_or(&path).to_path_buf()
            } else {
                path
            }
        } else {
            return Err("Task not found".to_string());
        };

        opener::open(&path_to_open).map_err(|e| format!("Cannot open folder: {}", e))?;
        Ok(())
    }

    /// Lists all current download tasks.
    pub async fn list_tasks(&self) -> Vec<TaskInfo> {
        let active_tasks: Vec<Arc<ActiveTask>> = {
            let tasks = self.tasks.read().await;
            tasks.values().cloned().collect()
        };
        let mut list = Vec::with_capacity(active_tasks.len());
        for active in active_tasks {
            let info = active.info.read().await.clone();
            list.push(info);
        }
        list.sort_by(|a, b| {
            let seq_a = a.id.strip_prefix("task-").and_then(|s| s.parse::<usize>().ok());
            let seq_b = b.id.strip_prefix("task-").and_then(|s| s.parse::<usize>().ok());
            match (seq_a, seq_b) {
                (Some(na), Some(nb)) => nb.cmp(&na),
                _ => b.id.cmp(&a.id),
            }
        });
        list
    }
}

async fn build_http_client(gateway_addr: &str, watchdog_seconds: u64) -> Client {
    let gw_url = format!("http://{}", gateway_addr);
    let read_timeout = Duration::from_secs(watchdog_seconds.max(15));
    if let Ok(proxy) = Proxy::all(&gw_url) {
        if let Ok(client) = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .read_timeout(read_timeout)
            .timeout(CHUNK_TIMEOUT)
            .proxy(proxy)
            .build()
        {
            return client;
        }
    }
    Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .read_timeout(read_timeout)
        .timeout(CHUNK_TIMEOUT)
        .build()
        .unwrap_or_default()
}

async fn run_download_task(
    link: MegaLink,
    req: DownloadRequest,
    gateway_addr: String,
    pool: Arc<ProxyPool>,
    _config_lock: Arc<RwLock<DownloaderConfig>>,
    settings: Arc<RwLock<AppSettings>>,
    last_host_509_at: Arc<RwLock<Option<Instant>>>,
    last_509_cmd_at: Arc<RwLock<Option<Instant>>>,
    rate_limiter: Arc<RateLimiter>,
    task_info: Arc<RwLock<TaskInfo>>,
    completed_chunks_map: Arc<RwLock<HashMap<String, HashSet<usize>>>>,
    using_proxies: Arc<AtomicBool>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    let gw_url = format!("http://{}", gateway_addr);
    let mega = Arc::new(MegaClient::new(Some(&gw_url)));
    let base_out = PathBuf::from(&req.output_dir);
    tokio::fs::create_dir_all(&base_out)
        .await
        .map_err(|e| format!("Failed to create output directory {}: {}", base_out.display(), e))?;

    let (workers_per_file, max_concurrent_files, upstream_proxy, watchdog_secs) = {
        let s = settings.read().await;
        (
            s.slots_per_file.clamp(1, 24),
            s.max_parallel_downloads.clamp(1, 10),
            s.upstream_proxy.clone(),
            s.stall_watchdog_seconds,
        )
    };

    let direct_http = {
        let read_timeout = Duration::from_secs(watchdog_secs.max(15));
        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .read_timeout(read_timeout)
            .timeout(CHUNK_TIMEOUT);
        if let Some(ref up) = upstream_proxy {
            if let Ok(proxy) = Proxy::all(up) {
                builder = builder.proxy(proxy);
            }
        }
        Arc::new(builder.build().unwrap_or_default())
    };
    let gw_http = Arc::new(build_http_client(&gateway_addr, watchdog_secs).await);

    if link.is_folder_scope() {
        let tree = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            r = mega.fetch_folder_tree(&link) => r.map_err(|e| format!("Failed to fetch folder tree: {}", e))?,
        };

        let candidate_title = req.title.as_deref().filter(|t| {
            let tr = t.trim();
            !tr.is_empty() && !tr.starts_with("Folder_") && !tr.starts_with("MEGA Folder (")
        });

        let folder_title = candidate_title
            .map(|t| sanitize_folder_name(t))
            .or_else(|| tree.root_title().map(|t| sanitize_folder_name(&t)))
            .or_else(|| {
                tree.directories()
                    .iter()
                    .find(|d| (d.parent_handle.is_empty() || d.handle == link.handle) && !d.name.is_empty() && d.name != link.handle)
                    .map(|d| sanitize_folder_name(&d.name))
            })
            .unwrap_or_else(|| format!("Folder_{}", link.handle));

        let current_out = task_info.read().await.output_path.clone();
        let folder_dest = if !current_out.is_empty() && current_out != req.output_dir && Path::new(&current_out).exists() {
            PathBuf::from(current_out)
        } else {
            resolve_unique_path(&base_out, &folder_title, true, Some(&link.handle), None)
        };
        tokio::fs::create_dir_all(&folder_dest)
            .await
            .map_err(|e| format!("Failed to create folder {}: {}", folder_dest.display(), e))?;

        for d in tree.directories() {
            if !d.relative_path.as_os_str().is_empty() {
                let dir_path = folder_dest.join(&d.relative_path);
                let _ = tokio::fs::create_dir_all(&dir_path).await;
            }
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
        let total_files = files.len();

        // INVARIANT: Disk Space Pre-Check
        check_available_disk_space(&folder_dest, total_bytes)?;

        {
            let mut info = task_info.write().await;
            info.title = folder_title.clone();
            info.total_bytes = total_bytes;
            info.output_path = folder_dest.to_string_lossy().to_string();
        }

        let downloaded_so_far = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        let file_semaphore = Arc::new(Semaphore::new(max_concurrent_files));

        for (idx, file_node) in files.iter().enumerate() {
            if cancel_token.is_cancelled() {
                return Ok(());
            }

            let file_idx = idx + 1;
            let chunks_count = ChunkIterator::new(file_node.size).count();

            info!(
                "Starting file [{}/{}]: '{}' ({} bytes, {} chunks)",
                file_idx, total_files, file_node.name, file_node.size, chunks_count
            );

            let permit = file_semaphore.clone().acquire_owned().await.map_err(|e| e.to_string())?;

            info!("Fetching storage URL for '{}'...", file_node.name);

            let (download_url, _) = tokio::select! {
                _ = cancel_token.cancelled() => {
                    drop(permit);
                    return Ok(());
                }
                r = mega.get_folder_file_url(&link.handle, &file_node.handle) => match r {
                    Ok(res) => res,
                    Err(e) => {
                        error!(
                            "Failed to fetch storage URL for file '{}' (handle: {}) after retries: {}",
                            file_node.name, file_node.handle, e
                        );
                        return Err(format!(
                            "Failed to get storage URL for '{}' after retries: {}",
                            file_node.name, e
                        ));
                    }
                }
            };

            let target_path = folder_dest.join(&file_node.relative_path);
            if let Some(parent) = target_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }

            let file_key = file_node
                .key
                .clone()
                .ok_or_else(|| format!("Missing key for {}", file_node.name))?;

            if let Err(e) = download_single_file(
                &file_node.handle,
                &file_node.name,
                Some(&link.handle),
                &download_url,
                file_node.size,
                file_key.aes_key,
                file_key.nonce,
                file_key.expected_mac,
                &target_path,
                Arc::clone(&mega),
                Arc::clone(&direct_http),
                Arc::clone(&gw_http),
                Arc::clone(&pool),
                Arc::clone(&rate_limiter),
                Arc::clone(&downloaded_so_far),
                total_bytes,
                start_time,
                workers_per_file,
                Arc::clone(&task_info),
                Arc::clone(&completed_chunks_map),
                Arc::clone(&using_proxies),
                Arc::clone(&settings),
                Arc::clone(&last_host_509_at),
                Arc::clone(&last_509_cmd_at),
                cancel_token.clone(),
            )
            .await
            {
                error!(
                    "Failed to download file '{}' (handle: {}): {}",
                    file_node.name, file_node.handle, e
                );
                return Err(e);
            }

            drop(permit);

            info!("Finalizing file '{}'...", file_node.name);
            info!("Completed file [{}/{}]: '{}'", file_idx, total_files, file_node.name);
        }

        info!("Folder transfer '{}' completed ({}/{} files)", folder_title, total_files, total_files);
    } else {
        let meta = tokio::select! {
            _ = cancel_token.cancelled() => return Ok(()),
            r = mega.resolve_file(&link) => r.map_err(|e| format!("Failed to resolve file: {}", e))?,
        };

        let current_out = task_info.read().await.output_path.clone();
        let target_path = if !current_out.is_empty() && current_out != req.output_dir && Path::new(&current_out).exists() {
            PathBuf::from(current_out)
        } else {
            resolve_unique_path(&base_out, &meta.name, false, Some(&meta.handle), Some(meta.size))
        };

        // INVARIANT: Disk Space Pre-Check
        check_available_disk_space(&target_path, meta.size)?;

        {
            let mut info = task_info.write().await;
            info.title = meta.name.clone();
            info.total_bytes = meta.size;
            info.output_path = target_path.to_string_lossy().to_string();
        }

        let downloaded_so_far = Arc::new(AtomicU64::new(0));
        let start_time = Instant::now();

        download_single_file(
            &meta.handle,
            &meta.name,
            None,
            &meta.download_url,
            meta.size,
            meta.key.aes_key,
            meta.key.nonce,
            meta.key.expected_mac,
            &target_path,
            Arc::clone(&mega),
            Arc::clone(&direct_http),
            Arc::clone(&gw_http),
            Arc::clone(&pool),
            Arc::clone(&rate_limiter),
            Arc::clone(&downloaded_so_far),
            meta.size,
            start_time,
            workers_per_file,
            Arc::clone(&task_info),
            Arc::clone(&completed_chunks_map),
            Arc::clone(&using_proxies),
            Arc::clone(&settings),
            Arc::clone(&last_host_509_at),
            Arc::clone(&last_509_cmd_at),
            cancel_token,
        )
        .await?;
    }

    Ok(())
}

#[derive(Debug)]
enum ChunkResult {
    Success { index: usize, size: u64, proxy: String },
    Failed { index: usize, error: String },
}

async fn refresh_storage_url_debounced(
    current_storage_url: &Arc<RwLock<String>>,
    refresh_lock: &Arc<tokio::sync::Mutex<Instant>>,
    mega_client: &Arc<MegaClient>,
    folder_handle_opt: Option<&str>,
    file_handle: &str,
    seen_url: &str,
) -> Result<String, String> {
    let mut last_refreshed = refresh_lock.lock().await;
    let curr = current_storage_url.read().await.clone();
    if curr != seen_url && !curr.is_empty() {
        return Ok(curr);
    }
    if last_refreshed.elapsed() < Duration::from_secs(3) && !curr.is_empty() {
        return Ok(curr);
    }
    match mega_client.refresh_file_download_url(folder_handle_opt, file_handle).await {
        Ok(new_url) => {
            *current_storage_url.write().await = new_url.clone();
            *last_refreshed = Instant::now();
            Ok(new_url)
        }
        Err(e) => Err(e.to_string()),
    }
}

pub async fn download_single_file(
    file_handle: &str,
    file_name: &str,
    folder_handle: Option<&str>,
    storage_url: &str,
    file_size: u64,
    aes_key: [u8; 16],
    nonce: [u8; 8],
    expected_mac: [u32; 2],
    out_path: &Path,
    mega_client: Arc<MegaClient>,
    direct_http: Arc<Client>,
    gw_http: Arc<Client>,
    pool: Arc<ProxyPool>,
    rate_limiter: Arc<RateLimiter>,
    cumulative_bytes: Arc<AtomicU64>,
    grand_total_bytes: u64,
    _start_time: Instant,
    concurrency_limit: usize,
    task_info: Arc<RwLock<TaskInfo>>,
    completed_chunks_map: Arc<RwLock<HashMap<String, HashSet<usize>>>>,
    using_proxies: Arc<AtomicBool>,
    settings: Arc<RwLock<AppSettings>>,
    last_host_509_at: Arc<RwLock<Option<Instant>>>,
    last_509_cmd_at: Arc<RwLock<Option<Instant>>>,
    cancel_token: CancellationToken,
) -> Result<(), String> {
    let (temp_chunk_dir, verify_cbc_mac) = {
        let s = settings.read().await;
        (s.temp_chunk_dir.clone(), s.verify_cbc_mac)
    };

    let (active_path, is_temp) = if let Some(ref tdir) = temp_chunk_dir {
        if !tdir.trim().is_empty() {
            let tdir_path = PathBuf::from(tdir);
            let _ = tokio::fs::create_dir_all(&tdir_path).await;
            let file_name_part = out_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(file_handle);
            let staging = tdir_path.join(format!("{}.part", file_name_part));
            (staging, true)
        } else {
            (out_path.to_path_buf(), false)
        }
    } else {
        (out_path.to_path_buf(), false)
    };

    let all_chunks: Vec<ChunkInfo> = ChunkIterator::new(file_size).collect();
    let total_chunks = all_chunks.len();

    // Handle 0-byte file edge case
    if total_chunks == 0 {
        if let Some(parent) = active_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let f = tokio::fs::File::create(&active_path)
            .await
            .map_err(|e| format!("Cannot create empty file {}: {}", active_path.display(), e))?;
        drop(f);

        if is_temp {
            if let Some(parent) = out_path.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let _ = tokio::fs::rename(&active_path, out_path).await;
        }
        return Ok(());
    }

    let mut already_done = {
        let guard = completed_chunks_map.read().await;
        guard.get(file_handle).cloned().unwrap_or_default()
    };

    if let Some(disk_completed) = load_resume_state(out_path, file_handle, file_size) {
        for idx in disk_completed {
            already_done.insert(idx);
        }
    }
    {
        let mut map = completed_chunks_map.write().await;
        map.insert(file_handle.to_string(), already_done.clone());
    }

    let scheduler = Arc::new(parking_lot::Mutex::new(ChunkScheduler::new(
        all_chunks.clone(),
        file_size,
        &already_done,
    )));
    let chunk_notify = Arc::new(tokio::sync::Notify::new());

    let mut completed_chunks_count = scheduler.lock().completed_count();
    let pre_completed_bytes: u64 = scheduler
        .lock()
        .completed_indices()
        .iter()
        .filter_map(|&idx| all_chunks.get(idx).map(|c| c.size))
        .sum();
    if pre_completed_bytes > 0 {
        let current_cum = cumulative_bytes.fetch_add(pre_completed_bytes, Ordering::Relaxed) + pre_completed_bytes;
        let progress = if grand_total_bytes > 0 {
            ((current_cum as f64 / grand_total_bytes as f64) * 1000.0).round() / 10.0
        } else {
            0.0
        };
        let mut info = task_info.write().await;
        info.downloaded_bytes = current_cum;
        info.progress_percent = progress.min(100.0);
    }

    // If temp staging is enabled and this file was already moved to final destination in a prior run, skip re-downloading.
    if completed_chunks_count == total_chunks && is_temp && !active_path.exists() && out_path.exists() {
        if tokio::fs::metadata(out_path).await.map(|m| m.len()).unwrap_or(0) == file_size {
            remove_resume_state(out_path);
            return Ok(());
        }
    }

    // 1. Pre-allocate sparse file if needed, preserving existing file content
    if let Some(parent) = active_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&active_path)
        .map_err(|e| format!("Cannot open {}: {}", active_path.display(), e))?;
    let _ = std_file.set_len(file_size);
    drop(std_file);

    let shared_file = Arc::new(Mutex::new(
        tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&active_path)
            .await
            .map_err(|e| format!("Async open failed: {}", e))?,
    ));

    if completed_chunks_count < total_chunks {
        let (result_tx, mut result_rx) = mpsc::channel::<ChunkResult>(total_chunks + 32);
        let file_cancel = cancel_token.child_token();

        let remaining = total_chunks.saturating_sub(completed_chunks_count);
        let concurrency = concurrency_limit.min(remaining).max(1);
        let mut handles = Vec::with_capacity(concurrency);
        let active_workers = Arc::new(AtomicUsize::new(0));

        let current_storage_url = Arc::new(RwLock::new(storage_url.to_string()));
        let refresh_lock = Arc::new(tokio::sync::Mutex::new(Instant::now()));
        let last_bytes_time = Arc::new(parking_lot::Mutex::new(Instant::now()));

        // Automatic Live Speed Decay Monitor (cleanly decays to 0.0 MB/s within 2 seconds of inactivity)
        let decay_cancel = file_cancel.child_token();
        let decay_task_info = Arc::clone(&task_info);
        let decay_cum = Arc::clone(&cumulative_bytes);
        let decay_last_bytes = Arc::clone(&last_bytes_time);
        tokio::spawn(async move {
            let mut prev_bytes = decay_cum.load(Ordering::Relaxed);
            let mut prev_time = Instant::now();
            while !decay_cancel.is_cancelled() {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if decay_cancel.is_cancelled() {
                    break;
                }
                let now = Instant::now();
                let curr_bytes = decay_cum.load(Ordering::Relaxed);
                let dt = now.duration_since(prev_time).as_secs_f64();
                let idle = decay_last_bytes.lock().elapsed();

                let speed_mbps = if idle >= Duration::from_secs(2) || dt < 0.1 {
                    0.0
                } else {
                    let delta = curr_bytes.saturating_sub(prev_bytes);
                    let bps = delta as f64 / dt;
                    ((bps / (1024.0 * 1024.0)) * 10.0).round() / 10.0
                };

                prev_bytes = curr_bytes;
                prev_time = now;

                let mut info = decay_task_info.write().await;
                if info.status == TaskStatus::Downloading {
                    info.speed_mbps = speed_mbps;
                    let remaining_b = grand_total_bytes.saturating_sub(curr_bytes);
                    info.eta_seconds = if speed_mbps > 0.05 {
                        (remaining_b as f64 / (speed_mbps * 1024.0 * 1024.0)) as u64
                    } else {
                        0
                    };
                }
            }
        });

        for worker_id in 0..concurrency {
            let scheduler = Arc::clone(&scheduler);
            let chunk_notify = Arc::clone(&chunk_notify);
            let result_tx = result_tx.clone();
            let direct_http = Arc::clone(&direct_http);
            let gw_http = Arc::clone(&gw_http);
            let pool = Arc::clone(&pool);
            let current_storage_url = Arc::clone(&current_storage_url);
            let refresh_lock = Arc::clone(&refresh_lock);
            let last_bytes_time = Arc::clone(&last_bytes_time);
            let mega_client = Arc::clone(&mega_client);
            let folder_handle_opt = folder_handle.map(|s| s.to_string());
            let file_name_str = file_name.to_string();
            let file_handle_str = file_handle.to_string();
            let file = Arc::clone(&shared_file);
            let task_info = Arc::clone(&task_info);
            let using_proxies = Arc::clone(&using_proxies);
            let active_workers = Arc::clone(&active_workers);
            let settings = Arc::clone(&settings);
            let last_host_509_at = Arc::clone(&last_host_509_at);
            let last_509_cmd_at = Arc::clone(&last_509_cmd_at);
            let cancel = file_cancel.clone();

            handles.push(tokio::spawn(async move {
                let mut cached_client: Option<(Arc<Client>, Option<Arc<ProxyItem>>, String)> = None;

                'worker_loop: loop {
                    if cancel.is_cancelled() {
                        break;
                    }

                    let (chunk, attempt) = loop {
                        if cancel.is_cancelled() {
                            break 'worker_loop;
                        }

                        enum AcquireAction {
                            Found(ChunkInfo, usize),
                            Wait,
                            Done,
                        }

                        let action = {
                            let mut sched = scheduler.lock();
                            if sched.is_all_completed() {
                                AcquireAction::Done
                            } else if let Some((c, att)) = sched.acquire_next_chunk(worker_id) {
                                AcquireAction::Found(c, att)
                            } else if let Some((c, att)) = sched.acquire_speculative_tail_chunk(worker_id, concurrency) {
                                info!(
                                    "Worker #{} acquired speculative tail retry for chunk #{} of '{}'",
                                    worker_id, c.index, file_name_str
                                );
                                AcquireAction::Found(c, att)
                            } else if sched.active_in_flight() == 0 {
                                AcquireAction::Done
                            } else {
                                AcquireAction::Wait
                            }
                        };

                        match action {
                            AcquireAction::Done => break 'worker_loop,
                            AcquireAction::Found(c, att) => break (c, att),
                            AcquireAction::Wait => {
                                tokio::select! {
                                    _ = cancel.cancelled() => break 'worker_loop,
                                    _ = chunk_notify.notified() => continue,
                                }
                            }
                        }
                    };

                    active_workers.fetch_add(1, Ordering::Relaxed);
                    {
                        let mut info = task_info.write().await;
                        info.active_workers = active_workers.load(Ordering::Relaxed);
                    }

                    let s = settings.read().await.clone();

                    // Sticky 509 check: while elapsed < sticky_509_seconds, route directly through proxies
                    let is_sticky_509 = {
                        let guard = last_host_509_at.read().await;
                        if let Some(t) = *guard {
                            t.elapsed() < Duration::from_secs(s.sticky_509_seconds)
                        } else {
                            false
                        }
                    };

                    let is_proxy_mode = is_sticky_509
                        || s.routing_mode.eq_ignore_ascii_case("force_proxy")
                        || using_proxies.load(Ordering::Relaxed);

                    // Acquire or reuse proxy client
                    let (active_http, proxy_candidate, proxy_addr) = if !is_proxy_mode {
                        cached_client = None;
                        (Arc::clone(&direct_http), None, "direct-host".to_string())
                    } else if !s.reset_proxy_per_chunk && cached_client.is_some() {
                        let (cli, cand, addr) = cached_client.as_ref().unwrap();
                        (Arc::clone(cli), cand.as_ref().map(Arc::clone), addr.clone())
                    } else {
                        let candidates = pool.get_mega_healthy_candidates_ordered(20, &s.proxy_selection_order);
                        if let Some(candidate) = candidates.first() {
                            let cand_addr = candidate.addr.to_string();
                            let read_timeout = Duration::from_secs(s.stall_watchdog_seconds.max(15));
                            let client = Client::builder()
                                .connect_timeout(Duration::from_secs(8))
                                .read_timeout(read_timeout)
                                .timeout(CHUNK_TIMEOUT)
                                .proxy(
                                    Proxy::all(candidate.to_url())
                                        .unwrap_or_else(|_| Proxy::all("http://127.0.0.1:8080").unwrap()),
                                )
                                .build()
                                .unwrap_or_else(|_| (*gw_http).clone());
                            let arc_cli = Arc::new(client);
                            let arc_cand = Some(Arc::clone(candidate));
                            cached_client = Some((Arc::clone(&arc_cli), arc_cand.clone(), cand_addr.clone()));
                            (arc_cli, arc_cand, cand_addr)
                        } else {
                            cached_client = None;
                            warn!("All proxies cooling down, waiting 5s before retrying...");
                            {
                                let mut info = task_info.write().await;
                                info.error = Some("All proxies cooling down, waiting 5s before retrying...".to_string());
                                info.speed_mbps = 0.0;
                                info.eta_seconds = 0;
                            }
                            let _ = scheduler.lock().mark_retry(chunk.index, MAX_CHUNK_RETRIES);
                            chunk_notify.notify_waiters();
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            active_workers.fetch_sub(1, Ordering::Relaxed);
                            continue;
                        }
                    };

                    info!(
                        "Assigned chunk #{} ({} bytes, offset {}) of '{}' to proxy {}",
                        chunk.index, chunk.size, chunk.offset, file_name_str, proxy_addr
                    );

                    let current_url = current_storage_url.read().await.clone();
                    let last_bytes_time_ref = Arc::clone(&last_bytes_time);

                    let download_fut = async {
                        let range_path_url = format!("{}/{}", current_url, chunk.path_range());
                        let mut resp = match active_http.get(&range_path_url).send().await {
                            Ok(r) if r.status().is_success() => r,
                            Ok(r) if r.status() == StatusCode::FORBIDDEN => {
                                return Err(MegaError::ApiError(403));
                            }
                            Ok(r) if r.status() == StatusCode::GONE => {
                                return Err(MegaError::ApiError(410));
                            }
                            Ok(r) if r.status() == StatusCode::from_u16(509).unwrap_or(StatusCode::TOO_MANY_REQUESTS) => {
                                return Err(MegaError::OverQuota);
                            }
                            _ => {
                                let range_val = format!("bytes={}-{}", chunk.offset, chunk.end_offset() - 1);
                                let r2 = active_http
                                    .get(&current_url)
                                    .header("Range", range_val)
                                    .send()
                                    .await
                                    .map_err(MegaError::Http)?;

                                if r2.status() == StatusCode::FORBIDDEN {
                                    return Err(MegaError::ApiError(403));
                                }
                                if r2.status() == StatusCode::GONE {
                                    return Err(MegaError::ApiError(410));
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

                        // Strict Per-Read Stall Timeout on Chunk Streams (abort immediately after 6s of no progress)
                        const PER_READ_NO_PROGRESS_TIMEOUT: Duration = Duration::from_secs(6);
                        let mut plaintext = Vec::with_capacity(chunk.size as usize);
                        loop {
                            let chunk_read = tokio::time::timeout(PER_READ_NO_PROGRESS_TIMEOUT, resp.chunk()).await;
                            match chunk_read {
                                Ok(Ok(Some(bytes))) => {
                                    if bytes.is_empty() {
                                        drop(resp);
                                        return Err(MegaError::Io(std::io::Error::new(
                                            std::io::ErrorKind::TimedOut,
                                            "Stall watchdog: read delivered 0 bytes",
                                        )));
                                    }
                                    *last_bytes_time_ref.lock() = Instant::now();
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
                                        "Stall watchdog: per-read no-progress timeout exceeded (no bytes for 6s)",
                                    )));
                                }
                            }
                        }

                        if plaintext.len() as u64 != chunk.size {
                            return Err(MegaError::Io(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                format!(
                                    "Truncated chunk: expected {} bytes, got {}",
                                    chunk.size,
                                    plaintext.len()
                                ),
                            )));
                        }

                        decrypt_ctr(&aes_key, &nonce, chunk.offset, &mut plaintext);

                        {
                            let mut f = file.lock().await;
                            f.seek(SeekFrom::Start(chunk.offset)).await?;
                            f.write_all(&plaintext).await?;
                            let _ = f.flush().await;
                        }

                        Ok::<(), MegaError>(())
                    };

                    let res = tokio::select! {
                        _ = cancel.cancelled() => {
                            active_workers.fetch_sub(1, Ordering::Relaxed);
                            break;
                        }
                        r = tokio::time::timeout(CHUNK_TIMEOUT, download_fut) => r,
                    };

                    active_workers.fetch_sub(1, Ordering::Relaxed);

                    match res {
                        Ok(Ok(())) => {
                            let is_newly_completed = {
                                scheduler.lock().mark_completed(chunk.index)
                            };
                            chunk_notify.notify_waiters();
                            if s.reset_proxy_per_chunk {
                                cached_client = None;
                            }
                            if is_newly_completed {
                                let _ = result_tx.send(ChunkResult::Success {
                                    index: chunk.index,
                                    size: chunk.size,
                                    proxy: proxy_addr,
                                }).await;
                            } else {
                                info!(
                                    "Chunk #{} of '{}' was already completed by a racing worker; ignoring duplicate completion",
                                    chunk.index, file_name_str
                                );
                            }
                        }
                        Ok(Err(MegaError::ApiError(code))) if code == 403 || code == 410 => {
                            cached_client = None;
                            if scheduler.lock().is_completed(chunk.index) {
                                info!("Chunk #{} had API error {} after being completed by another worker; ignoring", chunk.index, code);
                                chunk_notify.notify_waiters();
                                continue;
                            }
                            warn!("HTTP {} on file '{}'; refreshing temporary download URL...", code, file_name_str);
                            let _ = refresh_storage_url_debounced(
                                &current_storage_url,
                                &refresh_lock,
                                &mega_client,
                                folder_handle_opt.as_deref(),
                                &file_handle_str,
                                &current_url,
                            ).await;

                            let retry_result = { scheduler.lock().mark_worker_retry(chunk.index, Some(worker_id), MAX_CHUNK_RETRIES) };
                            match retry_result {
                                Ok(_) => {
                                    chunk_notify.notify_waiters();
                                }
                                Err(()) => {
                                    let _ = result_tx.send(ChunkResult::Failed {
                                        index: chunk.index,
                                        error: format!("Chunk {} failed: HTTP {} after retries", chunk.index, code),
                                    }).await;
                                }
                            }
                        }
                        Ok(Err(MegaError::OverQuota)) => {
                            cached_client = None;
                            if scheduler.lock().is_completed(chunk.index) {
                                info!("Chunk #{} hit 509 after being completed by another worker; ignoring", chunk.index);
                                chunk_notify.notify_waiters();
                                continue;
                            }
                            if let Some(candidate) = proxy_candidate {
                                info!("Proxy {} hit MEGA 509 quota; marking on cooldown", candidate.addr);
                                candidate.mark_mega_509_cooldown(Duration::from_secs(s.sticky_509_seconds.max(3600)));
                            } else {
                                warn!("Direct host connection hit MEGA 509 quota; switching workers to rotating proxy pool!");
                                *last_host_509_at.write().await = Some(Instant::now());
                                using_proxies.store(true, Ordering::SeqCst);
                                {
                                    let mut info = task_info.write().await;
                                    if !info.routing_mode.eq_ignore_ascii_case("force_proxy") {
                                        info.routing_mode = "509_failover".to_string();
                                    }
                                }

                                if let Some(cmd) = &s.cmd_on_509_limit {
                                    let mut last_cmd = last_509_cmd_at.write().await;
                                    let should_fire = match *last_cmd {
                                        Some(last_t) => last_t.elapsed() >= Duration::from_secs(s.sticky_509_seconds),
                                        None => true,
                                    };
                                    if should_fire {
                                        *last_cmd = Some(Instant::now());
                                        spawn_shell_command(cmd);
                                    }
                                }
                            }

                            // Refresh URL on 509 quota hit
                            let _ = refresh_storage_url_debounced(
                                &current_storage_url,
                                &refresh_lock,
                                &mega_client,
                                folder_handle_opt.as_deref(),
                                &file_handle_str,
                                &current_url,
                            ).await;

                            tokio::time::sleep(Duration::from_millis(500 * (attempt + 1) as u64)).await;

                            let retry_result = { scheduler.lock().mark_worker_retry(chunk.index, Some(worker_id), MAX_CHUNK_RETRIES) };
                            match retry_result {
                                Ok(_) => {
                                    chunk_notify.notify_waiters();
                                }
                                Err(()) => {
                                    error!("Chunk {} failed after {} quota retries", chunk.index, MAX_CHUNK_RETRIES);
                                    let _ = result_tx.send(ChunkResult::Failed {
                                        index: chunk.index,
                                        error: format!("Chunk {} failed: Quota limit after retries", chunk.index),
                                    }).await;
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            cached_client = None;
                            if let Some(candidate) = proxy_candidate {
                                pool.record_failure_at_all_levels(candidate.addr, Duration::from_secs(s.proxy_ban_seconds.max(60)));
                            }
                            if scheduler.lock().is_completed(chunk.index) {
                                info!("Chunk #{} had error ({}) after being completed by another worker; ignoring", chunk.index, e);
                                chunk_notify.notify_waiters();
                                continue;
                            }
                            warn!(
                                "Chunk stall/error on file '{}', chunk #{}, offset {}: dropping proxy stream {} ({})",
                                file_name_str, chunk.index, chunk.offset, proxy_addr, e
                            );
                            tokio::time::sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;

                            let retry_result = { scheduler.lock().mark_worker_retry(chunk.index, Some(worker_id), MAX_CHUNK_RETRIES) };
                            match retry_result {
                                Ok(_) => {
                                    chunk_notify.notify_waiters();
                                }
                                Err(()) => {
                                    let _ = result_tx.send(ChunkResult::Failed {
                                        index: chunk.index,
                                        error: format!("Chunk {} failed after {} retries: {}", chunk.index, MAX_CHUNK_RETRIES, e),
                                    }).await;
                                }
                            }
                        }
                        Err(_) => {
                            cached_client = None;
                            if let Some(candidate) = proxy_candidate {
                                pool.record_failure_at_all_levels(candidate.addr, Duration::from_secs(s.proxy_ban_seconds.max(60)));
                            }
                            if scheduler.lock().is_completed(chunk.index) {
                                info!("Chunk #{} timed out after being completed by another worker; ignoring", chunk.index);
                                chunk_notify.notify_waiters();
                                continue;
                            }
                            warn!(
                                "Chunk stall timeout on file '{}', chunk #{}, offset {}: dropping stalled proxy stream {}",
                                file_name_str, chunk.index, chunk.offset, proxy_addr
                            );

                            let retry_result = { scheduler.lock().mark_worker_retry(chunk.index, Some(worker_id), MAX_CHUNK_RETRIES) };
                            match retry_result {
                                Ok(_) => {
                                    chunk_notify.notify_waiters();
                                }
                                Err(()) => {
                                    let _ = result_tx.send(ChunkResult::Failed {
                                        index: chunk.index,
                                        error: format!("Chunk {} permanently timed out", chunk.index),
                                    }).await;
                                }
                            }
                        }
                    }
                }
            }));
        }

        drop(result_tx);

        let mut download_error: Option<String> = None;

        while completed_chunks_count < total_chunks {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    file_cancel.cancel();
                    chunk_notify.notify_waiters();
                    break;
                }
                res = result_rx.recv() => {
                    match res {
                        Some(ChunkResult::Success { index, size, proxy }) => {
                            completed_chunks_count += 1;

                            // Flush updated completed chunk bitmap to .looker-resume sidecar!
                            let completed_indices = scheduler.lock().completed_indices();
                            save_resume_state(out_path, file_handle, file_size, &completed_indices);

                            // Record chunk in memory completed bitmap
                            {
                                let mut map = completed_chunks_map.write().await;
                                map.entry(file_handle.to_string())
                                    .or_default()
                                    .insert(index);
                            }

                            // Apply live speed throttling
                            rate_limiter.throttle(size as usize).await;

                            let current_cum = cumulative_bytes.fetch_add(size, Ordering::Relaxed) + size;
                            let progress = if grand_total_bytes > 0 {
                                ((current_cum as f64 / grand_total_bytes as f64) * 1000.0).round() / 10.0
                            } else {
                                0.0
                            };

                            info!(
                                "Completed chunk #{} of file '{}' ({}/{} bytes, proxy: {})",
                                index, file_name, current_cum, grand_total_bytes, proxy
                            );

                            {
                                let mut info = task_info.write().await;
                                info.downloaded_bytes = current_cum;
                                info.progress_percent = progress.min(100.0);
                                info.active_workers = active_workers.load(Ordering::Relaxed);
                                if info.error.as_deref().map(|e| e.starts_with("All proxies cooling")).unwrap_or(false) {
                                    info.error = None;
                                }
                            }

                            if completed_chunks_count == total_chunks {
                                file_cancel.cancel();
                                chunk_notify.notify_waiters();
                                break;
                            }
                        }
                        Some(ChunkResult::Failed { index, error }) => {
                            error!("Chunk #{} of file '{}' failed: {}", index, file_name, error);
                            download_error = Some(error);
                            file_cancel.cancel();
                            chunk_notify.notify_waiters();
                            break;
                        }
                        None => {
                            if completed_chunks_count < total_chunks {
                                download_error = Some(format!(
                                    "Workers finished prematurely for '{}' ({}/{} chunks completed)",
                                    file_name, completed_chunks_count, total_chunks
                                ));
                            }
                            break;
                        }
                    }
                }
            }
        }

        // Cancel workers and await handles
        file_cancel.cancel();
        chunk_notify.notify_waiters();
        for h in handles {
            let _ = h.await;
        }

        if let Some(err) = download_error {
            {
                let mut f = shared_file.lock().await;
                let _ = f.flush().await;
            }
            drop(shared_file);
            let completed_indices = scheduler.lock().completed_indices();
            save_resume_state(out_path, file_handle, file_size, &completed_indices);
            return Err(err);
        }
    }

    if cancel_token.is_cancelled() {
        {
            let mut f = shared_file.lock().await;
            let _ = f.flush().await;
        }
        drop(shared_file);
        let completed_indices = scheduler.lock().completed_indices();
        save_resume_state(out_path, file_handle, file_size, &completed_indices);
        return Err("Download cancelled or paused by user".to_string());
    }

    // Explicitly flush and drop shared file handle before verification and moving
    {
        let mut f = shared_file.lock().await;
        let _ = f.flush().await;
    }
    drop(shared_file);

    // CBC-MAC Integrity Verification
    if verify_cbc_mac {
        let mut file = tokio::fs::File::open(&active_path)
            .await
            .map_err(|e| format!("Failed to open {} for CBC-MAC check: {}", active_path.display(), e))?;
        let mut accumulator = FileMacAccumulator::new(&aes_key);
        for chunk in ChunkIterator::new(file_size) {
            file.seek(SeekFrom::Start(chunk.offset))
                .await
                .map_err(|e| format!("Seek failed during CBC-MAC check: {}", e))?;
            let mut buf = vec![0u8; chunk.size as usize];
            file.read_exact(&mut buf)
                .await
                .map_err(|e| format!("Read failed during CBC-MAC check: {}", e))?;
            let chunk_mac = compute_chunk_mac(&aes_key, &nonce, &buf);
            accumulator.accumulate(&chunk_mac);
        }
        accumulator
            .verify(expected_mac)
            .map_err(|e| format!("CBC-MAC integrity verification mismatch for {}: {}", file_handle, e))?;
        drop(file); // Explicitly drop file handle after verification!
        info!("CBC-MAC verified successfully for {}", file_handle);
    }

    // Move from staging temp directory to final destination if needed
    if is_temp {
        if let Some(parent) = out_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if tokio::fs::rename(&active_path, out_path).await.is_err() {
            tokio::fs::copy(&active_path, out_path)
                .await
                .map_err(|e| format!("Failed to move temp chunk file to destination: {}", e))?;
            let _ = tokio::fs::remove_file(&active_path).await;
        }
    }

    // Remove .looker-resume sidecar file upon successful completion!
    remove_resume_state(out_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atomic_chunk_scheduler_never_duplicates() {
        let chunks: Vec<ChunkInfo> = (0..20)
            .map(|i| ChunkInfo {
                index: i,
                offset: (i * 1024) as u64,
                size: 1024,
            })
            .collect();

        let mut completed_set = HashSet::new();
        completed_set.insert(0);
        completed_set.insert(1);

        let mut scheduler = ChunkScheduler::new(chunks.clone(), 20 * 1024, &completed_set);
        assert_eq!(scheduler.completed_count(), 2);
        assert_eq!(scheduler.total_chunks(), 20);
        assert_eq!(scheduler.total_size(), 20 * 1024);
        assert!(!scheduler.is_all_completed());

        // Simulate 4 concurrent workers acquiring chunks
        let mut acquired = Vec::new();
        for worker_id in 0..4 {
            if let Some((c, attempt)) = scheduler.acquire_next_chunk(worker_id) {
                acquired.push(c.index);
                assert_eq!(attempt, 0);
            }
        }

        // Chunks 0 and 1 were pre-completed, so workers must get indices 2, 3, 4, 5
        assert_eq!(acquired, vec![2, 3, 4, 5]);
        assert_eq!(scheduler.active_in_flight(), 4);

        // All acquired indices must be distinct
        let set: HashSet<usize> = acquired.iter().copied().collect();
        assert_eq!(set.len(), acquired.len(), "Atomic scheduler must never assign duplicate chunks");

        // Worker 0 completes chunk 2
        scheduler.mark_completed(2);
        assert_eq!(scheduler.completed_count(), 3);
        assert_eq!(scheduler.active_in_flight(), 3);

        // Worker 1 fails chunk 3 and marks retry
        let retry_attempt = scheduler.mark_retry(3, 8).unwrap();
        assert_eq!(retry_attempt, 1);

        // Next worker acquires retried chunk 3
        let (re_chunk, _) = scheduler.acquire_next_chunk(99).unwrap();
        assert_eq!(re_chunk.index, 3);
    }

    #[test]
    fn test_collision_safe_unique_path_generation() {
        let temp_dir = std::env::temp_dir().join(format!("looker_test_collision_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        // 1. Folder collision test
        let album_dir = temp_dir.join("Album");
        std::fs::create_dir_all(&album_dir).unwrap();

        let unique_folder1 = resolve_unique_path(&temp_dir, "Album", true, None, None);
        assert_eq!(unique_folder1, temp_dir.join("Album (1)"));

        std::fs::create_dir_all(&unique_folder1).unwrap();
        let unique_folder2 = resolve_unique_path(&temp_dir, "Album", true, None, None);
        assert_eq!(unique_folder2, temp_dir.join("Album (2)"));

        // 2. File collision test without resume
        let file_path = temp_dir.join("report.pdf");
        std::fs::write(&file_path, b"content").unwrap();

        let unique_file1 = resolve_unique_path(&temp_dir, "report.pdf", false, None, None);
        assert_eq!(unique_file1, temp_dir.join("report (1).pdf"));

        // 3. File resume preservation test
        let partial_path = temp_dir.join("download.zip");
        std::fs::write(&partial_path, b"partial").unwrap();
        save_resume_state(&partial_path, "handle_xyz", 1000, &[0, 1]);

        // When file_handle and size match existing .looker-resume sidecar, it must resume same path!
        let resumed_path = resolve_unique_path(&temp_dir, "download.zip", false, Some("handle_xyz"), Some(1000));
        assert_eq!(resumed_path, partial_path, "Must preserve existing partial file path when resume state matches");

        // Clean up
        remove_resume_state(&partial_path);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_speculative_tail_retries_when_few_chunks_remain() {
        let chunks: Vec<ChunkInfo> = (0..5)
            .map(|i| ChunkInfo {
                index: i,
                offset: (i * 1024) as u64,
                size: 1024,
            })
            .collect();

        // Chunks 0, 1, 2 already completed
        let mut completed_set = HashSet::new();
        completed_set.insert(0);
        completed_set.insert(1);
        completed_set.insert(2);

        let mut scheduler = ChunkScheduler::new(chunks, 5 * 1024, &completed_set);
        assert_eq!(scheduler.completed_count(), 3);

        // Worker 0 acquires chunk 3, Worker 1 acquires chunk 4
        let (c3, _) = scheduler.acquire_next_chunk(0).unwrap();
        assert_eq!(c3.index, 3);
        let (c4, _) = scheduler.acquire_next_chunk(1).unwrap();
        assert_eq!(c4.index, 4);

        // No more pending chunks
        assert!(scheduler.acquire_next_chunk(2).is_none());

        // Max workers = 4. Remaining uncompleted chunks = 2 < 4 -> tail phase!
        // Worker 2 should speculatively acquire chunk 3
        let (spec_chunk, attempt) = scheduler.acquire_speculative_tail_chunk(2, 4).unwrap();
        assert_eq!(spec_chunk.index, 3);
        assert_eq!(attempt, 1);

        // Worker 2 finishes chunk 3 first
        assert!(scheduler.mark_completed(3));
        assert_eq!(scheduler.completed_count(), 4);

        // Worker 0 later finishes chunk 3 -> duplicate ignored
        assert!(!scheduler.mark_completed(3));
        assert_eq!(scheduler.completed_count(), 4);
    }

    #[tokio::test]
    async fn test_freeze_before_start_pause_resume_and_queue_controls() {
        let temp_dir = std::env::temp_dir().join(format!("looker_queue_ctrl_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);

        let mut settings = AppSettings::default();
        settings.freeze_before_start = true;
        settings.speed_limit_mbps = 12.5;
        settings.default_download_dir = temp_dir.to_string_lossy().to_string();

        let pool = Arc::new(ProxyPool::new());
        let mgr = DownloadManager::new_ephemeral("127.0.0.1:0".to_string(), pool, settings);

        // Speed limit should stay directly in MB/s without KB/s conversion loss
        let cfg = mgr.get_config().await;
        assert_eq!(cfg.speed_limit_mbps, 12.5);

        let req1 = DownloadRequest {
            url: "https://mega.nz/file/abc12345#0123456789abcdef0123456789abcdef".to_string(),
            selected_handles: vec![],
            output_dir: temp_dir.to_string_lossy().to_string(),
            category: "General".to_string(),
            title: Some("Frozen File 1".to_string()),
        };
        let req2 = DownloadRequest {
            url: "https://mega.nz/file/def67890#0123456789abcdef0123456789abcdef".to_string(),
            selected_handles: vec![],
            output_dir: temp_dir.to_string_lossy().to_string(),
            category: "General".to_string(),
            title: Some("Frozen File 2".to_string()),
        };

        let id1 = mgr.start_download(req1).await.unwrap();
        let id2 = mgr.start_download(req2).await.unwrap();

        let tasks = mgr.list_tasks().await;
        assert_eq!(tasks.len(), 2);
        assert!(tasks.iter().all(|t| t.status == TaskStatus::Paused));

        // Resume task 1, then verify pause_task cancels its replaced cancel_token
        assert!(mgr.resume_task(&id1).await.unwrap());
        {
            let map = mgr.tasks.read().await;
            let t1 = map.get(&id1).unwrap();
            assert_eq!(t1.generation.load(Ordering::SeqCst), 1);
            assert!(!t1.cancel_token.lock().is_cancelled());
        }

        assert!(mgr.pause_task(&id1).await);
        {
            let map = mgr.tasks.read().await;
            let t1 = map.get(&id1).unwrap();
            assert_eq!(t1.info.read().await.status, TaskStatus::Paused);
            assert!(t1.cancel_token.lock().is_cancelled());
        }

        // Resume again (gen 2) and pause again -> verifies cancel_token replacement works repeatedly!
        assert!(mgr.resume_task(&id1).await.unwrap());
        {
            let map = mgr.tasks.read().await;
            let t1 = map.get(&id1).unwrap();
            assert_eq!(t1.generation.load(Ordering::SeqCst), 2);
            assert!(!t1.cancel_token.lock().is_cancelled());
        }
        assert_eq!(mgr.pause_all_tasks().await, 1);
        {
            let map = mgr.tasks.read().await;
            let t1 = map.get(&id1).unwrap();
            assert_eq!(t1.info.read().await.status, TaskStatus::Paused);
            assert!(t1.cancel_token.lock().is_cancelled());
        }

        // Mark task 2 completed and test clear_completed_tasks
        {
            let map = mgr.tasks.read().await;
            map.get(&id2).unwrap().info.write().await.status = TaskStatus::Completed;
        }
        assert_eq!(mgr.clear_completed_tasks().await, 1);
        let remaining = mgr.list_tasks().await;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, id1);

        // Delete remaining task
        assert!(mgr.delete_task(&id1).await);
        assert!(mgr.list_tasks().await.is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
