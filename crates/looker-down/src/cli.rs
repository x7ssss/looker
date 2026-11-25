use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Args, Parser, Subcommand};
use looker_gateway::{AppSettings, DownloadManager, DownloadRequest, TaskInfo, TaskStatus};
use looker_geo::GeoResolver;
use looker_mega::MegaLink;
use looker_pool::ProxyPool;
use looker_scraper::{load_warm_boot_candidates, CheckerConfig, ProxyChecker, ProxyScraper};
use tokio_util::sync::CancellationToken;

#[derive(Parser, Debug)]
#[command(
    name = "looker",
    version,
    about = "Looker headless CLI & proxy-accelerated MEGA downloader"
)]
pub struct LookerCli {
    #[command(subcommand)]
    pub command: LookerCommand,
}

#[derive(Subcommand, Debug)]
pub enum LookerCommand {
    /// Download a MEGA.nz file or folder without launching the GUI
    Dl(DlArgs),
}

#[derive(Args, Debug, Clone)]
pub struct DlArgs {
    /// MEGA.nz public file or folder URL
    pub url: String,

    /// Destination output directory (defaults to current working directory)
    #[arg(short = 'o', long = "output", visible_alias = "output-dir")]
    pub output_dir: Option<PathBuf>,

    /// Number of concurrent chunk workers per file (1-24)
    #[arg(short = 'w', long = "workers")]
    pub workers: Option<usize>,

    /// Route all chunks through the rotating proxy pool from byte 0
    #[arg(long = "force-proxy")]
    pub force_proxy: bool,
}

fn truncate_display_title(title: &str, max_chars: usize) -> String {
    let char_count = title.chars().count();
    if char_count <= max_chars {
        title.to_string()
    } else if max_chars <= 3 {
        title.chars().take(max_chars).collect()
    } else {
        let mut s: String = title.chars().take(max_chars - 3).collect();
        s.push_str("...");
        s
    }
}

/// Formats routing mode cleanly for terminal output, highlighting active 509 failover.
pub fn format_routing_status(routing_mode: &str, healthy_proxies: usize) -> String {
    if routing_mode.eq_ignore_ascii_case("509_failover") {
        format!("509 FAILOVER ACTIVE ({} proxies)", healthy_proxies)
    } else if routing_mode.eq_ignore_ascii_case("force_proxy") {
        format!("FORCE PROXY ({} proxies)", healthy_proxies)
    } else if healthy_proxies > 0 {
        format!("DIRECT (pool ready: {} proxies)", healthy_proxies)
    } else {
        "DIRECT".to_string()
    }
}

/// Formats a single compact terminal progress status line covering filename, %, MB/s, and 509 status.
pub fn format_cli_progress_line(info: &TaskInfo, healthy_proxies: usize) -> String {
    let name = truncate_display_title(&info.title, 32);
    let dl_mb = info.downloaded_bytes as f64 / (1024.0 * 1024.0);
    let total_mb = info.total_bytes as f64 / (1024.0 * 1024.0);
    let route = format_routing_status(&info.routing_mode, healthy_proxies);

    if info.total_bytes > 0 {
        format!(
            "[{}] {:5.1}% | {:.2}/{:.2} MB | {:5.2} MB/s | {}",
            name, info.progress_percent, dl_mb, total_mb, info.speed_mbps, route
        )
    } else {
        format!(
            "[{}] Resolving... | {:5.2} MB/s | {}",
            name, info.speed_mbps, route
        )
    }
}

fn spawn_background_proxy_engine(pool: Arc<ProxyPool>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let geo = Arc::new(GeoResolver::empty());
        let scraper = ProxyScraper::new();
        let checker_cfg = CheckerConfig {
            max_concurrency: 350,
            timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(10),
            target_authority: "g.api.mega.co.nz:443".to_string(),
            verify_tls: true,
        };
        let checker = ProxyChecker::with_config(geo, checker_cfg, None);

        // Warm-boot from cached survivors if available
        let warm_file = Path::new("out/proxies.json");
        let warm = load_warm_boot_candidates(warm_file);
        if !warm.is_empty() && !cancel.is_cancelled() {
            let verified = checker.check_all_streaming(warm, Arc::clone(&pool)).await;
            scraper.record_survivors(&verified);
        }

        loop {
            if cancel.is_cancelled() {
                break;
            }
            if let Ok(candidates) = scraper.collect_all().await {
                if cancel.is_cancelled() {
                    break;
                }
                if !candidates.is_empty() {
                    let verified = checker
                        .check_all_streaming(candidates, Arc::clone(&pool))
                        .await;
                    scraper.record_survivors(&verified);
                }
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(600)) => {}
            }
        }
    });
}

/// Runs a single headless MEGA download using the Looker Rust engine.
pub async fn run_dl(args: DlArgs) -> Result<(), Box<dyn std::error::Error>> {
    let _parsed = MegaLink::parse(&args.url)
        .map_err(|e| format!("Invalid MEGA URL '{}': {}", args.url, e))?;

    let output_dir = match args.output_dir {
        Some(dir) => dir,
        None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
    };
    std::fs::create_dir_all(&output_dir)?;

    let mut settings = AppSettings::load();
    settings.freeze_before_start = false;
    settings.auto_accept_folders = true;
    settings.default_download_dir = output_dir.to_string_lossy().to_string();
    settings.last_used_download_dir = Some(settings.default_download_dir.clone());
    if let Some(workers) = args.workers {
        settings.slots_per_file = workers.clamp(1, 24);
    }
    settings.routing_mode = if args.force_proxy {
        "force_proxy".to_string()
    } else {
        "passive".to_string()
    };
    settings.sanitize();

    let pool = Arc::new(ProxyPool::new().with_cooldown(Duration::from_secs(60)));
    let engine_cancel = CancellationToken::new();
    spawn_background_proxy_engine(Arc::clone(&pool), engine_cancel.clone());

    let mgr = Arc::new(DownloadManager::new_ephemeral(
        "127.0.0.1:0".to_string(),
        Arc::clone(&pool),
        settings.clone(),
    ));

    let mode_label = if args.force_proxy {
        "Force Proxy"
    } else {
        "Passive (Direct -> Auto 509 Proxy Failover)"
    };
    println!(
        "Looker CLI v{} | Workers: {} | Mode: {} | Output: {}",
        env!("CARGO_PKG_VERSION"),
        settings.slots_per_file,
        mode_label,
        output_dir.display()
    );

    let req = DownloadRequest {
        url: args.url.clone(),
        selected_handles: vec![],
        output_dir: settings.default_download_dir.clone(),
        category: "CLI".to_string(),
        title: None,
    };

    let task_id = mgr
        .start_download(req)
        .await
        .map_err(|e| format!("Failed to start download: {}", e))?;

    // Listen for Ctrl-C to gracefully pause/cancel without leaving truncated garbage
    let ctrlc_cancel = engine_cancel.clone();
    let mgr_ctrlc = Arc::clone(&mgr);
    let task_ctrlc = task_id.clone();
    let interrupted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let interrupted_flag = Arc::clone(&interrupted);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            interrupted_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = mgr_ctrlc.pause_task(&task_ctrlc).await;
            ctrlc_cancel.cancel();
        }
    });

    let is_tty = std::io::stdout().is_terminal();
    let mut announced_509 = false;
    let mut last_non_tty_print = Instant::now() - Duration::from_secs(5);
    let mut last_rendered = String::new();

    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;

        let tasks = mgr.list_tasks().await;
        let Some(info) = tasks.into_iter().find(|t| t.id == task_id) else {
            engine_cancel.cancel();
            if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
                return Err("Download interrupted by user".into());
            }
            return Err("Download task unexpectedly removed".into());
        };

        let healthy = pool.healthy_count();
        if !announced_509 && info.routing_mode.eq_ignore_ascii_case("509_failover") {
            announced_509 = true;
            if is_tty {
                println!(
                    "\r\x1b[2K[509] Direct host quota reached — failing over to rotating proxy pool ({} healthy proxies)",
                    healthy
                );
            } else {
                println!(
                    "[509] Direct host quota reached — failing over to rotating proxy pool ({} healthy proxies)",
                    healthy
                );
            }
        }

        match info.status {
            TaskStatus::Downloading | TaskStatus::Paused => {
                if interrupted.load(std::sync::atomic::Ordering::SeqCst) {
                    if is_tty {
                        println!("\r\x1b[2K[PAUSED] Interrupted cleanly; partial chunks flushed.");
                    } else {
                        println!("[PAUSED] Interrupted cleanly; partial chunks flushed.");
                    }
                    engine_cancel.cancel();
                    return Err("Download interrupted by user".into());
                }
                let line = format_cli_progress_line(&info, healthy);
                if is_tty {
                    print!("\r\x1b[2K{}", line);
                    let _ = std::io::stdout().flush();
                } else if line != last_rendered && last_non_tty_print.elapsed() >= Duration::from_secs(1) {
                    println!("{}", line);
                    last_rendered = line;
                    last_non_tty_print = Instant::now();
                }
            }
            TaskStatus::Completed => {
                engine_cancel.cancel();
                let mb = info.total_bytes as f64 / (1024.0 * 1024.0);
                if is_tty {
                    println!(
                        "\r\x1b[2K[DONE] {} | 100.0% ({:.2} MB) -> {}",
                        info.title, mb, info.output_path
                    );
                } else {
                    println!(
                        "[DONE] {} | 100.0% ({:.2} MB) -> {}",
                        info.title, mb, info.output_path
                    );
                }
                return Ok(());
            }
            TaskStatus::Failed => {
                engine_cancel.cancel();
                let err_msg = info.error.unwrap_or_else(|| "Unknown transfer error".to_string());
                if is_tty {
                    eprintln!("\r\x1b[2K[FAILED] {}: {}", info.title, err_msg);
                } else {
                    eprintln!("[FAILED] {}: {}", info.title, err_msg);
                }
                return Err(err_msg.into());
            }
            TaskStatus::Cancelled => {
                engine_cancel.cancel();
                if is_tty {
                    eprintln!("\r\x1b[2K[CANCELLED] {}", info.title);
                } else {
                    eprintln!("[CANCELLED] {}", info.title);
                }
                return Err("Download cancelled".into());
            }
        }
    }
}

/// Entrypoint for the headless `looker` CLI binary.
pub async fn main_entry() -> Result<(), Box<dyn std::error::Error>> {
    let cli = LookerCli::parse();
    match cli.command {
        LookerCommand::Dl(args) => run_dl(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_dl_flags() {
        let cli = LookerCli::try_parse_from([
            "looker",
            "dl",
            "https://mega.nz/file/abc12345#0123456789abcdef0123456789abcdef",
            "-o",
            "/tmp/downloads",
            "--workers",
            "12",
            "--force-proxy",
        ])
        .unwrap();

        match cli.command {
            LookerCommand::Dl(args) => {
                assert_eq!(
                    args.url,
                    "https://mega.nz/file/abc12345#0123456789abcdef0123456789abcdef"
                );
                assert_eq!(args.output_dir, Some(PathBuf::from("/tmp/downloads")));
                assert_eq!(args.workers, Some(12));
                assert!(args.force_proxy);
            }
        }
    }

    #[test]
    fn test_cli_parse_dl_defaults() {
        let cli = LookerCli::try_parse_from([
            "looker",
            "dl",
            "https://mega.nz/folder/xyz98765#fedcba9876543210",
        ])
        .unwrap();

        match cli.command {
            LookerCommand::Dl(args) => {
                assert_eq!(args.output_dir, None);
                assert_eq!(args.workers, None);
                assert!(!args.force_proxy);
            }
        }
    }

    #[test]
    fn test_format_cli_progress_line_includes_file_pct_speed_and_509_status() {
        let info = TaskInfo {
            id: "task-1".to_string(),
            title: "VeryLongVideoArchiveName_WithUTF8_éàç_Final_Build.iso".to_string(),
            category: "CLI".to_string(),
            status: TaskStatus::Downloading,
            total_bytes: 100 * 1024 * 1024,
            downloaded_bytes: 42 * 1024 * 1024,
            progress_percent: 42.0,
            speed_mbps: 12.34,
            eta_seconds: 5,
            output_path: "/tmp/out.iso".to_string(),
            error: None,
            routing_mode: "509_failover".to_string(),
            active_workers: 6,
        };

        let rendered = format_cli_progress_line(&info, 37);
        assert!(rendered.contains("42.0%"));
        assert!(rendered.contains("12.34 MB/s"));
        assert!(rendered.contains("509 FAILOVER ACTIVE (37 proxies)"));
        assert!(rendered.contains("VeryLongVideoArchiveName"));
    }
}
