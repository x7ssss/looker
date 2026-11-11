use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use looker_gateway::{GatewayConfig, ProxyGateway};
use looker_geo::GeoResolver;
use looker_pool::ProxyPool;
use looker_scraper::{resolve_direct_ip, CheckerConfig, ProxyChecker, ProxyScraper, DEFAULT_SOURCES};

#[derive(Parser, Debug)]
#[command(name = "looker-proxy", version, about = "High-speed rotating proxy infrastructure daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Runs the autonomous rotating proxy daemon and local gateway listener
    Daemon {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        bind: SocketAddr,

        /// Automatically open the web dashboard in default browser on startup
        #[arg(long, default_value_t = false)]
        open: bool,

        /// Interval in seconds between background scraper runs (default: 15 min)
        #[arg(long, default_value_t = 900)]
        scrape_interval: u64,

        /// Maximum in-flight pre-commit retries per CONNECT request
        #[arg(long, default_value_t = 4)]
        max_retries: usize,

        /// Maximum concurrent candidate sockets checked in validation pipeline
        #[arg(long, default_value_t = 500)]
        concurrency: usize,

        /// Path to MaxMind GeoLite2-City.mmdb
        #[arg(long)]
        city_db: Option<PathBuf>,

        /// Path to MaxMind GeoLite2-ASN.mmdb
        #[arg(long)]
        asn_db: Option<PathBuf>,
    },

    /// Scrapes public sources, checks candidates, and exports verified nodes to out/
    Scrape {
        /// Destination directory for output dumps (out/proxies.txt, out/proxies.json)
        #[arg(short, long, default_value = "out")]
        output_dir: PathBuf,

        /// Maximum concurrent candidate sockets checked in validation pipeline
        #[arg(long, default_value_t = 500)]
        concurrency: usize,

        /// Path to MaxMind GeoLite2-City.mmdb
        #[arg(long)]
        city_db: Option<PathBuf>,

        /// Path to MaxMind GeoLite2-ASN.mmdb
        #[arg(long)]
        asn_db: Option<PathBuf>,
    },
}

fn init_geo_resolver(city_db: Option<&Path>, asn_db: Option<&Path>) -> Arc<GeoResolver> {
    // Check user-specified paths or local standard files
    let default_city = Path::new("GeoLite2-City.mmdb");
    let default_asn = Path::new("GeoLite2-ASN.mmdb");

    let city_path = city_db.or_else(|| if default_city.exists() { Some(default_city) } else { None });
    let asn_path = asn_db.or_else(|| if default_asn.exists() { Some(default_asn) } else { None });

    match GeoResolver::from_paths(city_path, asn_path) {
        Ok(resolver) => {
            info!("GeoResolver loaded successfully (zero-copy memory-mapped)");
            Arc::new(resolver)
        }
        Err(e) => {
            warn!("GeoResolver offline database not loaded: {}. Running with empty geo.", e);
            Arc::new(GeoResolver::empty())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "looker=info,looker_proxy=info,looker_gateway=info,looker_scraper=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon {
            bind,
            open,
            scrape_interval,
            max_retries,
            concurrency,
            city_db,
            asn_db,
        } => {
            println!("============================================================");
            println!("     Looker Rotating Proxy Infrastructure Daemon           ");
            println!("============================================================");
            info!("Initializing daemon on http://{}...", bind);

            let cancel_token = CancellationToken::new();

            // Spawn OS signal listener (Ctrl-C / SIGINT)
            let signal_token = cancel_token.clone();
            tokio::spawn(async move {
                if let Ok(()) = tokio::signal::ctrl_c().await {
                    info!("Shutdown signal received (Ctrl-C). Initiating graceful shutdown...");
                    signal_token.cancel();
                }
            });

            let geo_resolver = init_geo_resolver(city_db.as_deref(), asn_db.as_deref());
            let direct_ip = resolve_direct_ip().await;
            info!("Direct client IP baseline: {:?}", direct_ip);

            let pool = Arc::new(ProxyPool::new().with_cooldown(Duration::from_secs(60)));
            let scraper = Arc::new(ProxyScraper::new());

            let checker_config = CheckerConfig {
                max_concurrency: concurrency,
                timeout: Duration::from_secs(5),
                target_authority: "cloudflare.com:443".to_string(),
            };
            let checker = Arc::new(ProxyChecker::with_config(
                Arc::clone(&geo_resolver),
                checker_config,
                direct_ip,
            ));

            info!(
                "Configured {} public proxy feeds across Monosans, ProxyScrape, TheSpeedX, Proxifly",
                DEFAULT_SOURCES.len()
            );

            // Spawn background active validation pipeline with cancellation support
            let pool_clone = Arc::clone(&pool);
            let scraper_clone = Arc::clone(&scraper);
            let checker_clone = Arc::clone(&checker);
            let scraper_cancel = cancel_token.child_token();

            tokio::spawn(async move {
                loop {
                    if scraper_cancel.is_cancelled() {
                        debug!("Background scraper loop stopped.");
                        break;
                    }

                    info!("Running periodic proxy harvest & validation pipeline...");

                    // 1. Collect candidates from public sources
                    let candidates = match scraper_clone.collect_all().await {
                        Ok(c) => c,
                        Err(e) => {
                            error!("Error collecting candidates: {}", e);
                            Vec::new()
                        }
                    };

                    // 2. Add quarantined items to re-check queue
                    let mut all_to_check = candidates;
                    let quarantined = pool_clone.list_quarantined();
                    if !quarantined.is_empty() {
                        debug!("Re-checking {} quarantined proxies...", quarantined.len());
                        for q in quarantined {
                            all_to_check.push(looker_scraper::CandidateProxy::new(q.addr, Some(q.proto)));
                        }
                    }

                    // 3. Run validation pipeline
                    if !all_to_check.is_empty() {
                        let verified = checker_clone.check_all(all_to_check).await;
                        for v in verified {
                            pool_clone.add_or_update(v);
                        }
                    }

                    let stats = pool_clone.stats();
                    info!(
                        "[POOL STATUS] Total: {}, Healthy/Active: {}, Quarantined: {}, Avg Latency: {} ms",
                        stats.total_proxies,
                        stats.healthy_proxies,
                        stats.quarantined_proxies,
                        stats.avg_latency_ms
                    );

                    info!("Next automated refresh scheduled in {} seconds", scrape_interval);

                    tokio::select! {
                        _ = scraper_cancel.cancelled() => {
                            debug!("Background scraper loop cancelled.");
                            break;
                        }
                        _ = tokio::time::sleep(Duration::from_secs(scrape_interval)) => {}
                    }
                }
            });

            // Auto-launch web dashboard in default browser if requested
            if open {
                let dashboard_url = format!("http://{}/ui", bind);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    match opener::open(&dashboard_url) {
                        Ok(_) => info!("Dashboard opened in default browser: {}", dashboard_url),
                        Err(e) => info!(
                            "Dashboard available at {} (could not launch browser: {})",
                            dashboard_url, e
                        ),
                    }
                });
            }

            // Start transparent gateway listener with cancellation support
            let config = GatewayConfig {
                bind_addr: bind,
                max_retries,
                connect_timeout: Duration::from_secs(6),
                buffer_size: 16384,
            };

            let gateway = ProxyGateway::new(config, Arc::clone(&pool));
            gateway.run_with_cancellation(cancel_token.clone()).await?;

            // Graceful shutdown completed: export latest healthy proxy snapshot
            let out_dir = Path::new("out");
            if let Err(e) = fs::create_dir_all(out_dir) {
                warn!("Could not create out/ directory on shutdown: {}", e);
            } else {
                let shutdown_file = out_dir.join("proxies_last_shutdown.txt");
                let live_text = pool.export_live_text();
                match fs::write(&shutdown_file, &live_text) {
                    Ok(_) => info!(
                        "Exported {} healthy proxies to {} on shutdown.",
                        pool.healthy_count(),
                        shutdown_file.display()
                    ),
                    Err(e) => warn!("Failed to write {}: {}", shutdown_file.display(), e),
                }
            }

            info!("Looker proxy daemon exited cleanly.");
        }

        Commands::Scrape {
            output_dir,
            concurrency,
            city_db,
            asn_db,
        } => {
            println!("============================================================");
            println!("       Looker One-Shot Proxy Harvester & Validator         ");
            println!("============================================================");

            let geo_resolver = init_geo_resolver(city_db.as_deref(), asn_db.as_deref());
            let direct_ip = resolve_direct_ip().await;
            info!("Direct client IP baseline: {:?}", direct_ip);

            let scraper = ProxyScraper::new();
            let candidates = scraper.collect_all().await?;
            info!("Extracted {} unique bogon-filtered candidate proxies", candidates.len());

            let checker_config = CheckerConfig {
                max_concurrency: concurrency,
                timeout: Duration::from_secs(5),
                target_authority: "cloudflare.com:443".to_string(),
            };
            let checker = ProxyChecker::with_config(geo_resolver, checker_config, direct_ip);

            let verified = checker.check_all(candidates).await;
            info!("Successfully verified {} alive proxies", verified.len());

            fs::create_dir_all(&output_dir)?;
            let txt_path = output_dir.join("proxies.txt");
            let json_path = output_dir.join("proxies.json");

            // Write plain text feed (proto://addr)
            let mut txt_file = fs::File::create(&txt_path)?;
            for p in &verified {
                writeln!(txt_file, "{}", p.to_url())?;
            }
            info!("Wrote plain text proxy list to {}", txt_path.display());

            // Write detailed JSON dump
            let json_file = fs::File::create(&json_path)?;
            serde_json::to_writer_pretty(json_file, &verified)?;
            info!("Wrote detailed JSON proxy dump to {}", json_path.display());

            println!("\nTop 10 Fastest Verified Proxies:");
            println!("------------------------------------------------------------");
            let mut sorted = verified;
            sorted.sort_by_key(|p| p.latency);
            for p in sorted.iter().take(10) {
                let geo_str = p
                    .geo
                    .as_ref()
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "Unknown".to_string());
                println!(
                    "{:<25} | {:<12} | {:>4} ms | {}",
                    p.to_url(),
                    p.anonymity.to_string(),
                    p.latency.as_millis(),
                    geo_str
                );
            }
            println!("------------------------------------------------------------");
            println!("Done! Output saved to: {}", output_dir.display());
        }
    }

    Ok(())
}
