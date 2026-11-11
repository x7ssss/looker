use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

            // Spawn background active validation pipeline
            let pool_clone = Arc::clone(&pool);
            let scraper_clone = Arc::clone(&scraper);
            let checker_clone = Arc::clone(&checker);

            tokio::spawn(async move {
                loop {
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
                    tokio::time::sleep(Duration::from_secs(scrape_interval)).await;
                }
            });

            // Start transparent gateway listener
            let config = GatewayConfig {
                bind_addr: bind,
                max_retries,
                connect_timeout: Duration::from_secs(6),
                buffer_size: 16384,
            };

            let gateway = ProxyGateway::new(config, pool);
            gateway.run().await?;
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
