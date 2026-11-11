use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use looker_gateway::{GatewayConfig, ProxyGateway};
use looker_geo::GeoResolver;
use looker_pool::ProxyPool;
use looker_protocol::ProxyProto;
use looker_scraper::ProxyScraper;

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

        #[arg(long, default_value_t = 300)]
        scrape_interval: u64,

        #[arg(long, default_value_t = 4)]
        max_retries: usize,

        #[arg(long)]
        city_db: Option<PathBuf>,

        #[arg(long)]
        asn_db: Option<PathBuf>,
    },

    /// Scrapes public sources once and displays discovered candidates
    Scrape {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "looker=info,looker_proxy=info,looker_gateway=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon {
            bind,
            scrape_interval,
            max_retries,
            city_db,
            asn_db,
        } => {
            info!("Starting Looker Rotating Proxy Daemon...");

            let geo_resolver = Arc::new(
                GeoResolver::from_paths(city_db.as_deref(), asn_db.as_deref())
                    .unwrap_or_else(|e| {
                        warn!("GeoResolver offline database not loaded: {}. Running with empty geo.", e);
                        GeoResolver::empty()
                    }),
            );

            let pool = Arc::new(ProxyPool::new().with_cooldown(Duration::from_secs(60)));
            let scraper = Arc::new(ProxyScraper::new());

            // Initial scrape
            let pool_clone = Arc::clone(&pool);
            let scraper_clone = Arc::clone(&scraper);
            let geo_clone = Arc::clone(&geo_resolver);

            tokio::spawn(async move {
                loop {
                    match scraper_clone.scrape_all().await {
                        Ok(candidates) => {
                            let mut added = 0;
                            for c in candidates {
                                let proto = c.proto.unwrap_or(ProxyProto::HttpConnect);
                                let geo = geo_clone.lookup(c.addr.ip());
                                if pool_clone.add(c.addr, proto, Some(geo)) {
                                    added += 1;
                                }
                            }
                            info!(
                                "Pool refreshed: added {} new proxies. Total in pool: {}, Healthy: {}",
                                added,
                                pool_clone.total_count(),
                                pool_clone.healthy_count()
                            );
                        }
                        Err(e) => {
                            error!("Error running background scraper: {}", e);
                        }
                    }

                    tokio::time::sleep(Duration::from_secs(scrape_interval)).await;
                }
            });

            let config = GatewayConfig {
                bind_addr: bind,
                max_retries,
                connect_timeout: Duration::from_secs(6),
                buffer_size: 16384,
            };

            let gateway = ProxyGateway::new(config, pool);
            gateway.run().await?;
        }

        Commands::Scrape { output } => {
            let scraper = ProxyScraper::new();
            let candidates = scraper.scrape_all().await?;
            info!("Total candidates scraped: {}", candidates.len());

            if let Some(path) = output {
                use std::io::Write;
                let mut file = std::fs::File::create(&path)?;
                for c in &candidates {
                    let proto_str = c
                        .proto
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "http".to_string());
                    writeln!(file, "{}://{}", proto_str, c.addr)?;
                }
                info!("Saved {} proxies to {}", candidates.len(), path.display());
            } else {
                for c in candidates.iter().take(20) {
                    println!(
                        "{}://{}",
                        c.proto
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "http".to_string()),
                        c.addr
                    );
                }
                if candidates.len() > 20 {
                    println!("... and {} more candidates", candidates.len() - 20);
                }
            }
        }
    }

    Ok(())
}
