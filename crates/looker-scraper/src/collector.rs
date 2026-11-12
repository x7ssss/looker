use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::error::ScraperError;
use crate::extractor::{CandidateExtractor, CandidateProxy};
pub use crate::sources::{ProxySource, DEFAULT_SOURCES};

pub struct ProxyScraper {
    client: Client,
    extractor: Arc<CandidateExtractor>,
    sources: Vec<ProxySource>,
    concurrency_limit: usize,
}

impl Default for ProxyScraper {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyScraper {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Looker/0.1")
            .build()
            .expect("Failed to build HTTP client for scraper");

        Self {
            client,
            extractor: Arc::new(CandidateExtractor::new()),
            sources: DEFAULT_SOURCES.to_vec(),
            concurrency_limit: 24,
        }
    }

    pub fn with_sources(mut self, sources: Vec<ProxySource>) -> Self {
        self.sources = sources;
        self
    }

    pub fn with_concurrency(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit;
        self
    }

    /// Concurrently fetches all configured public sources with strict 10-second timeouts,
    /// extracts candidate tokens, deduplicates, and drops bogons.
    pub async fn collect_all(&self) -> Result<Vec<CandidateProxy>, ScraperError> {
        info!("Collecting proxy candidates from {} public sources (10s timeout)...", self.sources.len());

        let sem = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut tasks = Vec::with_capacity(self.sources.len());

        for source in &self.sources {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
            let source = source.clone();
            let extractor = Arc::clone(&self.extractor);

            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                debug!("Fetching source '{}' from {}", source.name, source.url);

                match client.get(source.url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            if let Ok(text) = resp.text().await {
                                let mut extracted = extractor.extract(&text);
                                if let Some(proto) = source.default_proto {
                                    for c in &mut extracted {
                                        if c.proto.is_none() {
                                            c.proto = Some(proto);
                                        }
                                    }
                                }
                                debug!(
                                    "Source '{}' yielded {} candidates",
                                    source.name,
                                    extracted.len()
                                );
                                return extracted;
                            }
                        } else {
                            debug!(
                                "Source '{}' returned HTTP status {}",
                                source.name,
                                resp.status()
                            );
                        }
                    }
                    Err(e) => {
                        debug!("Failed to fetch source '{}': {}", source.name, e);
                    }
                }
                Vec::new()
            }));
        }

        let mut candidate_set = HashSet::new();
        for task in tasks {
            if let Ok(candidates) = task.await {
                for c in candidates {
                    candidate_set.insert(c);
                }
            }
        }

        let result: Vec<CandidateProxy> = candidate_set.into_iter().collect();
        info!("Collected {} unique valid public proxy candidates", result.len());
        Ok(result)
    }

    /// Alias for `collect_all`.
    pub async fn scrape_all(&self) -> Result<Vec<CandidateProxy>, ScraperError> {
        self.collect_all().await
    }
}

/// Loads previously saved survivor proxies from disk (`out/proxies.json`) for warm-boot priority seeding.
/// Gracefully handles `CheckedProxy` format, `ProxySnapshot` format, or raw candidate arrays.
pub fn load_warm_boot_candidates<P: AsRef<std::path::Path>>(path: P) -> Vec<CandidateProxy> {
    let p = path.as_ref();
    if !p.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(p) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    // 1. Try parsing as Vec<looker_pool::CheckedProxy>
    if let Ok(checked) = serde_json::from_str::<Vec<looker_pool::CheckedProxy>>(&content) {
        for cp in checked {
            if !crate::bogon::is_bogon(cp.addr.ip()) && seen.insert((cp.addr, cp.proto)) {
                candidates.push(CandidateProxy::new(cp.addr, Some(cp.proto)));
            }
        }
        if !candidates.is_empty() {
            return candidates;
        }
    }

    // 2. Try parsing as Vec<looker_pool::ProxySnapshot>
    if let Ok(snapshots) = serde_json::from_str::<Vec<looker_pool::ProxySnapshot>>(&content) {
        for ps in snapshots {
            if ps.healthy && !crate::bogon::is_bogon(ps.addr.ip()) && seen.insert((ps.addr, ps.proto)) {
                candidates.push(CandidateProxy::new(ps.addr, Some(ps.proto)));
            }
        }
        if !candidates.is_empty() {
            return candidates;
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use looker_pool::{AnonymityLevel, CheckedProxy};
    use looker_protocol::ProxyProto;
    use std::net::SocketAddr;

    #[test]
    fn test_load_warm_boot_candidates() {
        let now_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("looker_warm_test_{}", now_nano));
        let _ = std::fs::create_dir_all(&temp_dir);
        let json_file = temp_dir.join("proxies.json");

        let addr1: SocketAddr = "1.2.3.4:8080".parse().unwrap();
        let addr2: SocketAddr = "5.6.7.8:1080".parse().unwrap();
        let proxies = vec![
            CheckedProxy {
                addr: addr1,
                proto: ProxyProto::HttpConnect,
                latency: Duration::from_millis(50),
                exit_ip: None,
                anonymity: AnonymityLevel::Elite,
                geo: None,
            },
            CheckedProxy {
                addr: addr2,
                proto: ProxyProto::Socks5,
                latency: Duration::from_millis(100),
                exit_ip: None,
                anonymity: AnonymityLevel::Elite,
                geo: None,
            },
        ];

        let serialized = serde_json::to_string_pretty(&proxies).unwrap();
        std::fs::write(&json_file, serialized).unwrap();

        let candidates = load_warm_boot_candidates(&json_file);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].addr, addr1);
        assert_eq!(candidates[0].proto, Some(ProxyProto::HttpConnect));
        assert_eq!(candidates[1].addr, addr2);
        assert_eq!(candidates[1].proto, Some(ProxyProto::Socks5));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
