use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use looker_pool::CheckedProxy;
use looker_protocol::ProxyProto;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::error::ScraperError;
use crate::extractor::{CandidateExtractor, CandidateProxy};
pub use crate::sources::{ProxySource, DEFAULT_SOURCES};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct FeedYieldStats {
    pub name: String,
    pub url: String,
    pub candidates_fetched: u64,
    pub survivors: u64,
    pub fetch_failures: u64,
    pub last_yield_rate: f64,
    pub runs: u64,
    pub last_updated_epoch_secs: u64,
}

impl FeedYieldStats {
    pub fn priority_score(&self) -> f64 {
        if self.runs == 0 {
            // Untested sources get exploratory priority above dead 0-yield feeds
            return 0.15;
        }
        let yield_rate = if self.candidates_fetched > 0 {
            self.survivors as f64 / self.candidates_fetched as f64
        } else {
            0.0
        };
        let volume_bonus = (self.survivors as f64).ln_1p() * 0.025;
        let fail_penalty = (self.fetch_failures as f64) * 0.05;
        (yield_rate + volume_bonus - fail_penalty).max(-1.0)
    }
}

pub struct ProxyScraper {
    client: Client,
    extractor: Arc<CandidateExtractor>,
    sources: Vec<ProxySource>,
    concurrency_limit: usize,
    feed_stats: Arc<RwLock<HashMap<String, FeedYieldStats>>>,
    last_provenance: Arc<RwLock<HashMap<(SocketAddr, Option<ProxyProto>), Vec<String>>>>,
    stats_path: Option<PathBuf>,
}

impl Default for ProxyScraper {
    fn default() -> Self {
        Self::new()
    }
}

fn load_feed_stats_from_disk(path: &Path) -> HashMap<String, FeedYieldStats> {
    if !path.exists() {
        return HashMap::new();
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    let list: Vec<FeedYieldStats> = match serde_json::from_str(&content) {
        Ok(l) => l,
        Err(_) => return HashMap::new(),
    };
    list.into_iter().map(|s| (s.name.clone(), s)).collect()
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

impl ProxyScraper {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Looker/0.1")
            .build()
            .expect("Failed to build HTTP client for scraper");

        let default_stats_path = PathBuf::from("out").join("feed_stats.json");
        let loaded = load_feed_stats_from_disk(&default_stats_path);

        Self {
            client,
            extractor: Arc::new(CandidateExtractor::new()),
            sources: DEFAULT_SOURCES.to_vec(),
            concurrency_limit: 24,
            feed_stats: Arc::new(RwLock::new(loaded)),
            last_provenance: Arc::new(RwLock::new(HashMap::new())),
            stats_path: Some(default_stats_path),
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

    pub fn with_stats_path(mut self, path: Option<PathBuf>) -> Self {
        let loaded = path
            .as_ref()
            .map(|p| load_feed_stats_from_disk(p))
            .unwrap_or_default();
        self.stats_path = path;
        if let Ok(mut guard) = self.feed_stats.write() {
            *guard = loaded;
        }
        self
    }

    /// Returns sources ordered by descending historical survivor yield score.
    pub fn prioritized_sources(&self) -> Vec<ProxySource> {
        let mut ordered = self.sources.clone();
        let stats_guard = self.feed_stats.read().ok();
        ordered.sort_by(|a, b| {
            let score_a = stats_guard
                .as_ref()
                .and_then(|m| m.get(a.name))
                .map(|s| s.priority_score())
                .unwrap_or(0.15);
            let score_b = stats_guard
                .as_ref()
                .and_then(|m| m.get(b.name))
                .map(|s| s.priority_score())
                .unwrap_or(0.15);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        ordered
    }

    /// Concurrently fetches all configured public sources prioritized by historical yield,
    /// extracts candidate tokens, deduplicates while keeping higher-yield candidates first,
    /// and drops bogons.
    pub async fn collect_all(&self) -> Result<Vec<CandidateProxy>, ScraperError> {
        let prioritized = self.prioritized_sources();
        info!(
            "Collecting proxy candidates from {} public sources (10s timeout, yield-prioritized)...",
            prioritized.len()
        );

        let sem = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut tasks = Vec::with_capacity(prioritized.len());

        for source in prioritized {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let client = self.client.clone();
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
                                return (source.name, source.url, true, extracted);
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
                (source.name, source.url, false, Vec::new())
            }));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut candidate_set = HashSet::new();
        let mut ordered_candidates = Vec::new();
        let mut provenance: HashMap<(SocketAddr, Option<ProxyProto>), Vec<String>> = HashMap::new();

        for task in tasks {
            if let Ok((name, url, ok, candidates)) = task.await {
                if let Ok(mut stats_map) = self.feed_stats.write() {
                    let entry = stats_map
                        .entry(name.to_string())
                        .or_insert_with(|| FeedYieldStats {
                            name: name.to_string(),
                            url: url.to_string(),
                            ..Default::default()
                        });
                    entry.url = url.to_string();
                    entry.runs += 1;
                    entry.last_updated_epoch_secs = now_secs;
                    if ok {
                        entry.candidates_fetched += candidates.len() as u64;
                    } else {
                        entry.fetch_failures += 1;
                    }
                    if entry.candidates_fetched > 0 {
                        entry.last_yield_rate =
                            entry.survivors as f64 / entry.candidates_fetched as f64;
                    }
                }

                for c in candidates {
                    provenance
                        .entry((c.addr, c.proto))
                        .or_default()
                        .push(name.to_string());
                    if candidate_set.insert(c.clone()) {
                        ordered_candidates.push(c);
                    }
                }
            }
        }

        if let Ok(mut prov_guard) = self.last_provenance.write() {
            *prov_guard = provenance;
        }

        info!(
            "Collected {} unique valid public proxy candidates",
            ordered_candidates.len()
        );
        Ok(ordered_candidates)
    }

    /// Records verified survivors against the feeds that yielded them and atomically persists
    /// feed yield metrics to `out/feed_stats.json`.
    pub fn record_survivors(&self, verified: &[CheckedProxy]) {
        let prov = match self.last_provenance.read() {
            Ok(g) => g.clone(),
            Err(_) => return,
        };

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut feed_hits: HashMap<String, u64> = HashMap::new();
        for cp in verified {
            let mut matched = false;
            if let Some(sources) = prov.get(&(cp.addr, Some(cp.proto))) {
                for s in sources {
                    *feed_hits.entry(s.clone()).or_insert(0) += 1;
                    matched = true;
                }
            }
            if !matched {
                if let Some(sources) = prov.get(&(cp.addr, None)) {
                    for s in sources {
                        *feed_hits.entry(s.clone()).or_insert(0) += 1;
                    }
                }
            }
        }

        if let Ok(mut stats_map) = self.feed_stats.write() {
            for (source_name, hits) in feed_hits {
                if let Some(entry) = stats_map.get_mut(&source_name) {
                    entry.survivors += hits;
                    entry.last_updated_epoch_secs = now_secs;
                    if entry.candidates_fetched > 0 {
                        entry.last_yield_rate =
                            entry.survivors as f64 / entry.candidates_fetched as f64;
                    }
                }
            }

            if let Some(ref path) = self.stats_path {
                let mut sorted: Vec<FeedYieldStats> = stats_map.values().cloned().collect();
                sorted.sort_by(|a, b| {
                    b.survivors
                        .cmp(&a.survivors)
                        .then_with(|| {
                            b.last_yield_rate
                                .partial_cmp(&a.last_yield_rate)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                });
                let _ = atomic_write_json(path, &sorted);
            }
        }
    }

    /// Returns a snapshot of per-feed yield statistics sorted by survivor count descending.
    pub fn feed_stats(&self) -> Vec<FeedYieldStats> {
        let mut sorted: Vec<FeedYieldStats> = self
            .feed_stats
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        sorted.sort_by(|a, b| {
            b.survivors.cmp(&a.survivors).then_with(|| {
                b.last_yield_rate
                    .partial_cmp(&a.last_yield_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        sorted
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
                throughput_bps: 0,
            },
            CheckedProxy {
                addr: addr2,
                proto: ProxyProto::Socks5,
                latency: Duration::from_millis(100),
                exit_ip: None,
                anonymity: AnonymityLevel::Elite,
                geo: None,
                throughput_bps: 0,
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

    #[test]
    fn test_feed_yield_prioritization_and_persistence() {
        let now_nano = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!("looker_feed_yield_{}", now_nano));
        let _ = std::fs::create_dir_all(&temp_dir);
        let stats_file = temp_dir.join("feed_stats.json");

        let initial_stats = vec![
            FeedYieldStats {
                name: "dead-feed".to_string(),
                url: "https://example.invalid/dead.txt".to_string(),
                candidates_fetched: 500,
                survivors: 0,
                fetch_failures: 1,
                last_yield_rate: 0.0,
                runs: 3,
                last_updated_epoch_secs: 1,
            },
            FeedYieldStats {
                name: "gold-feed".to_string(),
                url: "https://example.invalid/gold.txt".to_string(),
                candidates_fetched: 100,
                survivors: 40,
                fetch_failures: 0,
                last_yield_rate: 0.40,
                runs: 3,
                last_updated_epoch_secs: 1,
            },
        ];
        atomic_write_json(&stats_file, &initial_stats).unwrap();

        let sources = vec![
            ProxySource {
                name: "dead-feed",
                url: "https://example.invalid/dead.txt",
                default_proto: Some(ProxyProto::HttpConnect),
            },
            ProxySource {
                name: "new-feed",
                url: "https://example.invalid/new.txt",
                default_proto: Some(ProxyProto::Socks5),
            },
            ProxySource {
                name: "gold-feed",
                url: "https://example.invalid/gold.txt",
                default_proto: Some(ProxyProto::Socks5),
            },
        ];

        let scraper = ProxyScraper::new()
            .with_sources(sources)
            .with_stats_path(Some(stats_file.clone()));

        let ordered = scraper.prioritized_sources();
        assert_eq!(ordered[0].name, "gold-feed");
        assert_eq!(ordered[1].name, "new-feed");
        assert_eq!(ordered[2].name, "dead-feed");

        // Record survivor from gold-feed via provenance map
        let survivor_addr: SocketAddr = "9.9.9.9:1080".parse().unwrap();
        {
            let mut prov = scraper.last_provenance.write().unwrap();
            prov.insert(
                (survivor_addr, Some(ProxyProto::Socks5)),
                vec!["gold-feed".to_string()],
            );
        }
        scraper.record_survivors(&[CheckedProxy {
            addr: survivor_addr,
            proto: ProxyProto::Socks5,
            latency: Duration::from_millis(80),
            exit_ip: None,
            anonymity: AnonymityLevel::Elite,
            geo: None,
            throughput_bps: 0,
        }]);

        let reloaded = load_feed_stats_from_disk(&stats_file);
        assert_eq!(reloaded.get("gold-feed").unwrap().survivors, 41);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
