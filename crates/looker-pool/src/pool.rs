use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use rand::Rng;

use crate::error::PoolError;
use crate::item::{AnonymityLevel, CheckedProxy, ProxyItem, ProxySnapshot};
use looker_geo::GeoInfo;
use looker_protocol::ProxyProto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    #[default]
    RoundRobin,
    LowestLatency,
    Random,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PoolStats {
    pub total_proxies: usize,
    pub healthy_proxies: usize,
    pub quarantined_proxies: usize,
    pub avg_latency_ms: u64,
    pub total_requests: u64,
    pub healthy_http: usize,
    pub healthy_socks4: usize,
    pub healthy_socks5: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HealthyByProto {
    pub http: usize,
    pub socks4: usize,
    pub socks5: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApiStatus {
    pub total_candidates: usize,
    pub checked_count: usize,
    pub working_count: usize,
    pub quarantined_count: usize,
    pub avg_latency_ms: u64,
    pub is_scraping: bool,
    pub healthy_by_proto: HealthyByProto,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxyApiItem {
    pub endpoint: String,
    pub proto: String,
    pub latency_ms: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate_pct: u8,
    pub speed_kbps: f64,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

fn sort_by_composite_score(items: &mut [Arc<ProxyItem>]) {
    items.sort_by(|a, b| {
        b.composite_score()
            .partial_cmp(&a.composite_score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let ams = a.latency_ms.load(Ordering::Relaxed);
                let bms = b.latency_ms.load(Ordering::Relaxed);
                let a_key = if ams == 0 { u64::MAX } else { ams };
                let b_key = if bms == 0 { u64::MAX } else { bms };
                a_key.cmp(&b_key)
            })
    });
}

fn item_to_api(item: &ProxyItem) -> ProxyApiItem {
    let succ = item.successful_requests.load(Ordering::Relaxed);
    let total = item.total_requests.load(Ordering::Relaxed);
    let fails = total
        .saturating_sub(succ)
        .max(item.total_failures.load(Ordering::Relaxed) as u64);
    let speed_kbps = ((item.throughput_bps.load(Ordering::Relaxed) as f64 / 1024.0) * 10.0).round() / 10.0;
    let score = (item.composite_score() * 100.0).round() / 100.0;

    ProxyApiItem {
        endpoint: item.addr.to_string(),
        proto: item.proto.to_string().to_uppercase(),
        latency_ms: item.latency_ms.load(Ordering::Relaxed),
        success_count: succ,
        failure_count: fails,
        success_rate_pct: item.success_rate_pct(),
        speed_kbps,
        score,
        country: item.geo.as_ref().and_then(|g| g.country_code.clone()),
    }
}

pub struct ProxyPool {
    items: RwLock<Vec<Arc<ProxyItem>>>,
    fastest: Arc<RwLock<Vec<CheckedProxy>>>,
    rr_index: AtomicUsize,
    default_cooldown: Duration,
    total_candidates: AtomicUsize,
    checked_count: AtomicUsize,
    working_count: AtomicUsize,
    is_scraping: std::sync::atomic::AtomicBool,

    // Three-tier failure tracking and cooldowns:
    host_failures: RwLock<HashMap<IpAddr, u32>>,
    host_cooldowns: RwLock<HashMap<IpAddr, Instant>>,
    subnet_failures: RwLock<HashMap<[u8; 3], HashSet<SocketAddr>>>,
    subnet_cooldowns: RwLock<HashMap<[u8; 3], Instant>>,
}

impl Default for ProxyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            items: RwLock::new(Vec::new()),
            fastest: Arc::new(RwLock::new(Vec::new())),
            rr_index: AtomicUsize::new(0),
            default_cooldown: Duration::from_secs(60),
            total_candidates: AtomicUsize::new(0),
            checked_count: AtomicUsize::new(0),
            working_count: AtomicUsize::new(0),
            is_scraping: std::sync::atomic::AtomicBool::new(false),
            host_failures: RwLock::new(HashMap::new()),
            host_cooldowns: RwLock::new(HashMap::new()),
            subnet_failures: RwLock::new(HashMap::new()),
            subnet_cooldowns: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.default_cooldown = cooldown;
        self
    }

    /// Adds or updates a checked proxy in the registry.
    /// If existing, updates latency (EMA), resets consecutive failures, and marks healthy.
    /// If new, registers the proxy in the active pool.
    pub fn add_or_update(&self, proxy: CheckedProxy) {
        {
            let mut fastest = self.fastest.write();
            fastest.retain(|p| !(p.addr == proxy.addr && p.proto == proxy.proto));
            fastest.push(proxy.clone());
            fastest.sort_by_key(|p| p.latency);
            fastest.truncate(10);
        }

        let mut items = self.items.write();
        if let Some(existing) = items
            .iter()
            .find(|i| i.addr == proxy.addr && i.proto == proxy.proto)
        {
            existing.record_success(proxy.latency);
            if proxy.throughput_bps > 0 {
                let old_bps = existing.throughput_bps.load(Ordering::Relaxed);
                let new_bps = if old_bps == 0 {
                    proxy.throughput_bps
                } else {
                    (old_bps * 3 + proxy.throughput_bps) / 4
                };
                existing.throughput_bps.store(new_bps, Ordering::Relaxed);
            }
            existing.consecutive_failures.store(0, Ordering::Relaxed);
            existing.total_failures.store(0, Ordering::Relaxed);
            existing.healthy.store(true, Ordering::Release);
            existing.circuit_open_until_epoch_ms.store(0, Ordering::Relaxed);
        } else {
            let item = ProxyItem::new_validated(
                proxy.addr,
                proxy.proto,
                proxy.latency,
                proxy.throughput_bps,
                proxy.anonymity,
                proxy.exit_ip,
                proxy.geo,
            );
            items.push(Arc::new(item));
        }

        self.working_count.store(
            items.iter().filter(|i| i.is_healthy()).count(),
            Ordering::Relaxed,
        );
    }

    /// Backwards-compatible simple registration.
    pub fn add(&self, addr: SocketAddr, proto: ProxyProto, geo: Option<GeoInfo>) -> bool {
        let mut items = self.items.write();
        if items.iter().any(|item| item.addr == addr && item.proto == proto) {
            return false;
        }

        let item = ProxyItem::new(
            addr,
            proto,
            Duration::ZERO,
            AnonymityLevel::Elite,
            None,
            geo,
        );
        items.push(Arc::new(item));
        true
    }

    /// Selects a healthy proxy according to the specified strategy without locking selection loops.
    pub fn select(&self, strategy: SelectionStrategy) -> Result<Arc<ProxyItem>, PoolError> {
        let items = self.items.read();
        let healthy: Vec<&Arc<ProxyItem>> = items.iter().filter(|i| i.is_healthy()).collect();

        if healthy.is_empty() {
            return Err(PoolError::NoProxiesAvailable);
        }

        match strategy {
            SelectionStrategy::RoundRobin => {
                let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Ok(Arc::clone(healthy[idx]))
            }
            SelectionStrategy::LowestLatency => {
                let non_cooldown: Vec<Arc<ProxyItem>> = healthy
                    .iter()
                    .filter(|i| !self.is_ip_or_subnet_cooldown(i.addr))
                    .map(|i| Arc::clone(i))
                    .collect();
                let mut sorted = if non_cooldown.is_empty() {
                    healthy.into_iter().cloned().collect()
                } else {
                    non_cooldown
                };
                sort_by_composite_score(&mut sorted);
                let top_window = sorted.len().min(6);
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..top_window);
                Ok(Arc::clone(&sorted[idx]))
            }
            SelectionStrategy::Random => {
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..healthy.len());
                Ok(Arc::clone(healthy[idx]))
            }
        }
    }

    /// Returns a list of healthy proxies ranked by composite score (success rate, throughput, latency).
    pub fn get_healthy_candidates(&self, max_candidates: usize) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        let mut healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| i.is_healthy())
            .map(Arc::clone)
            .collect();

        sort_by_composite_score(&mut healthy);

        healthy.truncate(max_candidates);
        healthy
    }

    /// Returns healthy proxy candidates that are not on MEGA 509 cooldown, ordered by "sequential" (composite score descending) or "random".
    /// If all healthy proxies are in cooldown, falls back to regular healthy candidates to prevent hard stalls.
    pub fn get_mega_healthy_candidates_ordered(&self, max_candidates: usize, order: &str) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        let mut mega_healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| i.is_healthy() && !i.is_mega_cooldown() && !self.is_ip_or_subnet_cooldown(i.addr))
            .map(Arc::clone)
            .collect();

        if mega_healthy.is_empty() {
            let mut fallback: Vec<Arc<ProxyItem>> = items
                .iter()
                .filter(|i| i.is_healthy() && !self.is_ip_or_subnet_cooldown(i.addr))
                .map(Arc::clone)
                .collect();
            if fallback.is_empty() {
                fallback = items.iter().filter(|i| i.is_healthy()).map(Arc::clone).collect();
            }
            if order.eq_ignore_ascii_case("random") {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                fallback.shuffle(&mut rng);
            } else {
                sort_by_composite_score(&mut fallback);
                let top_window = fallback.len().min(6);
                if top_window > 1 {
                    use rand::seq::SliceRandom;
                    let mut rng = rand::thread_rng();
                    fallback[..top_window].shuffle(&mut rng);
                }
            }
            fallback.truncate(max_candidates);
            return fallback;
        }

        if order.eq_ignore_ascii_case("random") {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            mega_healthy.shuffle(&mut rng);
        } else {
            sort_by_composite_score(&mut mega_healthy);
            // Light top-6 jitter among highest-scoring nodes to spread chunk load without pulling in slow proxies
            let top_window = mega_healthy.len().min(6);
            if top_window > 1 {
                use rand::seq::SliceRandom;
                let mut rng = rand::thread_rng();
                mega_healthy[..top_window].shuffle(&mut rng);
            }
        }

        mega_healthy.truncate(max_candidates);
        mega_healthy
    }

    /// Returns healthy proxy candidates that are not on MEGA 509 cooldown, sorted by latency (sequential).
    pub fn get_mega_healthy_candidates(&self, max_candidates: usize) -> Vec<Arc<ProxyItem>> {
        self.get_mega_healthy_candidates_ordered(max_candidates, "sequential")
    }

    /// Checks if a socket address is blocked by an active host IP cooldown or /24 subnet cooldown.
    pub fn is_ip_or_subnet_cooldown(&self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        {
            let hc = self.host_cooldowns.read();
            if let Some(&until) = hc.get(&addr.ip()) {
                if now < until {
                    return true;
                }
            }
        }
        if let IpAddr::V4(v4) = addr.ip() {
            let oct = v4.octets();
            let subnet = [oct[0], oct[1], oct[2]];
            let sc = self.subnet_cooldowns.read();
            if let Some(&until) = sc.get(&subnet) {
                if now < until {
                    return true;
                }
            }
        }
        false
    }

    /// Returns whether the host IP is on active host cooldown.
    pub fn is_host_ip_cooldown(&self, ip: IpAddr) -> bool {
        let hc = self.host_cooldowns.read();
        if let Some(&until) = hc.get(&ip) {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Returns whether the /24 subnet is on active subnet cooldown.
    pub fn is_subnet_cooldown(&self, subnet: [u8; 3]) -> bool {
        let sc = self.subnet_cooldowns.read();
        if let Some(&until) = sc.get(&subnet) {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Records failure and updates cooldowns at three levels:
    /// 1. Exact endpoint (addr)
    /// 2. Host IP: if an IP fails 3 times across any of its ports, puts the entire IP on cooldown
    /// 3. /24 subnet: if 5 distinct failures occur from the same /24 subnet, puts the prefix on a 15-minute cooldown
    pub fn record_failure_at_all_levels(&self, addr: SocketAddr, cooldown: Duration) {
        // 1. Exact endpoint cooldown
        {
            let items = self.items.read();
            if let Some(item) = items.iter().find(|i| i.addr == addr) {
                item.mark_mega_509_cooldown(cooldown);
                let (_quarantined, total) = item.record_failure(cooldown);
                let proto = item.proto;
                if total >= 3 {
                    drop(items);
                    self.remove_item(addr, proto);
                }
            }
        }

        // 2. Host IP failure tracking
        let ip = addr.ip();
        let ip_failures = {
            let mut hf = self.host_failures.write();
            let count = hf.entry(ip).or_insert(0);
            *count += 1;
            *count
        };

        if ip_failures >= 3 {
            let mut hc = self.host_cooldowns.write();
            hc.insert(ip, Instant::now() + cooldown);
        }

        // 3. /24 subnet failure tracking
        if let IpAddr::V4(v4) = ip {
            let oct = v4.octets();
            let subnet = [oct[0], oct[1], oct[2]];
            let distinct_failures = {
                let mut sf = self.subnet_failures.write();
                let set = sf.entry(subnet).or_default();
                set.insert(addr);
                set.len()
            };

            if distinct_failures >= 5 {
                let mut sc = self.subnet_cooldowns.write();
                // 15-minute cooldown on the /24 subnet
                sc.insert(subnet, Instant::now() + Duration::from_secs(15 * 60));
            }
        }
    }

    /// Marks a proxy identified by address on MEGA 509 quota cooldown or connection drop.
    pub fn mark_mega_cooldown(&self, addr: SocketAddr, cooldown: Duration) {
        self.record_failure_at_all_levels(addr, cooldown);
    }

    /// Returns count of proxies currently on active MEGA 509 cooldown.
    pub fn mega_cooldown_count(&self) -> usize {
        let items = self.items.read();
        items.iter().filter(|i| i.is_mega_cooldown()).count()
    }

    /// Returns all currently healthy proxies.
    pub fn list_healthy(&self) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        items.iter().filter(|i| i.is_healthy()).map(Arc::clone).collect()
    }

    /// Returns all quarantined (unhealthy) proxies for background re-validation.
    pub fn list_quarantined(&self) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        items.iter().filter(|i| !i.is_healthy()).map(Arc::clone).collect()
    }

    /// Generates a live text feed formatted as `proto://host:port\n` for all healthy proxies.
    pub fn export_live_text(&self) -> String {
        let healthy = self.list_healthy();
        let mut text = String::with_capacity(healthy.len() * 32);
        for item in healthy {
            text.push_str(&item.to_url());
            text.push('\n');
        }
        text
    }

    /// Generates raw `host:port\n` text feed for a specific protocol only (healthy proxies only).
    pub fn export_by_proto(&self, proto: ProxyProto) -> String {
        let items = self.items.read();
        let mut text = String::new();
        for item in items.iter() {
            if item.is_healthy() && item.proto == proto {
                text.push_str(&item.addr.to_string());
                text.push('\n');
            }
        }
        text
    }

    /// Returns a list of `CheckedProxy` structs for all currently healthy proxies.
    pub fn healthy_checked(&self) -> Vec<CheckedProxy> {
        let items = self.items.read();
        items
            .iter()
            .filter(|i| i.is_healthy())
            .map(|i| i.to_checked())
            .collect()
    }

    pub fn total_count(&self) -> usize {
        self.items.read().len()
    }

    pub fn healthy_count(&self) -> usize {
        self.items.read().iter().filter(|i| i.is_healthy()).count()
    }

    pub fn quarantined_count(&self) -> usize {
        self.items.read().iter().filter(|i| !i.is_healthy()).count()
    }

    /// Returns a point-in-time serializable snapshot of all proxies in the pool.
    pub fn snapshot(&self) -> Vec<ProxySnapshot> {
        let items = self.items.read();
        items.iter().map(|i| i.snapshot()).collect()
    }

    /// Permanently removes a proxy from the registry and fastest cache.
    pub fn remove_item(&self, addr: SocketAddr, proto: ProxyProto) -> bool {
        let removed = {
            let mut items = self.items.write();
            let before = items.len();
            items.retain(|i| !(i.addr == addr && i.proto == proto));
            items.len() < before
        };

        if removed {
            let mut fastest = self.fastest.write();
            fastest.retain(|p| !(p.addr == addr && p.proto == proto));
            self.working_count.store(self.healthy_count(), Ordering::Relaxed);
        }

        removed
    }

    /// Permanently evicts a proxy (alias for remove_item).
    pub fn evict(&self, addr: SocketAddr, proto: ProxyProto) -> bool {
        self.remove_item(addr, proto)
    }

    /// Permanently prunes any proxies with cumulative lifetime failures >= 3.
    pub fn prune_dead(&self) -> usize {
        let mut items = self.items.write();
        let before = items.len();
        items.retain(|i| i.total_failures.load(Ordering::Relaxed) < 3);
        let pruned = before - items.len();

        if pruned > 0 {
            let mut fastest = self.fastest.write();
            fastest.retain(|p| items.iter().any(|i| i.addr == p.addr && i.proto == p.proto));
            self.working_count.store(
                items.iter().filter(|i| i.is_healthy()).count(),
                Ordering::Relaxed,
            );
        }

        pruned
    }

    /// Handles a check failure during validation:
    /// - If the proxy is quarantined (unhealthy), failed re-verification evicts it immediately.
    /// - If the proxy is healthy, records failure. If total_failures >= 3, evicts it immediately.
    pub fn handle_check_failure(&self, addr: SocketAddr, proto: Option<ProxyProto>) {
        let mut evict_targets = Vec::new();

        {
            let items = self.items.read();
            for item in items.iter() {
                if item.addr == addr && proto.map_or(true, |p| p == item.proto) {
                    if !item.is_healthy() {
                        // Quarantined node failed re-verification: strike 3 / permanent eviction
                        evict_targets.push((item.addr, item.proto));
                    } else {
                        let (_quarantined, total) = item.record_failure(self.default_cooldown);
                        if total >= 3 {
                            evict_targets.push((item.addr, item.proto));
                        }
                    }
                }
            }
        }

        for (a, p) in evict_targets {
            self.remove_item(a, p);
        }
    }

    pub fn record_failure(&self, item: &ProxyItem) {
        self.record_failure_at_all_levels(item.addr, self.default_cooldown);
    }

    pub fn record_failure_by_addr(&self, addr: SocketAddr, _proto: ProxyProto) {
        self.record_failure_at_all_levels(addr, self.default_cooldown);
    }

    pub fn record_success(&self, item: &ProxyItem, latency: Duration) {
        item.record_success(latency);
    }

    /// Records a completed chunk transfer for a proxy, updating success count, latency,
    /// and moving-average throughput. Returns `true` if the proxy crawled under 50 KB/s
    /// and was benched/cooled down.
    pub fn record_chunk_success(
        &self,
        addr: SocketAddr,
        proto: ProxyProto,
        latency: Duration,
        bytes: u64,
        elapsed: Duration,
        slow_cooldown: Duration,
    ) -> bool {
        let benched = {
            let items = self.items.read();
            if let Some(item) = items.iter().find(|i| i.addr == addr && i.proto == proto) {
                item.record_transfer_success(latency, bytes, elapsed, slow_cooldown)
            } else {
                false
            }
        };
        if benched {
            self.working_count.store(self.healthy_count(), Ordering::Relaxed);
        }
        benched
    }

    /// Records throughput observed on a CONNECT tunnel without double-counting handshake success.
    pub fn record_tunnel_throughput(
        &self,
        addr: SocketAddr,
        proto: ProxyProto,
        bytes: u64,
        elapsed: Duration,
        slow_cooldown: Duration,
    ) -> bool {
        let benched = {
            let items = self.items.read();
            if let Some(item) = items.iter().find(|i| i.addr == addr && i.proto == proto) {
                item.record_throughput(bytes, elapsed, slow_cooldown)
            } else {
                false
            }
        };
        if benched {
            self.working_count.store(self.healthy_count(), Ordering::Relaxed);
        }
        benched
    }

    /// Exports all currently healthy proxies to the specified directory hierarchy:
    /// - <out_dir>/proxies.json
    /// - <out_dir>/proxies/all.txt
    /// - <out_dir>/proxies/http.txt
    /// - <out_dir>/proxies/socks4.txt
    /// - <out_dir>/proxies/socks5.txt
    pub fn export_to_dir(&self, out_dir: &std::path::Path) -> std::io::Result<()> {
        let healthy = self.healthy_checked();
        export_disk_hierarchy(out_dir, &healthy)
    }

    pub fn stats(&self) -> PoolStats {
        let items = self.items.read();
        let total = items.len();
        let mut healthy = 0;
        let mut quarantined = 0;
        let mut total_latency_ms: u64 = 0;
        let mut latency_count: u64 = 0;
        let mut total_requests: u64 = 0;
        let mut healthy_http = 0;
        let mut healthy_socks4 = 0;
        let mut healthy_socks5 = 0;

        for item in items.iter() {
            total_requests += item.total_requests.load(Ordering::Relaxed);
            if item.is_healthy() {
                healthy += 1;
                match item.proto {
                    ProxyProto::HttpConnect => healthy_http += 1,
                    ProxyProto::Socks4 => healthy_socks4 += 1,
                    ProxyProto::Socks5 => healthy_socks5 += 1,
                }
                let lat = item.latency_ms.load(Ordering::Relaxed);
                if lat > 0 {
                    total_latency_ms += lat;
                    latency_count += 1;
                }
            } else {
                quarantined += 1;
            }
        }

        let avg_latency_ms = if latency_count > 0 {
            total_latency_ms / latency_count
        } else {
            0
        };

        PoolStats {
            total_proxies: total,
            healthy_proxies: healthy,
            quarantined_proxies: quarantined,
            avg_latency_ms,
            total_requests,
            healthy_http,
            healthy_socks4,
            healthy_socks5,
        }
    }

    pub fn set_scraping(&self, val: bool) {
        self.is_scraping.store(val, Ordering::Relaxed);
    }

    pub fn reset_progress(&self, total_candidates: usize) {
        self.total_candidates.store(total_candidates, Ordering::Relaxed);
        self.checked_count.store(0, Ordering::Relaxed);
        self.working_count.store(self.healthy_count(), Ordering::Relaxed);
    }

    pub fn inc_checked(&self) {
        self.checked_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_working(&self) {
        self.working_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fastest_proxies(&self, limit: usize) -> Vec<CheckedProxy> {
        let fastest = self.fastest.read();
        fastest.iter().take(limit).cloned().collect()
    }

    pub fn api_fastest(&self, limit: usize) -> Vec<ProxyApiItem> {
        let live = self.api_proxies(None, Some(limit));
        if !live.is_empty() {
            return live;
        }
        let fastest = self.fastest.read();
        fastest
            .iter()
            .take(limit)
            .map(|p| ProxyApiItem {
                endpoint: p.addr.to_string(),
                proto: p.proto.to_string().to_uppercase(),
                latency_ms: p.latency.as_millis() as u64,
                success_count: 1,
                failure_count: 0,
                success_rate_pct: 100,
                speed_kbps: ((p.throughput_bps as f64 / 1024.0) * 10.0).round() / 10.0,
                score: 0.0,
                country: p.geo.as_ref().and_then(|g| g.country_code.clone()),
            })
            .collect()
    }

    pub fn api_proxies(&self, proto_filter: Option<ProxyProto>, limit: Option<usize>) -> Vec<ProxyApiItem> {
        let items = self.items.read();
        let mut healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| {
                if !i.is_healthy() {
                    return false;
                }
                if let Some(proto) = proto_filter {
                    if i.proto != proto {
                        return false;
                    }
                }
                true
            })
            .map(Arc::clone)
            .collect();
        sort_by_composite_score(&mut healthy);
        let take_count = limit.unwrap_or(healthy.len());
        healthy
            .iter()
            .take(take_count)
            .map(|item| item_to_api(item))
            .collect()
    }

    pub fn api_status(&self) -> ApiStatus {
        let stats = self.stats();
        ApiStatus {
            total_candidates: self.total_candidates.load(Ordering::Relaxed),
            checked_count: self.checked_count.load(Ordering::Relaxed),
            working_count: stats.healthy_proxies,
            quarantined_count: stats.quarantined_proxies,
            avg_latency_ms: stats.avg_latency_ms,
            is_scraping: self.is_scraping.load(Ordering::Relaxed),
            healthy_by_proto: HealthyByProto {
                http: stats.healthy_http,
                socks4: stats.healthy_socks4,
                socks5: stats.healthy_socks5,
            },
        }
    }
}

fn atomic_write_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp_path = std::path::PathBuf::from(format!("{}.tmp", path.display()));
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        let _ = f.sync_all();
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Exports protocol-segregated proxy hierarchy to disk with clean live survivors only (atomic .tmp -> rename).
pub fn export_disk_hierarchy(out_dir: &std::path::Path, proxies: &[CheckedProxy]) -> std::io::Result<()> {
    use std::fmt::Write as _;
    std::fs::create_dir_all(out_dir)?;
    let sub_dir = out_dir.join("proxies");
    std::fs::create_dir_all(&sub_dir)?;

    // 1. out/proxies.json
    let json_bytes = serde_json::to_vec_pretty(proxies)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    atomic_write_file(&out_dir.join("proxies.json"), &json_bytes)?;

    // 2. out/proxies/all.txt (proto://host:port)
    let mut all_txt = String::new();
    let mut http_txt = String::new();
    let mut socks4_txt = String::new();
    let mut socks5_txt = String::new();

    for p in proxies {
        let _ = writeln!(all_txt, "{}", p.to_url());
        match p.proto {
            ProxyProto::HttpConnect => {
                let _ = writeln!(http_txt, "{}", p.addr);
            }
            ProxyProto::Socks4 => {
                let _ = writeln!(socks4_txt, "{}", p.addr);
            }
            ProxyProto::Socks5 => {
                let _ = writeln!(socks5_txt, "{}", p.addr);
            }
        }
    }

    atomic_write_file(&sub_dir.join("all.txt"), all_txt.as_bytes())?;
    atomic_write_file(&sub_dir.join("http.txt"), http_txt.as_bytes())?;
    atomic_write_file(&sub_dir.join("socks4.txt"), socks4_txt.as_bytes())?;
    atomic_write_file(&sub_dir.join("socks5.txt"), socks5_txt.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_selection_and_circuit_breaker() {
        let pool = ProxyPool::new();
        let addr1: SocketAddr = "1.1.1.1:8080".parse().unwrap();
        let addr2: SocketAddr = "2.2.2.2:8080".parse().unwrap();

        pool.add(addr1, ProxyProto::HttpConnect, None);
        pool.add(addr2, ProxyProto::Socks5, None);

        assert_eq!(pool.total_count(), 2);
        assert_eq!(pool.healthy_count(), 2);

        // Select round robin
        let p1 = pool.select(SelectionStrategy::RoundRobin).unwrap();
        let p2 = pool.select(SelectionStrategy::RoundRobin).unwrap();
        assert_ne!(p1.addr, p2.addr);

        // Trip circuit breaker on p1 (2 failures per new spec)
        pool.record_failure(&p1);
        pool.record_failure(&p1);

        assert!(!p1.is_healthy());
        assert_eq!(pool.healthy_count(), 1);
        assert_eq!(pool.quarantined_count(), 1);

        // Next selection must yield p2
        let p3 = pool.select(SelectionStrategy::RoundRobin).unwrap();
        assert_eq!(p3.addr, addr2);

        // Live text export contains only p2
        let live_txt = pool.export_live_text();
        assert!(live_txt.contains("socks5://2.2.2.2:8080"));
        assert!(!live_txt.contains("1.1.1.1:8080"));
    }

    #[test]
    fn test_add_or_update_resurrects_quarantined() {
        let pool = ProxyPool::new();
        let addr: SocketAddr = "3.3.3.3:1080".parse().unwrap();
        pool.add(addr, ProxyProto::Socks5, None);

        let item = pool.select(SelectionStrategy::RoundRobin).unwrap();
        pool.record_failure(&item);
        pool.record_failure(&item);
        assert!(!item.is_healthy());

        // Resurrect via add_or_update
        let checked = CheckedProxy {
            addr,
            proto: ProxyProto::Socks5,
            latency: Duration::from_millis(120),
            exit_ip: Some("3.3.3.3".parse().unwrap()),
            anonymity: AnonymityLevel::Elite,
            geo: None,
            throughput_bps: 0,
        };
        pool.add_or_update(checked);

        assert!(item.is_healthy());
        assert_eq!(pool.healthy_count(), 1);
        assert_eq!(item.latency_ms.load(Ordering::Relaxed), 120);
    }

    #[test]
    fn test_protocol_segregation_exports_and_stats() {
        let pool = ProxyPool::new();
        let http_addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let s4_addr: SocketAddr = "10.0.0.2:1080".parse().unwrap();
        let s5_addr: SocketAddr = "10.0.0.3:1080".parse().unwrap();

        pool.add(http_addr, ProxyProto::HttpConnect, None);
        pool.add(s4_addr, ProxyProto::Socks4, None);
        pool.add(s5_addr, ProxyProto::Socks5, None);

        let stats = pool.stats();
        assert_eq!(stats.healthy_proxies, 3);
        assert_eq!(stats.healthy_http, 1);
        assert_eq!(stats.healthy_socks4, 1);
        assert_eq!(stats.healthy_socks5, 1);

        let status = pool.api_status();
        assert_eq!(status.healthy_by_proto.http, 1);
        assert_eq!(status.healthy_by_proto.socks4, 1);
        assert_eq!(status.healthy_by_proto.socks5, 1);

        // Test export_by_proto returns raw host:port\n
        let http_txt = pool.export_by_proto(ProxyProto::HttpConnect);
        assert_eq!(http_txt, "10.0.0.1:8080\n");

        let s4_txt = pool.export_by_proto(ProxyProto::Socks4);
        assert_eq!(s4_txt, "10.0.0.2:1080\n");

        let s5_txt = pool.export_by_proto(ProxyProto::Socks5);
        assert_eq!(s5_txt, "10.0.0.3:1080\n");

        // Checked conversion
        let checked = pool.healthy_checked();
        assert_eq!(checked.len(), 3);

        // Server-side filtered api_proxies
        let s5_items = pool.api_proxies(Some(ProxyProto::Socks5), None);
        assert_eq!(s5_items.len(), 1);
        assert_eq!(s5_items[0].endpoint, "10.0.0.3:1080");
        assert_eq!(s5_items[0].proto, "SOCKS5");

        let http_items = pool.api_proxies(Some(ProxyProto::HttpConnect), None);
        assert_eq!(http_items.len(), 1);
        assert_eq!(http_items[0].proto, "HTTP");

        let all_items = pool.api_proxies(None, None);
        assert_eq!(all_items.len(), 3);
    }

    #[test]
    fn test_hard_3_strike_eviction() {
        let pool = ProxyPool::new();
        let addr: SocketAddr = "4.4.4.4:8080".parse().unwrap();
        pool.add(addr, ProxyProto::HttpConnect, None);

        assert_eq!(pool.total_count(), 1);
        assert_eq!(pool.healthy_count(), 1);

        let item = pool.select(SelectionStrategy::RoundRobin).unwrap();

        // Strike 1: still healthy (needs 2 consecutive to quarantine)
        pool.record_failure(&item);
        assert_eq!(pool.total_count(), 1);
        assert_eq!(pool.healthy_count(), 1);
        assert_eq!(item.total_failures.load(Ordering::Relaxed), 1);

        // Strike 2: quarantined (healthy = false)
        pool.record_failure(&item);
        assert_eq!(pool.total_count(), 1);
        assert_eq!(pool.healthy_count(), 0);
        assert_eq!(pool.quarantined_count(), 1);
        assert_eq!(item.total_failures.load(Ordering::Relaxed), 2);

        // Strike 3: hard eviction! Proxy permanently removed from pool
        pool.record_failure(&item);
        assert_eq!(pool.total_count(), 0);
        assert_eq!(pool.healthy_count(), 0);
        assert_eq!(pool.quarantined_count(), 0);

        // Pool stats reflect removal
        let stats = pool.stats();
        assert_eq!(stats.total_proxies, 0);
    }

    #[test]
    fn test_quarantine_failed_reverification_eviction() {
        let pool = ProxyPool::new();
        let addr: SocketAddr = "5.5.5.5:8080".parse().unwrap();
        pool.add(addr, ProxyProto::HttpConnect, None);

        let item = pool.select(SelectionStrategy::RoundRobin).unwrap();
        // Quarantine it with 2 failures
        pool.record_failure(&item);
        pool.record_failure(&item);
        assert_eq!(pool.quarantined_count(), 1);
        assert_eq!(pool.total_count(), 1);

        // Re-verification fails -> handle_check_failure evicts it immediately
        pool.handle_check_failure(addr, Some(ProxyProto::HttpConnect));
        assert_eq!(pool.total_count(), 0);
        assert_eq!(pool.quarantined_count(), 0);
    }

    #[test]
    fn test_export_to_dir_clean_sync() {
        let temp_dir = std::env::temp_dir().join(format!("looker_test_export_{}", rand::random::<u32>()));
        let pool = ProxyPool::new();
        let addr: SocketAddr = "6.6.6.6:8080".parse().unwrap();
        pool.add(addr, ProxyProto::HttpConnect, None);

        assert!(pool.export_to_dir(&temp_dir).is_ok());

        assert!(temp_dir.join("proxies.json").exists());
        assert!(temp_dir.join("proxies/all.txt").exists());
        assert!(temp_dir.join("proxies/http.txt").exists());
        assert!(temp_dir.join("proxies/socks4.txt").exists());
        assert!(temp_dir.join("proxies/socks5.txt").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_mega_509_cooldown_does_not_evict_from_general_pool() {
        let pool = ProxyPool::new();
        let addr1: SocketAddr = "7.7.7.1:8080".parse().unwrap();
        let addr2: SocketAddr = "7.7.7.2:8080".parse().unwrap();

        pool.add(addr1, ProxyProto::HttpConnect, None);
        pool.add(addr2, ProxyProto::HttpConnect, None);

        assert_eq!(pool.healthy_count(), 2);
        assert_eq!(pool.mega_cooldown_count(), 0);

        // Mark addr1 on MEGA 509 cooldown
        pool.mark_mega_cooldown(addr1, Duration::from_secs(3600));

        // Proxy 1 is still healthy for general HTTP/SOCKS routing!
        assert_eq!(pool.healthy_count(), 2);
        assert_eq!(pool.mega_cooldown_count(), 1);

        // General healthy candidates include both proxies
        let general_candidates = pool.get_healthy_candidates(10);
        assert_eq!(general_candidates.len(), 2);

        // But MEGA candidates exclude addr1 and only return addr2
        let mega_candidates = pool.get_mega_healthy_candidates(10);
        assert_eq!(mega_candidates.len(), 1);
        assert_eq!(mega_candidates[0].addr, addr2);

        // Test sequential vs random ordered candidates
        let seq = pool.get_mega_healthy_candidates_ordered(10, "sequential");
        assert_eq!(seq.len(), 1);
        assert_eq!(seq[0].addr, addr2);

        let rnd = pool.get_mega_healthy_candidates_ordered(10, "random");
        assert_eq!(rnd.len(), 1);
        assert_eq!(rnd[0].addr, addr2);
    }

    #[test]
    fn test_ip_and_subnet_cooldowns() {
        let pool = ProxyPool::new();

        // 1. Host IP failure tracking: 3 failures across different ports put entire IP on cooldown
        let host_ip: IpAddr = "144.124.251.24".parse().unwrap();
        let port1: SocketAddr = "144.124.251.24:10154".parse().unwrap();
        let port2: SocketAddr = "144.124.251.24:10749".parse().unwrap();
        let port3: SocketAddr = "144.124.251.24:11124".parse().unwrap();

        pool.add(port1, ProxyProto::HttpConnect, None);
        pool.add(port2, ProxyProto::HttpConnect, None);
        pool.add(port3, ProxyProto::HttpConnect, None);

        assert!(!pool.is_host_ip_cooldown(host_ip));
        assert!(!pool.is_ip_or_subnet_cooldown(port3));

        // 2 failures on port 1
        pool.record_failure_at_all_levels(port1, Duration::from_secs(300));
        pool.record_failure_at_all_levels(port1, Duration::from_secs(300));
        assert!(!pool.is_host_ip_cooldown(host_ip));

        // 1 failure on port 2 -> total 3 failures for host 144.124.251.24
        pool.record_failure_at_all_levels(port2, Duration::from_secs(300));
        assert!(pool.is_host_ip_cooldown(host_ip));
        // Port 3 should now be blocked by host-level cooldown!
        assert!(pool.is_ip_or_subnet_cooldown(port3));

        // 2. IPv4 /24 Subnet failure tracking: 5 distinct failures put the /24 prefix on 15m cooldown
        let subnet = [145, 220, 227];
        let ep1: SocketAddr = "145.220.227.1:8080".parse().unwrap();
        let ep2: SocketAddr = "145.220.227.2:8080".parse().unwrap();
        let ep3: SocketAddr = "145.220.227.3:8080".parse().unwrap();
        let ep4: SocketAddr = "145.220.227.4:8080".parse().unwrap();
        let ep5: SocketAddr = "145.220.227.5:8080".parse().unwrap();
        let ep6: SocketAddr = "145.220.227.6:8080".parse().unwrap();

        pool.add(ep1, ProxyProto::Socks5, None);
        pool.add(ep2, ProxyProto::Socks5, None);
        pool.add(ep3, ProxyProto::Socks5, None);
        pool.add(ep4, ProxyProto::Socks5, None);
        pool.add(ep5, ProxyProto::Socks5, None);
        pool.add(ep6, ProxyProto::Socks5, None);

        assert!(!pool.is_subnet_cooldown(subnet));
        assert!(!pool.is_ip_or_subnet_cooldown(ep6));

        pool.record_failure_at_all_levels(ep1, Duration::from_secs(60));
        pool.record_failure_at_all_levels(ep2, Duration::from_secs(60));
        pool.record_failure_at_all_levels(ep3, Duration::from_secs(60));
        pool.record_failure_at_all_levels(ep4, Duration::from_secs(60));
        assert!(!pool.is_subnet_cooldown(subnet));

        // 5th distinct failure from the same /24 subnet
        pool.record_failure_at_all_levels(ep5, Duration::from_secs(60));
        assert!(pool.is_subnet_cooldown(subnet));
        // ep6 in the same subnet is now blocked by subnet-level cooldown!
        assert!(pool.is_ip_or_subnet_cooldown(ep6));
    }

    #[test]
    fn test_composite_score_and_slow_crawl_cooldown() {
        let pool = ProxyPool::new();
        let fast_reliable: SocketAddr = "8.8.4.1:1080".parse().unwrap();
        let low_ping_flaky: SocketAddr = "8.8.4.2:1080".parse().unwrap();
        let slow_crawler: SocketAddr = "8.8.4.3:1080".parse().unwrap();

        pool.add_or_update(CheckedProxy {
            addr: fast_reliable,
            proto: ProxyProto::Socks5,
            latency: Duration::from_millis(200),
            exit_ip: None,
            anonymity: AnonymityLevel::Elite,
            geo: None,
            throughput_bps: 0,
        });
        pool.add_or_update(CheckedProxy {
            addr: low_ping_flaky,
            proto: ProxyProto::Socks5,
            latency: Duration::from_millis(40),
            exit_ip: None,
            anonymity: AnonymityLevel::Elite,
            geo: None,
            throughput_bps: 0,
        });
        pool.add_or_update(CheckedProxy {
            addr: slow_crawler,
            proto: ProxyProto::Socks5,
            latency: Duration::from_millis(60),
            exit_ip: None,
            anonymity: AnonymityLevel::Elite,
            geo: None,
            throughput_bps: 0,
        });

        // fast_reliable delivers 5 fast 1 MB chunks in 0.5s (~2 MB/s)
        for _ in 0..5 {
            assert!(!pool.record_chunk_success(
                fast_reliable,
                ProxyProto::Socks5,
                Duration::from_millis(180),
                1024 * 1024,
                Duration::from_millis(500),
                Duration::from_secs(120),
            ));
        }

        // low_ping_flaky has 1 failure + 1 slowish success
        pool.record_failure_by_addr(low_ping_flaky, ProxyProto::Socks5);
        pool.record_chunk_success(
            low_ping_flaky,
            ProxyProto::Socks5,
            Duration::from_millis(40),
            128 * 1024,
            Duration::from_secs(1),
            Duration::from_secs(120),
        );

        // slow_crawler delivers 64 KB over 4s = 16 KB/s (< 50 KB/s) -> gets benched immediately!
        let benched = pool.record_chunk_success(
            slow_crawler,
            ProxyProto::Socks5,
            Duration::from_millis(60),
            64 * 1024,
            Duration::from_secs(4),
            Duration::from_secs(120),
        );
        assert!(benched);

        let ranked = pool.api_proxies(None, None);
        assert_eq!(ranked[0].endpoint, "8.8.4.1:1080");
        assert!(ranked[0].speed_kbps > 1000.0);
        assert_eq!(ranked[0].success_rate_pct, 100);
        // slow_crawler should be excluded from healthy/active pool during cooldown
        assert!(!ranked.iter().any(|p| p.endpoint == "8.8.4.3:1080"));
    }
}
