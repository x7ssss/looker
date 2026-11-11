use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

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
    pub country: Option<String>,
    pub anonymity: String,
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
            existing.consecutive_failures.store(0, Ordering::Relaxed);
            existing.healthy.store(true, Ordering::Release);
            existing.circuit_open_until_epoch_ms.store(0, Ordering::Relaxed);
        } else {
            let item = ProxyItem::new(
                proxy.addr,
                proxy.proto,
                proxy.latency,
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
                let best = healthy.iter().min_by_key(|i| {
                    let ms = i.latency_ms.load(Ordering::Relaxed);
                    if ms == 0 {
                        u64::MAX
                    } else {
                        ms
                    }
                });
                Ok(Arc::clone(best.unwrap()))
            }
            SelectionStrategy::Random => {
                let mut rng = rand::thread_rng();
                let idx = rng.gen_range(0..healthy.len());
                Ok(Arc::clone(healthy[idx]))
            }
        }
    }

    /// Returns a list of healthy proxies sorted by latency for multi-candidate retry loops.
    pub fn get_healthy_candidates(&self, max_candidates: usize) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        let mut healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| i.is_healthy())
            .map(Arc::clone)
            .collect();

        healthy.sort_by_key(|i| {
            let ms = i.latency_ms.load(Ordering::Relaxed);
            if ms == 0 {
                99999
            } else {
                ms
            }
        });

        healthy.truncate(max_candidates);
        healthy
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

    pub fn record_failure(&self, item: &ProxyItem) {
        item.record_failure(self.default_cooldown);
    }

    pub fn record_failure_by_addr(&self, addr: SocketAddr, proto: ProxyProto) {
        let items = self.items.read();
        if let Some(item) = items.iter().find(|i| i.addr == addr && i.proto == proto) {
            item.record_failure(self.default_cooldown);
        }
    }

    pub fn record_success(&self, item: &ProxyItem, latency: Duration) {
        item.record_success(latency);
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
        let fastest = self.fastest.read();
        if !fastest.is_empty() {
            fastest
                .iter()
                .take(limit)
                .map(|p| ProxyApiItem {
                    endpoint: p.addr.to_string(),
                    proto: p.proto.to_string().to_uppercase(),
                    latency_ms: p.latency.as_millis() as u64,
                    country: p.geo.as_ref().and_then(|g| g.country_code.clone()),
                    anonymity: match p.anonymity {
                        AnonymityLevel::Elite => "Elite".to_string(),
                        AnonymityLevel::Anonymous => "Anonymous".to_string(),
                        AnonymityLevel::Transparent => "Transparent".to_string(),
                    },
                })
                .collect()
        } else {
            self.api_proxies(Some(limit))
        }
    }

    pub fn api_proxies(&self, limit: Option<usize>) -> Vec<ProxyApiItem> {
        let items = self.items.read();
        let mut healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| i.is_healthy())
            .map(Arc::clone)
            .collect();
        healthy.sort_by_key(|i| {
            let ms = i.latency_ms.load(Ordering::Relaxed);
            if ms == 0 {
                99999
            } else {
                ms
            }
        });
        let take_count = limit.unwrap_or(healthy.len());
        healthy
            .iter()
            .take(take_count)
            .map(|item| ProxyApiItem {
                endpoint: item.addr.to_string(),
                proto: item.proto.to_string().to_uppercase(),
                latency_ms: item.latency_ms.load(Ordering::Relaxed),
                country: item.geo.as_ref().and_then(|g| g.country_code.clone()),
                anonymity: match item.anonymity {
                    AnonymityLevel::Elite => "Elite".to_string(),
                    AnonymityLevel::Anonymous => "Anonymous".to_string(),
                    AnonymityLevel::Transparent => "Transparent".to_string(),
                },
            })
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
    }
}
