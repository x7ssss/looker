use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use rand::Rng;

use crate::error::PoolError;
use crate::item::ProxyItem;
use looker_geo::GeoInfo;
use looker_protocol::ProxyProto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SelectionStrategy {
    #[default]
    RoundRobin,
    LowestLatency,
    Random,
}

pub struct ProxyPool {
    items: RwLock<Vec<Arc<ProxyItem>>>,
    rr_index: AtomicUsize,
    default_cooldown: Duration,
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
            rr_index: AtomicUsize::new(0),
            default_cooldown: Duration::from_secs(60),
        }
    }

    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.default_cooldown = cooldown;
        self
    }

    /// Adds a proxy to the pool if not already registered.
    pub fn add(&self, addr: SocketAddr, proto: ProxyProto, geo: Option<GeoInfo>) -> bool {
        let mut items = self.items.write();
        if items.iter().any(|item| item.addr == addr && item.proto == proto) {
            return false;
        }

        items.push(Arc::new(ProxyItem::new(addr, proto, geo)));
        true
    }

    /// Selects a healthy proxy according to the specified strategy.
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
                        u64::MAX // Unprobed proxies placed at end
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

    /// Returns a list of healthy proxies for multi-hop or retry loops.
    pub fn get_healthy_candidates(&self, max_candidates: usize) -> Vec<Arc<ProxyItem>> {
        let items = self.items.read();
        let mut healthy: Vec<Arc<ProxyItem>> = items
            .iter()
            .filter(|i| i.is_healthy())
            .map(Arc::clone)
            .collect();

        // Sort: lowest latency first, then random order
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

    pub fn total_count(&self) -> usize {
        self.items.read().len()
    }

    pub fn healthy_count(&self) -> usize {
        self.items.read().iter().filter(|i| i.is_healthy()).count()
    }

    pub fn record_failure(&self, item: &ProxyItem) {
        item.record_failure(self.default_cooldown);
    }

    pub fn record_success(&self, item: &ProxyItem, latency: Duration) {
        item.record_success(latency);
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

        // Trip circuit breaker on p1 (3 failures)
        pool.record_failure(&p1);
        pool.record_failure(&p1);
        pool.record_failure(&p1);

        assert!(!p1.is_healthy());
        assert_eq!(pool.healthy_count(), 1);

        // Next selection must yield p2
        let p3 = pool.select(SelectionStrategy::RoundRobin).unwrap();
        assert_eq!(p3.addr, addr2);
    }
}
