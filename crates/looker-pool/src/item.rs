use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use looker_geo::GeoInfo;
use looker_protocol::ProxyProto;

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[derive(Debug)]
pub struct ProxyItem {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
    pub latency_ms: AtomicU64,
    pub consecutive_failures: AtomicU32,
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub circuit_open_until_epoch_ms: AtomicU64,
    pub geo: Option<GeoInfo>,
    pub created_at: Instant,
}

impl ProxyItem {
    pub fn new(addr: SocketAddr, proto: ProxyProto, geo: Option<GeoInfo>) -> Self {
        Self {
            addr,
            proto,
            latency_ms: AtomicU64::new(0),
            consecutive_failures: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            circuit_open_until_epoch_ms: AtomicU64::new(0),
            geo,
            created_at: Instant::now(),
        }
    }

    /// Checks if the proxy is healthy and its circuit breaker is currently closed.
    pub fn is_healthy(&self) -> bool {
        let open_until = self.circuit_open_until_epoch_ms.load(Ordering::Relaxed);
        let now = current_epoch_ms();
        if now < open_until {
            return false;
        }

        self.consecutive_failures.load(Ordering::Relaxed) < 3
    }

    /// Records a successful connection and updates exponential moving average (EMA) latency.
    pub fn record_success(&self, latency: Duration) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        let sample_ms = latency.as_millis() as u64;
        let old_ms = self.latency_ms.load(Ordering::Relaxed);
        let new_ms = if old_ms == 0 {
            sample_ms
        } else {
            // EMA: (old * 3 + sample) / 4
            (old_ms * 3 + sample_ms) / 4
        };
        self.latency_ms.store(new_ms, Ordering::Relaxed);
    }

    /// Records a connection failure. Trips circuit breaker if failure threshold is reached.
    pub fn record_failure(&self, cooldown: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        if fails >= 3 {
            let until = current_epoch_ms() + (cooldown.as_millis() as u64);
            self.circuit_open_until_epoch_ms
                .store(until, Ordering::Relaxed);
        }
    }

    pub fn latency(&self) -> Option<Duration> {
        let ms = self.latency_ms.load(Ordering::Relaxed);
        if ms > 0 {
            Some(Duration::from_millis(ms))
        } else {
            None
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 1.0;
        }
        let success = self.successful_requests.load(Ordering::Relaxed);
        (success as f64) / (total as f64)
    }
}
