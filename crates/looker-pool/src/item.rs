use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use looker_geo::GeoInfo;
use looker_protocol::ProxyProto;

fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum AnonymityLevel {
    #[serde(rename = "transparent")]
    Transparent,
    #[serde(rename = "anonymous")]
    Anonymous,
    #[serde(rename = "elite")]
    Elite,
}

impl Default for AnonymityLevel {
    fn default() -> Self {
        AnonymityLevel::Elite
    }
}

impl AnonymityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnonymityLevel::Transparent => "transparent",
            AnonymityLevel::Anonymous => "anonymous",
            AnonymityLevel::Elite => "elite",
        }
    }
}

impl std::fmt::Display for AnonymityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckedProxy {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
    pub latency: Duration,
    pub exit_ip: Option<IpAddr>,
    pub anonymity: AnonymityLevel,
    pub geo: Option<GeoInfo>,
}

impl CheckedProxy {
    pub fn to_url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
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
    pub healthy: AtomicBool,
    pub anonymity: AnonymityLevel,
    pub exit_ip: Option<IpAddr>,
    pub geo: Option<GeoInfo>,
    pub created_at: Instant,
}

impl ProxyItem {
    pub fn new(
        addr: SocketAddr,
        proto: ProxyProto,
        latency: Duration,
        anonymity: AnonymityLevel,
        exit_ip: Option<IpAddr>,
        geo: Option<GeoInfo>,
    ) -> Self {
        Self {
            addr,
            proto,
            latency_ms: AtomicU64::new(latency.as_millis() as u64),
            consecutive_failures: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            circuit_open_until_epoch_ms: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            anonymity,
            exit_ip,
            geo,
            created_at: Instant::now(),
        }
    }

    /// Checks if the proxy is healthy and its circuit breaker is currently closed.
    pub fn is_healthy(&self) -> bool {
        if !self.healthy.load(Ordering::Acquire) {
            return false;
        }

        let open_until = self.circuit_open_until_epoch_ms.load(Ordering::Relaxed);
        let now = current_epoch_ms();
        if now < open_until {
            return false;
        }

        self.consecutive_failures.load(Ordering::Relaxed) < 2
    }

    /// Records a successful connection and updates exponential moving average (EMA) latency.
    pub fn record_success(&self, latency: Duration) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Release);

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

    /// Records a connection failure. If errors >= 2, marks healthy = false and trips circuit breaker.
    /// Returns true if proxy was quarantined by this failure.
    pub fn record_failure(&self, cooldown: Duration) -> bool {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;

        if fails >= 2 {
            self.healthy.store(false, Ordering::Release);
            let until = current_epoch_ms() + (cooldown.as_millis() as u64);
            self.circuit_open_until_epoch_ms
                .store(until, Ordering::Relaxed);
            true
        } else {
            false
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

    pub fn to_url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
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
