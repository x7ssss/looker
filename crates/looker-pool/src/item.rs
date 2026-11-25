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

pub const SLOW_PROXY_THRESHOLD_BPS: u64 = 50 * 1024; // 50 KB/s crawl threshold
pub const MIN_THROUGHPUT_SAMPLE_BYTES: u64 = 16 * 1024; // Ignore tiny handshake probes when detecting crawlers

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckedProxy {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
    pub latency: Duration,
    pub exit_ip: Option<IpAddr>,
    pub anonymity: AnonymityLevel,
    pub geo: Option<GeoInfo>,
    #[serde(default)]
    pub throughput_bps: u64,
}

impl CheckedProxy {
    pub fn to_url(&self) -> String {
        format!("{}://{}", self.proto, self.addr)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProxySnapshot {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
    pub latency_ms: u64,
    pub healthy: bool,
    pub consecutive_failures: u32,
    pub total_failures: u32,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub anonymity: AnonymityLevel,
    pub exit_ip: Option<IpAddr>,
    pub geo: Option<GeoInfo>,
    #[serde(default)]
    pub mega_cooldown: bool,
    #[serde(default)]
    pub throughput_bps: u64,
    #[serde(default)]
    pub slow_strikes: u32,
}

#[derive(Debug)]
pub struct ProxyItem {
    pub addr: SocketAddr,
    pub proto: ProxyProto,
    pub latency_ms: AtomicU64,
    pub throughput_bps: AtomicU64,
    pub slow_strikes: AtomicU32,
    pub consecutive_failures: AtomicU32,
    pub total_failures: AtomicU32,
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub circuit_open_until_epoch_ms: AtomicU64,
    pub healthy: AtomicBool,
    pub anonymity: AnonymityLevel,
    pub exit_ip: Option<IpAddr>,
    pub geo: Option<GeoInfo>,
    pub created_at: Instant,
    pub mega_cooldown_until: parking_lot::RwLock<Option<Instant>>,
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
            throughput_bps: AtomicU64::new(0),
            slow_strikes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            total_failures: AtomicU32::new(0),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            circuit_open_until_epoch_ms: AtomicU64::new(0),
            healthy: AtomicBool::new(true),
            anonymity,
            exit_ip,
            geo,
            created_at: Instant::now(),
            mega_cooldown_until: parking_lot::RwLock::new(None),
        }
    }

    pub fn new_validated(
        addr: SocketAddr,
        proto: ProxyProto,
        latency: Duration,
        throughput_bps: u64,
        anonymity: AnonymityLevel,
        exit_ip: Option<IpAddr>,
        geo: Option<GeoInfo>,
    ) -> Self {
        let item = Self::new(addr, proto, latency, anonymity, exit_ip, geo);
        item.throughput_bps.store(throughput_bps, Ordering::Relaxed);
        item.total_requests.store(1, Ordering::Relaxed);
        item.successful_requests.store(1, Ordering::Relaxed);
        item
    }

    /// Checks if this proxy is currently under MEGA 509 quota cooldown.
    pub fn is_mega_cooldown(&self) -> bool {
        let lock = self.mega_cooldown_until.read();
        if let Some(until) = *lock {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Marks the proxy on MEGA 509 cooldown for duration clamped between 10s and 3600s.
    /// Does NOT evict the proxy from general HTTP/SOCKS routing or trip the circuit breaker.
    pub fn mark_mega_509_cooldown(&self, cooldown: Duration) {
        let clamped_secs = cooldown.as_secs().clamp(10, 3600);
        let until = Instant::now() + Duration::from_secs(clamped_secs);
        let mut lock = self.mega_cooldown_until.write();
        *lock = Some(until);
    }

    /// Clears any active MEGA cooldown.
    pub fn clear_mega_cooldown(&self) {
        let mut lock = self.mega_cooldown_until.write();
        *lock = None;
    }

    /// Returns remaining seconds of MEGA cooldown if active.
    pub fn mega_cooldown_remaining_secs(&self) -> Option<u64> {
        let lock = self.mega_cooldown_until.read();
        if let Some(until) = *lock {
            let now = Instant::now();
            if until > now {
                Some((until - now).as_secs())
            } else {
                None
            }
        } else {
            None
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

    /// Records observed payload throughput and updates moving-average throughput (B/s).
    /// Returns `true` if the transfer crawled under `SLOW_PROXY_THRESHOLD_BPS` (50 KB/s) and
    /// caused the proxy to be aggressively cooled down / benched.
    pub fn record_throughput(&self, bytes: u64, elapsed: Duration, slow_cooldown: Duration) -> bool {
        if bytes == 0 {
            return false;
        }
        let secs = elapsed.as_secs_f64().max(0.001);
        let sample_bps = (bytes as f64 / secs) as u64;
        let old_bps = self.throughput_bps.load(Ordering::Relaxed);
        let new_bps = if old_bps == 0 {
            sample_bps
        } else {
            (old_bps * 3 + sample_bps) / 4
        };
        self.throughput_bps.store(new_bps, Ordering::Relaxed);

        if bytes >= MIN_THROUGHPUT_SAMPLE_BYTES && sample_bps < SLOW_PROXY_THRESHOLD_BPS {
            let strikes = self.slow_strikes.fetch_add(1, Ordering::Relaxed) + 1;
            self.mark_mega_509_cooldown(slow_cooldown);
            // Bench slow crawlers from active selection via circuit-breaker cooldown
            let cooldown_ms = slow_cooldown.as_millis().max(30_000) as u64;
            let until = current_epoch_ms() + cooldown_ms;
            self.circuit_open_until_epoch_ms.store(until, Ordering::Relaxed);
            if strikes >= 2 {
                self.healthy.store(false, Ordering::Release);
            }
            return true;
        }

        self.slow_strikes.store(0, Ordering::Relaxed);
        false
    }

    /// Records a successful chunk transfer (latency + throughput) and benches slow crawlers.
    pub fn record_transfer_success(
        &self,
        latency: Duration,
        bytes: u64,
        elapsed: Duration,
        slow_cooldown: Duration,
    ) -> bool {
        self.record_success(latency);
        self.record_throughput(bytes, elapsed, slow_cooldown)
    }

    /// Records a connection failure. If consecutive errors >= 2, marks healthy = false and trips circuit breaker.
    /// Returns (quarantined, total_failures).
    pub fn record_failure(&self, cooldown: Duration) -> (bool, u32) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let fails = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        let total = self.total_failures.fetch_add(1, Ordering::SeqCst) + 1;

        let quarantined = if fails >= 2 {
            self.healthy.store(false, Ordering::Release);
            let until = current_epoch_ms() + (cooldown.as_millis() as u64);
            self.circuit_open_until_epoch_ms
                .store(until, Ordering::Relaxed);
            true
        } else {
            false
        };
        (quarantined, total)
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

    pub fn success_rate_pct(&self) -> u8 {
        let total = self.total_requests.load(Ordering::Relaxed);
        if total == 0 {
            return 0;
        }
        let success = self.successful_requests.load(Ordering::Relaxed);
        ((success as f64 / total as f64) * 100.0).round().clamp(0.0, 100.0) as u8
    }

    pub fn throughput_kbps(&self) -> f64 {
        (self.throughput_bps.load(Ordering::Relaxed) as f64) / 1024.0
    }

    /// Composite selection score prioritizing proven high success rate and real throughput
    /// alongside low latency, while heavily penalizing failing or < 50 KB/s crawling nodes.
    pub fn composite_score(&self) -> f64 {
        let total = self.total_requests.load(Ordering::Relaxed);
        let succ = self.successful_requests.load(Ordering::Relaxed);
        let consec_fail = self.consecutive_failures.load(Ordering::Relaxed);
        let slow_strikes = self.slow_strikes.load(Ordering::Relaxed);
        let ms = self.latency_ms.load(Ordering::Relaxed);
        let bps = self.throughput_bps.load(Ordering::Relaxed);

        let rate = if total == 0 {
            0.50
        } else {
            (succ as f64 + 1.0) / (total as f64 + 2.0)
        };

        let latency_factor = if ms == 0 {
            0.35
        } else {
            1000.0 / (ms as f64 + 250.0)
        };

        let throughput_factor = if bps == 0 {
            0.90
        } else {
            let kbps = bps as f64 / 1024.0;
            if kbps < 50.0 {
                0.05
            } else {
                (kbps / 100.0).ln_1p().clamp(0.25, 5.0)
            }
        };

        let consec_penalty = if consec_fail > 0 { 0.45 } else { 1.0 };
        let slow_penalty = if slow_strikes > 0 || (bps > 0 && bps < SLOW_PROXY_THRESHOLD_BPS) {
            0.10
        } else {
            1.0
        };

        (rate * rate) * (0.40 * latency_factor + 0.60 * throughput_factor) * consec_penalty * slow_penalty
    }

    pub fn snapshot(&self) -> ProxySnapshot {
        ProxySnapshot {
            addr: self.addr,
            proto: self.proto,
            latency_ms: self.latency_ms.load(Ordering::Relaxed),
            healthy: self.is_healthy(),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            anonymity: self.anonymity,
            exit_ip: self.exit_ip,
            geo: self.geo.clone(),
            mega_cooldown: self.is_mega_cooldown(),
            throughput_bps: self.throughput_bps.load(Ordering::Relaxed),
            slow_strikes: self.slow_strikes.load(Ordering::Relaxed),
        }
    }

    pub fn to_checked(&self) -> CheckedProxy {
        CheckedProxy {
            addr: self.addr,
            proto: self.proto,
            latency: Duration::from_millis(self.latency_ms.load(Ordering::Relaxed)),
            exit_ip: self.exit_ip,
            anonymity: self.anonymity,
            geo: self.geo.clone(),
            throughput_bps: self.throughput_bps.load(Ordering::Relaxed),
        }
    }
}
