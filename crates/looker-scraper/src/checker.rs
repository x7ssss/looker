use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, info};

use crate::extractor::CandidateProxy;
use looker_geo::GeoResolver;
use looker_pool::{AnonymityLevel, CheckedProxy};
use looker_protocol::{
    handshake_socks4, handshake_socks5, ProtocolError, ProxyProto, TargetAddr,
};

/// Resolves direct public IP once at engine startup for leak baselining.
pub async fn resolve_direct_ip() -> Option<IpAddr> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
        .ok()?;

    let endpoints = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://cloudflare.com/cdn-cgi/trace",
    ];

    for ep in endpoints {
        if let Ok(resp) = client.get(ep).send().await {
            if let Ok(text) = resp.text().await {
                if text.contains("ip=") {
                    for line in text.lines() {
                        if let Some(ip_str) = line.strip_prefix("ip=") {
                            if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                                return Some(ip);
                            }
                        }
                    }
                }
                if let Ok(ip) = text.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    None
}

#[derive(Debug, Clone)]
pub struct CheckerConfig {
    pub max_concurrency: usize,
    pub timeout: Duration,
    pub target_authority: String,
}

impl Default for CheckerConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 500,
            timeout: Duration::from_secs(5),
            target_authority: "cloudflare.com:443".to_string(),
        }
    }
}

pub struct ProxyChecker {
    config: CheckerConfig,
    geo_resolver: Arc<GeoResolver>,
    semaphore: Arc<Semaphore>,
    direct_ip: Option<IpAddr>,
}

impl ProxyChecker {
    pub fn new(geo_resolver: Arc<GeoResolver>) -> Self {
        Self::with_config(geo_resolver, CheckerConfig::default(), None)
    }

    pub fn with_config(
        geo_resolver: Arc<GeoResolver>,
        config: CheckerConfig,
        direct_ip: Option<IpAddr>,
    ) -> Self {
        let sem = Arc::new(Semaphore::new(config.max_concurrency));
        Self {
            config,
            geo_resolver,
            semaphore: sem,
            direct_ip,
        }
    }

    pub fn set_direct_ip(&mut self, ip: Option<IpAddr>) {
        self.direct_ip = ip;
    }

    /// Validates a single candidate proxy with bounded timeout and raw socket handshake.
    pub async fn check_candidate(&self, candidate: &CandidateProxy) -> Option<CheckedProxy> {
        let _permit = self.semaphore.acquire().await.ok()?;
        let target = TargetAddr::try_from(self.config.target_authority.as_str()).ok()?;

        let protocols_to_try: Vec<ProxyProto> = match candidate.proto {
            Some(p) => vec![p],
            None => vec![
                ProxyProto::Socks5,
                ProxyProto::HttpConnect,
                ProxyProto::Socks4,
            ],
        };

        for proto in protocols_to_try {
            let t0 = Instant::now();

            let stream_res = tokio::time::timeout(
                self.config.timeout,
                TcpStream::connect(candidate.addr),
            )
            .await;

            let mut stream = match stream_res {
                Ok(Ok(s)) => s,
                _ => continue,
            };

            // Configure socket options
            let _ = stream.set_nodelay(true);
            let sock = SockRef::from(&stream);
            let _ = sock.set_send_buffer_size(16384);
            let _ = sock.set_recv_buffer_size(16384);
            let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
            let _ = sock.set_tcp_keepalive(&keepalive);

            let check_res = match proto {
                ProxyProto::Socks5 => {
                    tokio::time::timeout(
                        self.config.timeout,
                        handshake_socks5(&mut stream, &target),
                    )
                    .await
                    .map(|r| r.map(|_| AnonymityLevel::Elite))
                }
                ProxyProto::Socks4 => {
                    tokio::time::timeout(
                        self.config.timeout,
                        handshake_socks4(&mut stream, &target),
                    )
                    .await
                    .map(|r| r.map(|_| AnonymityLevel::Elite))
                }
                ProxyProto::HttpConnect => {
                    let auth = self.config.target_authority.clone();
                    let dip = self.direct_ip;
                    tokio::time::timeout(
                        self.config.timeout,
                        check_http_connect_anonymity(&mut stream, &auth, dip),
                    )
                    .await
                }
            };

            if let Ok(Ok(anonymity)) = check_res {
                let latency = t0.elapsed();
                let exit_ip = candidate.addr.ip();
                let geo = self.geo_resolver.lookup(exit_ip);
                let geo_opt = if geo.is_empty() { None } else { Some(geo) };

                debug!(
                    "Proxy {} verified via {} in {:?} ({})",
                    candidate.addr, proto, latency, anonymity
                );

                return Some(CheckedProxy {
                    addr: candidate.addr,
                    proto,
                    latency,
                    exit_ip: Some(exit_ip),
                    anonymity,
                    geo: geo_opt,
                });
            }
        }

        None
    }

    /// Concurrently checks all candidates with bounded concurrency (default 500 in-flight sockets).
    pub async fn check_all(&self, candidates: Vec<CandidateProxy>) -> Vec<CheckedProxy> {
        info!(
            "Starting validation pipeline over {} candidates (concurrency limit: {})...",
            candidates.len(),
            self.config.max_concurrency
        );

        let mut tasks = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let checker = Arc::new(self.clone_checker());
            tasks.push(tokio::spawn(async move {
                checker.check_candidate(&candidate).await
            }));
        }

        let mut verified = Vec::new();
        for task in tasks {
            if let Ok(Some(checked)) = task.await {
                verified.push(checked);
            }
        }

        info!("Validation pipeline completed: {} proxies survived", verified.len());
        verified
    }

    fn clone_checker(&self) -> Self {
        Self {
            config: self.config.clone(),
            geo_resolver: Arc::clone(&self.geo_resolver),
            semaphore: Arc::clone(&self.semaphore),
            direct_ip: self.direct_ip,
        }
    }
}

async fn check_http_connect_anonymity<S>(
    stream: &mut S,
    authority: &str,
    direct_ip: Option<IpAddr>,
) -> Result<AnonymityLevel, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Looker/0.1\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut header_bytes = Vec::with_capacity(512);
    let mut one_byte = [0u8; 1];

    loop {
        let n = stream.read(&mut one_byte).await?;
        if n == 0 {
            return Err(ProtocolError::UnexpectedEof);
        }
        header_bytes.push(one_byte[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_bytes.len() >= 4096 {
            return Err(ProtocolError::HeaderTooLarge(header_bytes.len()));
        }
    }

    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|_| ProtocolError::InvalidHttpResponse)?;

    let first_line = header_str
        .lines()
        .next()
        .ok_or(ProtocolError::InvalidHttpResponse)?;

    let mut parts = first_line.split_whitespace();
    let _version = parts.next().ok_or(ProtocolError::InvalidHttpResponse)?;
    let status_str = parts.next().ok_or(ProtocolError::InvalidHttpResponse)?;
    let status = status_str
        .parse::<u16>()
        .map_err(|_| ProtocolError::InvalidHttpResponse)?;

    if !(200..300).contains(&status) {
        let reason = parts.collect::<Vec<&str>>().join(" ");
        return Err(ProtocolError::HttpConnectRejected { status, reason });
    }

    // Inspect headers for anonymity
    let lower_headers = header_str.to_ascii_lowercase();

    // 1. Transparent: direct IP leaked in headers
    if let Some(dip) = direct_ip {
        if lower_headers.contains(&dip.to_string()) {
            return Ok(AnonymityLevel::Transparent);
        }
    }

    // 2. Anonymous: proxy markers present
    if lower_headers.contains("via:")
        || lower_headers.contains("x-forwarded-for:")
        || lower_headers.contains("forwarded:")
        || lower_headers.contains("x-proxy-id:")
    {
        return Ok(AnonymityLevel::Anonymous);
    }

    // 3. Elite
    Ok(AnonymityLevel::Elite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_anonymity_detection_elite_and_transparent() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let n = server.read(&mut buf).await.unwrap();
            let _ = &buf[..n];
            // Mock elite reply
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });

        let direct_ip: Option<IpAddr> = Some("1.2.3.4".parse().unwrap());
        let res = check_http_connect_anonymity(&mut client, "test.local:443", direct_ip).await;
        assert_eq!(res.unwrap(), AnonymityLevel::Elite);

        // Test transparent reply with IP leak
        let (mut client2, mut server2) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server2.read(&mut buf).await.unwrap();
            server2
                .write_all(b"HTTP/1.1 200 OK\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n")
                .await
                .unwrap();
        });

        let res2 = check_http_connect_anonymity(&mut client2, "test.local:443", direct_ip).await;
        assert_eq!(res2.unwrap(), AnonymityLevel::Transparent);
    }
}
