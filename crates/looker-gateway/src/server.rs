use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::error::GatewayError;
use looker_pool::ProxyPool;
use looker_protocol::{
    handshake_http_connect, handshake_socks4, handshake_socks5, ProxyProto, TargetAddr,
};

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub bind_addr: SocketAddr,
    pub max_retries: usize,
    pub connect_timeout: Duration,
    pub buffer_size: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:8080".parse().unwrap(),
            max_retries: 4,
            connect_timeout: Duration::from_secs(6),
            buffer_size: 16384, // 16 KiB
        }
    }
}

pub struct ProxyGateway {
    config: GatewayConfig,
    pool: Arc<ProxyPool>,
}

impl ProxyGateway {
    pub fn new(config: GatewayConfig, pool: Arc<ProxyPool>) -> Self {
        Self { config, pool }
    }

    /// Launches the gateway server loop listening on `config.bind_addr`.
    pub async fn run(&self) -> Result<(), GatewayError> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("Looker proxy gateway listening on http://{}", local_addr);
        self.run_on_listener(listener).await
    }

    /// Runs the gateway accept loop on an already bound TcpListener.
    pub async fn run_on_listener(&self, listener: TcpListener) -> Result<(), GatewayError> {
        loop {
            let (client_stream, client_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!("Error accepting incoming connection: {}", e);
                    continue;
                }
            };

            let pool = Arc::clone(&self.pool);
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_client(client_stream, client_addr, pool, config).await {
                    debug!("Client {} finished with error: {}", client_addr, e);
                }
            });
        }
    }
}

pub fn configure_tcp_socket(stream: &TcpStream, buf_size: usize) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_send_buffer_size(buf_size);
    let _ = sock.set_recv_buffer_size(buf_size);
    let keepalive = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = sock.set_tcp_keepalive(&keepalive);
}

async fn handle_client(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    pool: Arc<ProxyPool>,
    config: GatewayConfig,
) -> Result<(), GatewayError> {
    configure_tcp_socket(&client_stream, config.buffer_size);

    // Read incoming HTTP request line & headers (until \r\n\r\n)
    let mut header_buf = Vec::with_capacity(512);
    let mut byte_buf = [0u8; 1];

    loop {
        let n = client_stream.read(&mut byte_buf).await?;
        if n == 0 {
            return Ok(());
        }
        header_buf.push(byte_buf[0]);
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 8192 {
            return Err(GatewayError::InvalidConnectRequest);
        }
    }

    let header_str = std::str::from_utf8(&header_buf)
        .map_err(|_| GatewayError::InvalidConnectRequest)?;

    let first_line = header_str
        .lines()
        .next()
        .ok_or(GatewayError::InvalidConnectRequest)?;

    let mut parts = first_line.split_whitespace();
    let method = parts.next().ok_or(GatewayError::InvalidConnectRequest)?;
    let path_or_target = parts.next().ok_or(GatewayError::InvalidConnectRequest)?;

    // Route 1: Local Live Proxy Feed (GET /live.txt)
    if method.eq_ignore_ascii_case("GET") && path_or_target == "/live.txt" {
        let text_feed = pool.export_live_text();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            text_feed.len(),
            text_feed
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 2: Local Status Endpoint (GET /status)
    if method.eq_ignore_ascii_case("GET") && path_or_target == "/status" {
        let stats = pool.stats();
        let json_body = serde_json::to_string_pretty(&stats).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 3: Transparent HTTP CONNECT Tunnel
    if !method.eq_ignore_ascii_case("CONNECT") {
        let response = b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT, GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = client_stream.write_all(response).await;
        return Err(GatewayError::InvalidConnectRequest);
    }

    let target = TargetAddr::try_from(path_or_target)
        .map_err(|_| GatewayError::InvalidConnectRequest)?;

    debug!("Client {} requested tunnel to {}", client_addr, target);

    // INVARIANT 2: Pre-Commit Retry Rule
    // Select candidates and attempt upstream connection BEFORE sending HTTP 200 OK.
    let candidates = pool.get_healthy_candidates(config.max_retries.max(1));
    if candidates.is_empty() {
        warn!("No healthy proxies available in pool to service request to {}", target);
        let _ = client_stream
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err(GatewayError::NoProxies);
    }

    let mut upstream_opt = None;

    for candidate in &candidates {
        let t0 = Instant::now();
        debug!(
            "Attempting upstream connection via {} ({}) to {}",
            candidate.addr, candidate.proto, target
        );

        let connect_fut = TcpStream::connect(candidate.addr);
        let mut upstream = match tokio::time::timeout(config.connect_timeout, connect_fut).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!("Failed to connect to proxy {}: {}", candidate.addr, e);
                pool.record_failure(candidate);
                continue;
            }
            Err(_) => {
                debug!("Timeout connecting to proxy {}", candidate.addr);
                pool.record_failure(candidate);
                continue;
            }
        };

        configure_tcp_socket(&upstream, config.buffer_size);

        // Perform protocol handshake
        let handshake_res = match candidate.proto {
            ProxyProto::Socks5 => {
                tokio::time::timeout(
                    config.connect_timeout,
                    handshake_socks5(&mut upstream, &target),
                )
                .await
            }
            ProxyProto::Socks4 => {
                tokio::time::timeout(
                    config.connect_timeout,
                    handshake_socks4(&mut upstream, &target),
                )
                .await
            }
            ProxyProto::HttpConnect => {
                let authority = target.to_authority();
                tokio::time::timeout(
                    config.connect_timeout,
                    handshake_http_connect(&mut upstream, &authority),
                )
                .await
            }
        };

        match handshake_res {
            Ok(Ok(())) => {
                pool.record_success(candidate, t0.elapsed());
                upstream_opt = Some(upstream);
                break;
            }
            Ok(Err(e)) => {
                debug!("Handshake failed via proxy {}: {}", candidate.addr, e);
                pool.record_failure(candidate);
            }
            Err(_) => {
                debug!("Handshake timeout via proxy {}", candidate.addr);
                pool.record_failure(candidate);
            }
        }
    }

    let mut upstream_stream = match upstream_opt {
        Some(stream) => stream,
        None => {
            warn!("All {} proxy attempts failed for target {}", candidates.len(), target);
            let _ = client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(GatewayError::AllRetriesFailed(candidates.len()));
        }
    };

    // Upstream handshake succeeded! Commit 200 Connection Established to client.
    client_stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Looker/0.1\r\n\r\n")
        .await?;
    client_stream.flush().await?;

    // The tunnel is now committed and becomes an opaque bidirectional pipe.
    let (from_client, from_upstream) =
        tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await?;

    debug!(
        "Tunnel closed for {}: client sent {} bytes, upstream sent {} bytes",
        target, from_client, from_upstream
    );

    Ok(())
}
