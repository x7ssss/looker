use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::download::DownloadManager;
use crate::error::GatewayError;
use looker_pool::ProxyPool;
use looker_protocol::{
    handshake_http_connect, handshake_socks4, handshake_socks5, ProxyProto, TargetAddr,
};

#[derive(rust_embed::RustEmbed)]
#[folder = "ui/dist"]
struct Asset;

fn mime_type_for(path: &str) -> &'static str {
    if path.ends_with(".html") || path.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else if path.ends_with(".txt") {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

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
    download_mgr: Arc<DownloadManager>,
}

impl ProxyGateway {
    pub fn new(mut config: GatewayConfig, pool: Arc<ProxyPool>) -> Self {
        // Enforce strict 127.0.0.1 binding (never bind to 0.0.0.0 or external interfaces)
        if !config.bind_addr.ip().is_loopback() {
            warn!(
                "Configured gateway bind address {} is not loopback. Enforcing strict 127.0.0.1 binding.",
                config.bind_addr
            );
            config.bind_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        }
        let download_mgr = Arc::new(DownloadManager::new(
            config.bind_addr.to_string(),
            Arc::clone(&pool),
        ));
        Self {
            config,
            pool,
            download_mgr,
        }
    }

    pub fn with_download_manager(mut self, mgr: Arc<DownloadManager>) -> Self {
        self.download_mgr = mgr;
        self
    }

    pub fn download_manager(&self) -> Arc<DownloadManager> {
        Arc::clone(&self.download_mgr)
    }

    /// Launches the gateway server loop listening on `config.bind_addr`.
    pub async fn run(&self) -> Result<(), GatewayError> {
        self.run_with_cancellation(tokio_util::sync::CancellationToken::new()).await
    }

    /// Launches the gateway server loop listening on `config.bind_addr` with cancellation support.
    pub async fn run_with_cancellation(
        &self,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<(), GatewayError> {
        let mut bind_addr = self.config.bind_addr;
        if !bind_addr.ip().is_loopback() {
            warn!(
                "Configured gateway bind address {} is not loopback. Enforcing strict 127.0.0.1 binding.",
                bind_addr
            );
            bind_addr.set_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
        }
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        info!("Looker proxy gateway listening on http://{}", local_addr);
        self.run_on_listener_with_cancellation(listener, cancel_token).await
    }

    /// Runs the gateway accept loop on an already bound TcpListener.
    pub async fn run_on_listener(&self, listener: TcpListener) -> Result<(), GatewayError> {
        self.run_on_listener_with_cancellation(listener, tokio_util::sync::CancellationToken::new()).await
    }

    /// Runs the gateway accept loop on an already bound TcpListener with cancellation and in-flight tracking.
    pub async fn run_on_listener_with_cancellation(
        &self,
        listener: TcpListener,
        cancel_token: tokio_util::sync::CancellationToken,
    ) -> Result<(), GatewayError> {
        let local_addr = listener.local_addr()?;
        if !local_addr.ip().is_loopback() {
            return Err(GatewayError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Gateway listener rejected non-loopback bind address {}", local_addr),
            )));
        }
        let tracker = tokio_util::task::TaskTracker::new();

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => {
                    info!("Gateway listener received shutdown signal, stopping accept loop...");
                    break;
                }
                res = listener.accept() => {
                    let (client_stream, client_addr) = match res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Error accepting incoming connection: {}", e);
                            continue;
                        }
                    };

                    let pool = Arc::clone(&self.pool);
                    let config = self.config.clone();
                    let download_mgr = Arc::clone(&self.download_mgr);

                    tracker.spawn(async move {
                        if let Err(e) = handle_client(client_stream, client_addr, pool, config, download_mgr).await {
                            debug!("Client {} finished with error: {}", client_addr, e);
                        }
                    });
                }
            }
        }

        // Close tracker to disallow new connections
        tracker.close();

        // Allow active in-flight proxy gateway tunnels a 3-second grace window before hard aborting
        info!("Waiting up to 3 seconds for active in-flight gateway tunnels to finish...");
        let _ = tokio::time::timeout(Duration::from_secs(3), tracker.wait()).await;
        info!("Gateway graceful shutdown completed.");

        Ok(())
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

/// Checks whether an Origin header is permitted to access local /api/* endpoints.
/// Strictly permits only missing origin, loopback variants (127.0.0.1, localhost), or Tauri shell.
pub fn is_allowed_origin(origin: &str, bound_addr: Option<SocketAddr>) -> bool {
    let clean = origin.trim().trim_end_matches('/');
    if clean.eq_ignore_ascii_case("http://127.0.0.1:8080")
        || clean.eq_ignore_ascii_case("http://localhost:8080")
        || clean.eq_ignore_ascii_case("tauri://localhost")
    {
        return true;
    }
    if let Some(addr) = bound_addr {
        if clean.eq_ignore_ascii_case(&format!("http://{}", addr))
            || clean.eq_ignore_ascii_case(&format!("http://127.0.0.1:{}", addr.port()))
            || clean.eq_ignore_ascii_case(&format!("http://localhost:{}", addr.port()))
        {
            return true;
        }
    }
    false
}

/// Checks whether a Referer header is permitted to access local /api/* endpoints.
pub fn is_allowed_referer(referer: &str, bound_addr: Option<SocketAddr>) -> bool {
    let clean = referer.trim();
    if clean.starts_with("http://127.0.0.1:8080")
        || clean.starts_with("http://localhost:8080")
        || clean.starts_with("tauri://localhost")
    {
        return true;
    }
    if let Some(addr) = bound_addr {
        if clean.starts_with(&format!("http://{}", addr))
            || clean.starts_with(&format!("http://127.0.0.1:{}", addr.port()))
            || clean.starts_with(&format!("http://localhost:{}", addr.port()))
        {
            return true;
        }
    }
    false
}

async fn handle_client(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    pool: Arc<ProxyPool>,
    config: GatewayConfig,
    download_mgr: Arc<DownloadManager>,
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

    let (req_path, req_query) = match path_or_target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_or_target, None),
    };

    let local_addr = client_stream.local_addr().ok();

    // CSRF & Cross-Origin Middleware Guard:
    // Reject any request to /api/* that has an external Origin or Referer header.
    // Prevents malicious third-party websites from executing local commands or accessing settings.
    if req_path.starts_with("/api/") {
        let mut external_origin_or_referer = false;
        for line in header_str.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("origin:") {
                let trimmed = val.trim();
                if !trimmed.is_empty() && !is_allowed_origin(trimmed, local_addr) {
                    external_origin_or_referer = true;
                    break;
                }
            } else if let Some(val) = lower.strip_prefix("referer:") {
                let trimmed = val.trim();
                if !trimmed.is_empty() && !is_allowed_referer(trimmed, local_addr) {
                    external_origin_or_referer = true;
                    break;
                }
            }
        }

        if external_origin_or_referer {
            warn!(
                "Rejected cross-origin request to '{}' with external Origin/Referer header",
                req_path
            );
            let resp = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: null\r\nConnection: close\r\n\r\n{\"error\":\"Forbidden: External cross-origin request rejected\"}";
            client_stream.write_all(resp.as_bytes()).await?;
            client_stream.flush().await?;
            return Ok(());
        }
    }

    // Handle CORS preflight
    if method.eq_ignore_ascii_case("OPTIONS") {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n";
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Read body if Content-Length present (for POST requests)
    let mut body = Vec::new();
    if method.eq_ignore_ascii_case("POST") {
        let mut content_length = 0;
        for line in header_str.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("content-length:") {
                content_length = val.trim().parse::<usize>().unwrap_or(0);
                break;
            }
        }
        if content_length > 0 {
            if content_length > 10 * 1024 * 1024 {
                return Err(GatewayError::InvalidConnectRequest);
            }
            body.resize(content_length, 0);
            client_stream.read_exact(&mut body).await?;
        }
    }

    // Route 1: Local Live Proxy Feeds (GET /all.txt, GET /live.txt, GET /http.txt, GET /socks4.txt, GET /socks5.txt)
    if method.eq_ignore_ascii_case("GET") && (req_path == "/all.txt" || req_path == "/live.txt") {
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

    if method.eq_ignore_ascii_case("GET") && req_path == "/http.txt" {
        let text_feed = pool.export_by_proto(ProxyProto::HttpConnect);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            text_feed.len(),
            text_feed
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("GET") && req_path == "/socks4.txt" {
        let text_feed = pool.export_by_proto(ProxyProto::Socks4);
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            text_feed.len(),
            text_feed
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("GET") && req_path == "/socks5.txt" {
        let text_feed = pool.export_by_proto(ProxyProto::Socks5);
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
    if method.eq_ignore_ascii_case("GET") && req_path == "/status" {
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

    // Route 3: Detailed Live Scraper & Pool Status API (GET /api/status)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/status" {
        let api_status = pool.api_status();
        let json_body = serde_json::to_string(&api_status).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 4: Real-time Top-10 Fastest Nodes (GET /api/fastest)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/fastest" {
        let fastest = pool.api_fastest(10);
        let json_body = serde_json::to_string(&fastest).unwrap_or_else(|_| "[]".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5: Healthy Proxies Snapshot API (GET /api/proxies, supports ?limit=N and ?proto=socks5|socks4|http|all)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/proxies" {
        let mut limit = None;
        let mut proto_filter = None;

        if let Some(q) = req_query {
            for param in q.split('&') {
                if let Some(val) = param.strip_prefix("limit=") {
                    limit = val.parse::<usize>().ok();
                } else if let Some(val) = param.strip_prefix("proto=") {
                    let val_lower = val.to_ascii_lowercase();
                    match val_lower.as_str() {
                        "socks5" | "socks5h" => proto_filter = Some(ProxyProto::Socks5),
                        "socks4" | "socks4a" => proto_filter = Some(ProxyProto::Socks4),
                        "http" | "https" | "httpconnect" | "connect" => {
                            proto_filter = Some(ProxyProto::HttpConnect)
                        }
                        _ => {} // "all" or unrecognized => None
                    }
                }
            }
        }
        let proxies = pool.api_proxies(proto_filter, limit);
        let json_body = serde_json::to_string(&proxies).unwrap_or_else(|_| "[]".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5-import: Manual Proxy Import API (POST /api/proxies/import)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/proxies/import" {
        #[derive(serde::Deserialize)]
        struct ImportReq {
            proxies: Vec<String>,
        }

        let resp_str = match serde_json::from_slice::<ImportReq>(&body) {
            Ok(req) => {
                let mut count = 0;
                for line in req.proxies {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let (proto, addr_str) = if let Some(rest) = trimmed.strip_prefix("socks5://") {
                        (ProxyProto::Socks5, rest)
                    } else if let Some(rest) = trimmed.strip_prefix("socks4://") {
                        (ProxyProto::Socks4, rest)
                    } else if let Some(rest) = trimmed.strip_prefix("http://") {
                        (ProxyProto::HttpConnect, rest)
                    } else if let Some(rest) = trimmed.strip_prefix("https://") {
                        (ProxyProto::HttpConnect, rest)
                    } else {
                        (ProxyProto::Socks5, trimmed)
                    };
                    if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                        if pool.add(addr, proto, None) {
                            count += 1;
                        }
                    }
                }
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"imported\":{}}}",
                    count
                )
            }
            Err(e) => format!(
                "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{{\"error\":\"{}\"}}",
                e
            ),
        };
        client_stream.write_all(resp_str.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5a: MEGA URL Inspection API (POST /api/mega/inspect)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/inspect" {
        #[derive(serde::Deserialize)]
        struct InspectReq {
            url: String,
        }

        let resp_str = match serde_json::from_slice::<InspectReq>(&body) {
            Ok(req) => match download_mgr.inspect(&req.url).await {
                Ok(res) => {
                    let json = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(),
                        json
                    )
                }
                Err(err) => {
                    let err_json = serde_json::json!({ "error": err }).to_string();
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        err_json.len(),
                        err_json
                    )
                }
            },
            Err(e) => {
                let err_json = serde_json::json!({ "error": format!("Invalid JSON request: {}", e) }).to_string();
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                )
            }
        };

        client_stream.write_all(resp_str.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5b: MEGA Asynchronous Download Task API (POST /api/mega/download)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/download" {
        let resp_str = match serde_json::from_slice::<crate::download::DownloadRequest>(&body) {
            Ok(req) => match download_mgr.start_download(req).await {
                Ok(task_id) => {
                    let json = serde_json::json!({ "task_id": task_id, "status": "started" }).to_string();
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        json.len(),
                        json
                    )
                }
                Err(err) => {
                    let err_json = serde_json::json!({ "error": err }).to_string();
                    format!(
                        "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        err_json.len(),
                        err_json
                    )
                }
            },
            Err(e) => {
                let err_json = serde_json::json!({ "error": format!("Invalid JSON request: {}", e) }).to_string();
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                )
            }
        };

        client_stream.write_all(resp_str.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5c: MEGA Active Download Tasks Status API (GET /api/mega/tasks)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/mega/tasks" {
        let tasks = download_mgr.list_tasks().await;
        let json_body = serde_json::to_string(&tasks).unwrap_or_else(|_| "[]".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json_body.len(),
            json_body
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5c-1: Pause All MEGA Download Tasks (POST /api/mega/tasks/pause-all)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/tasks/pause-all" {
        let paused = download_mgr.pause_all_tasks().await;
        let json = serde_json::json!({ "success": true, "paused": paused }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5c-2: Resume All MEGA Download Tasks (POST /api/mega/tasks/resume-all)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/tasks/resume-all" {
        let resumed = download_mgr.resume_all_tasks().await;
        let json = serde_json::json!({ "success": true, "resumed": resumed }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5c-3: Clear Completed MEGA Download Tasks (POST /api/mega/tasks/clear-completed)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/tasks/clear-completed" {
        let cleared = download_mgr.clear_completed_tasks().await;
        let json = serde_json::json!({ "success": true, "cleared": cleared }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d: Cancel MEGA Download Task API (POST /api/mega/tasks/:id/cancel)
    if method.eq_ignore_ascii_case("POST")
        && req_path.starts_with("/api/mega/tasks/")
        && req_path.ends_with("/cancel")
    {
        let task_id = req_path
            .strip_prefix("/api/mega/tasks/")
            .and_then(|s| s.strip_suffix("/cancel"))
            .unwrap_or("");

        let success = download_mgr.cancel_task(task_id).await;
        let json = serde_json::json!({ "success": success }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d-2: Pause MEGA Download Task API (POST /api/mega/tasks/:id/pause)
    if method.eq_ignore_ascii_case("POST")
        && req_path.starts_with("/api/mega/tasks/")
        && req_path.ends_with("/pause")
    {
        let task_id = req_path
            .strip_prefix("/api/mega/tasks/")
            .and_then(|s| s.strip_suffix("/pause"))
            .unwrap_or("");

        let success = download_mgr.pause_task(task_id).await;
        let json = serde_json::json!({ "success": success }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d-3: Resume MEGA Download Task API (POST /api/mega/tasks/:id/resume)
    if method.eq_ignore_ascii_case("POST")
        && req_path.starts_with("/api/mega/tasks/")
        && req_path.ends_with("/resume")
    {
        let task_id = req_path
            .strip_prefix("/api/mega/tasks/")
            .and_then(|s| s.strip_suffix("/resume"))
            .unwrap_or("");

        let res = download_mgr.resume_task(task_id).await;
        let json = match res {
            Ok(started) => serde_json::json!({ "success": started }).to_string(),
            Err(e) => serde_json::json!({ "success": false, "error": e }).to_string(),
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d-4: Delete/Remove MEGA Download Task API (DELETE /api/mega/tasks/:id or POST /api/mega/tasks/:id/delete)
    if (method.eq_ignore_ascii_case("DELETE") || method.eq_ignore_ascii_case("POST"))
        && req_path.starts_with("/api/mega/tasks/")
        && (method.eq_ignore_ascii_case("DELETE") || req_path.ends_with("/delete"))
    {
        let task_id = if method.eq_ignore_ascii_case("DELETE") {
            req_path.strip_prefix("/api/mega/tasks/").unwrap_or("")
        } else {
            req_path
                .strip_prefix("/api/mega/tasks/")
                .and_then(|s| s.strip_suffix("/delete"))
                .unwrap_or("")
        };

        let success = download_mgr.delete_task(task_id).await;
        let json = serde_json::json!({ "success": success }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d-5: Open Folder for Task (POST /api/mega/tasks/:id/open-folder)
    if method.eq_ignore_ascii_case("POST")
        && req_path.starts_with("/api/mega/tasks/")
        && req_path.ends_with("/open-folder")
    {
        let task_id = req_path
            .strip_prefix("/api/mega/tasks/")
            .and_then(|s| s.strip_suffix("/open-folder"))
            .unwrap_or("");

        let res = download_mgr.open_task_folder(task_id).await;
        let json = match res {
            Ok(()) => serde_json::json!({ "success": true }).to_string(),
            Err(e) => serde_json::json!({ "success": false, "error": e }).to_string(),
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5d-6: Live Downloader Configuration (GET & POST /api/mega/config)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/mega/config" {
        let cfg = download_mgr.get_config().await;
        let json = serde_json::to_string(&cfg).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("POST") && req_path == "/api/mega/config" {
        let resp_str = match serde_json::from_slice::<crate::download::DownloaderConfig>(&body) {
            Ok(new_cfg) => {
                let updated = download_mgr.update_config(new_cfg).await;
                let json = serde_json::to_string(&updated).unwrap_or_else(|_| "{}".to_string());
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                )
            }
            Err(e) => {
                let err_json = serde_json::json!({ "error": format!("Invalid config JSON: {}", e) }).to_string();
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                )
            }
        };
        client_stream.write_all(resp_str.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5e: System Default Download Directory API (GET /api/system/default-dir)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/system/default-dir" {
        let default_dir = crate::resolve_default_download_dir();
        let last_used = download_mgr.get_last_used_download_dir().await;
        let base_dir = last_used.clone().unwrap_or_else(|| default_dir.to_string_lossy().to_string());
        let json = serde_json::json!({
            "base_dir": base_dir,
            "default_dir": default_dir.to_string_lossy().to_string(),
            "last_used_dir": last_used,
        }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5f: System Native Folder Picker API (POST /api/system/pick-folder)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/system/pick-folder" {
        let selected_path = match rfd::AsyncFileDialog::new().pick_folder().await {
            Some(folder_handle) => Some(folder_handle.path().to_string_lossy().to_string()),
            None => None,
        };
        let json = serde_json::json!({
            "path": selected_path
        }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5g: Get Application Settings (GET /api/settings)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/settings" {
        let settings = download_mgr.get_settings().await;
        let json = serde_json::to_string(&settings).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5h: Update Application Settings (POST /api/settings)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/settings" {
        let resp_str = match serde_json::from_slice::<crate::settings::AppSettings>(&body) {
            Ok(new_settings) => {
                let updated = download_mgr.update_settings(new_settings).await;
                let json = serde_json::to_string(&updated).unwrap_or_else(|_| "{}".to_string());
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json.len(),
                    json
                )
            }
            Err(e) => {
                let err_json = serde_json::json!({ "error": format!("Invalid settings JSON: {}", e) }).to_string();
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    err_json.len(),
                    err_json
                )
            }
        };
        client_stream.write_all(resp_str.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5i: Reset Application Settings (POST /api/settings/reset)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/settings/reset" {
        let def = download_mgr.reset_settings().await;
        let json = serde_json::to_string(&def).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5j: In-Memory Debug Logs API (GET /api/debug/logs?limit=300)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/debug/logs" {
        let mut limit = 300;
        if let Some(q) = req_query {
            for param in q.split('&') {
                if let Some(val) = param.strip_prefix("limit=") {
                    if let Ok(parsed) = val.parse::<usize>() {
                        limit = parsed;
                    }
                }
            }
        }
        let logs = crate::logging::global_log_buffer().get_recent(limit);
        let json = serde_json::to_string(&logs).unwrap_or_else(|_| "[]".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5k: Clear Debug Logs API (POST /api/debug/clear)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/debug/clear" {
        crate::logging::global_log_buffer().clear();
        let json = serde_json::json!({ "status": "cleared" }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5l: Toggle Release DevTools in Tauri Shell (POST /api/system/open-devtools)
    if method.eq_ignore_ascii_case("POST") && req_path == "/api/system/open-devtools" {
        crate::trigger_devtools();
        let json = serde_json::json!({ "status": "ok" }).to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 5m: Quiet Cached Release Update Status (GET /api/update)
    if method.eq_ignore_ascii_case("GET") && req_path == "/api/update" {
        let status = crate::update::get_cached_update_status();
        let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Favicon endpoint to eliminate 405 Method Not Allowed
    if method.eq_ignore_ascii_case("GET") && req_path == "/favicon.ico" {
        let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        client_stream.write_all(resp.as_bytes()).await?;
        client_stream.flush().await?;
        return Ok(());
    }

    // Route 6: Embedded Dashboard UI (GET /ui, GET /ui/*, GET /)
    if method.eq_ignore_ascii_case("GET")
        && (req_path == "/"
            || req_path == "/ui"
            || req_path == "/ui/"
            || req_path.starts_with("/ui/"))
    {
        let rel_path = if req_path == "/" || req_path == "/ui" || req_path == "/ui/" {
            "index.html"
        } else {
            req_path.trim_start_matches("/ui/").trim_start_matches('/')
        };

        let file_opt = Asset::get(rel_path).or_else(|| Asset::get("index.html"));
        if let Some(file) = file_opt {
            let content_type = mime_type_for(rel_path);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                content_type,
                file.data.len()
            );
            client_stream.write_all(resp.as_bytes()).await?;
            client_stream.write_all(&file.data).await?;
            client_stream.flush().await?;
            return Ok(());
        } else {
            let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found";
            client_stream.write_all(resp).await?;
            client_stream.flush().await?;
            return Ok(());
        }
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

    let mut connected_candidate = None;

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
                connected_candidate = Some((candidate.addr, candidate.proto));
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
    let tunnel_start = Instant::now();
    let (from_client, from_upstream) =
        tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await?;

    if let Some((cand_addr, cand_proto)) = connected_candidate {
        pool.record_tunnel_throughput(
            cand_addr,
            cand_proto,
            from_upstream,
            tunnel_start.elapsed(),
            Duration::from_secs(120),
        );
    }

    debug!(
        "Tunnel closed for {}: client sent {} bytes, upstream sent {} bytes",
        target, from_client, from_upstream
    );

    Ok(())
}
