use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use looker_gateway::{GatewayConfig, ProxyGateway};
use looker_pool::{AnonymityLevel, CheckedProxy, ProxyPool};
use looker_protocol::ProxyProto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Mock SOCKS5 server that deliberately fails handshakes to simulate a dead/broken proxy.
async fn spawn_failing_socks5_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            // Read greeting then reject with 0xFF (no acceptable auth methods)
            let mut buf = [0u8; 3];
            let _ = socket.read_exact(&mut buf).await;
            let _ = socket.write_all(&[0x05, 0xff]).await;
            let _ = socket.shutdown().await;
        }
    });

    addr
}

/// Mock SOCKS5 server that succeeds handshake and acts as an echo server.
async fn spawn_healthy_socks5_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                // 1. Handshake greeting: [0x05, 0x01, 0x00]
                let mut greeting = [0u8; 3];
                if socket.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                // Reply: NO_AUTH [0x05, 0x00]
                if socket.write_all(&[0x05, 0x00]).await.is_err() {
                    return;
                }

                // 2. Read CONNECT command
                // Header: [0x05, 0x01, 0x00, atyp]
                let mut cmd_header = [0u8; 4];
                if socket.read_exact(&mut cmd_header).await.is_err() {
                    return;
                }
                match cmd_header[3] {
                    0x01 => {
                        let mut rest = [0u8; 6];
                        let _ = socket.read_exact(&mut rest).await;
                    }
                    0x03 => {
                        let mut len_buf = [0u8; 1];
                        let _ = socket.read_exact(&mut len_buf).await;
                        let mut rest = vec![0u8; len_buf[0] as usize + 2];
                        let _ = socket.read_exact(&mut rest).await;
                    }
                    0x04 => {
                        let mut rest = [0u8; 18];
                        let _ = socket.read_exact(&mut rest).await;
                    }
                    _ => return,
                }

                // Reply: Success with bound IPv4 0.0.0.0:0
                let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                if socket.write_all(&reply).await.is_err() {
                    return;
                }

                // 3. Echo tunnel payload
                let mut buf = [0u8; 1024];
                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    if socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    addr
}

#[tokio::test]
async fn test_pre_commit_retry_rule_success() {
    // 1. Spin up mock bad server and mock good server
    let bad_addr = spawn_failing_socks5_server().await;
    let good_addr = spawn_healthy_socks5_server().await;

    // 2. Populate pool: bad server has lower latency (ranks 1st), good server ranks 2nd
    let pool = Arc::new(ProxyPool::new().with_cooldown(Duration::from_secs(60)));
    pool.add_or_update(CheckedProxy {
        addr: bad_addr,
        proto: ProxyProto::Socks5,
        latency: Duration::from_millis(5),
        exit_ip: Some(bad_addr.ip()),
        anonymity: AnonymityLevel::Elite,
        geo: None,
        throughput_bps: 0,
    });
    pool.add_or_update(CheckedProxy {
        addr: good_addr,
        proto: ProxyProto::Socks5,
        latency: Duration::from_millis(50),
        exit_ip: Some(good_addr.ip()),
        anonymity: AnonymityLevel::Elite,
        geo: None,
        throughput_bps: 0,
    });

    // 3. Start gateway on ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let gateway_config = GatewayConfig {
        bind_addr: gateway_addr,
        max_retries: 3,
        connect_timeout: Duration::from_millis(500),
        buffer_size: 16384,
    };
    let gateway = ProxyGateway::new(gateway_config, Arc::clone(&pool));
    tokio::spawn(async move {
        gateway.run_on_listener(listener).await.unwrap();
    });

    // 4. Test client sends CONNECT request through gateway
    let mut client = TcpStream::connect(gateway_addr).await.unwrap();
    client
        .write_all(b"CONNECT test.domain:80 HTTP/1.1\r\nHost: test.domain:80\r\n\r\n")
        .await
        .unwrap();

    // 5. Client should receive HTTP/1.1 200 Connection Established
    let mut resp_buf = vec![0u8; 1024];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 Connection Established"),
        "Gateway did not return 200 OK. Got: {}",
        resp_str
    );

    // 6. Test bidirectional data pipe (echo test)
    let test_msg = b"Hello through Looker retry gateway!";
    client.write_all(test_msg).await.unwrap();

    let mut echo_buf = vec![0u8; test_msg.len()];
    client.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, test_msg);

    // 7. Verify pool state: bad proxy recorded failure
    let stats = pool.stats();
    assert_eq!(stats.total_proxies, 2);
    // Bad proxy should have at least 1 failure recorded
    let candidates = pool.get_healthy_candidates(10);
    // Good proxy should now be preferred
    assert!(candidates.iter().any(|c| c.addr == good_addr));
}

#[tokio::test]
async fn test_gateway_live_and_status_endpoints() {
    let pool = Arc::new(ProxyPool::new());
    let proxy_addr: SocketAddr = "192.0.2.1:1080".parse().unwrap();
    pool.add_or_update(CheckedProxy {
        addr: proxy_addr,
        proto: ProxyProto::Socks5,
        latency: Duration::from_millis(25),
        exit_ip: Some(proxy_addr.ip()),
        anonymity: AnonymityLevel::Elite,
        geo: None,
        throughput_bps: 0,
    });
    let http_addr: SocketAddr = "192.0.2.2:8080".parse().unwrap();
    pool.add_or_update(CheckedProxy {
        addr: http_addr,
        proto: ProxyProto::HttpConnect,
        latency: Duration::from_millis(35),
        exit_ip: Some(http_addr.ip()),
        anonymity: AnonymityLevel::Elite,
        geo: None,
        throughput_bps: 0,
    });
    let s4_addr: SocketAddr = "192.0.2.3:1080".parse().unwrap();
    pool.add_or_update(CheckedProxy {
        addr: s4_addr,
        proto: ProxyProto::Socks4,
        latency: Duration::from_millis(45),
        exit_ip: Some(s4_addr.ip()),
        anonymity: AnonymityLevel::Elite,
        geo: None,
        throughput_bps: 0,
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let gateway = ProxyGateway::new(GatewayConfig::default(), Arc::clone(&pool));
    tokio::spawn(async move {
        gateway.run_on_listener(listener).await.unwrap();
    });

    // 1. Test GET /live.txt and /all.txt
    let mut client = TcpStream::connect(gateway_addr).await.unwrap();
    client
        .write_all(b"GET /live.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf = vec![0u8; 1024];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("Content-Type: text/plain"));
    assert!(resp_str.contains("socks5://192.0.2.1:1080"));

    let mut client_all = TcpStream::connect(gateway_addr).await.unwrap();
    client_all
        .write_all(b"GET /all.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf_all = vec![0u8; 1024];
    let n_all = client_all.read(&mut resp_buf_all).await.unwrap();
    let resp_str_all = String::from_utf8_lossy(&resp_buf_all[..n_all]);
    assert!(resp_str_all.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str_all.contains("socks5://192.0.2.1:1080"));
    assert!(resp_str_all.contains("http://192.0.2.2:8080"));
    assert!(resp_str_all.contains("socks4://192.0.2.3:1080"));

    // Test protocol-segregated feeds: /http.txt, /socks4.txt, /socks5.txt
    let mut client_http = TcpStream::connect(gateway_addr).await.unwrap();
    client_http
        .write_all(b"GET /http.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf_http = vec![0u8; 1024];
    let n_http = client_http.read(&mut resp_buf_http).await.unwrap();
    let resp_str_http = String::from_utf8_lossy(&resp_buf_http[..n_http]);
    assert!(resp_str_http.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str_http.contains("192.0.2.2:8080"));
    assert!(!resp_str_http.contains("http://"));
    assert!(!resp_str_http.contains("192.0.2.1:1080"));

    let mut client_s4 = TcpStream::connect(gateway_addr).await.unwrap();
    client_s4
        .write_all(b"GET /socks4.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf_s4 = vec![0u8; 1024];
    let n_s4 = client_s4.read(&mut resp_buf_s4).await.unwrap();
    let resp_str_s4 = String::from_utf8_lossy(&resp_buf_s4[..n_s4]);
    assert!(resp_str_s4.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str_s4.contains("192.0.2.3:1080"));
    assert!(!resp_str_s4.contains("socks4://"));

    let mut client_s5 = TcpStream::connect(gateway_addr).await.unwrap();
    client_s5
        .write_all(b"GET /socks5.txt HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf_s5 = vec![0u8; 1024];
    let n_s5 = client_s5.read(&mut resp_buf_s5).await.unwrap();
    let resp_str_s5 = String::from_utf8_lossy(&resp_buf_s5[..n_s5]);
    assert!(resp_str_s5.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str_s5.contains("192.0.2.1:1080"));
    assert!(!resp_str_s5.contains("socks5://"));

    // 2. Test GET /status
    let mut client2 = TcpStream::connect(gateway_addr).await.unwrap();
    client2
        .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf2 = vec![0u8; 1024];
    let n2 = client2.read(&mut resp_buf2).await.unwrap();
    let resp_str2 = String::from_utf8_lossy(&resp_buf2[..n2]);

    assert!(resp_str2.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str2.contains("Content-Type: application/json"));
    assert!(resp_str2.contains("\"total_proxies\": 3"));
    assert!(resp_str2.contains("\"healthy_proxies\": 3"));
    assert!(resp_str2.contains("\"healthy_http\": 1"));
    assert!(resp_str2.contains("\"healthy_socks4\": 1"));
    assert!(resp_str2.contains("\"healthy_socks5\": 1"));

    // 3. Test GET /ui (Embedded Dashboard)
    let mut client3 = TcpStream::connect(gateway_addr).await.unwrap();
    client3
        .write_all(b"GET /ui HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf3 = vec![0u8; 2048];
    let n3 = client3.read(&mut resp_buf3).await.unwrap();
    let resp_str3 = String::from_utf8_lossy(&resp_buf3[..n3]);

    assert!(resp_str3.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str3.contains("Content-Type: text/html"));
    assert!(resp_str3.contains("Looker") || resp_str3.contains("LOOKER"));

    // 4. Test GET /api/proxies
    let mut client4 = TcpStream::connect(gateway_addr).await.unwrap();
    client4
        .write_all(b"GET /api/proxies?limit=10 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf4 = vec![0u8; 2048];
    let n4 = client4.read(&mut resp_buf4).await.unwrap();
    let resp_str4 = String::from_utf8_lossy(&resp_buf4[..n4]);

    assert!(resp_str4.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str4.contains("Content-Type: application/json"));
    assert!(resp_str4.contains("192.0.2.1:1080"));

    // 5. Test GET /api/status
    let mut client5 = TcpStream::connect(gateway_addr).await.unwrap();
    client5
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf5 = vec![0u8; 1024];
    let n5 = client5.read(&mut resp_buf5).await.unwrap();
    let resp_str5 = String::from_utf8_lossy(&resp_buf5[..n5]);

    assert!(resp_str5.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str5.contains("Content-Type: application/json"));
    assert!(resp_str5.contains("\"working_count\":3"));
    assert!(resp_str5.contains("\"healthy_by_proto\""));
    assert!(resp_str5.contains("\"http\":1"));
    assert!(resp_str5.contains("\"socks4\":1"));
    assert!(resp_str5.contains("\"socks5\":1"));

    // 6. Test GET /api/fastest
    let mut client6 = TcpStream::connect(gateway_addr).await.unwrap();
    client6
        .write_all(b"GET /api/fastest HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut resp_buf6 = vec![0u8; 2048];
    let n6 = client6.read(&mut resp_buf6).await.unwrap();
    let resp_str6 = String::from_utf8_lossy(&resp_buf6[..n6]);

    assert!(resp_str6.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str6.contains("Content-Type: application/json"));
    assert!(resp_str6.contains("192.0.2.1:1080"));

    // 7. Test GET /api/proxies?proto=socks5 (Server-side filtering)
    let mut client7 = TcpStream::connect(gateway_addr).await.unwrap();
    client7
        .write_all(b"GET /api/proxies?proto=socks5 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf7 = vec![0u8; 2048];
    let n7 = client7.read(&mut resp_buf7).await.unwrap();
    let resp_str7 = String::from_utf8_lossy(&resp_buf7[..n7]);

    assert!(resp_str7.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str7.contains("\"endpoint\":\"192.0.2.1:1080\""));
    assert!(!resp_str7.contains("\"endpoint\":\"192.0.2.2:8080\""));

    // 8. Test GET /api/mega/tasks
    let mut client8 = TcpStream::connect(gateway_addr).await.unwrap();
    client8
        .write_all(b"GET /api/mega/tasks HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf8 = vec![0u8; 1024];
    let n8 = client8.read(&mut resp_buf8).await.unwrap();
    let resp_str8 = String::from_utf8_lossy(&resp_buf8[..n8]);
    assert!(resp_str8.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str8.contains("[]"));

    // 9. Test POST /api/mega/inspect (malformed input -> 400 Bad Request)
    let mut client9 = TcpStream::connect(gateway_addr).await.unwrap();
    client9
        .write_all(b"POST /api/mega/inspect HTTP/1.1\r\nHost: localhost\r\nContent-Length: 17\r\n\r\n{\"url\":\"invalid\"}")
        .await
        .unwrap();
    let mut resp_buf9 = vec![0u8; 1024];
    let n9 = client9.read(&mut resp_buf9).await.unwrap();
    let resp_str9 = String::from_utf8_lossy(&resp_buf9[..n9]);
    assert!(resp_str9.starts_with("HTTP/1.1 400 Bad Request"));
    assert!(resp_str9.contains("\"error\""));

    // 10. Test GET /api/system/default-dir
    let mut client10 = TcpStream::connect(gateway_addr).await.unwrap();
    client10
        .write_all(b"GET /api/system/default-dir HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf10 = vec![0u8; 1024];
    let n10 = client10.read(&mut resp_buf10).await.unwrap();
    let resp_str10 = String::from_utf8_lossy(&resp_buf10[..n10]);
    assert!(resp_str10.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str10.contains("\"base_dir\""));

    // 11. Test GET /favicon.ico (eliminated 405 error)
    let mut client11 = TcpStream::connect(gateway_addr).await.unwrap();
    client11
        .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf11 = vec![0u8; 1024];
    let n11 = client11.read(&mut resp_buf11).await.unwrap();
    let resp_str11 = String::from_utf8_lossy(&resp_buf11[..n11]);
    assert!(resp_str11.starts_with("HTTP/1.1 204 No Content"));

    // 12. Test GET /api/mega/config
    let mut client12 = TcpStream::connect(gateway_addr).await.unwrap();
    client12
        .write_all(b"GET /api/mega/config HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut resp_buf12 = vec![0u8; 1024];
    let n12 = client12.read(&mut resp_buf12).await.unwrap();
    let resp_str12 = String::from_utf8_lossy(&resp_buf12[..n12]);
    assert!(resp_str12.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str12.contains("\"routing_mode\""));
    assert!(resp_str12.contains("\"workers_per_file\""));

    // 13. Test POST /api/mega/config
    let mut client13 = TcpStream::connect(gateway_addr).await.unwrap();
    let cfg_payload = b"{\"routing_mode\":\"force_proxy\",\"workers_per_file\":12,\"max_concurrent_files\":3,\"speed_limit_mbps\":50.0}";
    client13
        .write_all(format!("POST /api/mega/config HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}", cfg_payload.len(), std::str::from_utf8(cfg_payload).unwrap()).as_bytes())
        .await
        .unwrap();
    let mut resp_buf13 = vec![0u8; 1024];
    let n13 = client13.read(&mut resp_buf13).await.unwrap();
    let resp_str13 = String::from_utf8_lossy(&resp_buf13[..n13]);
    assert!(resp_str13.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str13.contains("\"force_proxy\""));
    assert!(resp_str13.contains("\"workers_per_file\":12"));
}

#[tokio::test]
async fn test_disk_space_and_config_validation() {
    use looker_gateway::download::{check_available_disk_space, DownloaderConfig};

    // Test disk check with 0 or small bytes on temp dir
    let temp_dir = std::env::temp_dir();
    assert!(check_available_disk_space(&temp_dir, 1024).is_ok());

    // Test enormous requirement (e.g. 10,000 Terabytes) should fail
    let huge_bytes = 10_000_000_000_000_000u64;
    let res = check_available_disk_space(&temp_dir, huge_bytes);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Insufficient disk space"));

    // Test DownloaderConfig clamping
    let mut cfg = DownloaderConfig {
        routing_mode: "INVALID".to_string(),
        workers_per_file: 999,
        max_concurrent_files: 99,
        speed_limit_mbps: -10.0,
    };
    cfg.sanitize();
    assert_eq!(cfg.routing_mode, "passive");
    assert_eq!(cfg.workers_per_file, 24);
    assert_eq!(cfg.max_concurrent_files, 5);
    assert_eq!(cfg.speed_limit_mbps, 0.0);
}

#[tokio::test]
async fn test_api_csrf_origin_guard_and_strict_bind() {
    let pool = Arc::new(ProxyPool::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let config = GatewayConfig {
        bind_addr: gateway_addr,
        max_retries: 2,
        connect_timeout: Duration::from_secs(2),
        buffer_size: 16384,
    };
    let gateway = ProxyGateway::new(config, Arc::clone(&pool));

    tokio::spawn(async move {
        let _ = gateway.run_on_listener(listener).await;
    });

    // 1. External Origin rejected on /api/* (403 Forbidden)
    let mut client1 = TcpStream::connect(gateway_addr).await.unwrap();
    client1
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://malicious-site.com\r\n\r\n")
        .await
        .unwrap();
    let mut buf1 = vec![0u8; 1024];
    let n1 = client1.read(&mut buf1).await.unwrap();
    let resp1 = String::from_utf8_lossy(&buf1[..n1]);
    assert!(resp1.starts_with("HTTP/1.1 403 Forbidden"), "Expected 403 Forbidden for external Origin, got: {}", resp1);

    // 2. External Referer rejected on /api/* (403 Forbidden)
    let mut client2 = TcpStream::connect(gateway_addr).await.unwrap();
    client2
        .write_all(b"GET /api/settings HTTP/1.1\r\nHost: 127.0.0.1\r\nReferer: https://evil.org/steal.html\r\n\r\n")
        .await
        .unwrap();
    let mut buf2 = vec![0u8; 1024];
    let n2 = client2.read(&mut buf2).await.unwrap();
    let resp2 = String::from_utf8_lossy(&buf2[..n2]);
    assert!(resp2.starts_with("HTTP/1.1 403 Forbidden"), "Expected 403 Forbidden for external Referer, got: {}", resp2);

    // 3. Allowed Origin http://127.0.0.1:8080 succeeds (200 OK)
    let mut client3 = TcpStream::connect(gateway_addr).await.unwrap();
    client3
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:8080\r\n\r\n")
        .await
        .unwrap();
    let mut buf3 = vec![0u8; 1024];
    let n3 = client3.read(&mut buf3).await.unwrap();
    let resp3 = String::from_utf8_lossy(&buf3[..n3]);
    assert!(resp3.starts_with("HTTP/1.1 200 OK"), "Expected 200 OK for allowed 127.0.0.1:8080 Origin, got: {}", resp3);

    // 4. Allowed Origin http://localhost:8080 succeeds (200 OK)
    let mut client4 = TcpStream::connect(gateway_addr).await.unwrap();
    client4
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://localhost:8080\r\n\r\n")
        .await
        .unwrap();
    let mut buf4 = vec![0u8; 1024];
    let n4 = client4.read(&mut buf4).await.unwrap();
    let resp4 = String::from_utf8_lossy(&buf4[..n4]);
    assert!(resp4.starts_with("HTTP/1.1 200 OK"), "Expected 200 OK for allowed localhost:8080 Origin, got: {}", resp4);

    // 5. Allowed Origin tauri://localhost succeeds (200 OK)
    let mut client5 = TcpStream::connect(gateway_addr).await.unwrap();
    client5
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: tauri://localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf5 = vec![0u8; 1024];
    let n5 = client5.read(&mut buf5).await.unwrap();
    let resp5 = String::from_utf8_lossy(&buf5[..n5]);
    assert!(resp5.starts_with("HTTP/1.1 200 OK"), "Expected 200 OK for tauri://localhost Origin, got: {}", resp5);

    // 6. Missing Origin and Referer succeeds (200 OK)
    let mut client6 = TcpStream::connect(gateway_addr).await.unwrap();
    client6
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    let mut buf6 = vec![0u8; 1024];
    let n6 = client6.read(&mut buf6).await.unwrap();
    let resp6 = String::from_utf8_lossy(&buf6[..n6]);
    assert!(resp6.starts_with("HTTP/1.1 200 OK"), "Expected 200 OK for missing Origin/Referer, got: {}", resp6);

    // 7. Non-API route (/live.txt) with external Origin is NOT blocked
    let mut client7 = TcpStream::connect(gateway_addr).await.unwrap();
    client7
        .write_all(b"GET /live.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://some-other-site.com\r\n\r\n")
        .await
        .unwrap();
    let mut buf7 = vec![0u8; 1024];
    let n7 = client7.read(&mut buf7).await.unwrap();
    let resp7 = String::from_utf8_lossy(&buf7[..n7]);
    assert!(resp7.starts_with("HTTP/1.1 200 OK"), "Expected 200 OK on /live.txt, got: {}", resp7);
}

#[tokio::test]
async fn test_task_pause_resume_and_bulk_queue_routes() {
    use looker_gateway::{AppSettings, DownloadManager};

    let temp_dir = std::env::temp_dir().join(format!("looker_routes_test_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let pool = Arc::new(ProxyPool::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let mut settings = AppSettings::default();
    settings.freeze_before_start = true;
    settings.default_download_dir = temp_dir.to_string_lossy().to_string();

    let mgr = Arc::new(DownloadManager::new_ephemeral(
        gateway_addr.to_string(),
        Arc::clone(&pool),
        settings,
    ));
    let gateway = ProxyGateway::new(GatewayConfig::default(), Arc::clone(&pool))
        .with_download_manager(Arc::clone(&mgr));

    tokio::spawn(async move {
        let _ = gateway.run_on_listener(listener).await;
    });

    // 1. Create a frozen task via POST /api/mega/download
    let payload = serde_json::json!({
        "url": "https://mega.nz/file/abc12345#0123456789abcdef0123456789abcdef",
        "selected_handles": [],
        "output_dir": temp_dir.to_string_lossy().to_string(),
        "category": "General",
        "title": "Route Test File"
    })
    .to_string();

    let mut c1 = TcpStream::connect(gateway_addr).await.unwrap();
    c1.write_all(
        format!(
            "POST /api/mega/download HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
            payload.len(),
            payload
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf1 = vec![0u8; 2048];
    let n1 = c1.read(&mut buf1).await.unwrap();
    let resp1 = String::from_utf8_lossy(&buf1[..n1]);
    assert!(resp1.starts_with("HTTP/1.1 200 OK"), "Unexpected response: {}", resp1);
    let body1 = resp1.split("\r\n\r\n").nth(1).unwrap_or("");
    let json1: serde_json::Value = serde_json::from_str(body1).unwrap();
    let task_id = json1["task_id"].as_str().unwrap().to_string();

    // Verify task is paused (because freeze_before_start = true)
    let tasks = mgr.list_tasks().await;
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].status, looker_gateway::TaskStatus::Paused);

    // 2. Resume task via POST /api/mega/tasks/:id/resume
    let mut c2 = TcpStream::connect(gateway_addr).await.unwrap();
    c2.write_all(
        format!(
            "POST /api/mega/tasks/{}/resume HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
            task_id
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf2 = vec![0u8; 1024];
    let n2 = c2.read(&mut buf2).await.unwrap();
    let resp2 = String::from_utf8_lossy(&buf2[..n2]);
    assert!(resp2.contains("\"success\":true"));

    // 3. Pause all via POST /api/mega/tasks/pause-all
    let mut c3 = TcpStream::connect(gateway_addr).await.unwrap();
    c3.write_all(b"POST /api/mega/tasks/pause-all HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut buf3 = vec![0u8; 1024];
    let n3 = c3.read(&mut buf3).await.unwrap();
    let resp3 = String::from_utf8_lossy(&buf3[..n3]);
    assert!(resp3.starts_with("HTTP/1.1 200 OK"));
    assert!(resp3.contains("\"success\":true"));

    // 4. Clear completed via POST /api/mega/tasks/clear-completed
    let mut c4 = TcpStream::connect(gateway_addr).await.unwrap();
    c4.write_all(b"POST /api/mega/tasks/clear-completed HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();
    let mut buf4 = vec![0u8; 1024];
    let n4 = c4.read(&mut buf4).await.unwrap();
    let resp4 = String::from_utf8_lossy(&buf4[..n4]);
    assert!(resp4.starts_with("HTTP/1.1 200 OK"));
    assert!(resp4.contains("\"cleared\":0"));

    // 5. Delete task via DELETE /api/mega/tasks/:id
    let mut c5 = TcpStream::connect(gateway_addr).await.unwrap();
    c5.write_all(
        format!(
            "DELETE /api/mega/tasks/{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            task_id
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf5 = vec![0u8; 1024];
    let n5 = c5.read(&mut buf5).await.unwrap();
    let resp5 = String::from_utf8_lossy(&buf5[..n5]);
    assert!(resp5.starts_with("HTTP/1.1 200 OK"));
    assert!(resp5.contains("\"success\":true"));
    assert!(mgr.list_tasks().await.is_empty());

    let _ = std::fs::remove_dir_all(&temp_dir);
}
