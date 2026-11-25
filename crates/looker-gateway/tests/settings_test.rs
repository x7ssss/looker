use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use looker_gateway::{AppSettings, GatewayConfig, ProxyGateway};
use looker_pool::ProxyPool;

#[tokio::test]
async fn test_settings_api_lifecycle() {
    let pool = Arc::new(ProxyPool::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr = listener.local_addr().unwrap();

    let gateway = ProxyGateway::new(GatewayConfig::default(), Arc::clone(&pool));
    tokio::spawn(async move {
        gateway.run_on_listener(listener).await.unwrap();
    });

    // 1. GET /api/settings -> should return 200 OK with default settings
    let mut client = TcpStream::connect(gateway_addr).await.unwrap();
    client
        .write_all(b"GET /api/settings HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let n = client.read(&mut buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&buf[..n]);
    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("\"max_parallel_downloads\""));
    assert!(resp_str.contains("\"slots_per_file\""));
    assert!(resp_str.contains("\"routing_mode\""));
    assert!(resp_str.contains("\"stall_watchdog_seconds\""));

    // 2. POST /api/settings -> update settings
    let mut updated_settings = AppSettings::default();
    updated_settings.slots_per_file = 16;
    updated_settings.max_parallel_downloads = 5;
    updated_settings.speed_limit_mbps = 10.0; // 10 MB/s
    updated_settings.routing_mode = "force_proxy".to_string();
    updated_settings.proxy_selection_order = "random".to_string();
    updated_settings.clipboard_monitor = true;
    updated_settings.auto_accept_folders = true;
    updated_settings.freeze_before_start = true;
    updated_settings.stall_watchdog_seconds = 45;
    updated_settings.proxy_ban_seconds = 600;
    updated_settings.cmd_on_509_limit = Some("echo 509".to_string());
    updated_settings.cmd_on_all_finished = Some("echo done".to_string());

    let payload = serde_json::to_vec(&updated_settings).unwrap();

    let mut client2 = TcpStream::connect(gateway_addr).await.unwrap();
    let req = format!(
        "POST /api/settings HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
        payload.len(),
        std::str::from_utf8(&payload).unwrap()
    );
    client2.write_all(req.as_bytes()).await.unwrap();

    let mut buf2 = vec![0u8; 4096];
    let n2 = client2.read(&mut buf2).await.unwrap();
    let resp_str2 = String::from_utf8_lossy(&buf2[..n2]);
    assert!(resp_str2.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str2.contains("\"slots_per_file\":16") || resp_str2.contains("\"slots_per_file\": 16"));
    assert!(resp_str2.contains("\"speed_limit_mbps\":10.0") || resp_str2.contains("\"speed_limit_mbps\": 10.0"));
    assert!(resp_str2.contains("\"routing_mode\":\"force_proxy\"") || resp_str2.contains("\"routing_mode\": \"force_proxy\""));
    assert!(resp_str2.contains("\"clipboard_monitor\":true") || resp_str2.contains("\"clipboard_monitor\": true"));
    assert!(resp_str2.contains("\"stall_watchdog_seconds\":45") || resp_str2.contains("\"stall_watchdog_seconds\": 45"));

    // 3. GET /api/settings -> verify update persisted in gateway state
    let mut client3 = TcpStream::connect(gateway_addr).await.unwrap();
    client3
        .write_all(b"GET /api/settings HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let mut buf3 = vec![0u8; 4096];
    let n3 = client3.read(&mut buf3).await.unwrap();
    let resp_str3 = String::from_utf8_lossy(&buf3[..n3]);
    assert!(resp_str3.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str3.contains("\"slots_per_file\":16") || resp_str3.contains("\"slots_per_file\": 16"));
    assert!(resp_str3.contains("\"clipboard_monitor\":true") || resp_str3.contains("\"clipboard_monitor\": true"));

    // 4. POST /api/settings/reset -> reset back to defaults
    let mut client4 = TcpStream::connect(gateway_addr).await.unwrap();
    client4
        .write_all(b"POST /api/settings/reset HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
        .await
        .unwrap();

    let mut buf4 = vec![0u8; 4096];
    let n4 = client4.read(&mut buf4).await.unwrap();
    let resp_str4 = String::from_utf8_lossy(&buf4[..n4]);
    assert!(resp_str4.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str4.contains("\"slots_per_file\":6") || resp_str4.contains("\"slots_per_file\": 6"));
    assert!(resp_str4.contains("\"clipboard_monitor\":false") || resp_str4.contains("\"clipboard_monitor\": false"));
}
