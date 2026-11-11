pub mod error;
pub mod http_connect;
pub mod probe;
pub mod socks4;
pub mod socks5;
pub mod target;

pub use error::ProtocolError;
pub use http_connect::handshake_http_connect;
pub use probe::{ProbeResult, ProxyProto};
pub use socks4::handshake_socks4;
pub use socks5::handshake_socks5;
pub use target::TargetAddr;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_socks5_handshake_success() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let target = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 1, 1, 1),
            443,
        )));

        let server_task = tokio::spawn(async move {
            // Read greeting [5, 1, 0]
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);

            // Reply NO_AUTH [5, 0]
            server.write_all(&[0x05, 0x00]).await.unwrap();

            // Read CONNECT request [5, 1, 0, 1, 1, 1, 1, 1, 1, 187]
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(&req[0..4], &[0x05, 0x01, 0x00, 0x01]);

            // Reply success with IPv4 bound addr [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let client_res = handshake_socks5(&mut client, &target).await;
        assert!(client_res.is_ok());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_socks4_handshake_success() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let target = TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(8, 8, 8, 8),
            80,
        )));

        let server_task = tokio::spawn(async move {
            let mut req = [0u8; 9];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req[0], 0x04); // VN
            assert_eq!(req[1], 0x01); // CD: CONNECT
            assert_eq!(&req[2..4], &80u16.to_be_bytes()); // Port
            assert_eq!(&req[4..8], &[8, 8, 8, 8]); // IP
            assert_eq!(req[8], 0x00); // Null term

            // Server reply: 8 bytes [0, 90, 0, 0, 0, 0, 0, 0] (90 = 0x5a = granted)
            server
                .write_all(&[0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await
                .unwrap();
        });

        let client_res = handshake_socks4(&mut client, &target).await;
        assert!(client_res.is_ok());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_http_connect_handshake_success() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 256];
            let n = server.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(req_str.starts_with("CONNECT mega.nz:443 HTTP/1.1\r\n"));

            // Reply HTTP 200 Connection Established
            server
                .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: Looker\r\n\r\n")
                .await
                .unwrap();
        });

        let client_res = handshake_http_connect(&mut client, "mega.nz:443").await;
        assert!(client_res.is_ok());
        server_task.await.unwrap();
    }
}
