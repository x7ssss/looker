use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::target::TargetAddr;

/// Performs a SOCKS4 / SOCKS4a handshake on an asynchronous byte stream.
///
/// Implements standard SOCKS4 (IPv4 targets) and SOCKS4a extension (domain targets
/// resolved on the remote proxy side). Returns an error if target is IPv6.
pub async fn handshake_socks4<S>(stream: &mut S, target: &TargetAddr) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = Vec::with_capacity(64);
    // VN = 0x04, CD = 0x01 (CONNECT)
    req.push(0x04);
    req.push(0x01);

    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            // Port (2 bytes)
            req.extend_from_slice(&v4.port().to_be_bytes());
            // IPv4 IP (4 bytes)
            req.extend_from_slice(&v4.ip().octets());
            // User ID: empty null-terminated string
            req.push(0x00);
        }
        TargetAddr::Domain(domain, port) => {
            // Port (2 bytes)
            req.extend_from_slice(&port.to_be_bytes());
            // SOCKS4a sentinel IP: 0.0.0.x (x != 0)
            req.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            // User ID: empty null-terminated string
            req.push(0x00);
            // Domain name null-terminated
            req.extend_from_slice(domain.as_bytes());
            req.push(0x00);
        }
        TargetAddr::Ip(SocketAddr::V6(_)) => {
            return Err(ProtocolError::Socks4Ipv6Unsupported);
        }
    }

    stream.write_all(&req).await?;
    stream.flush().await?;

    // Server reply: 8 bytes: [VN, CD, DSTPORT(2), DSTIP(4)]
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;

    // CD: 0x5A (90) = Request granted
    let cd = reply[1];
    if cd != 0x5a {
        return Err(ProtocolError::Socks4ReplyError(cd));
    }

    Ok(())
}
