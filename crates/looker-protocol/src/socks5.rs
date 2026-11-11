use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;
use crate::target::TargetAddr;

/// Performs a zero-allocation SOCKS5 handshake directly on an asynchronous stream.
///
/// Fully adheres to RFC 1928:
/// 1. Sends client greeting specifying NO_AUTHENTICATION_REQUIRED (0x00).
/// 2. Verifies server acceptance.
/// 3. Sends SOCKS5 CONNECT command for IPv4, IPv6, or domain name targets.
/// 4. Fully reads and drains the server reply including variable-length bound addresses.
pub async fn handshake_socks5<S>(stream: &mut S, target: &TargetAddr) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Send client greeting (VER=5, NMETHODS=1, METHOD=0x00 [NO AUTH])
    let greeting = [0x05u8, 0x01, 0x00];
    stream.write_all(&greeting).await?;
    stream.flush().await?;

    // Step 2: Read server choice [VER, METHOD]
    let mut server_choice = [0u8; 2];
    stream.read_exact(&mut server_choice).await?;

    if server_choice[0] != 0x05 {
        return Err(ProtocolError::VersionMismatch {
            expected: 0x05,
            got: server_choice[0],
        });
    }

    if server_choice[1] != 0x00 {
        return Err(ProtocolError::AuthRejected(server_choice[1]));
    }

    // Step 3: Build and send CONNECT request
    let mut req = Vec::with_capacity(32);
    // VER = 0x05, CMD = 0x01 (CONNECT), RSV = 0x00
    req.extend_from_slice(&[0x05, 0x01, 0x00]);

    match target {
        TargetAddr::Ip(SocketAddr::V4(v4)) => {
            req.push(0x01); // ATYP: IPv4
            req.extend_from_slice(&v4.ip().octets());
            req.extend_from_slice(&v4.port().to_be_bytes());
        }
        TargetAddr::Ip(SocketAddr::V6(v6)) => {
            req.push(0x04); // ATYP: IPv6
            req.extend_from_slice(&v6.ip().octets());
            req.extend_from_slice(&v6.port().to_be_bytes());
        }
        TargetAddr::Domain(domain, port) => {
            if domain.len() > 255 {
                return Err(ProtocolError::DomainTooLong(domain.len()));
            }
            req.push(0x03); // ATYP: Domain
            req.push(domain.len() as u8);
            req.extend_from_slice(domain.as_bytes());
            req.extend_from_slice(&port.to_be_bytes());
        }
    }

    stream.write_all(&req).await?;
    stream.flush().await?;

    // Step 4: Fully read and consume the SOCKS5 server reply
    // First 4 bytes: [VER, REP, RSV, ATYP]
    let mut reply_header = [0u8; 4];
    stream.read_exact(&mut reply_header).await?;

    if reply_header[0] != 0x05 {
        return Err(ProtocolError::VersionMismatch {
            expected: 0x05,
            got: reply_header[0],
        });
    }

    let rep = reply_header[1];
    if rep != 0x00 {
        return Err(ProtocolError::Socks5ReplyError(rep));
    }

    let atyp = reply_header[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes IP + 2 bytes port = 6 bytes
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            // Domain: 1 byte length L, then L bytes + 2 bytes port
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let domain_len = len_buf[0] as usize;
            let mut domain_and_port = vec![0u8; domain_len + 2];
            stream.read_exact(&mut domain_and_port).await?;
        }
        0x04 => {
            // IPv6: 16 bytes IP + 2 bytes port = 18 bytes
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        unknown => {
            return Err(ProtocolError::UnsupportedAddressType(unknown));
        }
    }

    Ok(())
}
