use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::ProtocolError;

const MAX_HTTP_HEADER_SIZE: usize = 4096;

/// Performs an HTTP CONNECT handshake without over-reading bytes past `\r\n\r\n`.
///
/// By reading strictly until the end of the HTTP response header delimiter (`\r\n\r\n`),
/// any subsequent bytes (e.g. TLS ClientHello or forwarded payload) remain unread in the
/// socket buffer, ready for transparent bidirectional piping.
pub async fn handshake_http_connect<S>(stream: &mut S, authority: &str) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\nUser-Agent: Looker/0.1\r\n\r\n"
    );

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut header_bytes = Vec::with_capacity(256);
    let mut one_byte = [0u8; 1];

    loop {
        let n = stream.read(&mut one_byte).await?;
        if n == 0 {
            return Err(ProtocolError::UnexpectedEof);
        }

        header_bytes.push(one_byte[0]);

        if header_bytes.len() >= 4 && header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }

        if header_bytes.len() >= MAX_HTTP_HEADER_SIZE {
            return Err(ProtocolError::HeaderTooLarge(header_bytes.len()));
        }
    }

    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|_| ProtocolError::InvalidHttpResponse)?;

    // Parse status line: HTTP/1.x <STATUS_CODE> <REASON>
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

    let reason: String = parts.collect::<Vec<&str>>().join(" ");

    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(ProtocolError::HttpConnectRejected { status, reason })
    }
}
