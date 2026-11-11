use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("I/O error during handshake: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsupported protocol version: expected {expected:#x}, got {got:#x}")]
    VersionMismatch { expected: u8, got: u8 },

    #[error("SOCKS authentication rejected or unsupported: method {0:#x}")]
    AuthRejected(u8),

    #[error("SOCKS5 command failed with reply code: {0:#x}")]
    Socks5ReplyError(u8),

    #[error("SOCKS4 command failed with reply code: {0:#x}")]
    Socks4ReplyError(u8),

    #[error("HTTP CONNECT rejected: status {status}, reason: {reason}")]
    HttpConnectRejected { status: u16, reason: String },

    #[error("Invalid HTTP CONNECT response header")]
    InvalidHttpResponse,

    #[error("Header exceeds maximum size limit ({0} bytes)")]
    HeaderTooLarge(usize),

    #[error("Unsupported address type: {0:#x}")]
    UnsupportedAddressType(u8),

    #[error("Domain name is too long: length {0} exceeds 255")]
    DomainTooLong(usize),

    #[error("IPv6 address not supported in SOCKS4/SOCKS4a")]
    Socks4Ipv6Unsupported,

    #[error("Connection closed unexpectedly by upstream proxy")]
    UnexpectedEof,
}
