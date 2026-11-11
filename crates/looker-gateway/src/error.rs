use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("I/O error in gateway: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error in gateway: {0}")]
    Protocol(#[from] looker_protocol::ProtocolError),

    #[error("Proxy pool exhausted or no proxies available")]
    NoProxies,

    #[error("Invalid incoming client HTTP CONNECT request")]
    InvalidConnectRequest,

    #[error("Upstream tunnel establishment failed after {0} retries")]
    AllRetriesFailed(usize),
}
