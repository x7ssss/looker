use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoolError {
    #[error("No healthy proxies available in the pool")]
    NoProxiesAvailable,

    #[error("Proxy already registered: {0}")]
    AlreadyExists(String),
}
