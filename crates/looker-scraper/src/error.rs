use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScraperError {
    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid CIDR format: {0}")]
    InvalidCidr(String),

    #[error("CIDR range exceeds maximum expansion limit ({0} hosts)")]
    CidrTooLarge(usize),
}
