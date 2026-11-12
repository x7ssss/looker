use std::error::Error;
use thiserror::Error;

/// Walks the entire chain of error sources and joins them with `: `.
pub fn format_error_chain(err: &(dyn Error + 'static)) -> String {
    let mut msg = err.to_string();
    let mut curr = err.source();
    while let Some(src) = curr {
        msg.push_str(": ");
        msg.push_str(&src.to_string());
        curr = src.source();
    }
    msg
}

pub fn format_reqwest_error(err: &reqwest::Error) -> String {
    format_error_chain(err)
}

#[derive(Error, Debug)]
pub enum MegaError {
    #[error("Invalid MEGA URL format: {0}")]
    InvalidUrl(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Decrypted attributes missing MEGA magic prefix")]
    InvalidAttributeMagic,

    #[error("Attribute JSON deserialization failed: {0}")]
    AttributeJson(#[from] serde_json::Error),

    #[error("HTTP request to MEGA failed: {}", format_reqwest_error(.0))]
    Http(#[from] reqwest::Error),

    #[error("MEGA bandwidth transfer quota exceeded (EOVERQUOTA -17 / HTTP 509)")]
    OverQuota,

    #[error("MEGA resource not found (ENOENT -9)")]
    NotFound,

    #[error("MEGA resource blocked or access denied (EBLOCKED -16)")]
    Blocked,

    #[error("MEGA API error code: {0}")]
    ApiError(i32),

    #[error("MAC integrity verification mismatch: expected [{expected0:#010x}, {expected1:#010x}], got [{computed0:#010x}, {computed1:#010x}]")]
    MacMismatch {
        expected0: u32,
        expected1: u32,
        computed0: u32,
        computed1: u32,
    },

    #[error("File size mismatch: expected {expected}, actual {actual}")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Chunk download failed after {0} attempts")]
    ChunkDownloadFailed(usize),
}
