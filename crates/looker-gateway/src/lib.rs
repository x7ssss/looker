pub mod download;
pub mod error;
pub mod server;

pub use download::{
    DownloadManager, DownloadRequest, InspectNode, InspectResponse, TaskInfo, TaskStatus,
};
pub use error::GatewayError;
pub use server::{GatewayConfig, ProxyGateway};

use std::path::PathBuf;

/// Resolves the default base download directory using `dirs::download_dir()` joined with `"Looker"`,
/// falling back to `./downloads` only if the user download directory is unavailable.
pub fn resolve_default_download_dir() -> PathBuf {
    if let Some(dl) = dirs::download_dir() {
        dl.join("Looker")
    } else {
        PathBuf::from("./downloads")
    }
}
