pub mod download;
pub mod error;
pub mod logging;
pub mod server;
pub mod settings;

pub use download::{
    DownloadManager, DownloadRequest, InspectNode, InspectResponse, TaskInfo, TaskStatus,
};
pub use error::GatewayError;
pub use logging::{global_log_buffer, DebugLogEntry, LogBuffer, LogBufferLayer};
pub use server::{GatewayConfig, ProxyGateway};
pub use settings::AppSettings;

use std::path::PathBuf;

static DEVTOOLS_TRIGGER: parking_lot::RwLock<Option<tokio::sync::mpsc::UnboundedSender<()>>> =
    parking_lot::RwLock::new(None);

pub fn set_devtools_trigger(tx: tokio::sync::mpsc::UnboundedSender<()>) {
    *DEVTOOLS_TRIGGER.write() = Some(tx);
}

pub fn trigger_devtools() {
    if let Some(ref tx) = *DEVTOOLS_TRIGGER.read() {
        let _ = tx.send(());
    }
}

/// Resolves the default base download directory using `dirs::download_dir()` joined with `"Looker"`,
/// falling back to `./downloads` only if the user download directory is unavailable.
pub fn resolve_default_download_dir() -> PathBuf {
    if let Some(dl) = dirs::download_dir() {
        dl.join("Looker")
    } else {
        PathBuf::from("./downloads")
    }
}
