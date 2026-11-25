use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Complete power-user application settings for Looker.
/// Persisted to `%LOCALAPPDATA%\looker\settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AppSettings {
    #[serde(default = "default_download_dir")]
    pub default_download_dir: String,

    #[serde(default)]
    pub temp_chunk_dir: Option<String>,

    #[serde(default = "default_max_parallel_downloads")]
    pub max_parallel_downloads: usize,

    #[serde(default = "default_slots_per_file")]
    pub slots_per_file: usize,

    #[serde(default)]
    pub speed_limit_mbps: f64,

    #[serde(default = "default_true")]
    pub verify_cbc_mac: bool,

    #[serde(default)]
    pub clipboard_monitor: bool,

    #[serde(default)]
    pub auto_accept_folders: bool,

    #[serde(default)]
    pub freeze_before_start: bool,

    #[serde(default = "default_routing_mode")]
    pub routing_mode: String,

    #[serde(default = "default_sticky_509_seconds")]
    pub sticky_509_seconds: u64,

    #[serde(default = "default_proxy_selection_order")]
    pub proxy_selection_order: String,

    #[serde(default = "default_true")]
    pub reset_proxy_per_chunk: bool,

    #[serde(default = "default_proxy_ban_seconds")]
    pub proxy_ban_seconds: u64,

    #[serde(default = "default_stall_watchdog_seconds")]
    pub stall_watchdog_seconds: u64,

    #[serde(default)]
    pub upstream_proxy: Option<String>,

    #[serde(default)]
    pub cmd_on_509_limit: Option<String>,

    #[serde(default)]
    pub cmd_on_all_finished: Option<String>,

    #[serde(default)]
    pub last_used_download_dir: Option<String>,
}

fn default_download_dir() -> String {
    crate::resolve_default_download_dir().to_string_lossy().to_string()
}

fn default_max_parallel_downloads() -> usize {
    3
}

fn default_slots_per_file() -> usize {
    6
}

fn default_true() -> bool {
    true
}

fn default_routing_mode() -> String {
    "passive".to_string()
}

fn default_sticky_509_seconds() -> u64 {
    3600
}

fn default_proxy_selection_order() -> String {
    "sequential".to_string()
}

fn default_proxy_ban_seconds() -> u64 {
    300
}

fn default_stall_watchdog_seconds() -> u64 {
    90
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_download_dir: default_download_dir(),
            temp_chunk_dir: None,
            max_parallel_downloads: default_max_parallel_downloads(),
            slots_per_file: default_slots_per_file(),
            speed_limit_mbps: 0.0,
            verify_cbc_mac: true,
            clipboard_monitor: false,
            auto_accept_folders: false,
            freeze_before_start: false,
            routing_mode: default_routing_mode(),
            sticky_509_seconds: default_sticky_509_seconds(),
            proxy_selection_order: default_proxy_selection_order(),
            reset_proxy_per_chunk: true,
            proxy_ban_seconds: default_proxy_ban_seconds(),
            stall_watchdog_seconds: default_stall_watchdog_seconds(),
            upstream_proxy: None,
            cmd_on_509_limit: None,
            cmd_on_all_finished: None,
            last_used_download_dir: None,
        }
    }
}

pub fn get_settings_file_path() -> PathBuf {
    if let Some(mut dir) = dirs::data_local_dir() {
        dir.push("looker");
        dir.push("settings.json");
        dir
    } else {
        PathBuf::from("settings.json")
    }
}

impl AppSettings {
    /// Validates and sanitizes settings values within allowed operating boundaries.
    pub fn sanitize(&mut self) {
        if self.default_download_dir.trim().is_empty() {
            self.default_download_dir = default_download_dir();
        }

        if let Some(ref d) = self.temp_chunk_dir {
            if d.trim().is_empty() {
                self.temp_chunk_dir = None;
            }
        }

        self.max_parallel_downloads = self.max_parallel_downloads.clamp(1, 10);
        self.slots_per_file = self.slots_per_file.clamp(1, 24);
        if !self.speed_limit_mbps.is_finite() || self.speed_limit_mbps < 0.0 {
            self.speed_limit_mbps = 0.0;
        }

        if !self.routing_mode.eq_ignore_ascii_case("force_proxy")
            && !self.routing_mode.eq_ignore_ascii_case("force")
        {
            self.routing_mode = "passive".to_string();
        } else {
            self.routing_mode = "force_proxy".to_string();
        }

        if !self.proxy_selection_order.eq_ignore_ascii_case("random") {
            self.proxy_selection_order = "sequential".to_string();
        } else {
            self.proxy_selection_order = "random".to_string();
        }

        self.sticky_509_seconds = self.sticky_509_seconds.clamp(10, 86400);
        self.proxy_ban_seconds = self.proxy_ban_seconds.clamp(0, 86400);
        self.stall_watchdog_seconds = self.stall_watchdog_seconds.clamp(5, 600);

        if let Some(ref u) = self.upstream_proxy {
            if u.trim().is_empty() {
                self.upstream_proxy = None;
            }
        }

        if let Some(ref c) = self.cmd_on_509_limit {
            if c.trim().is_empty() {
                self.cmd_on_509_limit = None;
            }
        }

        if let Some(ref c) = self.cmd_on_all_finished {
            if c.trim().is_empty() {
                self.cmd_on_all_finished = None;
            }
        }
    }

    /// Loads settings from `%LOCALAPPDATA%\looker\settings.json` synchronously.
    /// Falls back to defaults if file does not exist or has invalid JSON.
    pub fn load() -> Self {
        let path = get_settings_file_path();
        if path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(mut settings) = serde_json::from_str::<AppSettings>(&contents) {
                    // Migrate legacy speed_limit_kbps if speed_limit_mbps was not set
                    if settings.speed_limit_mbps == 0.0 {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&contents) {
                            if val.get("speed_limit_mbps").is_none() {
                                if let Some(kbps) = val.get("speed_limit_kbps").and_then(|v| v.as_f64()) {
                                    if kbps > 0.0 {
                                        settings.speed_limit_mbps = ((kbps / 1024.0) * 100.0).round() / 100.0;
                                    }
                                }
                            }
                        }
                    }
                    settings.sanitize();
                    return settings;
                }
            }
        }
        let mut def = AppSettings::default();
        def.sanitize();
        def
    }

    /// Saves settings to `%LOCALAPPDATA%\looker\settings.json`.
    pub fn save(&self) -> Result<(), String> {
        let path = get_settings_file_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write settings to {}: {}", path.display(), e))
    }

    /// Asynchronously saves settings to `%LOCALAPPDATA%\looker\settings.json`.
    pub async fn save_async(&self) -> Result<(), String> {
        let path = get_settings_file_path();
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize settings: {}", e))?;
        tokio::fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write settings to {}: {}", path.display(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings_and_sanitization() {
        let mut settings = AppSettings::default();
        assert_eq!(settings.max_parallel_downloads, 3);
        assert_eq!(settings.slots_per_file, 6);
        assert_eq!(settings.routing_mode, "passive");
        assert_eq!(settings.sticky_509_seconds, 3600);
        assert_eq!(settings.proxy_selection_order, "sequential");
        assert!(settings.verify_cbc_mac);
        assert!(settings.reset_proxy_per_chunk);
        assert!(!settings.clipboard_monitor);
        assert!(!settings.auto_accept_folders);
        assert!(!settings.freeze_before_start);

        settings.max_parallel_downloads = 999;
        settings.slots_per_file = 0;
        settings.speed_limit_mbps = -5.0;
        settings.routing_mode = "FORCE".to_string();
        settings.proxy_selection_order = "RANDOM".to_string();
        settings.stall_watchdog_seconds = 1;
        settings.sanitize();

        assert_eq!(settings.max_parallel_downloads, 10);
        assert_eq!(settings.slots_per_file, 1);
        assert_eq!(settings.speed_limit_mbps, 0.0);
        assert_eq!(settings.routing_mode, "force_proxy");
        assert_eq!(settings.proxy_selection_order, "random");
        assert_eq!(settings.stall_watchdog_seconds, 5);
    }

    #[test]
    fn test_settings_serde_roundtrip() {
        let mut original = AppSettings::default();
        original.speed_limit_mbps = 7.5;
        let serialized = serde_json::to_string(&original).expect("serialize");
        let deserialized: AppSettings = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_legacy_kbps_migration_logic() {
        let legacy_json = r#"{"speed_limit_kbps": 5120, "slots_per_file": 8}"#;
        let mut settings: AppSettings = serde_json::from_str(legacy_json).unwrap();
        let val: serde_json::Value = serde_json::from_str(legacy_json).unwrap();
        if settings.speed_limit_mbps == 0.0 && val.get("speed_limit_mbps").is_none() {
            if let Some(kbps) = val.get("speed_limit_kbps").and_then(|v| v.as_f64()) {
                settings.speed_limit_mbps = ((kbps / 1024.0) * 100.0).round() / 100.0;
            }
        }
        assert_eq!(settings.speed_limit_mbps, 5.0);
        assert_eq!(settings.slots_per_file, 8);
    }
}
