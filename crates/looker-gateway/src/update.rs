use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::debug;

pub const GITHUB_LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/x7ssss/looker/releases/latest";
pub const GITHUB_RELEASES_URL: &str = "https://github.com/x7ssss/looker/releases";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateStatus {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub update_available: bool,
    pub release_url: String,
    pub checked: bool,
}

static UPDATE_CACHE: OnceLock<RwLock<UpdateStatus>> = OnceLock::new();
static CHECK_DISPATCHED: AtomicBool = AtomicBool::new(false);

fn cache_cell() -> &'static RwLock<UpdateStatus> {
    UPDATE_CACHE.get_or_init(|| {
        RwLock::new(UpdateStatus {
            current_version: CURRENT_VERSION.to_string(),
            latest_version: None,
            update_available: false,
            release_url: GITHUB_RELEASES_URL.to_string(),
            checked: false,
        })
    })
}

/// Returns the cached GitHub latest-release status without performing network I/O.
pub fn get_cached_update_status() -> UpdateStatus {
    cache_cell().read().clone()
}

/// Parses a `vMAJOR.MINOR.PATCH` (or `MAJOR.MINOR.PATCH`) string into `(major, minor, patch)`.
/// Returns `None` if malformed or if the version carries a pre-release suffix.
pub fn parse_stable_semver(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    let without_build = trimmed.split('+').next()?.trim();
    if without_build.contains('-') {
        return None;
    }
    let mut parts = without_build.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// Returns true only if `candidate` is a valid stable release strictly newer than `current`.
pub fn is_newer_version(current: &str, candidate: &str) -> bool {
    let Some(cur) = parse_stable_semver(current.split('-').next().unwrap_or(current)) else {
        return false;
    };
    let Some(cand) = parse_stable_semver(candidate) else {
        return false;
    };
    cand > cur
}

#[derive(Debug, Deserialize)]
struct GithubLatestRelease {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// Parses a GitHub `/releases/latest` JSON payload against `current_version`.
pub fn evaluate_release_json(current_version: &str, body: &str) -> Option<(String, String, bool)> {
    let release: GithubLatestRelease = serde_json::from_str(body).ok()?;
    if release.draft || release.prerelease {
        return None;
    }
    let normalized = release
        .tag_name
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    let _ = parse_stable_semver(&normalized)?;

    let url = if release.html_url.starts_with("https://github.com/x7ssss/looker/") {
        release.html_url
    } else {
        GITHUB_RELEASES_URL.to_string()
    };
    let update_available = is_newer_version(current_version, &normalized);
    Some((normalized, url, update_available))
}

/// Fires a single non-blocking background GET to GitHub Releases on startup with a short timeout
/// and descriptive User-Agent. Errors, offline states, or rate limits fail silently.
pub fn spawn_startup_update_check() {
    if CHECK_DISPATCHED.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = cache_cell();

    tokio::spawn(async {
        let user_agent = format!(
            "Looker/{} (+https://github.com/x7ssss/looker)",
            CURRENT_VERSION
        );
        let client = match reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(4))
            .user_agent(user_agent)
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                cache_cell().write().checked = true;
                return;
            }
        };

        let resp = match client
            .get(GITHUB_LATEST_RELEASE_API)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                debug!("Update check skipped cleanly (HTTP {})", r.status());
                cache_cell().write().checked = true;
                return;
            }
            Err(e) => {
                debug!("Update check skipped cleanly (network unavailable: {})", e);
                cache_cell().write().checked = true;
                return;
            }
        };

        if let Ok(body) = resp.text().await {
            if let Some((latest, url, available)) = evaluate_release_json(CURRENT_VERSION, &body) {
                let mut guard = cache_cell().write();
                guard.latest_version = Some(latest);
                guard.release_url = url;
                guard.update_available = available;
                guard.checked = true;
                return;
            }
        }

        cache_cell().write().checked = true;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_comparison() {
        assert!(is_newer_version("0.1.3", "v0.1.4"));
        assert!(is_newer_version("0.1.3", "0.2.0"));
        assert!(is_newer_version("0.1.3", "1.0.0"));
        assert!(!is_newer_version("0.1.3", "v0.1.3"));
        assert!(!is_newer_version("0.1.3", "v0.1.2"));
        assert!(!is_newer_version("0.1.3", "v0.1.4-beta.1"));
        assert!(!is_newer_version("0.1.3", "not-a-version"));
    }

    #[test]
    fn test_parse_github_release_json() {
        let newer = r#"{
            "tag_name": "v0.1.4",
            "html_url": "https://github.com/x7ssss/looker/releases/tag/v0.1.4",
            "draft": false,
            "prerelease": false
        }"#;
        let parsed = evaluate_release_json("0.1.3", newer).unwrap();
        assert_eq!(parsed.0, "0.1.4");
        assert_eq!(
            parsed.1,
            "https://github.com/x7ssss/looker/releases/tag/v0.1.4"
        );
        assert!(parsed.2);

        let same = r#"{
            "tag_name": "v0.1.3",
            "html_url": "https://evil.example.com/phish",
            "draft": false,
            "prerelease": false
        }"#;
        let parsed_same = evaluate_release_json("0.1.3", same).unwrap();
        assert_eq!(parsed_same.0, "0.1.3");
        assert_eq!(parsed_same.1, GITHUB_RELEASES_URL);
        assert!(!parsed_same.2);

        let prerelease = r#"{
            "tag_name": "v0.1.5",
            "html_url": "https://github.com/x7ssss/looker/releases/tag/v0.1.5",
            "draft": false,
            "prerelease": true
        }"#;
        assert!(evaluate_release_json("0.1.3", prerelease).is_none());
    }
}
