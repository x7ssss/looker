use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_attributes, MegaFileAttributes, MegaKey};
use crate::error::MegaError;
use crate::folder::{parse_folder_share_key, parse_folder_tree, MegaFolderTree, RawFolderNode};
use crate::link::MegaLink;

static SEQ_COUNTER: AtomicU64 = AtomicU64::new(1000);

#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub handle: String,
    pub name: String,
    pub size: u64,
    pub download_url: String,
    pub key: MegaKey,
}

pub type MegaFileInfo = FileMetadata;

#[derive(Serialize)]
struct DownloadReq<'a> {
    a: &'a str,
    g: u32,
    ssl: u32,
    p: &'a str,
}

#[derive(Serialize)]
struct FolderTreeReq<'a> {
    a: &'a str,
    c: u32,
    r: u32,
    ca: u32,
}

#[derive(Serialize)]
struct FolderFileDownloadReq<'a> {
    a: &'a str,
    g: u32,
    ssl: u32,
    n: &'a str,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ApiResponse {
    Success(Vec<DownloadResp>),
    ErrorArray(Vec<i32>),
    Error(i32),
}

#[derive(Deserialize)]
struct DownloadResp {
    s: u64,
    #[serde(default)]
    at: String,
    g: String,
}

#[derive(Deserialize)]
struct FolderTreeResp {
    f: Vec<RawFolderNode>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FolderTreeApiResponse {
    Success(Vec<FolderTreeResp>),
    ErrorArray(Vec<i32>),
    Error(i32),
}

pub struct MegaClient {
    direct_http: Client,
    gateway_http: Option<Client>,
    api_url: &'static str,
}

impl Default for MegaClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MegaClient {
    /// Creates a new MegaClient.
    ///
    /// - `proxy_url`: Optional rotating gateway URL (e.g. `http://127.0.0.1:8080`).
    ///
    /// In accordance with clean-room protocol findings, all metadata and command server API calls
    /// (`https://g.api.mega.co.nz/cs`) are routed DIRECTLY with explicit timeouts and rustls TLS
    /// to eliminate proxy drops during inspection and directory traversal.
    /// If direct access is blocked (e.g. ISP censorship), requests automatically fall back to the gateway proxy.
    /// Quota-bypassing chunk data transfers use `chunk_client()`.
    pub fn new(proxy_url: Option<&str>) -> Self {
        let direct_http = Client::builder()
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Looker/0.1.0")
            .build()
            .expect("Failed to build direct HTTPS client");

        let gateway_http = proxy_url.and_then(|proxy| {
            if let Ok(p) = Proxy::all(proxy) {
                Client::builder()
                    .use_rustls_tls()
                    .connect_timeout(Duration::from_secs(10))
                    .timeout(Duration::from_secs(25))
                    .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Looker/0.1.0")
                    .proxy(p)
                    .build()
                    .ok()
            } else {
                None
            }
        });

        Self {
            direct_http,
            gateway_http,
            api_url: "https://g.api.mega.co.nz/cs",
        }
    }

    /// Creates a direct-only MegaClient without proxy fallback.
    pub fn new_direct() -> Self {
        Self::new(None)
    }

    /// Returns a reference to the direct HTTPS client.
    pub fn direct_client(&self) -> &Client {
        &self.direct_http
    }

    /// Returns the gateway-routed client if configured, or falls back to direct client.
    /// Used for high-throughput chunk data transfers where proxy rotation bypasses quotas.
    pub fn chunk_client(&self) -> &Client {
        self.gateway_http.as_ref().unwrap_or(&self.direct_http)
    }

    /// Sends a JSON POST request to the MEGA API with automated transient retry
    /// (up to 2 retries with 500ms backoff) and fallback to gateway proxy if direct is blocked.
    async fn post_api<T: Serialize + ?Sized, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        payload: &T,
    ) -> Result<R, MegaError> {
        let mut last_error: Option<MegaError> = None;

        // 1. Direct requests with transient retry (up to 2 retries = 3 attempts total)
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                tracing::debug!("Retrying direct MEGA API request (attempt {})...", attempt + 1);
            }

            match self.direct_http.post(url).json(payload).send().await {
                Ok(resp) => {
                    match resp.json::<R>().await {
                        Ok(data) => return Ok(data),
                        Err(e) => {
                            last_error = Some(MegaError::from(e));
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(MegaError::from(e));
                }
            }
        }

        // 2. Fallback to gateway proxy if direct fails (e.g. ISP block of mega.co.nz)
        if let Some(gw_client) = &self.gateway_http {
            tracing::warn!("Direct MEGA API requests failed, falling back to gateway proxy...");
            match gw_client.post(url).json(payload).send().await {
                Ok(resp) => {
                    match resp.json::<R>().await {
                        Ok(data) => return Ok(data),
                        Err(e) => {
                            last_error = Some(MegaError::from(e));
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(MegaError::from(e));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| MegaError::ApiError(-1)))
    }

    /// Resolves file metadata and storage node URL from a public MEGA link.
    pub async fn resolve_file(&self, link: &MegaLink) -> Result<MegaFileInfo, MegaError> {
        self.get_file_metadata(link).await
    }

    /// Queries the MEGA API to retrieve storage node URL and file metadata for a standalone public file.
    pub async fn get_file_metadata(&self, link: &MegaLink) -> Result<FileMetadata, MegaError> {
        let key = MegaKey::from_base64_key(&link.key)?;
        let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}?id={}", self.api_url, seq);

        let payload = vec![DownloadReq {
            a: "g",
            g: 1,
            ssl: 2,
            p: &link.handle,
        }];

        let api_resp: ApiResponse = self.post_api(&url, &payload).await?;

        match api_resp {
            ApiResponse::Success(mut list) => {
                let first = list.pop().ok_or(MegaError::NotFound)?;
                let attrs: MegaFileAttributes = decrypt_attributes(&key.aes_key, &first.at)?;

                Ok(FileMetadata {
                    handle: link.handle.clone(),
                    name: attrs.name,
                    size: first.s,
                    download_url: first.g,
                    key,
                })
            }
            ApiResponse::ErrorArray(errs) => {
                let err_code = errs.first().copied().unwrap_or(-1);
                match err_code {
                    -17 => Err(MegaError::OverQuota),
                    -9 => Err(MegaError::NotFound),
                    -16 => Err(MegaError::Blocked),
                    code => Err(MegaError::ApiError(code)),
                }
            }
            ApiResponse::Error(err_code) => match err_code {
                -17 => Err(MegaError::OverQuota),
                -9 => Err(MegaError::NotFound),
                -16 => Err(MegaError::Blocked),
                code => Err(MegaError::ApiError(code)),
            },
        }
    }

    /// Fetches and decrypts the entire recursive node tree of a public MEGA folder.
    /// Uses query parameter `?n={folder_id}` to authenticate public scope.
    pub async fn fetch_folder_tree(&self, link: &MegaLink) -> Result<MegaFolderTree, MegaError> {
        let folder_share_key = parse_folder_share_key(&link.key)?;
        let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}?id={}&n={}", self.api_url, seq, link.handle);

        let payload = vec![FolderTreeReq {
            a: "f",
            c: 1,
            r: 1,
            ca: 1,
        }];

        let api_resp: FolderTreeApiResponse = self.post_api(&url, &payload).await?;

        match api_resp {
            FolderTreeApiResponse::Success(mut list) => {
                let first = list.pop().ok_or(MegaError::NotFound)?;
                let mut tree = parse_folder_tree(&link.handle, &folder_share_key, first.f)?;
                tree.apply_scope(
                    link.sub_folder_id.as_deref(),
                    link.target_file_id
                        .as_deref()
                        .or(link.subfile_handle.as_deref()),
                );
                Ok(tree)
            }
            FolderTreeApiResponse::ErrorArray(errs) => {
                let err = errs.first().copied().unwrap_or(-1);
                match err {
                    -17 => Err(MegaError::OverQuota),
                    -9 => Err(MegaError::NotFound),
                    -16 => Err(MegaError::Blocked),
                    code => Err(MegaError::ApiError(code)),
                }
            }
            FolderTreeApiResponse::Error(err_code) => match err_code {
                -17 => Err(MegaError::OverQuota),
                -9 => Err(MegaError::NotFound),
                -16 => Err(MegaError::Blocked),
                code => Err(MegaError::ApiError(code)),
            },
        }
    }

    /// Resolves temporary storage node URL for a specific file node inside a public folder.
    /// INVARIANT: Never pass `"v": 2` to the MEGA API.
    pub async fn get_folder_file_url(
        &self,
        folder_id: &str,
        file_node_handle: &str,
    ) -> Result<(String, u64), MegaError> {
        let seq = SEQ_COUNTER.fetch_add(1, Ordering::Relaxed);
        let url = format!("{}?id={}&n={}", self.api_url, seq, folder_id);

        let payload = vec![FolderFileDownloadReq {
            a: "g",
            g: 1,
            ssl: 2,
            n: file_node_handle,
        }];

        let api_resp: ApiResponse = self.post_api(&url, &payload).await?;

        match api_resp {
            ApiResponse::Success(mut list) => {
                let first = list.pop().ok_or(MegaError::NotFound)?;
                Ok((first.g, first.s))
            }
            ApiResponse::ErrorArray(errs) => {
                let err = errs.first().copied().unwrap_or(-1);
                match err {
                    -17 => Err(MegaError::OverQuota),
                    -9 => Err(MegaError::NotFound),
                    -16 => Err(MegaError::Blocked),
                    code => Err(MegaError::ApiError(code)),
                }
            }
            ApiResponse::Error(err_code) => match err_code {
                -17 => Err(MegaError::OverQuota),
                -9 => Err(MegaError::NotFound),
                -16 => Err(MegaError::Blocked),
                code => Err(MegaError::ApiError(code)),
            },
        }
    }
}
