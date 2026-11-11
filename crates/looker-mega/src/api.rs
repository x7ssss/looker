use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_attributes, MegaFileAttributes, MegaKey};
use crate::error::MegaError;
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
    at: String,
    g: String,
}

pub struct MegaClient {
    http: Client,
    api_url: &'static str,
}

impl Default for MegaClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl MegaClient {
    pub fn new(proxy_url: Option<&str>) -> Self {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("Looker/0.1");

        if let Some(proxy) = proxy_url {
            if let Ok(p) = Proxy::all(proxy) {
                builder = builder.proxy(p);
            }
        }

        let http = builder.build().expect("Failed to build HTTP client");
        Self {
            http,
            api_url: "https://g.api.mega.co.nz/cs",
        }
    }

    /// Resolves file metadata and storage node URL from a public MEGA link.
    pub async fn resolve_file(&self, link: &MegaLink) -> Result<MegaFileInfo, MegaError> {
        self.get_file_metadata(link).await
    }

    /// Queries the MEGA API to retrieve storage node URL and file metadata.
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

        let resp = self.http.post(&url).json(&payload).send().await?;
        let api_resp: ApiResponse = resp.json().await?;

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
}
