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

        let resp = self.http.post(&url).json(&payload).send().await?;
        let api_resp: FolderTreeApiResponse = resp.json().await?;

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

        let resp = self.http.post(&url).json(&payload).send().await?;
        let api_resp: ApiResponse = resp.json().await?;

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
