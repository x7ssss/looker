use std::collections::HashMap;
use std::path::PathBuf;

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, KeyInit};
use serde::{Deserialize, Serialize};

use crate::crypto::{base64url_decode, decrypt_attributes, sanitize_filename, MegaKey};
use crate::error::MegaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolderNodeType {
    File = 0,
    Folder = 1,
}

#[derive(Debug, Clone)]
pub struct MegaFolderNode {
    pub handle: String,
    pub parent_handle: String,
    pub node_type: FolderNodeType,
    pub name: String,
    pub size: u64,
    pub relative_path: PathBuf,
    pub key: Option<MegaKey>,
    pub attr_key: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct MegaFolderTree {
    pub folder_handle: String,
    pub nodes: Vec<MegaFolderNode>,
}

impl MegaFolderTree {
    pub fn files(&self) -> Vec<&MegaFolderNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == FolderNodeType::File)
            .collect()
    }

    pub fn directories(&self) -> Vec<&MegaFolderNode> {
        self.nodes
            .iter()
            .filter(|n| n.node_type == FolderNodeType::Folder)
            .collect()
    }

    pub fn find_node(&self, handle: &str) -> Option<&MegaFolderNode> {
        self.nodes.iter().find(|n| n.handle == handle)
    }

    pub fn total_bytes(&self) -> u64 {
        self.files().iter().map(|f| f.size).sum()
    }

    /// Resolves the human-readable root folder title, if present.
    pub fn root_title(&self) -> Option<String> {
        // 1. Look for a folder node whose handle matches folder_handle
        if let Some(n) = self.nodes.iter().find(|n| n.node_type == FolderNodeType::Folder && n.handle == self.folder_handle) {
            if !n.name.is_empty() && n.name != self.folder_handle {
                return Some(n.name.clone());
            }
        }
        // 2. Look for directory with empty parent_handle
        if let Some(n) = self.nodes.iter().find(|n| n.node_type == FolderNodeType::Folder && n.parent_handle.is_empty()) {
            if !n.name.is_empty() && n.name != self.folder_handle {
                return Some(n.name.clone());
            }
        }
        // 3. Fall back to any directory in the tree that has a non-empty name and != folder_handle
        if let Some(d) = self.directories().iter().find(|d| !d.name.is_empty() && d.name != self.folder_handle) {
            return Some(d.name.clone());
        }
        None
    }

    /// Filters tree nodes based on deep-link subfolder or target file scope.
    ///
    /// - If `target_file_id` is specified: scopes the tree to only that single file node.
    /// - If `sub_folder_id` is specified: scopes the tree to `target_h` and all recursive children
    ///   whose ancestor chain passes through `target_h`. Recomputes relative paths so `target_h`
    ///   acts as the download root.
    pub fn apply_scope(&mut self, sub_folder_id: Option<&str>, target_file_id: Option<&str>) {
        if let Some(target_file) = target_file_id {
            if let Some(mut file_node) = self.nodes.iter().find(|n| n.handle == target_file).cloned() {
                file_node.relative_path = PathBuf::from(&file_node.name);
                self.nodes = vec![file_node];
            } else {
                self.nodes.clear();
            }
            return;
        }

        if let Some(target_sub) = sub_folder_id {
            let target_exists = self.nodes.iter().any(|n| n.handle == target_sub);
            if !target_exists {
                self.nodes.clear();
                return;
            }

            // Build parent map: handle -> parent_handle
            let parent_map: HashMap<String, String> = self
                .nodes
                .iter()
                .map(|n| (n.handle.clone(), n.parent_handle.clone()))
                .collect();

            let is_descendant = |handle: &str| -> bool {
                if handle == target_sub {
                    return true;
                }
                let mut curr = parent_map.get(handle).cloned();
                while let Some(p) = curr {
                    if p == target_sub {
                        return true;
                    }
                    if p.is_empty() || p == self.folder_handle {
                        break;
                    }
                    curr = parent_map.get(&p).cloned();
                }
                false
            };

            // Build name map: handle -> name
            let name_map: HashMap<String, String> = self
                .nodes
                .iter()
                .map(|n| (n.handle.clone(), n.name.clone()))
                .collect();

            let mut filtered = Vec::new();
            for mut node in self.nodes.drain(..) {
                if is_descendant(&node.handle) {
                    if node.handle == target_sub {
                        node.relative_path = PathBuf::new();
                    } else {
                        // Recompute relative path from target_sub downwards
                        let mut comps = vec![node.name.clone()];
                        let mut curr_p = node.parent_handle.clone();
                        while !curr_p.is_empty() && curr_p != target_sub {
                            if let Some(pname) = name_map.get(&curr_p) {
                                comps.push(pname.clone());
                                curr_p = parent_map.get(&curr_p).cloned().unwrap_or_default();
                            } else {
                                break;
                            }
                        }
                        comps.reverse();
                        let mut pbuf = PathBuf::new();
                        for c in comps {
                            pbuf.push(c);
                        }
                        node.relative_path = pbuf;
                    }
                    filtered.push(node);
                }
            }
            self.nodes = filtered;
            self.folder_handle = target_sub.to_string();
        }
    }
}

/// Parses the 16-byte folder master share key from Base64URL string.
pub fn parse_folder_share_key(b64: &str) -> Result<[u8; 16], MegaError> {
    let raw = base64url_decode(b64)?;
    if raw.len() != 16 {
        return Err(MegaError::InvalidKeyLength(raw.len()));
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&raw);
    Ok(key)
}

/// Extracts ordered candidate b64_keys from a node's "k" string.
/// Splits by ',' into "<share_handle>:<b64_key>" entries.
/// Prioritizes the entry matching `folder_id` (if provided).
pub fn extract_key_candidates<'a>(k_param: &'a str, folder_id: Option<&str>) -> Vec<(&'a str, &'a str)> {
    let mut prioritized = Vec::new();
    let mut others = Vec::new();

    for entry in k_param.split(',') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (share_h, b64_key) = if let Some(colon_idx) = trimmed.find(':') {
            let sh = trimmed[..colon_idx].trim();
            let after = trimmed[colon_idx + 1..].trim();
            let key = after.split('/').next().unwrap_or(after).trim();
            (sh, key)
        } else {
            let key = trimmed.split('/').next().unwrap_or(trimmed).trim();
            ("", key)
        };

        if !b64_key.is_empty() {
            if let Some(fid) = folder_id {
                if !share_h.is_empty() && share_h == fid {
                    prioritized.push((share_h, b64_key));
                    continue;
                }
            }
            others.push((share_h, b64_key));
        }
    }

    prioritized.extend(others);
    prioritized
}

/// Decrypts a single Base64URL-encoded node key using the 16-byte folder share key via AES-128-ECB.
///
/// For folders (`t = 1`): decrypts 16 bytes of attribute key.
/// For files (`t = 0`): decrypts 32 bytes `[k0..k7]` and derives the 16-byte AES key by XOR-folding
/// `decrypted[i] ^ decrypted[i + 16]`, 8-byte IV/nonce from `decrypted[16..24]`, and 8-byte meta MAC from `decrypted[24..32]`.
pub fn decrypt_node_key_bytes(
    b64_key: &str,
    folder_share_key: &[u8; 16],
    node_type: FolderNodeType,
) -> Result<(Option<MegaKey>, Option<[u8; 16]>), MegaError> {
    let raw_bytes = base64url_decode(b64_key)?;
    if raw_bytes.len() < 16 || raw_bytes.len() % 16 != 0 {
        return Err(MegaError::InvalidKeyLength(raw_bytes.len()));
    }

    let cipher = Aes128::new(GenericArray::from_slice(folder_share_key));
    let mut dec = raw_bytes;
    for chunk in dec.chunks_exact_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }

    match node_type {
        FolderNodeType::Folder => {
            if dec.len() < 16 {
                return Err(MegaError::InvalidKeyLength(dec.len()));
            }
            let mut attr_key = [0u8; 16];
            attr_key.copy_from_slice(&dec[0..16]);
            Ok((None, Some(attr_key)))
        }
        FolderNodeType::File => {
            if dec.len() < 32 {
                return Err(MegaError::InvalidKeyLength(dec.len()));
            }
            // Derive the 16-byte file/attribute key by XOR-folding:
            // node_key[i] = decrypted[i] ^ decrypted[i + 16] for i in 0..16
            let mut aes_key = [0u8; 16];
            for i in 0..16 {
                aes_key[i] = dec[i] ^ dec[i + 16];
            }

            // Extract the 8-byte file AES-CTR IV/nonce from decrypted[16..24]
            let mut nonce = [0u8; 8];
            nonce.copy_from_slice(&dec[16..24]);

            // Extract 8-byte meta MAC from decrypted[24..32]
            let mut words = [0u32; 8];
            for i in 0..8 {
                words[i] = u32::from_be_bytes(dec[i * 4..i * 4 + 4].try_into().unwrap());
            }
            let expected_mac = [words[6], words[7]];

            Ok((
                Some(MegaKey {
                    raw_words: words,
                    aes_key,
                    nonce,
                    expected_mac,
                }),
                None,
            ))
        }
    }
}

/// Unwraps node key using the 16-byte folder share key via AES-128-ECB.
///
/// For folders (`t = 1`): decrypts 16 bytes of attribute key.
/// For files (`t = 0`): decrypts 32 bytes `[k0..k7]` and folds into 16-byte AES key, 8-byte nonce, and MAC words.
pub fn unwrap_node_key(
    k_param: &str,
    folder_share_key: &[u8; 16],
    node_type: FolderNodeType,
) -> Result<(Option<MegaKey>, Option<[u8; 16]>), MegaError> {
    unwrap_node_key_prioritized(k_param, folder_share_key, None, node_type)
}

/// Unwraps node key with prioritized `folder_id` entry matching.
pub fn unwrap_node_key_prioritized(
    k_param: &str,
    folder_share_key: &[u8; 16],
    folder_id: Option<&str>,
    node_type: FolderNodeType,
) -> Result<(Option<MegaKey>, Option<[u8; 16]>), MegaError> {
    let candidates = extract_key_candidates(k_param, folder_id);
    let mut last_err = MegaError::InvalidKeyLength(0);

    for (_share_h, b64_key) in candidates {
        match decrypt_node_key_bytes(b64_key, folder_share_key, node_type) {
            Ok(res) => return Ok(res),
            Err(e) => last_err = e,
        }
    }

    Err(last_err)
}

/// Raw node structure deserialized from the MEGA API response `f` array.
#[derive(Debug, Deserialize)]
pub struct RawFolderNode {
    pub h: String,
    pub p: String,
    pub t: u8,
    pub a: String,
    pub k: String,
    #[serde(default)]
    pub s: Option<u64>,
}

/// Reconstructs the complete hierarchical folder tree from raw API nodes.
pub fn parse_folder_tree(
    folder_handle: &str,
    folder_share_key: &[u8; 16],
    raw_nodes: Vec<RawFolderNode>,
) -> Result<MegaFolderTree, MegaError> {
    let mut intermediate_nodes = Vec::with_capacity(raw_nodes.len());

    for raw in raw_nodes {
        let node_type = if raw.t == 1 {
            FolderNodeType::Folder
        } else {
            FolderNodeType::File
        };

        let candidates = extract_key_candidates(&raw.k, Some(folder_handle));
        let mut key_opt = None;
        let mut attr_key_opt = None;
        let mut decrypted_name = None;
        let mut last_error = None;

        for (_share_h, b64_key) in candidates {
            match decrypt_node_key_bytes(b64_key, folder_share_key, node_type) {
                Ok((k_opt, ak_opt)) => {
                    match node_type {
                        FolderNodeType::Folder => {
                            if let Some(ref ak) = ak_opt {
                                match decrypt_attributes(ak, &raw.a) {
                                    Ok(attrs) => {
                                        attr_key_opt = ak_opt;
                                        decrypted_name = Some(attrs.name);
                                        break;
                                    }
                                    Err(e) => {
                                        last_error = Some(e);
                                    }
                                }
                            }
                        }
                        FolderNodeType::File => {
                            if let Some(ref fk) = k_opt {
                                match decrypt_attributes(&fk.aes_key, &raw.a) {
                                    Ok(attrs) => {
                                        key_opt = k_opt;
                                        decrypted_name = Some(attrs.name);
                                        break;
                                    }
                                    Err(e) => {
                                        last_error = Some(e);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // If none matched or validation failed, try direct folder_share_key for folder nodes
        if decrypted_name.is_none() && node_type == FolderNodeType::Folder {
            if let Ok(attrs) = decrypt_attributes(folder_share_key, &raw.a) {
                attr_key_opt = Some(*folder_share_key);
                decrypted_name = Some(attrs.name);
            }
        }

        let name = match decrypted_name {
            Some(n) => sanitize_filename(&n),
            None => {
                if let Some(ref err) = last_error {
                    tracing::warn!(
                        "Failed to decrypt attributes for node {} (handle={}, type={:?}): {}",
                        raw.h, raw.h, node_type, err
                    );
                } else {
                    tracing::warn!(
                        "Failed to decrypt attributes for node {} (handle={}, type={:?}): no valid key candidate in k={:?}",
                        raw.h, raw.h, node_type, raw.k
                    );
                }
                raw.h.clone()
            }
        };

        intermediate_nodes.push((
            raw.h,
            raw.p,
            node_type,
            name,
            raw.s.unwrap_or(0),
            key_opt,
            attr_key_opt,
        ));
    }

    // Build parent-to-children and handle-to-node maps for path resolution
    let node_map: HashMap<String, (String, String, FolderNodeType)> = intermediate_nodes
        .iter()
        .map(|(h, p, t, name, _, _, _)| (h.clone(), (p.clone(), name.clone(), *t)))
        .collect();

    let mut resolved_nodes = Vec::with_capacity(intermediate_nodes.len());

    for (h, p, t, name, size, key, attr_key) in intermediate_nodes {
        // Resolve relative path up to the root folder
        let relative_path = if h == folder_handle {
            PathBuf::new()
        } else {
            let mut path_components = vec![name.clone()];
            let mut curr_parent = p.clone();

            while !curr_parent.is_empty() && curr_parent != folder_handle {
                if let Some((next_parent, parent_name, _)) = node_map.get(&curr_parent) {
                    path_components.push(parent_name.clone());
                    curr_parent = next_parent.clone();
                } else {
                    break;
                }
            }

            path_components.reverse();
            let mut pbuf = PathBuf::new();
            for comp in path_components {
                pbuf.push(comp);
            }
            pbuf
        };

        resolved_nodes.push(MegaFolderNode {
            handle: h,
            parent_handle: p,
            node_type: t,
            name,
            size,
            relative_path,
            key,
            attr_key,
        });
    }

    Ok(MegaFolderTree {
        folder_handle: folder_handle.to_string(),
        nodes: resolved_nodes,
    })
}
