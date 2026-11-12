use std::collections::HashMap;
use std::path::PathBuf;

use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockDecrypt, KeyInit};
use serde::{Deserialize, Serialize};

use crate::crypto::{base64url_decode, decrypt_attributes, MegaKey};
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

/// Unwraps node key using the 16-byte folder share key via AES-128-ECB.
///
/// For folders (`t = 1`): decrypts 16 bytes of attribute key.
/// For files (`t = 0`): decrypts 32 bytes `[k0..k7]` and folds into 16-byte AES key, 8-byte nonce, and MAC words.
pub fn unwrap_node_key(
    k_param: &str,
    folder_share_key: &[u8; 16],
    node_type: FolderNodeType,
) -> Result<(Option<MegaKey>, Option<[u8; 16]>), MegaError> {
    // k_param is typically "<handle>:<enc_key>" or multiple separated by "/"
    let enc_key_str = if let Some(idx) = k_param.find(':') {
        let after = &k_param[idx + 1..];
        after.split('/').next().unwrap_or(after).trim()
    } else {
        k_param.trim()
    };

    let raw_bytes = base64url_decode(enc_key_str)?;
    let cipher = Aes128::new(GenericArray::from_slice(folder_share_key));

    match node_type {
        FolderNodeType::Folder => {
            if raw_bytes.len() < 16 {
                return Err(MegaError::InvalidKeyLength(raw_bytes.len()));
            }
            let mut block = GenericArray::clone_from_slice(&raw_bytes[0..16]);
            cipher.decrypt_block(&mut block);
            let attr_key: [u8; 16] = block.into();
            Ok((None, Some(attr_key)))
        }
        FolderNodeType::File => {
            if raw_bytes.len() < 32 {
                return Err(MegaError::InvalidKeyLength(raw_bytes.len()));
            }
            let mut block0 = GenericArray::clone_from_slice(&raw_bytes[0..16]);
            let mut block1 = GenericArray::clone_from_slice(&raw_bytes[16..32]);
            cipher.decrypt_block(&mut block0);
            cipher.decrypt_block(&mut block1);

            let mut dec_32 = [0u8; 32];
            dec_32[0..16].copy_from_slice(&block0);
            dec_32[16..32].copy_from_slice(&block1);

            let mut words = [0u32; 8];
            for i in 0..8 {
                words[i] = u32::from_be_bytes(dec_32[i * 4..i * 4 + 4].try_into().unwrap());
            }

            // AES Key: [k0^k4, k1^k5, k2^k6, k3^k7]
            let mut aes_key = [0u8; 16];
            for i in 0..4 {
                let kw = words[i] ^ words[i + 4];
                aes_key[i * 4..i * 4 + 4].copy_from_slice(&kw.to_be_bytes());
            }

            // Nonce: [k4, k5]
            let mut nonce = [0u8; 8];
            nonce[0..4].copy_from_slice(&words[4].to_be_bytes());
            nonce[4..8].copy_from_slice(&words[5].to_be_bytes());

            // Expected MAC: [k6, k7]
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

        let (key_opt, attr_key_opt) = match unwrap_node_key(&raw.k, folder_share_key, node_type) {
            Ok(k) => k,
            Err(_) => continue, // Skip un-decryptable root or auxiliary nodes
        };

        let name = match node_type {
            FolderNodeType::Folder => {
                if let Some(ak) = &attr_key_opt {
                    decrypt_attributes(ak, &raw.a)
                        .map(|attrs| attrs.name)
                        .unwrap_or_else(|_| raw.h.clone())
                } else {
                    raw.h.clone()
                }
            }
            FolderNodeType::File => {
                if let Some(fk) = &key_opt {
                    decrypt_attributes(&fk.aes_key, &raw.a)
                        .map(|attrs| attrs.name)
                        .unwrap_or_else(|_| raw.h.clone())
                } else {
                    raw.h.clone()
                }
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
        let mut relative_path = PathBuf::new();
        for comp in path_components {
            relative_path.push(comp);
        }

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
