use crate::error::MegaError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaLink {
    pub handle: String,
    pub key: String,
    pub is_folder: bool,
    pub subfile_handle: Option<String>,
    pub sub_folder_id: Option<String>,
    pub target_file_id: Option<String>,
}

impl MegaLink {
    /// Parses public MEGA link formats:
    /// - Modern File: `https://mega.nz/file/{handle}#{key}`
    /// - Legacy File: `https://mega.nz/#!{handle}!{key}`
    /// - Modern Folder: `https://mega.nz/folder/{root_id}#{key}`
    /// - Modern Subfolder Deep-Link: `https://mega.nz/folder/{root_id}#{key}/folder/{sub_folder_id}`
    /// - Modern Folder File Deep-Link: `https://mega.nz/folder/{root_id}#{key}/file/{target_file_id}`
    /// Parses public MEGA link formats:
    /// - Modern File: `https://mega.nz/file/{handle}#{key}`
    /// - Legacy File: `https://mega.nz/#!{handle}!{key}`
    /// - Modern Folder: `https://mega.nz/folder/{root_id}#{key}`
    /// - Modern Subfolder Deep-Link: `https://mega.nz/folder/{root_id}#{key}/folder/{sub_folder_id}`
    /// - Modern Folder File Deep-Link: `https://mega.nz/folder/{root_id}#{key}/file/{target_file_id}`
    /// - Legacy Folder: `https://mega.nz/#F!{id}!{key}` and `https://mega.nz/#F!{id}@{sub_id}!{key}`
    pub fn parse(url: &str) -> Result<Self, MegaError> {
        let clean = url.trim();

        // 1. Modern Folder & Deep-Links: /folder/{root_id}#{fragment} or folder/{root_id}#{fragment}
        if let Some(pos) = clean.find("/folder/").map(|p| p + 8).or_else(|| clean.find("folder/").map(|p| p + 7)) {
            let after = &clean[pos..];
            let mut parts = after.splitn(2, '#');
            let handle = parts.next().unwrap_or("").trim();
            let fragment = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !fragment.is_empty() {
                let clean_frag = fragment.split('?').next().unwrap_or(fragment).trim();
                let segs: Vec<&str> = clean_frag.split('/').filter(|s| !s.is_empty()).collect();

                if !segs.is_empty() {
                    let key = segs[0].trim().to_string();
                    let mut sub_folder_id = None;
                    let mut target_file_id = None;
                    let mut is_folder = true;

                    if segs.len() >= 3 {
                        if segs[1].eq_ignore_ascii_case("folder") {
                            sub_folder_id = Some(segs[2].trim().to_string());
                            is_folder = true;
                        } else if segs[1].eq_ignore_ascii_case("file") {
                            target_file_id = Some(segs[2].trim().to_string());
                            is_folder = false;
                        }
                    }

                    let subfile_handle = target_file_id.clone();

                    return Ok(Self {
                        handle: handle.to_string(),
                        key,
                        is_folder,
                        subfile_handle,
                        sub_folder_id,
                        target_file_id,
                    });
                }
            }
        }

        // 2. Legacy Folder: #F!{id}!{key} or #F!{id}@{sub_id}!{key} (optional !{subfile_id})
        if let Some(pos) = clean.find("#F!") {
            let after = &clean[pos + 3..];
            let parts: Vec<&str> = after.split('!').collect();
            if parts.len() >= 2 {
                let raw_handle = parts[0].trim();
                let key = parts[1].trim().to_string();

                let (handle, sub_folder_id) = if let Some(at_idx) = raw_handle.find('@') {
                    let root = raw_handle[..at_idx].trim().to_string();
                    let sub = raw_handle[at_idx + 1..].trim().to_string();
                    (root, if sub.is_empty() { None } else { Some(sub) })
                } else {
                    (raw_handle.to_string(), None)
                };

                let subfile_handle = if parts.len() >= 3 && !parts[2].trim().is_empty() {
                    Some(parts[2].trim().to_string())
                } else {
                    None
                };

                let is_folder = subfile_handle.is_none();
                let target_file_id = subfile_handle.clone();
                if !handle.is_empty() && !key.is_empty() {
                    return Ok(Self {
                        handle,
                        key,
                        is_folder,
                        subfile_handle,
                        sub_folder_id,
                        target_file_id,
                    });
                }
            }
        }

        // 3. Modern File: /file/{handle}#{key} or file/{handle}#{key}
        if let Some(pos) = clean.find("/file/").map(|p| p + 6).or_else(|| clean.find("file/").map(|p| p + 5)) {
            let after = &clean[pos..];
            let mut parts = after.splitn(2, '#');
            let handle = parts.next().unwrap_or("").trim();
            let key = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                    is_folder: false,
                    subfile_handle: None,
                    sub_folder_id: None,
                    target_file_id: None,
                });
            }
        }

        // 4. Legacy File: #!{handle}!{key}
        if let Some(pos) = clean.find("#!") {
            let after = &clean[pos + 2..];
            let mut parts = after.splitn(2, '!');
            let handle = parts.next().unwrap_or("").trim();
            let key = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                    is_folder: false,
                    subfile_handle: None,
                    sub_folder_id: None,
                    target_file_id: None,
                });
            }
        }

        Err(MegaError::InvalidUrl(url.to_string()))
    }

    pub fn root_id(&self) -> &str {
        &self.handle
    }

    pub fn is_folder(&self) -> bool {
        self.is_folder
    }

    pub fn is_folder_scope(&self) -> bool {
        self.is_folder || self.sub_folder_id.is_some() || self.target_file_id.is_some() || self.subfile_handle.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_v1_and_v2_links() {
        let url1 = "https://mega.nz/file/ABCDEF12#abcdefghijklmnopqrstuvwxyz0123456789ABCDEF1";
        let link1 = MegaLink::parse(url1).unwrap();
        assert_eq!(link1.handle, "ABCDEF12");
        assert_eq!(link1.key, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF1");
        assert!(!link1.is_folder());

        let url2 = "https://mega.nz/#!12345678!zyxwvutsrqponmlkjihgfedcba9876543210FEDCBA2";
        let link2 = MegaLink::parse(url2).unwrap();
        assert_eq!(link2.handle, "12345678");
        assert_eq!(link2.key, "zyxwvutsrqponmlkjihgfedcba9876543210FEDCBA2");
        assert!(!link2.is_folder());
    }

    #[test]
    fn test_parse_folder_links() {
        let folder_url = "https://mega.nz/folder/Folder12#FolderKey12345678901234";
        let link = MegaLink::parse(folder_url).unwrap();
        assert_eq!(link.handle, "Folder12");
        assert_eq!(link.key, "FolderKey12345678901234");
        assert!(link.is_folder());

        let legacy_folder = "https://mega.nz/#F!LegFolder!LegFolderKey12345678";
        let link_leg = MegaLink::parse(legacy_folder).unwrap();
        assert_eq!(link_leg.handle, "LegFolder");
        assert_eq!(link_leg.key, "LegFolderKey12345678");
        assert!(link_leg.is_folder());

        let subfile_url = "https://mega.nz/folder/Folder12#FolderKey12345678901234/file/SubFile1";
        let link_sub = MegaLink::parse(subfile_url).unwrap();
        assert_eq!(link_sub.handle, "Folder12");
        assert_eq!(link_sub.key, "FolderKey12345678901234");
        assert!(!link_sub.is_folder());
        assert_eq!(link_sub.subfile_handle.as_deref(), Some("SubFile1"));

        let legacy_subfolder = "https://mega.nz/#F!HqJUnY4J@fzxBDZKC!lBStkttzdoYm7HA0M13nmg";
        let link_legacy_sub = MegaLink::parse(legacy_subfolder).unwrap();
        assert_eq!(link_legacy_sub.root_id(), "HqJUnY4J");
        assert_eq!(link_legacy_sub.handle, "HqJUnY4J");
        assert_eq!(link_legacy_sub.sub_folder_id.as_deref(), Some("fzxBDZKC"));
        assert_eq!(link_legacy_sub.key, "lBStkttzdoYm7HA0M13nmg");
        assert!(link_legacy_sub.is_folder());
    }
}
