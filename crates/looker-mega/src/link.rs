use crate::error::MegaError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaLink {
    pub handle: String,
    pub key: String,
    pub is_folder: bool,
    pub subfile_handle: Option<String>,
}

impl MegaLink {
    /// Parses public MEGA link formats:
    /// - Modern File: `https://mega.nz/file/{handle}#{key}`
    /// - Legacy File: `https://mega.nz/#!{handle}!{key}`
    /// - Modern Folder: `https://mega.nz/folder/{id}#{key}`
    /// - Legacy Folder: `https://mega.nz/#F!{id}!{key}`
    /// - Folder Sub-File: `https://mega.nz/folder/{id}#{key}/file/{file_handle}`
    pub fn parse(url: &str) -> Result<Self, MegaError> {
        let clean = url.trim();

        // 1. Modern Folder Sub-File: /folder/{id}#{key}/file/{file_handle}
        if let Some(pos) = clean.find("/folder/") {
            let after = &clean[pos + 8..];
            if let Some(sub_pos) = after.find("/file/") {
                let folder_part = &after[..sub_pos];
                let subfile_handle = after[sub_pos + 6..].trim().to_string();

                let mut parts = folder_part.splitn(2, '#');
                let handle = parts.next().unwrap_or("").trim();
                let key = parts.next().unwrap_or("").trim();

                if !handle.is_empty() && !key.is_empty() {
                    return Ok(Self {
                        handle: handle.to_string(),
                        key: key.to_string(),
                        is_folder: false, // downloading the specific subfile
                        subfile_handle: Some(subfile_handle),
                    });
                }
            }

            // Modern Folder: /folder/{id}#{key}
            let mut parts = after.splitn(2, '#');
            let handle = parts.next().unwrap_or("").trim();
            let key = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                    is_folder: true,
                    subfile_handle: None,
                });
            }
        }

        // 2. Legacy Folder: /#F!{id}!{key}
        if let Some(pos) = clean.find("/#F!") {
            let after = &clean[pos + 4..];
            let parts: Vec<&str> = after.split('!').collect();
            if parts.len() >= 2 {
                let handle = parts[0].trim().to_string();
                let key = parts[1].trim().to_string();
                let subfile_handle = if parts.len() >= 3 && !parts[2].is_empty() {
                    Some(parts[2].trim().to_string())
                } else {
                    None
                };

                let is_folder = subfile_handle.is_none();
                if !handle.is_empty() && !key.is_empty() {
                    return Ok(Self {
                        handle,
                        key,
                        is_folder,
                        subfile_handle,
                    });
                }
            }
        }

        // 3. Modern File: /file/{handle}#{key}
        if let Some(pos) = clean.find("/file/") {
            let after = &clean[pos + 6..];
            let mut parts = after.splitn(2, '#');
            let handle = parts.next().unwrap_or("").trim();
            let key = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                    is_folder: false,
                    subfile_handle: None,
                });
            }
        }

        // 4. Legacy File: /#!{handle}!{key}
        if let Some(pos) = clean.find("/#!") {
            let after = &clean[pos + 3..];
            let mut parts = after.splitn(2, '!');
            let handle = parts.next().unwrap_or("").trim();
            let key = parts.next().unwrap_or("").trim();

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                    is_folder: false,
                    subfile_handle: None,
                });
            }
        }

        Err(MegaError::InvalidUrl(url.to_string()))
    }

    pub fn is_folder(&self) -> bool {
        self.is_folder
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
    }
}
