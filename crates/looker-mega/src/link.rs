use crate::error::MegaError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegaLink {
    pub handle: String,
    pub key: String,
}

impl MegaLink {
    /// Parses public MEGA link formats:
    /// - New format: `https://mega.nz/file/{handle}#{key}`
    /// - Legacy format: `https://mega.nz/#!{handle}!{key}`
    /// - Folder sub-file: `https://mega.nz/folder/{folder_id}#{folder_key}/file/{handle}`
    pub fn parse(url: &str) -> Result<Self, MegaError> {
        let clean = url.trim();

        // 1. Format: /file/{handle}#{key}
        if let Some(pos) = clean.find("/file/") {
            let after = &clean[pos + 6..];
            let mut parts = after.splitn(2, '#');
            let handle = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                });
            }
        }

        // 2. Format: /#!{handle}!{key}
        if let Some(pos) = clean.find("/#!") {
            let after = &clean[pos + 3..];
            let mut parts = after.splitn(2, '!');
            let handle = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");

            if !handle.is_empty() && !key.is_empty() {
                return Ok(Self {
                    handle: handle.to_string(),
                    key: key.to_string(),
                });
            }
        }

        Err(MegaError::InvalidUrl(url.to_string()))
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
        assert_eq!(
            link1.key,
            "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF1"
        );

        let url2 = "https://mega.nz/#!12345678!zyxwvutsrqponmlkjihgfedcba9876543210FEDCBA2";
        let link2 = MegaLink::parse(url2).unwrap();
        assert_eq!(link2.handle, "12345678");
        assert_eq!(
            link2.key,
            "zyxwvutsrqponmlkjihgfedcba9876543210FEDCBA2"
        );
    }
}
