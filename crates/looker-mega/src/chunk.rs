#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkInfo {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
}

impl ChunkInfo {
    pub fn end_offset(&self) -> u64 {
        self.offset + self.size
    }

    /// Returns storage path slice format: `{offset}-{end_offset - 1}`
    pub fn path_range(&self) -> String {
        if self.size == 0 {
            format!("{}-0", self.offset)
        } else {
            format!("{}-{}", self.offset, self.offset + self.size - 1)
        }
    }
}

/// Official MEGA chunk schedule iterator.
///
/// Chunks 0..7 scale linearly by 128 KiB: `(i + 1) * 131072`.
/// Chunks 8+ are fixed at 1 MiB (1048576 bytes).
/// The final chunk is clamped to remaining file size.
pub struct ChunkIterator {
    file_size: u64,
    current_offset: u64,
    current_index: usize,
}

impl ChunkIterator {
    pub fn new(file_size: u64) -> Self {
        Self {
            file_size,
            current_offset: 0,
            current_index: 0,
        }
    }
}

impl Iterator for ChunkIterator {
    type Item = ChunkInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset >= self.file_size {
            return None;
        }

        let standard_size = if self.current_index < 8 {
            ((self.current_index + 1) as u64) * 131072
        } else {
            1048576
        };

        let remaining = self.file_size - self.current_offset;
        let chunk_size = standard_size.min(remaining);

        let info = ChunkInfo {
            index: self.current_index,
            offset: self.current_offset,
            size: chunk_size,
        };

        self.current_offset += chunk_size;
        self.current_index += 1;

        Some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_schedule_scaling() {
        let total_size = 5 * 1024 * 1024; // 5 MiB
        let chunks: Vec<ChunkInfo> = ChunkIterator::new(total_size).collect();

        assert_eq!(chunks[0].size, 131072); // 128 KiB
        assert_eq!(chunks[1].size, 262144); // 256 KiB
        assert_eq!(chunks[2].size, 393216); // 384 KiB
        assert_eq!(chunks[3].size, 524288); // 512 KiB
        assert_eq!(chunks[4].size, 655360); // 640 KiB
        assert_eq!(chunks[5].size, 786432); // 768 KiB
        assert_eq!(chunks[6].size, 917504); // 896 KiB
        assert_eq!(chunks[7].size, 1048576); // 1024 KiB
        assert_eq!(chunks[8].size, 524288); // Remaining 512 KiB clamped

        let sum: u64 = chunks.iter().map(|c| c.size).sum();
        assert_eq!(sum, total_size);
    }
}
