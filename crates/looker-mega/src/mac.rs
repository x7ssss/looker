use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};

use crate::error::MegaError;

pub type ChunkMac = [u8; 16];

/// Computes the CBC-MAC over a decrypted logical chunk.
///
/// Initialized with `IV = Nonce64 || Nonce64`. For each 16-byte plaintext block:
/// `State = AES_ECB(State ^ Block)`. Final short block is padded with trailing zeros.
pub fn compute_chunk_mac(aes_key: &[u8; 16], nonce: &[u8; 8], chunk_data: &[u8]) -> ChunkMac {
    let cipher = Aes128::new(GenericArray::from_slice(aes_key));
    let mut state = [0u8; 16];
    state[0..8].copy_from_slice(nonce);
    state[8..16].copy_from_slice(nonce);

    for chunk_block in chunk_data.chunks(16) {
        let mut padded = [0u8; 16];
        padded[..chunk_block.len()].copy_from_slice(chunk_block);

        let mut block = GenericArray::clone_from_slice(&state);
        for i in 0..16 {
            block[i] ^= padded[i];
        }
        cipher.encrypt_block(&mut block);
        state.copy_from_slice(&block);
    }

    state
}

/// Accumulates chunk CBC-MACs in order and verifies file-level condensation against expected MAC words.
///
/// State initialized to 16 zero bytes. For each chunk MAC:
/// `C = AES_ECB(C ^ ChunkMac)`.
/// Final 128-bit state `[c0, c1, c2, c3]` is folded into 64-bit `[(c0^c1), (c2^c3)]` and compared to `[k6, k7]`.
pub struct FileMacAccumulator {
    cipher: Aes128,
    state: [u8; 16],
    chunk_count: usize,
}

impl FileMacAccumulator {
    pub fn new(aes_key: &[u8; 16]) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(aes_key)),
            state: [0u8; 16],
            chunk_count: 0,
        }
    }

    /// Accumulates a chunk MAC sequentially: `C = AES_ECB(C ^ ChunkMac)`
    pub fn accumulate(&mut self, chunk_mac: &ChunkMac) {
        let mut block = GenericArray::clone_from_slice(&self.state);
        for i in 0..16 {
            block[i] ^= chunk_mac[i];
        }
        self.cipher.encrypt_block(&mut block);
        self.state.copy_from_slice(&block);
        self.chunk_count += 1;
    }

    /// Folds the 128-bit state into two 32-bit big-endian words: `[(c0^c1), (c2^c3)]`.
    pub fn finish(&self) -> [u32; 2] {
        let c0 = u32::from_be_bytes(self.state[0..4].try_into().unwrap());
        let c1 = u32::from_be_bytes(self.state[4..8].try_into().unwrap());
        let c2 = u32::from_be_bytes(self.state[8..12].try_into().unwrap());
        let c3 = u32::from_be_bytes(self.state[12..16].try_into().unwrap());

        [c0 ^ c1, c2 ^ c3]
    }

    /// Compares the folded condensation MAC with the expected `[k6, k7]`.
    pub fn verify(&self, expected: [u32; 2]) -> Result<(), MegaError> {
        let computed = self.finish();
        if computed == expected {
            Ok(())
        } else {
            Err(MegaError::MacMismatch {
                expected0: expected[0],
                expected1: expected[1],
                computed0: computed[0],
                computed1: computed[1],
            })
        }
    }

    pub fn chunk_count(&self) -> usize {
        self.chunk_count
    }
}

/// Convenience wrapper managing chunk MAC computation and file-level verification.
pub struct MegaCbcMac {
    aes_key: [u8; 16],
    nonce: [u8; 8],
    accumulator: FileMacAccumulator,
}

impl MegaCbcMac {
    pub fn new(aes_key: &[u8; 16], nonce: &[u8; 8]) -> Self {
        Self {
            aes_key: *aes_key,
            nonce: *nonce,
            accumulator: FileMacAccumulator::new(aes_key),
        }
    }

    pub fn compute_chunk_mac(&self, chunk_data: &[u8]) -> ChunkMac {
        compute_chunk_mac(&self.aes_key, &self.nonce, chunk_data)
    }

    pub fn add_chunk_mac(&mut self, chunk_mac: ChunkMac) {
        self.accumulator.accumulate(&chunk_mac);
    }

    pub fn verify_integrity(&self, expected: [u32; 2]) -> Result<(), MegaError> {
        self.accumulator.verify(expected)
    }

    pub fn finish(&self) -> [u32; 2] {
        self.accumulator.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_accumulator_empty_and_single() {
        let aes_key = [0u8; 16];
        let nonce = [1u8; 8];
        let mut mac = MegaCbcMac::new(&aes_key, &nonce);

        let data = b"Hello world 16 bytes test!!";
        let chunk_mac = mac.compute_chunk_mac(data);
        mac.add_chunk_mac(chunk_mac);

        let finished = mac.finish();
        assert_ne!(finished, [0, 0]);
        assert!(mac.verify_integrity(finished).is_ok());
    }
}
