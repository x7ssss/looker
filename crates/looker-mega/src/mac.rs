use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};

use crate::error::MegaError;

pub struct MegaCbcMac {
    cipher: Aes128,
    nonce: [u8; 8],
    chunk_macs: Vec<[u8; 16]>,
}

impl MegaCbcMac {
    pub fn new(aes_key: &[u8; 16], nonce: &[u8; 8]) -> Self {
        Self {
            cipher: Aes128::new(GenericArray::from_slice(aes_key)),
            nonce: *nonce,
            chunk_macs: Vec::new(),
        }
    }

    /// Computes the CBC-MAC over a decrypted logical chunk.
    ///
    /// Initialized with `Nonce64 || Nonce64`. For each 16-byte block:
    /// `C = AES-ECB(C ^ M_c)`.
    pub fn compute_chunk_mac(&self, chunk_data: &[u8]) -> [u8; 16] {
        let mut c = [0u8; 16];
        c[0..8].copy_from_slice(&self.nonce);
        c[8..16].copy_from_slice(&self.nonce);

        for chunk_block in chunk_data.chunks(16) {
            let mut padded = [0u8; 16];
            padded[..chunk_block.len()].copy_from_slice(chunk_block);

            let mut block = GenericArray::clone_from_slice(&c);
            for i in 0..16 {
                block[i] ^= padded[i];
            }
            self.cipher.encrypt_block(&mut block);
            c.copy_from_slice(&block);
        }

        c
    }

    /// Appends a precomputed or calculated chunk MAC into the condensation accumulator.
    pub fn add_chunk_mac(&mut self, chunk_mac: [u8; 16]) {
        self.chunk_macs.push(chunk_mac);
    }

    /// Folds all chunk MACs via file-level condensation and compares with expected MAC words `[k6, k7]`.
    pub fn verify_integrity(&self, expected: [u32; 2]) -> Result<(), MegaError> {
        let mut f = [0u8; 16];

        for chunk_mac in &self.chunk_macs {
            let mut block = GenericArray::clone_from_slice(&f);
            for i in 0..16 {
                block[i] ^= chunk_mac[i];
            }
            self.cipher.encrypt_block(&mut block);
            f.copy_from_slice(&block);
        }

        let f0 = u32::from_be_bytes(f[0..4].try_into().unwrap());
        let f1 = u32::from_be_bytes(f[4..8].try_into().unwrap());
        let f2 = u32::from_be_bytes(f[8..12].try_into().unwrap());
        let f3 = u32::from_be_bytes(f[12..16].try_into().unwrap());

        let computed = [f0 ^ f1, f2 ^ f3];

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
}
