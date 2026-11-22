use aes::Aes128;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use cipher::generic_array::GenericArray;
use serde::{Deserialize, Serialize};

use crate::error::MegaError;

pub fn base64url_decode(input: &str) -> Result<Vec<u8>, MegaError> {
    let clean = input.trim();
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(clean) {
        return Ok(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(clean) {
        return Ok(bytes);
    }

    // Normalize to standard base64 and pad to multiple of 4
    let mut normalized = clean.replace('-', "+").replace('_', "/");
    let rem = normalized.len() % 4;
    if rem != 0 {
        normalized.push_str(&"===="[rem..]);
    }

    if let Ok(bytes) = STANDARD.decode(&normalized) {
        return Ok(bytes);
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(clean) {
        return Ok(bytes);
    }

    let bytes = STANDARD.decode(&normalized)?;
    Ok(bytes)
}

/// Sanitizes filename characters that are forbidden by common operating systems (< > : " / \ | ? *).
pub fn sanitize_filename(name: &str) -> String {
    let forbidden = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];
    let sanitized: String = name
        .chars()
        .map(|c| if forbidden.contains(&c) || c.is_ascii_control() { '_' } else { c })
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct MegaKey {
    pub raw_words: [u32; 8],
    pub aes_key: [u8; 16],
    pub nonce: [u8; 8],
    pub expected_mac: [u32; 2],
}

impl MegaKey {
    /// Derives 128-bit AES key, 64-bit Nonce, and Expected MAC words from a 43-character Base64URL key.
    pub fn from_base64_key(b64: &str) -> Result<Self, MegaError> {
        let raw = base64url_decode(b64)?;
        if raw.len() != 32 {
            return Err(MegaError::InvalidKeyLength(raw.len()));
        }

        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes(raw[i * 4..i * 4 + 4].try_into().unwrap());
        }

        // AES Key: k[0..3] ^ k[4..7]
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

        Ok(Self {
            raw_words: words,
            aes_key,
            nonce,
            expected_mac,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MegaFileAttributes {
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "s", default)]
    pub size: Option<u64>,
}

/// Decrypts file attributes returned by the MEGA API (`at` parameter).
///
/// Decrypted with AES-128-CBC (IV=0) using the derived 16-byte AES key.
/// Verifies the `MEGA` magic prefix and parses the JSON metadata.
pub fn decrypt_attributes(
    aes_key: &[u8; 16],
    encrypted_b64: &str,
) -> Result<MegaFileAttributes, MegaError> {
    let ciphertext = base64url_decode(encrypted_b64)?;
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(MegaError::InvalidKeyLength(ciphertext.len()));
    }

    let cipher = Aes128::new(GenericArray::from_slice(aes_key));
    let mut prev_block = [0u8; 16]; // IV = 0
    let mut plaintext = Vec::with_capacity(ciphertext.len());

    for chunk in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);

        // CBC XOR with previous ciphertext (or IV for first block)
        let mut decrypted_block = [0u8; 16];
        for i in 0..16 {
            decrypted_block[i] = block[i] ^ prev_block[i];
        }
        prev_block.copy_from_slice(chunk);
        plaintext.extend_from_slice(&decrypted_block);
    }

    // Verify "MEGA" magic prefix
    if !plaintext.starts_with(b"MEGA") {
        return Err(MegaError::InvalidAttributeMagic);
    }

    let json_bytes = &plaintext[4..];
    // Find the final '}' of the JSON object to exclude any trailing 0x00 or padding bytes
    let end = if let Some(last_brace_pos) = json_bytes.iter().rposition(|&b| b == b'}') {
        last_brace_pos + 1
    } else {
        let mut len = json_bytes.len();
        while len > 0 && json_bytes[len - 1] == 0 {
            len -= 1;
        }
        len
    };

    let json_str = std::str::from_utf8(&json_bytes[..end])
        .map_err(|e| MegaError::AttributeJson(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e,
        ))))?;

    let mut attrs: MegaFileAttributes = serde_json::from_str(json_str)?;
    attrs.name = sanitize_filename(&attrs.name);
    Ok(attrs)
}

/// In-place AES-128-CTR decryption adhering to MEGA counter specification.
///
/// Nonce64 || BE64(block_index), where block_index = pos / 16.
/// Only the lower 64 bits increment.
pub fn decrypt_ctr(
    aes_key: &[u8; 16],
    nonce: &[u8; 8],
    start_pos: u64,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let cipher = Aes128::new(GenericArray::from_slice(aes_key));
    let mut block_index = start_pos / 16;
    let mut block_offset = (start_pos % 16) as usize;
    let mut data_idx = 0;

    let mut counter_block = [0u8; 16];
    counter_block[0..8].copy_from_slice(nonce);

    while data_idx < data.len() {
        // Counter vector: Nonce64 || BE64(block_index)
        counter_block[8..16].copy_from_slice(&block_index.to_be_bytes());

        let mut keystream = GenericArray::clone_from_slice(&counter_block);
        cipher.encrypt_block(&mut keystream);

        while block_offset < 16 && data_idx < data.len() {
            data[data_idx] ^= keystream[block_offset];
            data_idx += 1;
            block_offset += 1;
        }

        block_offset = 0;
        block_index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_and_roundtrip() {
        // 32 zero bytes in base64url
        let b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = MegaKey::from_base64_key(b64).unwrap();
        assert_eq!(key.aes_key, [0u8; 16]);
        assert_eq!(key.nonce, [0u8; 8]);
        assert_eq!(key.expected_mac, [0, 0]);

        // Test CTR encrypt / decrypt symmetry
        let mut data = b"Hello, Mega high speed download engine!".to_vec();
        let original = data.clone();
        decrypt_ctr(&key.aes_key, &key.nonce, 0, &mut data);
        assert_ne!(data, original);
        decrypt_ctr(&key.aes_key, &key.nonce, 0, &mut data);
        assert_eq!(data, original);
    }
}
