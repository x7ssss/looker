use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};
use looker_mega::{
    compute_chunk_mac, decrypt_attributes, decrypt_ctr, FileMacAccumulator, MegaError, MegaKey,
};

#[test]
fn test_key_derivation_exact_vectors() {
    let mut raw_bytes = Vec::with_capacity(32);
    let k: [u32; 8] = [
        0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
        0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20,
    ];
    for word in k {
        raw_bytes.extend_from_slice(&word.to_be_bytes());
    }

    let b64_key = URL_SAFE_NO_PAD.encode(&raw_bytes);
    let mega_key = MegaKey::from_base64_key(&b64_key).expect("Failed to parse key");

    // k[0..3] ^ k[4..7]
    let expected_aes_words = [
        k[0] ^ k[4], // 0x10101010
        k[1] ^ k[5], // 0x10101010
        k[2] ^ k[6], // 0x10101010
        k[3] ^ k[7], // 0x10101010
    ];
    let mut expected_aes_bytes = [0u8; 16];
    for i in 0..4 {
        expected_aes_bytes[i * 4..i * 4 + 4].copy_from_slice(&expected_aes_words[i].to_be_bytes());
    }

    assert_eq!(mega_key.aes_key, expected_aes_bytes);

    // Nonce = [k4, k5]
    let mut expected_nonce = [0u8; 8];
    expected_nonce[0..4].copy_from_slice(&k[4].to_be_bytes());
    expected_nonce[4..8].copy_from_slice(&k[5].to_be_bytes());
    assert_eq!(mega_key.nonce, expected_nonce);

    // Expected MAC = [k6, k7]
    assert_eq!(mega_key.expected_mac, [k[6], k[7]]);
}

#[test]
fn test_ctr_counter_offset_and_keystream() {
    let aes_key = [0x2bu8; 16];
    let nonce = [0x7cu8; 8];

    let full_payload = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut encrypted = full_payload.to_vec();

    // Encrypt whole stream from offset 0
    decrypt_ctr(&aes_key, &nonce, 0, &mut encrypted);
    assert_ne!(&encrypted, full_payload);

    // Decrypt segment starting at non-aligned offset pos=17
    let slice_start = 17;
    let slice_len = 25;
    let mut slice = encrypted[slice_start..slice_start + slice_len].to_vec();

    decrypt_ctr(&aes_key, &nonce, slice_start as u64, &mut slice);

    assert_eq!(
        slice,
        full_payload[slice_start..slice_start + slice_len],
        "CTR decryption at arbitrary offset failed to match original payload"
    );
}

#[test]
fn test_attribute_decryption_with_mock_cbc() {
    let aes_key = [0x55u8; 16];
    let json_text = br#"MEGA{"n":"looker_backup_v1.tar.gz","s":104857600}"#;

    // Pad to 16-byte boundary with zeros
    let mut plaintext = json_text.to_vec();
    while plaintext.len() % 16 != 0 {
        plaintext.push(0);
    }

    // Encrypt with AES-128-CBC with IV=0
    let cipher = Aes128::new(GenericArray::from_slice(&aes_key));
    let mut prev = [0u8; 16]; // IV = 0
    let mut ciphertext = Vec::new();

    for block_chunk in plaintext.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(block_chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        ciphertext.extend_from_slice(&block);
    }

    let b64 = URL_SAFE_NO_PAD.encode(&ciphertext);

    let attrs = decrypt_attributes(&aes_key, &b64).expect("Attribute decryption failed");
    assert_eq!(attrs.name, "looker_backup_v1.tar.gz");
    assert_eq!(attrs.size, Some(104857600));
}

#[test]
fn test_cbc_mac_accumulation_and_folding_verification() {
    let aes_key = [0x42u8; 16];
    let nonce = [0x13u8; 8];

    let chunk0_data = vec![0xAAu8; 131072]; // 128 KiB chunk
    let chunk1_data = vec![0xBBu8; 262144]; // 256 KiB chunk

    let mac0 = compute_chunk_mac(&aes_key, &nonce, &chunk0_data);
    let mac1 = compute_chunk_mac(&aes_key, &nonce, &chunk1_data);

    let mut accumulator = FileMacAccumulator::new(&aes_key);
    accumulator.accumulate(&mac0);
    accumulator.accumulate(&mac1);

    let expected_mac = accumulator.finish();

    // Verification must pass with expected MAC
    assert!(accumulator.verify(expected_mac).is_ok());

    // Corrupted MAC expectation must fail with MacMismatch
    let corrupted_mac = [expected_mac[0] ^ 1, expected_mac[1]];
    match accumulator.verify(corrupted_mac) {
        Err(MegaError::MacMismatch { expected0, computed0, .. }) => {
            assert_eq!(expected0, corrupted_mac[0]);
            assert_eq!(computed0, expected_mac[0]);
        }
        other => panic!("Expected MacMismatch, got {:?}", other),
    }
}

#[test]
fn test_mega_error_chain_formatting() {
    use std::io::{Error as IoError, ErrorKind};
    let root = IoError::new(ErrorKind::ConnectionRefused, "os error 10061: connection refused");
    let wrapped = IoError::new(ErrorKind::Other, root);
    let chain = looker_mega::format_error_chain(&wrapped);

    assert!(chain.contains("connection refused"));
    assert!(chain.contains(": "));
}

#[test]
fn test_mega_client_direct_and_gateway_routing() {
    let client = looker_mega::MegaClient::new(Some("http://127.0.0.1:8080"));
    let _ = client.direct_client();
    let _ = client.chunk_client();
}
