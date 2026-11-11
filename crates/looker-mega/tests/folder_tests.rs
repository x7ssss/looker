use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::prelude::*;
use looker_mega::folder::{
    parse_folder_share_key, parse_folder_tree, unwrap_node_key, FolderNodeType, RawFolderNode,
};
use looker_mega::link::MegaLink;

fn mock_encrypt_attributes(key: &[u8; 16], name: &str) -> String {
    let json_text = format!(r#"MEGA{{"n":"{}"}}"#, name);
    let mut plaintext = json_text.into_bytes();
    while plaintext.len() % 16 != 0 {
        plaintext.push(0);
    }

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut prev = [0u8; 16];
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

    BASE64_URL_SAFE_NO_PAD.encode(&ciphertext)
}

#[test]
fn test_folder_link_parsing() {
    let modern_url = "https://mega.nz/folder/AbCdEfGh#1234567890123456789012";
    let link = MegaLink::parse(modern_url).expect("Should parse modern folder link");
    assert!(link.is_folder);
    assert_eq!(link.handle, "AbCdEfGh");
    assert_eq!(link.key, "1234567890123456789012");
    assert_eq!(link.subfile_handle, None);

    let modern_with_file =
        "https://mega.nz/folder/AbCdEfGh#1234567890123456789012/file/FiLe1234";
    let link_file = MegaLink::parse(modern_with_file).expect("Should parse folder file link");
    assert!(!link_file.is_folder);
    assert_eq!(link_file.handle, "AbCdEfGh");
    assert_eq!(link_file.subfile_handle, Some("FiLe1234".to_string()));

    let legacy_url = "https://mega.nz/#F!XyZaBcDe!aBcDeFgHiJkLmNoPqRsTuV";
    let legacy_link = MegaLink::parse(legacy_url).expect("Should parse legacy folder link");
    assert!(legacy_link.is_folder);
    assert_eq!(legacy_link.handle, "XyZaBcDe");
    assert_eq!(legacy_link.key, "aBcDeFgHiJkLmNoPqRsTuV");
    assert_eq!(legacy_link.subfile_handle, None);
}

#[test]
fn test_folder_share_key_parsing() {
    // 16 bytes encoded with Base64URL without padding = 22 chars
    let raw_key = b"0123456789abcdef";
    let b64_key = BASE64_URL_SAFE_NO_PAD.encode(raw_key);
    assert_eq!(b64_key.len(), 22);

    let parsed = parse_folder_share_key(&b64_key).expect("Should parse share key");
    assert_eq!(&parsed, raw_key);
}

#[test]
fn test_unwrap_directory_node_key() {
    let share_key = [0x42u8; 16];
    let cipher = Aes128::new(GenericArray::from_slice(&share_key));

    // 16-byte raw directory key
    let dir_key_plain = [0x77u8; 16];
    let mut block = GenericArray::clone_from_slice(&dir_key_plain);
    cipher.encrypt_block(&mut block);

    let enc_b64 = BASE64_URL_SAFE_NO_PAD.encode(block.as_slice());
    let (key_opt, attr_key_opt) =
        unwrap_node_key(&enc_b64, &share_key, FolderNodeType::Folder)
            .expect("Should unwrap directory key");

    assert!(key_opt.is_none());
    assert_eq!(attr_key_opt, Some(dir_key_plain));
}

#[test]
fn test_unwrap_file_node_key() {
    let share_key = [0x33u8; 16];
    let cipher = Aes128::new(GenericArray::from_slice(&share_key));

    // 32-byte raw file key [k0..k7]
    let raw_file_key: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f,
    ];

    let mut b1 = GenericArray::clone_from_slice(&raw_file_key[0..16]);
    let mut b2 = GenericArray::clone_from_slice(&raw_file_key[16..32]);
    cipher.encrypt_block(&mut b1);
    cipher.encrypt_block(&mut b2);

    let mut enc_bytes = Vec::new();
    enc_bytes.extend_from_slice(b1.as_slice());
    enc_bytes.extend_from_slice(b2.as_slice());

    let enc_b64 = BASE64_URL_SAFE_NO_PAD.encode(&enc_bytes);
    let (key_opt, attr_key_opt) =
        unwrap_node_key(&enc_b64, &share_key, FolderNodeType::File)
            .expect("Should unwrap file key");

    assert!(attr_key_opt.is_none());
    let mega_key = key_opt.expect("File must produce MegaKey");

    // File key folding: k0^k4, k1^k5, k2^k6, k3^k7
    let mut expected_aes_key = [0u8; 16];
    for i in 0..16 {
        expected_aes_key[i] = raw_file_key[i] ^ raw_file_key[i + 16];
    }
    assert_eq!(mega_key.aes_key, expected_aes_key);
    assert_eq!(
        mega_key.nonce,
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]
    );

    let w6 = u32::from_be_bytes(raw_file_key[24..28].try_into().unwrap());
    let w7 = u32::from_be_bytes(raw_file_key[28..32].try_into().unwrap());
    assert_eq!(mega_key.expected_mac, [w6, w7]);
}

#[test]
fn test_folder_tree_relative_path_resolution() {
    let share_key = [0x55u8; 16];
    let cipher = Aes128::new(GenericArray::from_slice(&share_key));

    // Helper to encrypt a 16-byte key with ECB
    let encrypt_16 = |key: [u8; 16]| -> String {
        let mut b = GenericArray::clone_from_slice(&key);
        cipher.encrypt_block(&mut b);
        BASE64_URL_SAFE_NO_PAD.encode(b.as_slice())
    };

    // Helper to encrypt a 32-byte key with ECB
    let encrypt_32 = |key: [u8; 32]| -> String {
        let mut b1 = GenericArray::clone_from_slice(&key[0..16]);
        let mut b2 = GenericArray::clone_from_slice(&key[16..32]);
        cipher.encrypt_block(&mut b1);
        cipher.encrypt_block(&mut b2);
        let mut enc = Vec::new();
        enc.extend_from_slice(b1.as_slice());
        enc.extend_from_slice(b2.as_slice());
        BASE64_URL_SAFE_NO_PAD.encode(&enc)
    };

    let dir_attr_key = [0x11u8; 16];
    let file1_key = [0x22u8; 32];
    let file2_key = [0x33u8; 32];

    // Encrypt attribute JSONs
    let dir_enc_attr = mock_encrypt_attributes(&dir_attr_key, "Documents");
    // For files, attributes are encrypted with the folded 16-byte AES key
    let mut f1_folded = [0u8; 16];
    for i in 0..16 {
        f1_folded[i] = file1_key[i] ^ file1_key[i + 16];
    }
    let f1_enc_attr = mock_encrypt_attributes(&f1_folded, "doc.txt");

    let mut f2_folded = [0u8; 16];
    for i in 0..16 {
        f2_folded[i] = file2_key[i] ^ file2_key[i + 16];
    }
    let f2_enc_attr = mock_encrypt_attributes(&f2_folded, "root.png");

    let raw_nodes = vec![
        // Subfolder "Documents"
        RawFolderNode {
            h: "sub_h".to_string(),
            p: "root_h".to_string(),
            t: 1,
            a: dir_enc_attr,
            k: format!("sub_h:{}", encrypt_16(dir_attr_key)),
            s: None,
        },
        // File "doc.txt" inside "Documents"
        RawFolderNode {
            h: "f1".to_string(),
            p: "sub_h".to_string(),
            t: 0,
            a: f1_enc_attr,
            k: format!("f1:{}", encrypt_32(file1_key)),
            s: Some(1024),
        },
        // File "root.png" in root folder
        RawFolderNode {
            h: "f2".to_string(),
            p: "root_h".to_string(),
            t: 0,
            a: f2_enc_attr,
            k: format!("f2:{}", encrypt_32(file2_key)),
            s: Some(2048),
        },
    ];

    let tree = parse_folder_tree("root_h", &share_key, raw_nodes)
        .expect("Should parse folder tree");

    let doc = tree.find_node("f1").expect("Should find doc.txt");
    assert_eq!(doc.name, "doc.txt");
    assert_eq!(doc.relative_path.to_str().unwrap().replace('\\', "/"), "Documents/doc.txt");
    assert_eq!(doc.size, 1024);

    let img = tree.find_node("f2").expect("Should find root.png");
    assert_eq!(img.name, "root.png");
    assert_eq!(img.relative_path.to_str().unwrap().replace('\\', "/"), "root.png");
    assert_eq!(img.size, 2048);

    assert_eq!(tree.files().len(), 2);
    assert_eq!(tree.directories().len(), 1);
    assert_eq!(tree.total_bytes(), 3072);
}
