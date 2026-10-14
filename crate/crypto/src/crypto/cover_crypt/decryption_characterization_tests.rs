use cosmian_crypto_core::{Aes256Gcm, Dem, FixedSizeCBytes, Instantiable, Nonce, SymmetricKey};

use super::aead_decrypt;

#[test]
fn characterization_aead_decrypt_short_block_error() {
    let key_bytes = [0x42_u8; 32];
    let key = SymmetricKey::<32>::try_from_slice(&key_bytes).unwrap();
    let short_ctx = [0x11_u8; 11]; // Aes256Gcm::NONCE_LENGTH is 12

    let result = aead_decrypt(&key, &short_ctx, None);
    let err = result.unwrap_err();
    assert_eq!(err.to_string(), "encrypted block too short");
}

#[test]
fn characterization_aead_decrypt_valid_block() {
    let key_bytes = [0x42_u8; 32];
    let key = SymmetricKey::<32>::try_from_slice(&key_bytes).unwrap();
    let nonce_bytes = [0x01_u8; 12];
    let nonce = Nonce::try_from_slice(&nonce_bytes).unwrap();
    let pt = b"characterization test for cover_crypt aead";

    let ct = Aes256Gcm::new(&key)
        .encrypt(&nonce, pt.as_slice(), None)
        .unwrap();
    let mut full_ctx = Vec::new();
    full_ctx.extend_from_slice(&nonce_bytes);
    full_ctx.extend_from_slice(&ct);

    let decrypted = aead_decrypt(&key, &full_ctx, None).unwrap();
    assert_eq!(decrypted.as_slice(), pt.as_slice());
}
