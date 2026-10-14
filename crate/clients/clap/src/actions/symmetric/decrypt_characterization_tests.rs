use cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm;
use test_kms_server::start_default_test_kms_server;

use super::DecryptAction;
use crate::actions::symmetric::{
    KeyEncryptionAlgorithm, encrypt::EncryptAction, keys::create_key::CreateKeyAction,
};

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

async fn round_trip(
    kek_id: &str,
    client: cosmian_kms_client::KmsClient,
    algo: DataEncryptionAlgorithm,
    len: usize,
) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("in.bin");
    let enc = dir.path().join("in.enc");
    let dec = dir.path().join("in.dec");
    let plain = pattern(len);
    std::fs::write(&input, &plain).unwrap();
    EncryptAction {
        input_file: input,
        key_id: Some(kek_id.to_owned()),
        data_encryption_algorithm: algo,
        key_encryption_algorithm: Some(KeyEncryptionAlgorithm::AesGcm),
        output_file: Some(enc.clone()),
        ..EncryptAction::default()
    }
    .run(client.clone())
    .await
    .unwrap();
    DecryptAction {
        input_file: enc,
        key_id: Some(kek_id.to_owned()),
        data_encryption_algorithm: algo,
        key_encryption_algorithm: Some(KeyEncryptionAlgorithm::AesGcm),
        output_file: Some(dec.clone()),
        ..DecryptAction::default()
    }
    .run(client)
    .await
    .unwrap();
    let out = std::fs::read(&dec).unwrap();
    assert_eq!(out, plain);
    out
}

async fn new_kek(client: cosmian_kms_client::KmsClient) -> String {
    CreateKeyAction {
        number_of_bits: Some(256),
        ..CreateKeyAction::default()
    }
    .run(client)
    .await
    .unwrap()
    .to_string()
}

#[tokio::test]
async fn characterization_client_side_decrypt_with_file_chunk_boundaries_aes_gcm() {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let kek = new_kek(client.clone()).await;
    for len in [0, 1, 15, 16, 17, 18, 19, 33, 34, 35, 36, 37, 100, 1000] {
        let out = round_trip(&kek, client.clone(), DataEncryptionAlgorithm::AesGcm, len).await;
        assert_eq!(out.len(), len);
    }
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn characterization_client_side_decrypt_with_file_chunk_boundaries_chacha() {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let kek = new_kek(client.clone()).await;
    for len in [0, 1, 17, 18, 19, 35, 36, 37, 1000] {
        let out = round_trip(
            &kek,
            client.clone(),
            DataEncryptionAlgorithm::Chacha20Poly1305,
            len,
        )
        .await;
        assert_eq!(out.len(), len);
    }
}

async fn encrypt_to_file(
    client: cosmian_kms_client::KmsClient,
    kek: &str,
    dir: &std::path::Path,
    len: usize,
) -> std::path::PathBuf {
    let input = dir.join("in.bin");
    let enc = dir.join("in.enc");
    std::fs::write(&input, pattern(len)).unwrap();
    EncryptAction {
        input_file: input,
        key_id: Some(kek.to_owned()),
        key_encryption_algorithm: Some(KeyEncryptionAlgorithm::AesGcm),
        output_file: Some(enc.clone()),
        ..EncryptAction::default()
    }
    .run(client)
    .await
    .unwrap();
    enc
}

async fn decrypt_file(
    client: cosmian_kms_client::KmsClient,
    kek: &str,
    enc: std::path::PathBuf,
    out: std::path::PathBuf,
) -> crate::error::result::KmsCliResult<()> {
    DecryptAction {
        input_file: enc,
        key_id: Some(kek.to_owned()),
        key_encryption_algorithm: Some(KeyEncryptionAlgorithm::AesGcm),
        output_file: Some(out),
        ..DecryptAction::default()
    }
    .run(client)
    .await
}

#[tokio::test]
async fn characterization_client_side_decrypt_with_file_tampered_tag() {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let kek = new_kek(client.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_to_file(client.clone(), &kek, dir.path(), 40).await;
    let mut bytes = std::fs::read(&enc).unwrap();
    let last = bytes.last_mut().unwrap();
    *last ^= 0xff;
    std::fs::write(&enc, bytes).unwrap();
    let err = decrypt_file(client, &kek, enc, dir.path().join("o"))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "OpenSSL Error: Error: OpenSSL error. Details: ErrorStack([])"
    );
}

#[tokio::test]
async fn characterization_client_side_decrypt_with_file_missing_tag() {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();
    let kek = new_kek(client.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let enc = encrypt_to_file(client.clone(), &kek, dir.path(), 0).await;
    let mut bytes = std::fs::read(&enc).unwrap();
    bytes.pop();
    std::fs::write(&enc, bytes).unwrap();
    let err = decrypt_file(client, &kek, enc, dir.path().join("o"))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "The tag is missing from the encrypted file"
    );
}
