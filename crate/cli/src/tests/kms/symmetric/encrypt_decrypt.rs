use std::{fs, path::PathBuf};

use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::kmip_types::UniqueIdentifier,
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::{
        create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
    },
};
use cosmian_logger::log_init;
use strum::IntoEnumIterator;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::symmetric::{
        DecryptAction, EncryptAction, KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
};

pub(crate) async fn run_encrypt_decrypt_test(
    kms_client: &KmsClient,
    key_id: &UniqueIdentifier,
    data_encryption_algorithm: DataEncryptionAlgorithm,
    key_encryption_algorithm: Option<KeyEncryptionAlgorithm>,
    encryption_overhead: u64,
) -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(KmsCliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )));
    }

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(key_id.to_string()),
        data_encryption_algorithm,
        key_encryption_algorithm,
        tags: None,
        output_file: Some(output_file.clone()),
        nonce: None,
        authentication_data: Some(hex::encode(b"myid")),
    }
    .run(kms_client.clone())
    .await?;

    if encryption_overhead != 0 {
        assert_eq!(
            fs::metadata(output_file.clone())?.len(),
            fs::metadata(input_file.clone())?.len() + encryption_overhead
        );
    }

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(key_id.to_string()),
        data_encryption_algorithm,
        key_encryption_algorithm,
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some(hex::encode(b"myid")),
    }
    .run(kms_client.clone())
    .await?;

    if !recovered_file.exists() {
        return Err(KmsCliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )));
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(KmsCliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )));
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_server_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        None,
        12 /* nonce */  + 16, // tag
    )
    .await
}

#[tokio::test]
async fn test_aes_cbc_server_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesCbc,
        None,
        8 /* padding */ + 16, // iv
    )
    .await
}

#[tokio::test]
async fn test_aes_xts_server_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(512),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesXts,
        None,
        16, // tweak
    )
    .await
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_aes_gcm_siv_server_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcmSiv,
        None,
        12 /* nonce */ + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_chacha20_poly1305_server_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let dek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Chacha20,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        None,
        12 /* nonce */ + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_encrypt_decrypt_with_tags() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;
    let key_id = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        tags: vec!["tag_sym".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    if output_file.exists() {
        return Err(KmsCliError::Default(format!(
            "Output file {} could not be removed",
            output_file.to_str().unwrap()
        )));
    }

    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(key_id.to_string()),
        data_encryption_algorithm: DataEncryptionAlgorithm::Chacha20Poly1305,
        key_encryption_algorithm: None,
        tags: None,
        output_file: Some(output_file.clone()),
        nonce: None,
        authentication_data: Some(hex::encode(b"myid")),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(key_id.to_string()),
        data_encryption_algorithm: DataEncryptionAlgorithm::Chacha20Poly1305,
        key_encryption_algorithm: None,
        tags: None,
        output_file: Some(recovered_file.clone()),
        authentication_data: Some(hex::encode(b"myid")),
    }
    .run(ctx.get_owner_client())
    .await?;
    if !recovered_file.exists() {
        return Err(KmsCliError::Default(format!(
            "Recovered file {} does not exist",
            recovered_file.to_str().unwrap()
        )));
    }

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    if original_content != recovered_content {
        return Err(KmsCliError::Default(format!(
            "Recovered content in file {} does not match the original file content {}",
            recovered_file.to_str().unwrap(),
            input_file.to_str().unwrap()
        )));
    }

    Ok(())
}

#[tokio::test]
async fn test_aes_gcm_aes_gcm_client_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[tokio::test]
async fn test_aes_gcm_aes_xts_client_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &kek,
        DataEncryptionAlgorithm::AesXts,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 64 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 16, // tweak
    )
    .await
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_aes_gcm_chacha20_client_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &kek,
        DataEncryptionAlgorithm::Chacha20Poly1305,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[tokio::test]
async fn test_rfc5649_aes_gcm_client_side() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let kek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &kek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::RFC5649),
        8 + 32 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */ + 16, // tag
    )
    .await
}

#[tokio::test]
async fn test_client_side_encryption_with_buffer() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    let ctx = start_default_test_kms_server().await;
    let kek = CreateKeyAction {
        algorithm: SymmetricAlgorithm::Aes,
        number_of_bits: Some(256),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    // Generate an ephemeral key (DEK) and wrap it with the KEK.
    let (dek, encapsulation) = EncryptAction::default()
        .server_side_kem_encapsulation(
            ctx.get_owner_client(),
            &kek.to_string(),
            KeyEncryptionAlgorithm::RFC5649,
            DataEncryptionAlgorithm::AesGcm,
        )
        .await?;

    for size in [0, 1, 16, 64, 256, 1024, 4096, 16384] {
        let plaintext: Vec<u8> = vec![0; size];
        for dea in DataEncryptionAlgorithm::iter() {
            if dea == DataEncryptionAlgorithm::AesXts {
                continue;
            }
            let ciphertext = EncryptAction::default().client_side_encrypt_with_buffer(
                &dek,
                &encapsulation,
                dea,
                None,
                &plaintext,
                Some(hex::encode(b"my_auth_data").into_bytes()),
            )?;

            let cleartext = DecryptAction::default()
                .client_side_decrypt_with_buffer(
                    &ctx.get_owner_client(),
                    dea,
                    &kek.to_string(),
                    &ciphertext,
                    Some(hex::encode(b"my_auth_data").into_bytes()),
                )
                .await?;

            assert_eq!(cleartext, plaintext);
        }
    }

    Ok(())
}
