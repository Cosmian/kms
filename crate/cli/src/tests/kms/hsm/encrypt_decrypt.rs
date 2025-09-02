#[cfg(feature = "non-fips")]
use std::{fs, path::PathBuf};

use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_client::{
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use tempfile::TempDir;
use test_kms_server::TestsContext;
#[cfg(feature = "non-fips")]
use tracing::trace;
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::actions::kms::rsa::{
    decrypt::DecryptAction, encrypt::EncryptAction, keys::create_key_pair::CreateKeyPairAction,
};
use crate::{
    actions::kms::symmetric::{KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction},
    error::result::KmsCliResult,
    tests::kms::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
};

pub(crate) async fn test_aes_gcm(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(None);

    let dek = CreateKeyAction {
        key_id: Some("hsm::0::".to_owned() + &Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* tag */
    )
    .await
}

#[cfg(feature = "non-fips")]
pub(crate) async fn test_rsa_pkcs_oaep(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(None);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction {
        private_key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcsOaep,
        hash_fn: HashFn::Sha256,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    // the user key should NOT be able to decrypt with another algorithm
    assert!(
        DecryptAction {
            input_file: output_file.clone(),
            key_id: Some(private_key_id.to_string()),
            tags: None,
            encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaAesKeyWrap,
            hash_fn: HashFn::Sha256,
            output_file: Some(recovered_file.clone())
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    //TODO: The Proteccio HSM only offers SH256 as hash function; maybe this test should be revisited
    // // ... or another hash function
    // assert!(
    //     decrypt(
    //         KSM_HSM_CLIENT_CONF,
    //         output_file.to_str().unwrap(),
    //         &private_key_id,
    //         EncryptionAlgorithm::CkmRsaPkcsOaep,
    //         Some(HashFn::Sha1),
    //         Some(recovered_file.to_str().unwrap()),
    //         None,
    //     )
    //     .is_err()
    // );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}

#[cfg(feature = "non-fips")]
pub(crate) async fn test_rsa_pkcs_v15(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(None);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../test_data/plain.txt");
    let output_file = tmp_path.join("plain.enc");
    let recovered_file = tmp_path.join("plain.txt");

    fs::remove_file(&output_file).ok();
    assert!(!output_file.exists());

    let (private_key_id, public_key_id) = CreateKeyPairAction {
        private_key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    trace!("private_key_id: {private_key_id}");
    trace!("public_key_id: {public_key_id}");
    EncryptAction {
        input_file: input_file.clone(),
        key_id: Some(public_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcs,
        hash_fn: HashFn::Sha256,
        output_file: Some(output_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;

    // the user key should be able to decrypt the file
    DecryptAction {
        input_file: output_file.clone(),
        key_id: Some(private_key_id.to_string()),
        tags: None,
        encryption_algorithm: RsaEncryptionAlgorithm::CkmRsaPkcs,
        hash_fn: HashFn::Sha256,
        output_file: Some(recovered_file.clone()),
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(recovered_file.exists());
    assert_eq!(
        read_bytes_from_file(&input_file)?,
        read_bytes_from_file(&recovered_file)?
    );

    let original_content = read_bytes_from_file(&input_file)?;
    let recovered_content = read_bytes_from_file(&recovered_file)?;
    assert_eq!(original_content, recovered_content);

    Ok(())
}
