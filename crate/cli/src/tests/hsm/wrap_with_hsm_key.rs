use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    actions::{
        shared::ExportKeyFormat,
        symmetric::{DataEncryptionAlgorithm, KeyEncryptionAlgorithm},
    },
    error::result::CliResult,
    tests::{
        hsm::KMS_HSM_CLIENT_CONF,
        rsa::create_key_pair::{create_rsa_key_pair, RsaKeyPairOptions},
        shared::{export_key, ExportKeyParams},
        symmetric::{
            create_key::{create_symmetric_key, SymKeyOptions},
            encrypt_decrypt::run_encrypt_decrypt_test,
        },
    },
};

#[test]
pub(crate) fn test_wrap_with_aes_gcm() -> CliResult<()> {
    let wrapping_key_id = create_symmetric_key(
        KMS_HSM_CLIENT_CONF,
        &SymKeyOptions {
            key_id: Some("hsm::4::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: Some("aes".to_string()),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {}", wrapping_key_id);
    // let wrapping_key_id = "hsm::4::a44cca9e-a02a-49a0-998b-19d0924e9c6f".to_string();
    let dek = create_symmetric_key(
        KMS_HSM_CLIENT_CONF,
        &SymKeyOptions {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: Some("aes".to_string()),
            wrapping_key_id: Some(wrapping_key_id.clone()),
            ..Default::default()
        },
    )?;
    run_encrypt_decrypt_test(
        KMS_HSM_CLIENT_CONF,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        KMS_HSM_CLIENT_CONF,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[test]
pub(crate) fn test_wrap_with_rsa_oaep() -> CliResult<()> {
    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        KMS_HSM_CLIENT_CONF,
        &RsaKeyPairOptions {
            key_id: Some("hsm::4::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {}", public_key_id);
    let dek = create_symmetric_key(
        KMS_HSM_CLIENT_CONF,
        &SymKeyOptions {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: Some("aes".to_string()),
            wrapping_key_id: Some(public_key_id.clone()),
            ..Default::default()
        },
    )?;
    // let dek = "fad76bbe-4d53-421a-bcfa-e3af34318ecc".to_string();
    run_encrypt_decrypt_test(
        KMS_HSM_CLIENT_CONF,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        KMS_HSM_CLIENT_CONF,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, /* ag */
    )
}

#[test]
pub(crate) fn test_unwrap_on_export() -> CliResult<()> {
    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        KMS_HSM_CLIENT_CONF,
        &RsaKeyPairOptions {
            key_id: Some("hsm::4::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {}", public_key_id);
    let dek = create_symmetric_key(
        KMS_HSM_CLIENT_CONF,
        &SymKeyOptions {
            key_id: Some(Uuid::new_v4().to_string()),
            number_of_bits: Some(256),
            algorithm: Some("aes".to_string()),
            wrapping_key_id: Some(public_key_id.clone()),
            ..Default::default()
        },
    )?;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // let dek = "b558d64c-07a8-4ce4-8e88-d86756249672".to_string();
    export_key(ExportKeyParams {
        cli_conf_path: KMS_HSM_CLIENT_CONF.to_owned(),
        sub_command: "sym".to_owned(),
        key_id: dek,
        key_file: tmp_path.join("dek.pem").to_str().unwrap().to_owned(),
        unwrap: true,
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    Ok(())
}
