#[cfg(feature = "non-fips")]
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat;
use cosmian_kms_cli_actions::actions::symmetric::KeyEncryptionAlgorithm;
use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::symmetric_utils::DataEncryptionAlgorithm;
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use tempfile::TempDir;
#[cfg(feature = "non-fips")]
use cosmian_logger::info;
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::tests::rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair};
use crate::tests::utils::owner_config;
use crate::{
    error::result::CosmianResult,
    tests::{
        shared::{ExportKeyParams, export_key},
        symmetric::{create_key::create_symmetric_key, encrypt_decrypt::run_encrypt_decrypt_test},
    },
};
use test_kms_server::TestsContext;

pub(crate) fn test_wrap_with_aes_gcm(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));
    let owner_client_conf_path = owner_config(ctx);

    let hsm_key_id = "hsm::0::".to_string() + &Uuid::new_v4().to_string();
    let wrapping_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--sensitive",
            &hsm_key_id,
        ],
    )?;
    // println!("Wrapping key id: {wrapping_key_id}" );
    let dek_key_id = Uuid::new_v4().to_string();
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--wrapping-key-id",
            &wrapping_key_id,
            &dek_key_id,
        ],
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
pub(crate) fn test_wrap_with_rsa_oaep(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(None);
    // log_init(Some("debug"));
    let owner_client_conf_path = owner_config(ctx);

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    println!("Wrapping key id: {public_key_id}");
    let dek_key_id = Uuid::new_v4().to_string();
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--wrapping-key-id",
            &public_key_id,
            &dek_key_id,
        ],
    )?;
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &owner_client_conf_path,
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
}

#[cfg(feature = "non-fips")]
pub(crate) fn test_unwrap_on_export(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));
    let owner_client_conf_path = owner_config(ctx);

    let (_private_key_id, public_key_id) = create_rsa_key_pair(
        &owner_client_conf_path,
        &RsaKeyPairOptions {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            number_of_bits: Some(2048),
            sensitive: true,
            ..Default::default()
        },
    )?;
    info!("===> Wrapping key id: {public_key_id}");
    let dek_key_id = Uuid::new_v4().to_string();
    let dek = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--wrapping-key-id",
            &public_key_id,
            &dek_key_id,
        ],
    )?;
    info!("===> DEK id: {dek}");
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "sym".to_owned(),
        key_id: dek,
        key_file: tmp_path.join("dek.pem").to_str().unwrap().to_owned(),
        unwrap: true,
        key_format: Some(ExportKeyFormat::Raw),
        ..Default::default()
    })?;
    Ok(())
}

/// Issue #762 — `ckms sym keys unwrap -i hsm::<slot>::<id>` must work for sensitive HSM keys.
///
/// Before the fix the CLI attempted to export the HSM wrapping key locally, which failed with
/// "This key is sensitive and cannot be exported from the HSM".  The fix detects the `::` HSM
/// prefix and routes through a server-side `Import(key_wrap_type=NotWrapped)` round-trip that
/// lets the KMS crypto-oracle perform the unwrapping without ever exposing the KEK material.
pub(crate) fn test_unwrap_with_hsm_key(ctx: &TestsContext) -> CosmianResult<()> {
    use std::process::Command;

    use assert_cmd::prelude::CommandCargoExt;
    use cosmian_kms_cli_actions::reexport::cosmian_kms_client::read_object_from_json_ttlv_file;

    use crate::{
        config::CKMS_CONF_ENV,
        tests::{PROG_NAME, utils::recover_cmd_logs},
    };

    log_init(option_env!("RUST_LOG"));
    let owner_client_conf_path = owner_config(ctx);

    // Create a sensitive AES key on the HSM (non-extractable, identified by hsm:: prefix).
    let hsm_key_id = "hsm::0::".to_string() + &Uuid::new_v4().to_string();
    let wrapping_key_id = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--sensitive",
            &hsm_key_id,
        ],
    )?;

    // Create a DEK wrapped with the HSM key.
    let dek_uid = Uuid::new_v4().to_string();
    let dek_id = create_symmetric_key(
        &owner_client_conf_path,
        &[
            "--algorithm",
            "aes",
            "--number-of-bits",
            "256",
            "--wrapping-key-id",
            &wrapping_key_id,
            &dek_uid,
        ],
    )?;

    let tmp_dir = TempDir::new()?;
    let wrapped_file = tmp_dir.path().join("dek_wrapped.json");
    let unwrapped_file = tmp_dir.path().join("dek_unwrapped.json");

    // Export the DEK in KMIP JSON TTLV format — still wrapped by the HSM key.
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "sym".to_owned(),
        key_id: dek_id,
        key_file: wrapped_file.to_str().unwrap().to_owned(),
        key_format: Some(ExportKeyFormat::JsonTtlv),
        unwrap: false,
        ..Default::default()
    })?;

    // Unwrap using the server-side HSM crypto oracle (issue #762 fix).
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, &owner_client_conf_path);
    cmd.arg("sym").args([
        "keys",
        "unwrap",
        wrapped_file.to_str().unwrap(),
        unwrapped_file.to_str().unwrap(),
        "-i",
        &wrapping_key_id,
    ]);
    let output = recover_cmd_logs(&mut cmd);
    assert!(
        output.status.success(),
        "unwrap failed: {}",
        std::str::from_utf8(&output.stderr).unwrap_or("non-utf8")
    );

    // Verify the output file was produced and contains an unwrapped key.
    assert!(
        unwrapped_file.exists(),
        "unwrapped key file must be written to disk"
    );
    let unwrapped = read_object_from_json_ttlv_file(&unwrapped_file)?;
    assert!(
        !unwrapped.is_wrapped(),
        "key material in output file must not be wrapped"
    );

    Ok(())
}
