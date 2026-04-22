#[cfg(feature = "non-fips")]
use cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat;
use cosmian_kms_client::reexport::cosmian_kms_client_utils::{
    create_utils::SymmetricAlgorithm, symmetric_utils::DataEncryptionAlgorithm,
};
use cosmian_logger::{info, log_init};
use tempfile::TempDir;
use test_kms_server::TestsContext;
use uuid::Uuid;

use crate::{
    actions::{
        shared::{ExportSecretDataOrKeyAction, UnwrapSecretDataOrKeyAction},
        symmetric::{KeyEncryptionAlgorithm, keys::create_key::CreateKeyAction},
    },
    error::result::KmsCliResult,
    tests::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
};

pub(super) async fn test_wrap_with_aes_gcm(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));

    let wrapping_key_id = CreateKeyAction {
        key_id: Some("hsm::utimaco::0::".to_owned() + &Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("Created wrapping key: {wrapping_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    info!("Created DEK: {dek}");
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
    .await?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
pub(super) async fn test_wrap_with_rsa_oaep(ctx: &TestsContext) -> KmsCliResult<()> {
    use crate::{
        actions::rsa::keys::create_key_pair::CreateKeyPairAction,
        tests::symmetric::encrypt_decrypt::run_encrypt_decrypt_test,
    };

    log_init(None);
    // log_init(Some("debug"));

    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        private_key_id: Some("hsm::utimaco::0::".to_string() + &Uuid::new_v4().to_string()),
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("Wrapping key id: {public_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(public_key_id.to_string()),
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
            + 12 /* nonce */  + 16, // ag
    )
    .await?;
    // Hit the unwrap cache this time
    run_encrypt_decrypt_test(
        &ctx.get_owner_client(),
        &dek,
        DataEncryptionAlgorithm::AesGcm,
        Some(KeyEncryptionAlgorithm::AesGcm),
        12 + 32 + 16 /* encapsulation size */
            + 1 /* encapsulation len leb128 */
            + 12 /* nonce */  + 16, // ag
    )
    .await
}

#[cfg(feature = "non-fips")]
pub(super) async fn test_unwrap_on_export(ctx: &TestsContext) -> KmsCliResult<()> {
    use crate::actions::{
        rsa::keys::create_key_pair::CreateKeyPairAction, shared::ExportSecretDataOrKeyAction,
    };

    log_init(option_env!("RUST_LOG"));
    // log_init(Some("debug"));

    let (_private_key_id, public_key_id) = CreateKeyPairAction {
        key_size: 2048,
        private_key_id: Some("hsm::utimaco::0::".to_string() + &Uuid::new_v4().to_string()),
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> Wrapping key id: {public_key_id}");

    let dek = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(public_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> DEK id: {dek}");

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // TODO: Replace with equivalent export action when available
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("dek.pem"),
        key_id: Some(dek.to_string()),
        export_format: ExportKeyFormat::Raw,
        unwrap: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    Ok(())
}

/// Issue #762 — `ckms sym keys unwrap -i hsm::<slot>::<id>` must work for sensitive HSM keys.
///
/// Before the fix the CLI attempted to export the HSM wrapping key locally, which failed with
/// "This key is sensitive and cannot be exported from the HSM".  The fix detects the `::` HSM
/// prefix and routes through a server-side `Import(key_wrap_type=NotWrapped)` round-trip that
/// lets the KMS crypto-oracle perform the unwrapping without ever exposing the KEK material.
pub(super) async fn test_unwrap_with_hsm_key(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));

    // Create a sensitive AES key on the HSM (non-extractable, identified by hsm:: prefix).
    let wrapping_key_id = CreateKeyAction {
        key_id: Some("hsm::utimaco::0::".to_owned() + &Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        sensitive: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> Wrapping key id: {wrapping_key_id}");

    // Create a DEK wrapped with the HSM key.
    let dek_id = CreateKeyAction {
        key_id: Some(Uuid::new_v4().to_string()),
        number_of_bits: Some(256),
        algorithm: SymmetricAlgorithm::Aes,
        wrapping_key_id: Some(wrapping_key_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    info!("===> DEK id: {dek_id}");

    let tmp_dir = TempDir::new()?;
    let wrapped_file = tmp_dir.path().join("dek_wrapped.json");
    let unwrapped_file = tmp_dir.path().join("dek_unwrapped.json");

    // Export the DEK in KMIP JSON TTLV format — still wrapped by the HSM key.
    ExportSecretDataOrKeyAction {
        key_file: wrapped_file.clone(),
        key_id: Some(dek_id.to_string()),
        export_format: cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat::JsonTtlv,
        unwrap: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Unwrap using the server-side HSM crypto oracle (issue #762 fix).
    // The `::` in the key ID causes `UnwrapSecretDataOrKeyAction` to delegate
    // unwrapping to the KMS server instead of trying to export the HSM key.
    Box::pin(
        UnwrapSecretDataOrKeyAction {
            key_file_in: wrapped_file,
            key_file_out: Some(unwrapped_file.clone()),
            unwrap_key_id: Some(wrapping_key_id.to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // Verify the output file was produced and contains an unwrapped key.
    assert!(
        unwrapped_file.exists(),
        "unwrapped key file must be written to disk"
    );
    let unwrapped = cosmian_kms_client::read_object_from_json_ttlv_file(&unwrapped_file)?;
    assert!(
        !unwrapped.is_wrapped(),
        "key material in output file must not be wrapped"
    );

    Ok(())
}
