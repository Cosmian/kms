use cosmian_kms_client::read_object_from_json_ttlv_file;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::{
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::{create_key::CreateKeyAction, rekey::ReKeyAction},
    },
    error::result::KmsCliResult,
};

const AES_KEY_SIZE: usize = 256;

#[tokio::test]
pub(crate) async fn test_rekey_symmetric_key() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let ctx = start_default_test_kms_server().await;

    // AES 256 bit key
    let id = CreateKeyAction {
        number_of_bits: Some(AES_KEY_SIZE),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export as default (JsonTTLV with Raw Key Format Type)
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("aes_sym"),
        key_id: Some(id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // ReKey: per KMIP spec, creates a new key with a new UID
    let new_id = ReKeyAction {
        key_id: id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;

    // The new key MUST have a different UID than the old key
    assert_ne!(id, new_id);

    // Export the new key using its new UID
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("aes_sym_2"),
        key_id: Some(new_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Compare the symmetric key bytes: must be different
    let old_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym"))?;
    let new_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_2"))?;
    assert_ne!(
        old_object.key_block()?.key_bytes()?,
        new_object.key_block()?.key_bytes()?
    );

    // The new key must have the same cryptographic length
    assert_eq!(
        new_object.attributes()?.cryptographic_length.unwrap(),
        i32::try_from(AES_KEY_SIZE).unwrap()
    );

    // The old key remains Active after ReKey (KMIP 2.1 §6.1.46 does NOT deactivate it)
    // so it should still be exportable without allow_revoked
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("aes_sym_old_after_rekey"),
        key_id: Some(id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Verify the old key still has the same material as before ReKey
    let old_after_rekey =
        read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_old_after_rekey"))?;
    assert_eq!(
        old_object.key_block()?.key_bytes()?,
        old_after_rekey.key_block()?.key_bytes()?
    );

    Ok(())
}
