use cosmian_kms_client::read_object_from_json_ttlv_file;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        shared::ExportKeyAction,
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
    ExportKeyAction {
        key_file: tmp_path.join("aes_sym"),
        key_id: Some(id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // and refresh it
    let id_2 = ReKeyAction {
        key_id: id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(id, id_2);

    // Export as default (JsonTTLV with Raw Key Format Type)
    ExportKeyAction {
        key_file: tmp_path.join("aes_sym_2"),
        key_id: Some(id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Compare the symmetric key bytes
    let old_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym"))?;
    let new_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_2"))?;
    assert_ne!(
        old_object.key_block()?.symmetric_key_bytes()?,
        new_object.key_block()?.symmetric_key_bytes()?
    );

    // Compare the attributes
    assert_eq!(old_object.attributes()?, new_object.attributes()?);
    assert_eq!(
        new_object.attributes()?.cryptographic_length.unwrap(),
        i32::try_from(AES_KEY_SIZE).unwrap()
    );

    Ok(())
}
