use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_operations::GetAttributes,
        kmip_types::{LinkType, UniqueIdentifier},
    },
    read_object_from_json_ttlv_file,
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::{
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::{
            create_key::CreateKeyAction, rekey::ReKeyAction,
            set_rotation_policy::SetRotationPolicyAction,
        },
    },
    error::result::KmsCliResult,
};

/// Fetch all attributes for `uid` via the KMIP `GetAttributes` HTTP endpoint.
async fn get_all_attrs_cli(
    client: &KmsClient,
    uid: &str,
) -> KmsCliResult<cosmian_kms_client::kmip_2_1::kmip_attributes::Attributes> {
    Ok(client
        .get_attributes(GetAttributes {
            unique_identifier: Some(UniqueIdentifier::TextString(uid.to_owned())),
            attribute_reference: None,
        })
        .await?
        .attributes)
}

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

    // and rekey it — must produce a NEW unique identifier
    let id_2 = ReKeyAction {
        key_id: id.to_string(),
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_ne!(id, id_2, "rekey must produce a new unique identifier");

    // Export the NEW key (id_2) to compare material
    ExportSecretDataOrKeyAction {
        key_file: tmp_path.join("aes_sym_2"),
        key_id: Some(id_2.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Compare the symmetric key bytes
    let old_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym"))?;
    let new_object = read_object_from_json_ttlv_file(&tmp_path.join("aes_sym_2"))?;
    assert_ne!(
        old_object.key_block()?.key_bytes()?,
        new_object.key_block()?.key_bytes()?
    );

    // Cryptographic parameters must be preserved
    assert_eq!(
        new_object.attributes()?.cryptographic_length.unwrap(),
        i32::try_from(AES_KEY_SIZE).unwrap()
    );

    Ok(())
}

/// Test that after a manual rekey (`re-key`) the KMIP link chain is set up correctly:
///  - old key carries `ReplacementObjectLink` → new key UID
///  - new key carries `ReplacedObjectLink` → old key UID
///
/// We first configure a rotation policy on the key to confirm that manual rekey
/// behaves correctly regardless of any pre-existing rotation policy.
#[tokio::test]
async fn test_rekey_sets_link_chain_after_rotation_policy() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let client = ctx.get_owner_client();

    // Create AES-256 key.
    let old_id = CreateKeyAction {
        number_of_bits: Some(AES_KEY_SIZE),
        ..Default::default()
    }
    .run(client.clone())
    .await?
    .to_string();

    // Arm the key with a rotation policy so the rekey happens with a policy in place.
    SetRotationPolicyAction {
        key_id: old_id.clone(),
        interval: Some(3600),
        name: Some("hourly".to_owned()),
        offset: None,
    }
    .run(client.clone())
    .await?;

    // Perform a manual rekey.
    let new_id = ReKeyAction {
        key_id: old_id.clone(),
    }
    .run(client.clone())
    .await?
    .to_string();

    assert_ne!(old_id, new_id, "rekey must produce a new unique identifier");

    // Old key must have a ReplacementObjectLink pointing to the new key.
    let old_attrs = get_all_attrs_cli(&client, &old_id).await?;
    let replacement_link = old_attrs
        .get_link(LinkType::ReplacementObjectLink)
        .expect("old key must carry ReplacementObjectLink after manual rekey");
    assert_eq!(
        replacement_link.to_string(),
        new_id,
        "ReplacementObjectLink on old key must point to the new key UID"
    );

    // New key must have a ReplacedObjectLink pointing back to the old key.
    let new_attrs = get_all_attrs_cli(&client, &new_id).await?;
    let replaced_link = new_attrs
        .get_link(LinkType::ReplacedObjectLink)
        .expect("new key must carry ReplacedObjectLink after manual rekey");
    assert_eq!(
        replaced_link.to_string(),
        old_id,
        "ReplacedObjectLink on new key must point to the old key UID"
    );

    Ok(())
}
