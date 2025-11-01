use cosmian_kms_client::{
    read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::export_utils::ExportKeyFormat,
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::{
        opaque_object::{
            create::CreateOpaqueObjectAction, destroy::DestroyOpaqueObjectAction,
            revoke::RevokeOpaqueObjectAction,
        },
        shared::ExportSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_opaque_object_crud() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Create via inline data
    let opaque_id = CreateOpaqueObjectAction {
        data: Some("opaque-bytes".to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Export JSON TTLV
    let json_path = tmp_path.join("opaque.json");
    ExportSecretDataOrKeyAction {
        key_file: json_path.clone(),
        key_id: Some(opaque_id.to_string()),
        export_format: ExportKeyFormat::JsonTtlv,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let object = read_object_from_json_ttlv_file(&json_path)?;
    assert!(matches!(
        object,
        cosmian_kmip::kmip_2_1::kmip_objects::Object::OpaqueObject(_)
    ));

    // Export Base64
    let b64_path = tmp_path.join("opaque.b64");
    ExportSecretDataOrKeyAction {
        key_file: b64_path.clone(),
        key_id: Some(opaque_id.to_string()),
        export_format: ExportKeyFormat::Base64,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    assert!(b64_path.exists());

    // Export Raw (returns bytes for OpaqueObject)
    let raw_path = tmp_path.join("opaque.raw");
    ExportSecretDataOrKeyAction {
        key_file: raw_path.clone(),
        key_id: Some(opaque_id.to_string()),
        export_format: ExportKeyFormat::Raw,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let raw = std::fs::read(&raw_path)?;
    assert_eq!(raw, b"opaque-bytes".to_vec());

    // Revoke then Destroy (not removed)
    RevokeOpaqueObjectAction {
        revocation_reason: "test-revoke".to_string(),
        object_id: Some(opaque_id.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    DestroyOpaqueObjectAction {
        object_id: Some(opaque_id.to_string()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    Ok(())
}
