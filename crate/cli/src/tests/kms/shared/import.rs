use std::path::PathBuf;

use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::kmip_types::UniqueIdentifier, read_object_from_json_ttlv_file,
};
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

#[cfg(feature = "non-fips")]
use crate::actions::kms::{
    cover_crypt::keys::create_key_pair::CreateMasterKeyPairAction,
    elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
    symmetric::keys::create_key::CreateKeyAction,
};
use crate::{
    actions::kms::shared::{ExportKeyAction, ImportKeyAction},
    error::{KmsCliError, result::KmsCliResult},
};

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_import_cover_crypt() -> KmsCliResult<()> {
    use tempfile::TempDir;

    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (_master_secret_key_id, master_public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    let public_key_path = format!("{}", tmp_path.join("public_key.json").display());

    ExportKeyAction {
        key_id: Some(master_public_key_id.clone()),
        key_file: PathBuf::from(&public_key_path),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // reimporting the same key with the same id should fail
    assert!(
        ImportKeyAction {
            key_file: PathBuf::from(&public_key_path.to_string()),
            key_id: Some(master_public_key_id.clone()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    //...unless we force it with replace_existing
    let master_public_key_id_: String = ImportKeyAction {
        key_file: PathBuf::from(&public_key_path.to_string()),
        replace_existing: true,
        key_id: Some(master_public_key_id.clone()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    assert_eq!(master_public_key_id_, master_public_key_id);

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_generate_export_import() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    // log_init(Some("info,cosmian_kms_server=debug"));

    let ctx = start_default_test_kms_server().await;

    // Covercrypt import/export test
    let (private_key_id, _public_key_id) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0, key_ids.1)
    };
    export_import_test(&private_key_id, Some(CryptographicAlgorithm::CoverCrypt)).await?;

    // Test import/export of an EC Key Pair
    let (private_key_id, _public_key_id) = CreateEcKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;
    export_import_test(&private_key_id, Some(CryptographicAlgorithm::ECDH)).await?;

    // generate a symmetric key
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    export_import_test(&key_id, Some(CryptographicAlgorithm::AES)).await?;

    // generate a secret data
    let secret_id = crate::actions::kms::secret_data::create_secret::CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    export_import_test(&secret_id, None).await?;

    Ok(())
}

#[allow(dead_code)]
pub(crate) async fn export_import_test(
    private_key_id: &UniqueIdentifier,
    algorithm: Option<CryptographicAlgorithm>,
) -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Export
    ExportKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: PathBuf::from("/tmp/output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let object = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/output.export"))?;
    let key_bytes = match algorithm {
        None => object.key_block()?.secret_data_bytes()?,
        Some(CryptographicAlgorithm::AES) => object.key_block()?.symmetric_key_bytes()?,
        Some(CryptographicAlgorithm::ECDH) => object.key_block()?.ec_raw_bytes()?,
        Some(CryptographicAlgorithm::CoverCrypt) => object.key_block()?.covercrypt_key_bytes()?,
        x => {
            return Err(KmsCliError::Default(format!(
                "unsupported algorithm for export: {x:?}"
            )))
        }
    };

    // import and re-export
    let uid: String = ImportKeyAction {
        key_file: PathBuf::from("/tmp/output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    ExportKeyAction {
        key_id: Some(uid),
        key_file: PathBuf::from("/tmp/output2.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let object2 = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/output2.export"))?;
    let object2_key_bytes = match algorithm {
        None => object.key_block()?.secret_data_bytes()?,
        Some(CryptographicAlgorithm::AES) => object2.key_block()?.symmetric_key_bytes()?,
        Some(CryptographicAlgorithm::ECDH) => object2.key_block()?.ec_raw_bytes()?,
        Some(CryptographicAlgorithm::CoverCrypt) => object2.key_block()?.covercrypt_key_bytes()?,
        x => {
            return Err(KmsCliError::Default(format!(
                "unsupported algorithm for export: {x:?}"
            )))
        }
    };
    assert_eq!(object2_key_bytes, key_bytes);
    assert_eq!(object2.key_block()?.cryptographic_algorithm, algorithm);
    assert!(object2.key_block()?.key_wrapping_data.is_none());

    Ok(())
}
