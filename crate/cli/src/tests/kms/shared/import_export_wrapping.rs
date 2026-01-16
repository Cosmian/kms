use std::path::PathBuf;

use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::{
        kmip_objects::Object,
        kmip_types::{CryptographicAlgorithm, LinkType, UniqueIdentifier, WrappingMethod},
    },
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_data_structures::KeyValue,
        requests::create_symmetric_key_kmip_object,
    },
    read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::import_utils::KeyUsage,
    write_kmip_object_to_file,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_crypto::crypto::elliptic_curves::operation::create_x25519_key_pair;
use cosmian_kms_crypto::{
    crypto::wrap::unwrap_key_block,
    reexport::cosmian_crypto_core::{
        CsRng,
        reexport::rand_core::{RngCore, SeedableRng},
    },
};
use cosmian_logger::{debug, log_init, trace};
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::{
        cover_crypt::keys::create_key_pair::CreateMasterKeyPairAction,
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
        shared::{ExportSecretDataOrKeyAction, ImportSecretDataOrKeyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_import_export_wrap_rfc_5649() -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;
    // Generate a symmetric wrapping key
    let wrap_key_path = tmp_path.join("wrap.key");
    let mut rng = CsRng::from_entropy();
    let mut wrap_key_bytes = vec![0; 32];
    rng.fill_bytes(&mut wrap_key_bytes);
    let wrap_key = create_symmetric_key_kmip_object(
        &wrap_key_bytes,
        &Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),

            ..Default::default()
        },
    )?;
    write_kmip_object_to_file(&wrap_key, &wrap_key_path)?;

    // import the wrapping key
    trace!("importing wrapping key");
    let wrap_key_uid = ImportSecretDataOrKeyAction {
        key_file: wrap_key_path.clone(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // test CC
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
    test_import_export_wrap_private_key(ctx, &private_key_id, &wrap_key_uid, &wrap_key).await?;

    // test ec
    let (private_key_id, _public_key_id) = CreateEcKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;
    test_import_export_wrap_private_key(ctx, &private_key_id, &wrap_key_uid, &wrap_key).await?;

    // test sym
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    test_import_export_wrap_private_key(ctx, &key_id, &wrap_key_uid, &wrap_key).await?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
pub(crate) async fn test_import_export_wrap_ecies() -> KmsCliResult<()> {
    use cosmian_kms_client::kmip_0::kmip_types::CryptographicUsageMask;

    test_kms_server::init_test_logging();
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // init the test server
    let ctx = start_default_test_kms_server().await;
    // Generate a symmetric wrapping key
    let wrap_private_key_uid = "wrap_private_key_uid";
    let wrap_public_key_uid = "wrap_public_key_uid";

    let wrap_key_pair = create_x25519_key_pair(
        wrap_private_key_uid,
        wrap_public_key_uid,
        &CryptographicAlgorithm::EC,
        Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        },
        Some(Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Decrypt | CryptographicUsageMask::UnwrapKey,
            ),
            ..Default::default()
        }),
        Some(Attributes {
            cryptographic_usage_mask: Some(
                CryptographicUsageMask::Encrypt | CryptographicUsageMask::WrapKey,
            ),
            ..Default::default()
        }),
    )?;
    // Write the private key to a file and import it
    let wrap_private_key_path = tmp_path.join("wrap.private.key");
    write_kmip_object_to_file(wrap_key_pair.private_key(), &wrap_private_key_path)?;
    ImportSecretDataOrKeyAction {
        key_file: wrap_private_key_path.clone(),
        key_id: Some(wrap_private_key_uid.to_string()),
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // Write the public key to a file and import it
    let wrap_public_key_path = tmp_path.join("wrap.public.key");
    write_kmip_object_to_file(wrap_key_pair.public_key(), &wrap_public_key_path)?;
    let wrap_public_key_uid = ImportSecretDataOrKeyAction {
        key_file: wrap_public_key_path.clone(),
        replace_existing: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // test CC
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
    test_import_export_wrap_private_key(
        ctx,
        &private_key_id,
        &wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )
    .await?;

    debug!("testing EC keys");
    let (private_key_id, _public_key_id) = CreateEcKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;
    test_import_export_wrap_private_key(
        ctx,
        &private_key_id,
        &wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )
    .await?;

    debug!("testing symmetric keys");
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    test_import_export_wrap_private_key(
        ctx,
        &key_id,
        &wrap_public_key_uid,
        wrap_key_pair.private_key(),
    )
    .await?;
    Ok(())
}

async fn test_import_export_wrap_private_key(
    ctx: &TestsContext,
    private_key_id: &UniqueIdentifier,
    wrapping_key_uid: &UniqueIdentifier,
    unwrapping_key: &Object,
) -> KmsCliResult<()> {
    log_init(None);
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // Export the private key without wrapping
    let private_key_file = tmp_path.join("master_private.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: private_key_file.clone(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let private_key = read_object_from_json_ttlv_file(&private_key_file)?;

    // Export the private key with wrapping
    let wrapped_private_key_file = tmp_path.join("wrapped_master_private.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: wrapped_private_key_file.clone(),
        wrap_key_id: Some(wrapping_key_uid.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // test the exported private key with wrapping
    {
        let mut wrapped_private_key = read_object_from_json_ttlv_file(&wrapped_private_key_file)?;
        let wrapped_key_wrapping_data = wrapped_private_key.key_wrapping_data().unwrap();
        assert_eq!(
            wrapped_key_wrapping_data.wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .unique_identifier,
            *wrapping_key_uid
        );
        assert!(
            wrapped_key_wrapping_data
                .encryption_key_information
                .clone()
                .unwrap()
                .cryptographic_parameters
                .is_none()
        );
        unwrap_key_block(wrapped_private_key.key_block_mut()?, unwrapping_key)?;
        trace!(
            "wrapped_private_key: key_block after unwrapping: {}",
            wrapped_private_key.key_block()?
        );
        trace!(
            "private_key: key_block after unwrapping: {}",
            private_key.key_block()?
        );

        assert_eq!(
            wrapped_private_key.key_block()?.key_value,
            private_key.key_block()?.key_value
        );
    };

    // test the unwrapping on import
    {
        // import the wrapped key, unwrapping it on import
        let unwrapped_key_id = ImportSecretDataOrKeyAction {
            key_file: wrapped_private_key_file.clone(),
            replace_existing: true,
            unwrap: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        // re-export it as registered and check it was correctly unwrapped
        let re_exported_key_file = tmp_path.join("re_exported_master_private.key");
        ExportSecretDataOrKeyAction {
            key_id: Some(unwrapped_key_id.to_string()),
            key_file: re_exported_key_file.clone(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let re_exported_key = read_object_from_json_ttlv_file(&re_exported_key_file)?;
        let re_exported_key_material = {
            let Some(KeyValue::Structure { key_material, .. }) =
                &re_exported_key.key_block()?.key_value
            else {
                panic!("Key value is not a structure");
            };
            key_material
        };
        let private_key_key_material = {
            let Some(KeyValue::Structure { key_material, .. }) =
                &private_key.key_block()?.key_value
            else {
                panic!("Key value is not a structure");
            };
            key_material
        };
        assert_eq!(re_exported_key_material, private_key_key_material);
        assert_eq!(
            re_exported_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink),
            private_key
                .key_block()?
                .attributes()?
                .get_link(LinkType::PublicKeyLink)
        );
        assert!(re_exported_key.key_wrapping_data().is_none());
    };

    // test the unwrapping on export
    {
        // import the wrapped key, un wrapping it on import
        let wrapped_key_id = ImportSecretDataOrKeyAction {
            key_file: wrapped_private_key_file.clone(),
            replace_existing: true,
            unwrap: false,
            key_usage: Some(vec![KeyUsage::Unrestricted]),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        // re-export it as registered and check it was correctly unwrapped
        let exported_unwrapped_key_file = tmp_path.join("exported_unwrapped_master_private.key");
        ExportSecretDataOrKeyAction {
            key_id: Some(wrapped_key_id.to_string()),
            key_file: exported_unwrapped_key_file.clone(),
            unwrap: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let mut exported_unwrapped_key =
            read_object_from_json_ttlv_file(&exported_unwrapped_key_file)?;
        // keys should be identical save for the UniqueIdentifier attribute
        let exp_attrs = exported_unwrapped_key.key_block_mut()?.attributes_mut()?;
        exp_attrs.unique_identifier = private_key
            .key_block()?
            .attributes()?
            .unique_identifier
            .clone();

        // Fresh may legitimately be materialized as `Some(false)` after key material
        // is returned (e.g., via unwrap-on-export). Ignore it for this equivalence check.
        exp_attrs.fresh = None;

        assert_eq!(
            exported_unwrapped_key.key_block()?.key_value,
            private_key.key_block()?.key_value
        );
        assert!(exported_unwrapped_key.key_wrapping_data().is_none());
    };

    Ok(())
}
