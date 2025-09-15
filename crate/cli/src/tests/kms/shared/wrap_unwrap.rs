use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_client::{
    cosmian_kmip::kmip_2_1::kmip_types::{EncodingOption, WrappingMethod},
    kmip_2_1::kmip_types::UniqueIdentifier,
    read_object_from_json_ttlv_file,
};
use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
    CsRng,
    reexport::rand_core::{RngCore, SeedableRng},
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

use crate::{
    actions::kms::{
        cover_crypt::keys::create_key_pair::CreateMasterKeyPairAction,
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction as CreateEcKeyPairAction,
        shared::{
            ExportSecretDataOrKeyAction, UnwrapSecretDataOrKeyAction, WrapSecretDataOrKeyAction,
        },
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_password_wrap_import() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // CC
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
    password_wrap_import_test(ctx, "cc", &private_key_id).await?;

    // EC
    let (private_key_id, _public_key_id) = CreateEcKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;
    password_wrap_import_test(ctx, "ec", &private_key_id).await?;

    // sym
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;
    password_wrap_import_test(ctx, "sym", &key_id).await?;

    Ok(())
}

pub(crate) async fn password_wrap_import_test(
    ctx: &TestsContext,
    sub_command: &str,
    private_key_id: &UniqueIdentifier,
) -> KmsCliResult<()> {
    let temp_dir = TempDir::new()?;

    // Export
    let key_file = temp_dir.path().join("master_private.key");
    ExportSecretDataOrKeyAction {
        key_id: Some(private_key_id.to_string()),
        key_file: key_file.clone(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let object = read_object_from_json_ttlv_file(&key_file)?;
    let key_bytes = if sub_command == "ec" {
        object.key_block()?.ec_raw_bytes()?
    } else if sub_command == "cc" {
        object.key_block()?.covercrypt_key_bytes()?
    } else {
        object.key_block()?.key_bytes()?
    };

    //wrap and unwrap using a password
    {
        let b64_wrapping_key = WrapSecretDataOrKeyAction {
            key_file_in: key_file.clone(),
            wrap_password: Some("password".to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        let wrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::TTLVEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.wrapped_key_bytes()?, key_bytes);
        UnwrapSecretDataOrKeyAction {
            key_file_in: key_file.clone(),
            unwrap_key_b64: Some(b64_wrapping_key),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let unwrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(
            if sub_command == "ec" {
                unwrapped_object.key_block()?.ec_raw_bytes()?
            } else if sub_command == "cc" {
                unwrapped_object.key_block()?.covercrypt_key_bytes()?
            } else {
                unwrapped_object.key_block()?.key_bytes()?
            },
            key_bytes
        );
    }

    //wrap and unwrap using a base64 key
    {
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0_u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        WrapSecretDataOrKeyAction {
            key_file_in: key_file.clone(),
            wrap_key_b64: Some(key_b64.clone()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let wrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );

        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::TTLVEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.wrapped_key_bytes()?, key_bytes);
        UnwrapSecretDataOrKeyAction {
            key_file_in: key_file.clone(),
            unwrap_key_b64: Some(key_b64),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;
        let unwrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(
            if sub_command == "ec" {
                unwrapped_object.key_block()?.ec_raw_bytes()?
            } else if sub_command == "cc" {
                unwrapped_object.key_block()?.covercrypt_key_bytes()?
            } else {
                unwrapped_object.key_block()?.key_bytes()?
            },
            key_bytes
        );
    }

    // other wrap unwrap scenarios are covered by tests in utils/wrap_unwrap

    Ok(())
}
