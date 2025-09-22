use cosmian_kms_client::{
    kmip_2_1::kmip_data_structures::{KeyMaterial, KeyValue},
    read_object_from_json_ttlv_file,
};
use cosmian_logger::trace;
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};

#[cfg(feature = "non-fips")]
use crate::actions::kms::cover_crypt::keys::{
    create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
};
use crate::{
    actions::kms::{
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction,
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::{
            create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
        },
    },
    cli_bail,
    error::result::KmsCliResult,
};

async fn assert_destroyed(ctx: &TestsContext, key_id: &str, remove: bool) -> KmsCliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // should not be able to Get....
    ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_owned()),
        key_file: tmp_path.join("output.export"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // depending on whether the key is removed or not,
    // the key metadata should be exportable or not
    let export_res = ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_owned()),
        key_file: tmp_path.join("output.export"),
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    if remove {
        assert!(export_res.is_err());
    } else {
        export_res.unwrap();
        let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
        let Some(KeyValue::Structure { key_material, .. }) = &object.key_block()?.key_value else {
            cli_bail!("Invalid key value");
        };
        match &key_material {
            KeyMaterial::ByteString(v) => {
                assert!(v.is_empty());
            }
            _ => cli_bail!("Invalid key material"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_symmetric_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Create symmetric key
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?
        .to_string();

    // destroy should not work when not revoked
    DestroyKeyAction {
        key_id: Some(key_id.clone()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // revoke then destroy
    RevokeKeyAction {
        key_id: Some(key_id.clone()),
        revocation_reason: "revocation test".to_owned(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    DestroyKeyAction {
        key_id: Some(key_id.clone()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // assert
    assert_destroyed(ctx, &key_id, false).await
}

#[tokio::test]
async fn test_destroy_and_remove_symmetric_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Create symmetric key
    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await
        .unwrap()
        .to_string();

    // destroy should not work when not revoked
    DestroyKeyAction {
        key_id: Some(key_id.clone()),
        remove: true,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // revoke then destroy
    RevokeKeyAction {
        key_id: Some(key_id.clone()),
        revocation_reason: "revocation test".to_owned(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    DestroyKeyAction {
        key_id: Some(key_id.clone()),
        remove: true,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    // assert
    assert_destroyed(ctx, &key_id, true).await
}

#[tokio::test]
async fn test_destroy_ec_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // destroy via private key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        // destroy should not work when not revoked
        DestroyKeyAction {
            key_id: Some(private_key_id.to_string()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(private_key_id.to_string()),
            revocation_reason: "revocation test".to_owned(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        DestroyKeyAction {
            key_id: Some(private_key_id.to_string()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &private_key_id.to_string(), false).await?;
        assert_destroyed(ctx, &public_key_id.to_string(), false).await?;
    }

    // destroy via public key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        // destroy should not work when not revoked
        DestroyKeyAction {
            key_id: Some(public_key_id.to_string()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();

        trace!("OK. revoking");

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(public_key_id.to_string()),
            revocation_reason: "revocation test".to_owned(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        trace!("OK. destroying");

        DestroyKeyAction {
            key_id: Some(public_key_id.to_string()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &private_key_id.to_string(), false).await?;
        assert_destroyed(ctx, &public_key_id.to_string(), false).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_and_remove_ec_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // destroy via private key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        // destroy should not work when not revoked
        DestroyKeyAction {
            key_id: Some(private_key_id.to_string()),
            remove: true,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(private_key_id.to_string()),
            revocation_reason: "revocation test".to_owned(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        DestroyKeyAction {
            key_id: Some(private_key_id.to_string()),
            remove: true,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &private_key_id.to_string(), true).await?;
        assert_destroyed(ctx, &public_key_id.to_string(), true).await?;
    }

    // destroy via public key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        // destroy should not work when not revoked
        DestroyKeyAction {
            key_id: Some(public_key_id.to_string()),
            remove: true,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await
        .unwrap_err();

        trace!("OK. revoking");

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(public_key_id.to_string()),
            revocation_reason: "revocation test".to_owned(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        trace!("OK. destroying");

        DestroyKeyAction {
            key_id: Some(public_key_id.to_string()),
            remove: true,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &private_key_id.to_string(), true).await?;
        assert_destroyed(ctx, &public_key_id.to_string(), true).await?;
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
#[allow(clippy::large_stack_frames)]
async fn test_destroy_cover_crypt() -> KmsCliResult<()> {
    use std::path::PathBuf;

    let ctx = start_default_test_kms_server().await;

    // check revocation of all keys when the private key is destroyed
    {
        let (master_private_key_id, master_public_key_id) = {
            let action = CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                tags: vec![],
                sensitive: false,
                wrapping_key_id: None,
            };
            let key_ids = Box::pin(Box::pin(action.run(ctx.get_owner_client()))).await?;
            (key_ids.0.to_string(), key_ids.1.to_string())
        };

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        // destroy should not work when not revoked
        assert!(
            DestroyKeyAction {
                key_id: Some(master_private_key_id.clone()),
                remove: false,
                tags: None,
            }
            .run(ctx.get_owner_client())
            .await
            .is_err()
        );

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(master_private_key_id.clone()),
            revocation_reason: "revocation test".to_string(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        DestroyKeyAction {
            key_id: Some(master_private_key_id.clone()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &master_private_key_id, false).await?;
        assert_destroyed(ctx, &master_public_key_id, false).await?;
        assert_destroyed(ctx, &user_key_id_1, false).await?;
        assert_destroyed(ctx, &user_key_id_2, false).await?;
    }

    // check revocation of all keys when the public key is destroyed
    {
        let (master_private_key_id, master_public_key_id) = {
            let action = CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                tags: vec![],
                sensitive: false,
                wrapping_key_id: None,
            };
            let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
            (key_ids.0.to_string(), key_ids.1.to_string())
        };

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        // destroy should not work when not revoked
        assert!(
            DestroyKeyAction {
                key_id: Some(master_public_key_id.clone()),
                remove: false,
                tags: None,
            }
            .run(ctx.get_owner_client())
            .await
            .is_err()
        );

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(master_public_key_id.clone()),
            revocation_reason: "revocation test".to_string(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        DestroyKeyAction {
            key_id: Some(master_public_key_id.clone()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &master_private_key_id, false).await?;
        assert_destroyed(ctx, &master_public_key_id, false).await?;
        assert_destroyed(ctx, &user_key_id_1, false).await?;
        assert_destroyed(ctx, &user_key_id_2, false).await?;
    }

    // check that revoking a user key, does not destroy anything else
    {
        let (master_private_key_id, master_public_key_id) = {
            let action = CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                tags: vec![],
                sensitive: false,
                wrapping_key_id: None,
            };
            let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
            (key_ids.0.to_string(), key_ids.1.to_string())
        };

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_private_key_id.clone(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        }
        .run(ctx.get_owner_client())
        .await?
        .to_string();

        // destroy should not work when not revoked
        assert!(
            DestroyKeyAction {
                key_id: Some(user_key_id_1.clone()),
                remove: false,
                tags: None,
            }
            .run(ctx.get_owner_client())
            .await
            .is_err()
        );

        // revoke then destroy
        RevokeKeyAction {
            key_id: Some(user_key_id_1.clone()),
            revocation_reason: "revocation test".to_string(),
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        DestroyKeyAction {
            key_id: Some(user_key_id_1.clone()),
            remove: false,
            tags: None,
        }
        .run(ctx.get_owner_client())
        .await?;

        // assert
        assert_destroyed(ctx, &user_key_id_1.clone(), false).await?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            ExportSecretDataOrKeyAction {
                key_id: Some(master_private_key_id.clone()),
                key_file: tmp_path.join("output.export"),
                ..Default::default()
            }
            .run(ctx.get_owner_client())
            .await
            .is_ok()
        );
        assert!(
            ExportSecretDataOrKeyAction {
                key_id: Some(master_public_key_id.clone()),
                key_file: tmp_path.join("output.export"),
                ..Default::default()
            }
            .run(ctx.get_owner_client())
            .await
            .is_ok()
        );
        assert!(
            ExportSecretDataOrKeyAction {
                key_id: Some(user_key_id_2.clone()),
                key_file: tmp_path.join("output.export"),
                ..Default::default()
            }
            .run(ctx.get_owner_client())
            .await
            .is_ok()
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_secret_data() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Create secret data
    let secret_id =
        crate::actions::kms::secret_data::create_secret::CreateSecretDataAction::default()
            .run(ctx.get_owner_client())
            .await?
            .to_string();

    // destroy should not work when not revoked
    DestroyKeyAction {
        key_id: Some(secret_id.clone()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    // revoke then destroy
    RevokeKeyAction {
        key_id: Some(secret_id.clone()),
        revocation_reason: "revocation test".to_owned(),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    DestroyKeyAction {
        key_id: Some(secret_id.clone()),
        remove: false,
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    // assert
    assert_destroyed(ctx, &secret_id, false).await
}
