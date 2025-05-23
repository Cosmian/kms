use cosmian_kms_client::kmip_2_1::kmip_types::UniqueIdentifier;
use tempfile::TempDir;
use test_kms_server::{
    TestsContext, start_default_test_kms_server,
    start_default_test_kms_server_with_non_revocable_key_ids,
};
use uuid::Uuid;

use crate::{
    actions::kms::{
        elliptic_curves::keys::create_key_pair::CreateKeyPairAction,
        shared::ExportKeyAction,
        symmetric::keys::{create_key::CreateKeyAction, revoke_key::RevokeKeyAction},
    },
    error::result::KmsCliResult,
};

pub(crate) async fn assert_revoked(
    ctx: &TestsContext,
    key_id: &UniqueIdentifier,
) -> KmsCliResult<()> {
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // should not be able to Get....
    assert!(
        ExportKeyAction {
            key_file: tmp_path.join("output.export"),
            key_id: Some(key_id.to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await
        .is_err()
    );

    // but should be able to Export....
    assert!(
        ExportKeyAction {
            key_file: tmp_path.join("output.export"),
            key_id: Some(key_id.to_string()),
            allow_revoked: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await
        .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn test_revoke_symmetric_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    let key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "revocation test".to_string(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_revoked(ctx, &key_id).await?;
    Ok(())
}

#[tokio::test]
async fn test_revoke_ec_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // Revoke via private key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        RevokeKeyAction {
            key_id: Some(private_key_id.to_string()),
            revocation_reason: "revocation test".to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_revoked(ctx, &private_key_id).await?;
        assert_revoked(ctx, &public_key_id).await?;
    }

    // Revoke via public key
    {
        let (private_key_id, public_key_id) = CreateKeyPairAction::default()
            .run(ctx.get_owner_client())
            .await?;

        RevokeKeyAction {
            key_id: Some(public_key_id.to_string()),
            revocation_reason: "revocation test".to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_revoked(ctx, &private_key_id).await?;
        assert_revoked(ctx, &public_key_id).await?;
    }

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_revoke_cover_crypt() -> KmsCliResult<()> {
    use std::path::PathBuf;

    use crate::actions::kms::cover_crypt::keys::{
        create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
    };

    let ctx = start_default_test_kms_server().await;

    // Check revocation of all keys when the private key is revoked
    {
        let (master_secret_key_id, master_public_key_id) = Box::pin(
            CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                ..Default::default()
            }
            .run(ctx.get_owner_client()),
        )
        .await?;

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        RevokeKeyAction {
            key_id: Some(master_secret_key_id.to_string()),
            revocation_reason: "revocation test".to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_revoked(ctx, &master_secret_key_id).await?;
        assert_revoked(ctx, &master_public_key_id).await?;
        assert_revoked(ctx, &user_key_id_1).await?;
        assert_revoked(ctx, &user_key_id_2).await?;
    }

    // Check revocation of all keys when the public key is revoked
    {
        let (master_secret_key_id, master_public_key_id) = Box::pin(
            CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                ..Default::default()
            }
            .run(ctx.get_owner_client()),
        )
        .await?;

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        RevokeKeyAction {
            key_id: Some(master_public_key_id.to_string()),
            revocation_reason: "revocation test".to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_revoked(ctx, &master_secret_key_id).await?;
        assert_revoked(ctx, &master_public_key_id).await?;
        assert_revoked(ctx, &user_key_id_1).await?;
        assert_revoked(ctx, &user_key_id_2).await?;
    }

    // Check that revoking a user key does not revoke anything else
    {
        let (master_secret_key_id, master_public_key_id) = Box::pin(
            CreateMasterKeyPairAction {
                specification: PathBuf::from(
                    "../../test_data/access_structure_specifications.json",
                ),
                ..Default::default()
            }
            .run(ctx.get_owner_client()),
        )
        .await?;

        let user_key_id_1 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        let user_key_id_2 = CreateUserKeyAction {
            master_secret_key_id: master_secret_key_id.to_string(),
            access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
                .to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        RevokeKeyAction {
            key_id: Some(user_key_id_1.to_string()),
            revocation_reason: "revocation test".to_string(),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await?;

        assert_revoked(ctx, &user_key_id_1).await?;

        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();

        assert!(
            ExportKeyAction {
                key_file: tmp_path.join("output.export"),
                key_id: Some(master_secret_key_id.to_string()),
                ..Default::default()
            }
            .run(ctx.get_owner_client())
            .await
            .is_ok()
        );

        assert!(
            ExportKeyAction {
                key_file: tmp_path.join("output.export"),
                key_id: Some(master_public_key_id.to_string()),
                ..Default::default()
            }
            .run(ctx.get_owner_client())
            .await
            .is_ok()
        );

        assert!(
            ExportKeyAction {
                key_file: tmp_path.join("output.export"),
                key_id: Some(user_key_id_2.to_string()),
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
async fn test_non_revocable_symmetric_key() -> KmsCliResult<()> {
    let non_revocable_key = Uuid::new_v4().to_string();

    let ctx = start_default_test_kms_server_with_non_revocable_key_ids(Some(vec![
        non_revocable_key.clone(),
        Uuid::new_v4().to_string(),
    ]))
    .await;

    let key_id = CreateKeyAction {
        key_id: Some(non_revocable_key.clone()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(key_id.to_string(), non_revocable_key);

    RevokeKeyAction {
        key_id: Some(key_id.to_string()),
        revocation_reason: "revocation test".to_string(),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    assert!(
        ExportKeyAction {
            key_file: tmp_path.join("output.export"),
            key_id: Some(key_id.to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client())
        .await
        .is_ok()
    );

    Ok(())
}
