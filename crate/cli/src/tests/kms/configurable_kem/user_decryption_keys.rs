use std::path::PathBuf;

use test_kms_server::start_default_test_kms_server;

use crate::{
    actions::kms::cover_crypt::keys::{
        create_key_pair::CreateMasterKeyPairAction, create_user_key::CreateUserKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
pub(crate) async fn test_user_decryption_key() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_secret_key_id, _) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    // and a user key
    let user_key_id = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top Secret"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    assert!(!user_key_id.is_empty());

    Ok(())
}

#[tokio::test]
pub(crate) async fn test_user_decryption_key_error() -> KmsCliResult<()> {
    let ctx = start_default_test_kms_server().await;

    // generate a new master key pair
    let (master_secret_key_id, _) = {
        let action = CreateMasterKeyPairAction {
            specification: PathBuf::from("../../test_data/access_structure_specifications.json"),
            tags: vec![],
            sensitive: false,
            wrapping_key_id: None,
        };
        let key_ids = Box::pin(action.run(ctx.get_owner_client())).await?;
        (key_ids.0.to_string(), key_ids.1.to_string())
    };

    // bad attributes
    let err = CreateUserKeyAction {
        master_secret_key_id: master_secret_key_id.clone(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await
    .err()
    .unwrap();
    assert!(
        err.to_string().contains("REST Response Conversion Failed")
            || err
                .to_string()
                .contains("attribute not found: Top SecretZZZZZZ")
    );

    // bad master secret key
    let err = CreateUserKeyAction {
        master_secret_key_id: "BAD_KEY".to_string(),
        access_policy: "(Department::MKG || Department::FIN) && Security Level::Top SecretZZZZZZ"
            .to_string(),
        tags: vec![],
        sensitive: false,
        wrapping_key_id: None,
    }
    .run(ctx.get_owner_client())
    .await
    .err()
    .unwrap();
    // Both cases currently return REST deserialization errors
    assert!(
        err.to_string().contains("REST Response Conversion Failed")
            || err
                .to_string()
                .contains("no Covercrypt master secret key found for: BAD_KEY")
            || err.to_string().contains("Object not found")
    );
    Ok(())
}
