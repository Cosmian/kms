use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server_with_utimaco_hsm;
use tracing::debug;
use uuid::Uuid;

use crate::{
    actions::kms::symmetric::keys::{
        create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_revoke_symmetric_key() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server_with_utimaco_hsm().await;

    // sym
    let key_id = CreateKeyAction {
        key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // revoke
    let r = RevokeKeyAction {
        revocation_reason: "revocation test".to_string(),
        key_id: Some(key_id.to_string()),
        tags: None,
    }
    .run(ctx.get_owner_client())
    .await;

    match r {
        Ok(_) => {
            debug!("revocation successful");
        }
        Err(_) => {
            debug!("revocation not supported");
        }
    }

    // The key is always removed when it is an HSM
    DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        tags: None,
        remove: true,
    }
    .run(ctx.get_owner_client())
    .await?;

    let res = DestroyKeyAction {
        key_id: Some(key_id.to_string()),
        tags: None,
        remove: true,
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Object not found"));
    Ok(())
}
