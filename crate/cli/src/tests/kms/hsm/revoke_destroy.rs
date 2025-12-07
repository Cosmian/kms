use std::path::PathBuf;

use cosmian_logger::{debug, log_init};
use test_kms_server::TestsContext;
use uuid::Uuid;

use crate::{
    actions::kms::{
        shared::ExportSecretDataOrKeyAction,
        symmetric::keys::{
            create_key::CreateKeyAction, destroy_key::DestroyKeyAction, revoke_key::RevokeKeyAction,
        },
    },
    error::result::KmsCliResult,
};

pub(super) async fn test_revoke_symmetric_key(ctx: &TestsContext) -> KmsCliResult<()> {
    log_init(None);

    // sym
    let key_id = CreateKeyAction {
        key_id: Some("hsm::0::".to_owned() + &Uuid::new_v4().to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // revoke
    let r = RevokeKeyAction {
        revocation_reason: "revocation test".to_owned(),
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

    let res = ExportSecretDataOrKeyAction {
        key_id: Some(key_id.to_string()),
        key_file: PathBuf::from("/tmp/key"),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    res.as_ref().unwrap_err();
    if let Err(e) = res {
        assert!(e.to_string().contains("Object not found"));
    }
    Ok(())
}
