use cosmian_kms_cli::actions::kms::symmetric::keys::create_key::CreateKeyAction;
use cosmian_logger::{debug, log_init};
use test_kms_server::TestsContext;
use uuid::Uuid;

use crate::{
    error::result::CosmianResult,
    tests::{
        kms::{
            shared::{ExportKeyParams, destroy, export_key, revoke},
            symmetric::create_key::create_symmetric_key,
        },
        save_kms_cli_config,
    },
};

pub(crate) fn test_revoke_symmetric_key(ctx: &TestsContext) -> CosmianResult<()> {
    log_init(None);
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // sym
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            key_id: Some("hsm::0::".to_string() + &Uuid::new_v4().to_string()),
            ..Default::default()
        },
    )?;

    // revoke
    match revoke(&owner_client_conf_path, "sym", &key_id, "revocation test") {
        Ok(()) => {
            debug!("revocation successful");
        }
        Err(_) => {
            debug!("revocation not supported");
        }
    }

    // The key is always removed when it is an HSM
    destroy(&owner_client_conf_path, "sym", &key_id, true)?;

    let res = export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "sym".to_string(),
        key_id,
        key_file: "/tmp/key".to_string(),
        ..Default::default()
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Object not found"));
    Ok(())
}
