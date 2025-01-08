use tracing::debug;
use uuid::Uuid;

use crate::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    error::result::CliResult,
    tests::{
        hsm::KMS_HSM_CLIENT_CONF,
        shared::{destroy, export_key, revoke, ExportKeyParams},
        symmetric::create_key::create_symmetric_key,
    },
};

#[tokio::test]
async fn test_revoke_symmetric_key() -> CliResult<()> {
    // sym
    let key_id = create_symmetric_key(
        KMS_HSM_CLIENT_CONF,
        CreateKeyAction {
            key_id: Some("hsm::4::".to_string() + &Uuid::new_v4().to_string()),
            ..Default::default()
        },
    )?;

    // revoke
    match revoke(KMS_HSM_CLIENT_CONF, "sym", &key_id, "revocation test") {
        Ok(()) => {
            debug!("revocation successful");
        }
        Err(_) => {
            debug!("revocation not supported");
        }
    }

    // The key is always removed when it is an HSM
    destroy(KMS_HSM_CLIENT_CONF, "sym", &key_id, true)?;

    let res = export_key(ExportKeyParams {
        cli_conf_path: KMS_HSM_CLIENT_CONF.to_owned(),
        sub_command: "sym".to_string(),
        key_id,
        key_file: "/tmp/key".to_string(),
        ..Default::default()
    });
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Object not found"));
    Ok(())
}
