use std::process::Command;

use assert_cmd::prelude::*;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::start_default_test_kms_server;
use predicates::prelude::*;

use crate::{
    error::result::CliResult,
    tests::{cover_crypt::SUB_COMMAND, utils::recover_cmd_logs, PROG_NAME},
};

#[tokio::test]
async fn test_view_access_structure() -> CliResult<()> {
    let ctx = start_default_test_kms_server().await;
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "../../test_data/ttlv_public_key.json",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Security Level"))
        .stdout(predicate::str::contains("Top Secret"))
        .stdout(predicate::str::contains("R&D"));

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, &ctx.owner_client_conf_path);

    cmd.arg(SUB_COMMAND).args(vec![
        "policy",
        "view",
        "-f",
        "../../test_data/ttlv_public_key.json",
        "--detailed",
    ]);
    recover_cmd_logs(&mut cmd);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("\"Security Level\""))
        .stdout(predicate::str::contains("\"Top Secret\""))
        .stdout(predicate::str::contains(
            "Attribute { id: 6, encryption_hint: Classic, write_status: EncryptDecrypt }",
        ));

    Ok(())
}
