use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_client::KMS_CLI_CONF_ENV;
use kms_test_server::{
    start_default_test_kms_server, start_default_test_kms_server_with_non_revocable_key_ids,
};
use tempfile::TempDir;
use uuid::Uuid;

#[cfg(not(feature = "fips"))]
use crate::tests::cover_crypt::{
    master_key_pair::create_cc_master_key_pair, user_decryption_keys::create_user_decryption_key,
};
use crate::{
    actions::symmetric::keys::create_key::CreateKeyAction,
    error::{result::CliResult, CliError},
    tests::{
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::{export::export_key, ExportKeyParams},
        symmetric::create_key::create_symmetric_key,
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

pub(crate) fn revoke(
    cli_conf_path: &str,
    sub_command: &str,
    key_id: &str,
    revocation_reason: &str,
) -> CliResult<()> {
    let args: Vec<String> = ["keys", "revoke", "--key-id", key_id, revocation_reason]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);

    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn assert_revoked(cli_conf_path: &str, key_id: &str) -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // should not be able to Get....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: "ec".to_owned(),
            key_id: key_id.to_owned(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
            ..Default::default()
        })
        .is_err()
    );

    // but should be able to Export....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: "ec".to_owned(),
            key_id: key_id.to_owned(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
            allow_revoked: true,
            ..Default::default()
        })
        .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn test_revoke_symmetric_key() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // syn
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, CreateKeyAction::default())?;

    // revoke
    revoke(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        "revocation test",
    )?;

    // assert
    assert_revoked(&ctx.owner_client_conf_path, &key_id)
}

#[tokio::test]
async fn test_revoke_ec_key() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // revoke via private key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[], false)?;

        // revoke via the private key
        revoke(
            &ctx.owner_client_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&ctx.owner_client_conf_path, &private_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &public_key_id)?;
    }

    // revoke via public key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[], false)?;

        // revoke via the private key
        revoke(
            &ctx.owner_client_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&ctx.owner_client_conf_path, &private_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &public_key_id)?;
    }

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_revoke_cover_crypt() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // check revocation of all keys when the private key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "../../test_data/policy_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &master_private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&ctx.owner_client_conf_path, &master_private_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &master_public_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &user_key_id_1)?;
        assert_revoked(&ctx.owner_client_conf_path, &user_key_id_2)?;
    }

    // check revocation of all keys when the public key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "../../test_data/policy_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &master_public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&ctx.owner_client_conf_path, &master_private_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &master_public_key_id)?;
        assert_revoked(&ctx.owner_client_conf_path, &user_key_id_1)?;
        assert_revoked(&ctx.owner_client_conf_path, &user_key_id_2)?;
    }

    // check that revoking a user key, does not revoke anything else
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "../../test_data/policy_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &user_key_id_1,
            "revocation test",
        )?;

        // assert
        assert_revoked(&ctx.owner_client_conf_path, &user_key_id_1)?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.to_string(),
                sub_command: "cc".to_owned(),
                key_id: master_private_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.to_string(),
                sub_command: "cc".to_owned(),
                key_id: master_public_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.to_string(),
                sub_command: "cc".to_owned(),
                key_id: user_key_id_2,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
                ..Default::default()
            })
            .is_ok()
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_non_revocable_symmetric_key() -> CliResult<()> {
    //
    // Check that a non-revocable key cannot be revoked (and then still exportable)
    //
    let non_revocable_key = Uuid::new_v4().to_string();

    // init the test server with the non-revocable key in the parameter
    let ctx = start_default_test_kms_server_with_non_revocable_key_ids(Some(vec![
        non_revocable_key.clone(),
        Uuid::new_v4().to_string(),
    ]))
    .await;

    // sym
    let key_id = create_symmetric_key(
        &ctx.owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(non_revocable_key.clone()),
            ..Default::default()
        },
    )?;

    assert_eq!(key_id, non_revocable_key);

    // revoke
    revoke(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        "revocation test",
    )?;

    // assert the key is still exportable after revocation.
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // should be able to Get (even when revoked)....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: ctx.owner_client_conf_path.clone(),
            sub_command: "ec".to_owned(),
            key_id,
            key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
            ..Default::default()
        })
        .is_ok()
    );
    Ok(())
}
