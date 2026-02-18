use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_cli::actions::kms::symmetric::keys::create_key::CreateKeyAction;
use tempfile::TempDir;
use test_kms_server::{
    start_default_test_kms_server, start_default_test_kms_server_with_non_revocable_key_ids,
};
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::tests::kms::cover_crypt::{
    master_key_pair::create_cc_master_key_pair, user_decryption_keys::create_user_decryption_key,
};
#[cfg(feature = "non-fips")]
use crate::tests::kms::elliptic_curve::create_key_pair::create_ec_key_pair;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            shared::{ExportKeyParams, export::export_key},
            symmetric::create_key::create_symmetric_key,
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

pub(crate) fn revoke(
    cli_conf_path: &str,
    sub_command: &str,
    key_id: &str,
    revocation_reason: &str,
) -> CosmianResult<()> {
    let args: Vec<String> = ["keys", "revoke", "--key-id", key_id, revocation_reason]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn assert_revoked(cli_conf_path: &str, key_id: &str) -> CosmianResult<()> {
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
async fn test_revoke_symmetric_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // syn
    let key_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // revoke
    revoke(&owner_client_conf_path, "sym", &key_id, "revocation test")?;

    // assert
    assert_revoked(&owner_client_conf_path, &key_id)
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_revoke_ec_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // revoke via private key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // revoke via the private key
        revoke(
            &owner_client_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&owner_client_conf_path, &private_key_id)?;
        assert_revoked(&owner_client_conf_path, &public_key_id)?;
    }

    // revoke via public key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // revoke via the private key
        revoke(
            &owner_client_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&owner_client_conf_path, &private_key_id)?;
        assert_revoked(&owner_client_conf_path, &public_key_id)?;
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_revoke_cover_crypt() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // check revocation of all keys when the private key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &owner_client_conf_path,
            "--specification",
            "../../../test_data/access_structure_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &owner_client_conf_path,
            "cc",
            &master_private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&owner_client_conf_path, &master_private_key_id)?;
        assert_revoked(&owner_client_conf_path, &master_public_key_id)?;
        assert_revoked(&owner_client_conf_path, &user_key_id_1)?;
        assert_revoked(&owner_client_conf_path, &user_key_id_2)?;
    }

    // check revocation of all keys when the public key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &owner_client_conf_path,
            "--specification",
            "../../../test_data/access_structure_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &owner_client_conf_path,
            "cc",
            &master_public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoked(&owner_client_conf_path, &master_private_key_id)?;
        assert_revoked(&owner_client_conf_path, &master_public_key_id)?;
        assert_revoked(&owner_client_conf_path, &user_key_id_1)?;
        assert_revoked(&owner_client_conf_path, &user_key_id_2)?;
    }

    // check that revoking a user key, does not revoke anything else
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &owner_client_conf_path,
            "--specification",
            "../../../test_data/access_structure_specifications.json",
            &[],
            false,
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        let user_key_id_2 = create_user_decryption_key(
            &owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
            false,
        )?;

        revoke(
            &owner_client_conf_path,
            "cc",
            &user_key_id_1,
            "revocation test",
        )?;

        // assert
        assert_revoked(&owner_client_conf_path, &user_key_id_1)?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_private_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_public_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path,
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
async fn test_non_revocable_symmetric_key() -> CosmianResult<()> {
    // Check that a non-revocable key cannot be revoked (and then still exportable)
    //
    let non_revocable_key = Uuid::new_v4().to_string();

    // init the test server with the non-revocable key in the parameter
    let ctx = start_default_test_kms_server_with_non_revocable_key_ids(Some(vec![
        non_revocable_key.clone(),
        Uuid::new_v4().to_string(),
    ]))
    .await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // sym
    let key_id = create_symmetric_key(
        &owner_client_conf_path,
        CreateKeyAction {
            key_id: Some(non_revocable_key.clone()),
            ..Default::default()
        },
    )?;

    assert_eq!(key_id, non_revocable_key);

    // revoke
    revoke(&owner_client_conf_path, "sym", &key_id, "revocation test")?;

    // assert the key is still exportable after revocation.
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    // should be able to Get (even when revoked)....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: owner_client_conf_path,
            sub_command: "ec".to_owned(),
            key_id,
            key_file: tmp_path.join("output.export").to_str().unwrap().to_string(),
            ..Default::default()
        })
        .is_ok()
    );
    Ok(())
}
