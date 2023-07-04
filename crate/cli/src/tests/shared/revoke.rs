use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use tempfile::TempDir;

use crate::{
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
        },
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::export::export,
        symmetric::create_key::create_symmetric_key,
        utils::{init_test_server, ONCE},
        PROG_NAME,
    },
};

pub fn revoke(
    cli_conf_path: &str,
    sub_command: &str,
    key_id: &str,
    revocation_reason: &str,
) -> Result<(), CliError> {
    let args: Vec<String> = vec!["keys", "revoke", "--key-id", key_id, revocation_reason]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

fn assert_revoker(cli_conf_path: &str, key_id: &str) -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // should not be able to Get....
    assert!(
        export(
            cli_conf_path,
            "cc",
            key_id,
            tmp_path.join("output.export").to_str().unwrap(),
            false,
            false,
            None,
            false,
        )
        .is_err()
    );

    // but should be able to Export....
    assert!(
        export(
            cli_conf_path,
            "cc",
            key_id,
            tmp_path.join("output.export").to_str().unwrap(),
            false,
            false,
            None,
            true,
        )
        .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn test_revoke_symmetric_key() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(init_test_server).await;

    // syn
    let key_id = create_symmetric_key(&ctx.owner_cli_conf_path, None, None, None)?;

    // revoke
    revoke(&ctx.owner_cli_conf_path, "sym", &key_id, "revocation test")?;

    // assert
    assert_revoker(&ctx.owner_cli_conf_path, &key_id)
}

#[tokio::test]
async fn test_revoke_ec_key() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(init_test_server).await;

    // revoke via private key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair(&ctx.owner_cli_conf_path)?;

        // revoke via the private key
        revoke(
            &ctx.owner_cli_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoker(&ctx.owner_cli_conf_path, &private_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &public_key_id)?;
    }

    // revoke via public key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair(&ctx.owner_cli_conf_path)?;

        // revoke via the private key
        revoke(
            &ctx.owner_cli_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoker(&ctx.owner_cli_conf_path, &private_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &public_key_id)?;
    }

    Ok(())
}

#[tokio::test]
async fn test_revoke_cover_crypt() -> Result<(), CliError> {
    // init the test server
    let ctx = ONCE.get_or_init(init_test_server).await;

    // check revocation of all keys when the private key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_cli_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;

        revoke(
            &ctx.owner_cli_conf_path,
            "cc",
            &master_private_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoker(&ctx.owner_cli_conf_path, &master_private_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &master_public_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &user_key_id_1)?;
        assert_revoker(&ctx.owner_cli_conf_path, &user_key_id_2)?;
    }

    // check revocation of all keys when the public key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_cli_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;

        revoke(
            &ctx.owner_cli_conf_path,
            "cc",
            &master_public_key_id,
            "revocation test",
        )?;

        // assert
        assert_revoker(&ctx.owner_cli_conf_path, &master_private_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &master_public_key_id)?;
        assert_revoker(&ctx.owner_cli_conf_path, &user_key_id_1)?;
        assert_revoker(&ctx.owner_cli_conf_path, &user_key_id_2)?;
    }

    // check that revoking a user key, does not revoke anything else
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_cli_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;

        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_cli_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )?;

        revoke(
            &ctx.owner_cli_conf_path,
            "cc",
            &user_key_id_1,
            "revocation test",
        )?;

        // assert
        assert_revoker(&ctx.owner_cli_conf_path, &user_key_id_1)?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export(
                &ctx.owner_cli_conf_path,
                "cc",
                &master_private_key_id,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .is_ok()
        );
        assert!(
            export(
                &ctx.owner_cli_conf_path,
                "cc",
                &master_public_key_id,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .is_ok()
        );
        assert!(
            export(
                &ctx.owner_cli_conf_path,
                "cc",
                &user_key_id_2,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .is_ok()
        );
    }

    Ok(())
}
