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
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

pub async fn revoke(
    sub_command: &str,
    key_id: &str,
    revocation_reason: &str,
) -> Result<(), CliError> {
    let args: Vec<String> = vec!["keys", "revoke", key_id, revocation_reason]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, CONF_PATH);
    cmd.arg(sub_command).args(args);
    let output = cmd.output()?;
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

async fn assert_revoker(key_id: &str) -> Result<(), CliError> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // should not be able to Get....
    assert!(
        export(
            "cc",
            key_id,
            tmp_path.join("output.export").to_str().unwrap(),
            false,
            false,
            None,
            false,
        )
        .await
        .is_err()
    );

    // but should be able to Export....
    assert!(
        export(
            "cc",
            key_id,
            tmp_path.join("output.export").to_str().unwrap(),
            false,
            false,
            None,
            true,
        )
        .await
        .is_ok()
    );

    Ok(())
}

#[tokio::test]
async fn test_revoke_symmetric_key() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // syn
    let key_id = create_symmetric_key(None, None, None).await?;

    // revoke
    revoke("sym", &key_id, "revocation test").await?;

    // assert
    assert_revoker(&key_id).await
}

#[tokio::test]
async fn test_revoke_ec_key() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // revoke via private key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair().await?;

        // revoke via the private key
        revoke("ec", &private_key_id, "revocation test").await?;

        // assert
        assert_revoker(&private_key_id).await?;
        assert_revoker(&public_key_id).await?;
    }

    // revoke via public key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair().await?;

        // revoke via the private key
        revoke("ec", &public_key_id, "revocation test").await?;

        // assert
        assert_revoker(&private_key_id).await?;
        assert_revoker(&public_key_id).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_revoke_cover_crypt() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // check revocation of all keys when the private key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )
        .await?;

        let user_key_id_1 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;
        let user_key_id_2 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;

        revoke("cc", &master_private_key_id, "revocation test").await?;

        // assert
        assert_revoker(&master_private_key_id).await?;
        assert_revoker(&master_public_key_id).await?;
        assert_revoker(&user_key_id_1).await?;
        assert_revoker(&user_key_id_2).await?;
    }

    // check revocation of all keys when the public key is revoked
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )
        .await?;

        let user_key_id_1 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;
        let user_key_id_2 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;

        revoke("cc", &master_public_key_id, "revocation test").await?;

        // assert
        assert_revoker(&master_private_key_id).await?;
        assert_revoker(&master_public_key_id).await?;
        assert_revoker(&user_key_id_1).await?;
        assert_revoker(&user_key_id_2).await?;
    }

    // check that revoking a user key, does not revoke anything else
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            "--policy-specifications",
            "test_data/policy_specifications.json",
        )
        .await?;

        let user_key_id_1 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;

        let user_key_id_2 = create_user_decryption_key(
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        )
        .await?;

        revoke("cc", &user_key_id_1, "revocation test").await?;

        // assert
        assert_revoker(&user_key_id_1).await?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export(
                "cc",
                &master_private_key_id,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .await
            .is_ok()
        );
        assert!(
            export(
                "cc",
                &master_public_key_id,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .await
            .is_ok()
        );
        assert!(
            export(
                "cc",
                &user_key_id_2,
                tmp_path.join("output.export").to_str().unwrap(),
                false,
                false,
                None,
                false,
            )
            .await
            .is_ok()
        );
    }

    Ok(())
}
