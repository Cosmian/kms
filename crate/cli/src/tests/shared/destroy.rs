use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use tempfile::TempDir;

use crate::{
    actions::shared::utils::read_key_from_file,
    cli_bail,
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        cover_crypt::{
            master_key_pair::create_cc_master_key_pair,
            user_decryption_keys::create_user_decryption_key,
        },
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::{export::export, revoke::revoke},
        symmetric::create_key::create_symmetric_key,
        test_utils::{init_test_server, ONCE},
        CONF_PATH, PROG_NAME,
    },
};

pub async fn destroy(sub_command: &str, key_id: &str) -> Result<(), CliError> {
    let args: Vec<String> = vec!["keys", "destroy", key_id]
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

async fn assert_destroyed(key_id: &str) -> Result<(), CliError> {
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
    let object = read_key_from_file(&tmp_path.join("output.export"))?;
    match &object.key_block()?.key_value.key_material {
        cosmian_kmip::kmip::kmip_data_structures::KeyMaterial::ByteString(v) => {
            assert!(v.is_empty())
        }
        _ => cli_bail!("Invalid key material"),
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_symmetric_key() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // syn
    let key_id = create_symmetric_key(None, None, None).await?;

    // destroy should not work when not revoked
    assert!(destroy("sym", &key_id).await.is_err());

    // revoke then destroy
    revoke("sym", &key_id, "revocation test").await?;
    destroy("sym", &key_id).await?;

    // assert
    assert_destroyed(&key_id).await
}

#[tokio::test]
async fn test_destroy_ec_key() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // destroy via private key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair().await?;

        // destroy should not work when not revoked
        assert!(destroy("ec", &private_key_id).await.is_err());

        // revoke then destroy
        revoke("ec", &private_key_id, "revocation test").await?;
        // destroy via the private key
        destroy("ec", &private_key_id).await?;

        // assert
        assert_destroyed(&private_key_id).await?;
        assert_destroyed(&public_key_id).await?;
    }

    // destroy via public key
    {
        // syn
        let (private_key_id, public_key_id) = create_ec_key_pair().await?;

        // destroy should not work when not revoked
        assert!(destroy("ec", &public_key_id).await.is_err());

        // revoke then destroy
        revoke("ec", &public_key_id, "revocation test").await?;
        // destroy via the private key
        destroy("ec", &public_key_id).await?;

        // assert
        assert_destroyed(&private_key_id).await?;
        assert_destroyed(&public_key_id).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_cover_crypt() -> Result<(), CliError> {
    // init the test server
    ONCE.get_or_init(init_test_server).await;

    // check revocation of all keys when the private key is destroyd
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

        // destroy should not work when not revoked
        assert!(destroy("cc", &master_private_key_id).await.is_err());

        // revoke then destroy
        revoke("cc", &master_private_key_id, "revocation test").await?;
        destroy("cc", &master_private_key_id).await?;

        // assert
        assert_destroyed(&master_private_key_id).await?;
        assert_destroyed(&master_public_key_id).await?;
        assert_destroyed(&user_key_id_1).await?;
        assert_destroyed(&user_key_id_2).await?;
    }

    // check revocation of all keys when the public key is destroyed
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

        // destroy should not work when not revoked
        assert!(destroy("cc", &master_public_key_id).await.is_err());

        // revoke then destroy
        revoke("cc", &master_public_key_id, "revocation test").await?;
        destroy("cc", &master_public_key_id).await?;

        // assert
        assert_destroyed(&master_private_key_id).await?;
        assert_destroyed(&master_public_key_id).await?;
        assert_destroyed(&user_key_id_1).await?;
        assert_destroyed(&user_key_id_2).await?;
    }

    // check that revoking a user key, does not destroy anything else
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

        // destroy should not work when not revoked
        assert!(destroy("cc", &user_key_id_1).await.is_err());

        // revoke then destroy
        revoke("cc", &user_key_id_1, "revocation test").await?;
        destroy("cc", &user_key_id_1).await?;

        // assert
        assert_destroyed(&user_key_id_1).await?;

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
