use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_client::{read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV};
use kms_test_server::start_default_test_kms_server;
use tempfile::TempDir;
use tracing::trace;

#[cfg(not(feature = "fips"))]
use crate::tests::cover_crypt::{
    master_key_pair::create_cc_master_key_pair, user_decryption_keys::create_user_decryption_key,
};
use crate::{
    cli_bail,
    error::{result::CliResult, CliError},
    tests::{
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::{export::export_key, revoke::revoke, ExportKeyParams},
        symmetric::create_key::create_symmetric_key,
        utils::recover_cmd_logs,
        PROG_NAME,
    },
};

pub(crate) fn destroy(cli_conf_path: &str, sub_command: &str, key_id: &str) -> CliResult<()> {
    let args: Vec<String> = ["keys", "destroy", "--key-id", key_id]
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

fn assert_destroyed(cli_conf_path: &str, key_id: &str) -> CliResult<()> {
    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // should not be able to Get....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: "ec".to_owned(),
            key_id: key_id.to_string(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
            ..Default::default()
        })
        .is_err()
    );

    // but should be able to Export....
    assert!(
        export_key(ExportKeyParams {
            cli_conf_path: cli_conf_path.to_string(),
            sub_command: "ec".to_owned(),
            key_id: key_id.to_string(),
            key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
            allow_revoked: true,
            ..Default::default()
        })
        .is_ok()
    );
    let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
    match &object.key_block()?.key_value.key_material {
        cosmian_kms_client::cosmian_kmip::kmip::kmip_data_structures::KeyMaterial::ByteString(
            v,
        ) => {
            assert!(v.is_empty());
        }
        _ => cli_bail!("Invalid key material"),
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_symmetric_key() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // syn
    let key_id = create_symmetric_key(&ctx.owner_client_conf_path, None, None, None, &[])?;

    // destroy should not work when not revoked
    assert!(destroy(&ctx.owner_client_conf_path, "sym", &key_id).is_err());

    // revoke then destroy
    revoke(
        &ctx.owner_client_conf_path,
        "sym",
        &key_id,
        "revocation test",
    )?;
    destroy(&ctx.owner_client_conf_path, "sym", &key_id)?;

    // assert
    assert_destroyed(&ctx.owner_client_conf_path, &key_id)
}

#[tokio::test]
async fn test_destroy_ec_key() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // destroy via private key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[])?;

        // destroy should not work when not revoked
        assert!(destroy(&ctx.owner_client_conf_path, "ec", &private_key_id).is_err());

        // revoke then destroy
        revoke(
            &ctx.owner_client_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;
        // destroy via the private key
        destroy(&ctx.owner_client_conf_path, "ec", &private_key_id)?;

        // assert
        assert_destroyed(&ctx.owner_client_conf_path, &private_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &public_key_id)?;
    }

    // destroy via public key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&ctx.owner_client_conf_path, "nist-p256", &[])?;

        // destroy should not work when not revoked
        assert!(destroy(&ctx.owner_client_conf_path, "ec", &public_key_id).is_err());

        trace!("OK. revoking");

        // revoke then destroy
        revoke(
            &ctx.owner_client_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        trace!("OK. destroying");

        // destroy via the private key
        destroy(&ctx.owner_client_conf_path, "ec", &public_key_id)?;

        // assert
        assert_destroyed(&ctx.owner_client_conf_path, &private_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &public_key_id)?;
    }

    Ok(())
}

#[cfg(not(feature = "fips"))]
#[tokio::test]
async fn test_destroy_cover_crypt() -> CliResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;

    // check revocation of all keys when the private key is destroyed
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
            &[],
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;

        // destroy should not work when not revoked
        assert!(destroy(&ctx.owner_client_conf_path, "cc", &master_private_key_id).is_err());

        // revoke then destroy
        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &master_private_key_id,
            "revocation test",
        )?;
        destroy(&ctx.owner_client_conf_path, "cc", &master_private_key_id)?;

        // assert
        assert_destroyed(&ctx.owner_client_conf_path, &master_private_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &master_public_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &user_key_id_1)?;
        assert_destroyed(&ctx.owner_client_conf_path, &user_key_id_2)?;
    }

    // check revocation of all keys when the public key is destroyed
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
            &[],
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;
        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;

        // destroy should not work when not revoked
        assert!(destroy(&ctx.owner_client_conf_path, "cc", &master_public_key_id).is_err());

        // revoke then destroy
        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &master_public_key_id,
            "revocation test",
        )?;
        destroy(&ctx.owner_client_conf_path, "cc", &master_public_key_id)?;

        // assert
        assert_destroyed(&ctx.owner_client_conf_path, &master_private_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &master_public_key_id)?;
        assert_destroyed(&ctx.owner_client_conf_path, &user_key_id_1)?;
        assert_destroyed(&ctx.owner_client_conf_path, &user_key_id_2)?;
    }

    // check that revoking a user key, does not destroy anything else
    {
        // generate a new master key pair
        let (master_private_key_id, master_public_key_id) = create_cc_master_key_pair(
            &ctx.owner_client_conf_path,
            "--policy-specifications",
            "test_data/policy_specifications.json",
            &[],
        )?;

        let user_key_id_1 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;

        let user_key_id_2 = create_user_decryption_key(
            &ctx.owner_client_conf_path,
            &master_private_key_id,
            "(Department::MKG || Department::FIN) && Security Level::Top Secret",
            &[],
        )?;

        // destroy should not work when not revoked
        assert!(destroy(&ctx.owner_client_conf_path, "cc", &user_key_id_1).is_err());

        // revoke then destroy
        revoke(
            &ctx.owner_client_conf_path,
            "cc",
            &user_key_id_1,
            "revocation test",
        )?;
        destroy(&ctx.owner_client_conf_path, "cc", &user_key_id_1)?;

        // assert
        assert_destroyed(&ctx.owner_client_conf_path, &user_key_id_1)?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_private_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_public_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: ctx.owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: user_key_id_2,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
                ..Default::default()
            })
            .is_ok()
        );
    }

    Ok(())
}
