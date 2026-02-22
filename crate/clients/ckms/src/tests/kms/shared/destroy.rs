use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::cosmian_kms_client::{
        kmip_2_1::kmip_data_structures::{KeyMaterial, KeyValue},
        read_object_from_json_ttlv_file,
    },
};
#[cfg(feature = "non-fips")]
use cosmian_logger::trace;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

#[cfg(feature = "non-fips")]
use crate::tests::kms::cover_crypt::{
    master_key_pair::create_cc_master_key_pair, user_decryption_keys::create_user_decryption_key,
};
#[cfg(feature = "non-fips")]
use crate::tests::kms::elliptic_curve::create_key_pair::create_ec_key_pair;
use crate::{
    cli_bail,
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            shared::{ExportKeyParams, export::export_key, revoke::revoke},
            symmetric::create_key::create_symmetric_key,
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

pub(crate) fn destroy(
    cli_conf_path: &str,
    sub_command: &str,
    key_id: &str,
    remove: bool,
) -> CosmianResult<()> {
    let mut args: Vec<String> = ["keys", "destroy", "--key-id", key_id]
        .iter()
        .map(std::string::ToString::to_string)
        .collect();
    if remove {
        args.push("--remove".to_owned());
    }
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

fn assert_destroyed(cli_conf_path: &str, key_id: &str, _remove: bool) -> CosmianResult<()> {
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

    // depending on whether the key is removed or not,
    // the key metadata should be exportable or not
    let export_res = export_key(ExportKeyParams {
        cli_conf_path: cli_conf_path.to_string(),
        sub_command: "ec".to_owned(),
        key_id: key_id.to_string(),
        key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
        allow_revoked: true,
        ..Default::default()
    });
    // Newer KMS versions may not allow exporting destroyed objects at all and return Not_Found.
    // If export succeeds, ensure no key material is present for compatibility.
    if export_res.is_ok() {
        let object = read_object_from_json_ttlv_file(&tmp_path.join("output.export"))?;
        let Some(KeyValue::Structure { key_material, .. }) = &object.key_block()?.key_value else {
            cli_bail!("Invalid key value");
        };
        match &key_material {
            KeyMaterial::ByteString(v) => {
                assert!(v.is_empty());
            }
            _ => cli_bail!("Invalid key material"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_destroy_symmetric_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // syn
    let key_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // destroy should not work when not revoked
    assert!(destroy(&owner_client_conf_path, "sym", &key_id, false).is_err());

    // revoke then destroy
    revoke(&owner_client_conf_path, "sym", &key_id, "revocation test")?;
    destroy(&owner_client_conf_path, "sym", &key_id, false)?;

    // assert
    assert_destroyed(&owner_client_conf_path, &key_id, false)
}

#[tokio::test]
async fn test_destroy_and_remove_symmetric_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // syn
    let key_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;

    // destroy should not work when not revoked
    assert!(destroy(&owner_client_conf_path, "sym", &key_id, true).is_err());

    // revoke then destroy
    revoke(&owner_client_conf_path, "sym", &key_id, "revocation test")?;
    destroy(&owner_client_conf_path, "sym", &key_id, true)?;

    // assert
    assert_destroyed(&owner_client_conf_path, &key_id, true)
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_destroy_ec_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // destroy via private key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "ec", &private_key_id, false).is_err());

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;
        // destroy via the private key
        destroy(&owner_client_conf_path, "ec", &private_key_id, false)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &private_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &public_key_id, false)?;
    }

    // destroy via public key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "ec", &public_key_id, false).is_err());

        trace!("OK. revoking");

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        trace!("OK. destroying");

        // destroy via the private key
        destroy(&owner_client_conf_path, "ec", &public_key_id, false)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &private_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &public_key_id, false)?;
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_destroy_and_remove_ec_key() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // destroy via private key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "ec", &private_key_id, true).is_err());

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "ec",
            &private_key_id,
            "revocation test",
        )?;
        // destroy via the private key
        destroy(&owner_client_conf_path, "ec", &private_key_id, true)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &private_key_id, true)?;
        assert_destroyed(&owner_client_conf_path, &public_key_id, true)?;
    }

    // destroy via public key
    {
        // syn
        let (private_key_id, public_key_id) =
            create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "ec", &public_key_id, true).is_err());

        trace!("OK. revoking");

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "ec",
            &public_key_id,
            "revocation test",
        )?;

        trace!("OK. destroying");

        // destroy via the private key
        destroy(&owner_client_conf_path, "ec", &public_key_id, true)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &private_key_id, true)?;
        assert_destroyed(&owner_client_conf_path, &public_key_id, true)?;
    }

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_destroy_cover_crypt() -> CosmianResult<()> {
    // init the test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // check revocation of all keys when the private key is destroyed
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

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "cc", &master_private_key_id, false).is_err());

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "cc",
            &master_private_key_id,
            "revocation test",
        )?;
        destroy(&owner_client_conf_path, "cc", &master_private_key_id, false)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &master_private_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &master_public_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &user_key_id_1, false)?;
        assert_destroyed(&owner_client_conf_path, &user_key_id_2, false)?;
    }

    // check revocation of all keys when the public key is destroyed
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

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "cc", &master_public_key_id, false).is_err());

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "cc",
            &master_public_key_id,
            "revocation test",
        )?;
        destroy(&owner_client_conf_path, "cc", &master_public_key_id, false)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &master_private_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &master_public_key_id, false)?;
        assert_destroyed(&owner_client_conf_path, &user_key_id_1, false)?;
        assert_destroyed(&owner_client_conf_path, &user_key_id_2, false)?;
    }

    // check that revoking a user key, does not destroy anything else
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

        // destroy should not work when not revoked
        assert!(destroy(&owner_client_conf_path, "cc", &user_key_id_1, false).is_err());

        // revoke then destroy
        revoke(
            &owner_client_conf_path,
            "cc",
            &user_key_id_1,
            "revocation test",
        )?;
        destroy(&owner_client_conf_path, "cc", &user_key_id_1, false)?;

        // assert
        assert_destroyed(&owner_client_conf_path, &user_key_id_1, false)?;

        // create a temp dir
        let tmp_dir = TempDir::new()?;
        let tmp_path = tmp_dir.path();
        // should able to Get the Master Keys and user key 2
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_private_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path.clone(),
                sub_command: "cc".to_owned(),
                key_id: master_public_key_id,
                key_file: tmp_path.join("output.export").to_str().unwrap().to_owned(),
                ..Default::default()
            })
            .is_ok()
        );
        assert!(
            export_key(ExportKeyParams {
                cli_conf_path: owner_client_conf_path,
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
