use std::{
    path::{Path, PathBuf},
    process::Command,
};

use assert_cmd::prelude::CommandCargoExt;
use base64::{Engine as _, engine::general_purpose};
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::{
        cosmian_kms_client::{
            cosmian_kmip::kmip_2_1::kmip_types::{EncodingOption, WrappingMethod},
            read_object_from_json_ttlv_file,
        },
        cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng,
            reexport::rand_core::{RngCore, SeedableRng},
        },
    },
};
use cosmian_logger::log_init;
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use super::ExportKeyParams;
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            cover_crypt::master_key_pair::create_cc_master_key_pair,
            elliptic_curve::create_key_pair::create_ec_key_pair,
            shared::export::export_key,
            symmetric::create_key::create_symmetric_key,
            utils::{extract_uids::extract_wrapping_key, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn wrap(
    cli_conf_path: &str,
    sub_command: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    wrap_password: Option<String>,
    wrap_key_b64: Option<String>,
    wrap_key_id: Option<String>,
    wrap_key_file: Option<PathBuf>,
) -> CosmianResult<String> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "wrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }

    if let Some(wrap_password) = wrap_password {
        args.push("-p".to_owned());
        args.push(wrap_password);
    } else if let Some(wrap_key_b64) = wrap_key_b64 {
        args.push("-k".to_owned());
        args.push(wrap_key_b64);
    } else if let Some(wrap_key_id) = wrap_key_id {
        args.push("-i".to_owned());
        args.push(wrap_key_id);
    } else if let Some(wrap_key_file) = wrap_key_file {
        args.push("-f".to_owned());
        args.push(wrap_key_file.to_str().unwrap().to_owned());
    }

    cmd.arg(KMS_SUBCOMMAND).arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let wrap_output = std::str::from_utf8(&output.stdout)?;
        let b64_wrapping_key = extract_wrapping_key(wrap_output)
            .unwrap_or_default()
            .to_owned();
        return Ok(b64_wrapping_key);
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn unwrap(
    cli_conf_path: &str,
    sub_command: &str,
    key_file_in: &Path,
    key_file_out: Option<&PathBuf>,
    unwrap_password: Option<String>,
    unwrap_key_b64: Option<String>,
    unwrap_key_id: Option<String>,
    unwrap_key_file: Option<PathBuf>,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let mut args: Vec<String> = vec![
        "keys".to_owned(),
        "unwrap".to_owned(),
        key_file_in.to_str().unwrap().to_owned(),
    ];

    if let Some(key_file_out) = key_file_out {
        args.push(key_file_out.to_str().unwrap().to_owned());
    }

    if let Some(unwrap_password) = unwrap_password {
        args.push("-p".to_owned());
        args.push(unwrap_password);
    } else if let Some(unwrap_key_b64) = unwrap_key_b64 {
        args.push("-k".to_owned());
        args.push(unwrap_key_b64);
    } else if let Some(unwrap_key_id) = unwrap_key_id {
        args.push("-i".to_owned());
        args.push(unwrap_key_id);
    } else if let Some(unwrap_key_file) = unwrap_key_file {
        args.push("-f".to_owned());
        args.push(unwrap_key_file.to_str().unwrap().to_owned());
    }
    cmd.arg(KMS_SUBCOMMAND).arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
pub(crate) async fn test_password_wrap_import() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // CC
    let (private_key_id, _public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    password_wrap_import_test(&owner_client_conf_path, "cc", &private_key_id)?;

    // EC
    let (private_key_id, _public_key_id) =
        create_ec_key_pair(&owner_client_conf_path, "nist-p256", &[], false)?;
    password_wrap_import_test(&owner_client_conf_path, "ec", &private_key_id)?;

    // sym
    let key_id = create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;
    password_wrap_import_test(&owner_client_conf_path, "sym", &key_id)?;

    Ok(())
}

pub(crate) fn password_wrap_import_test(
    owner_client_conf_path: &str,
    sub_command: &str,
    private_key_id: &str,
) -> CosmianResult<()> {
    let temp_dir = TempDir::new()?;

    // Export
    let key_file = temp_dir.path().join("master_private.key");
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.to_string(),
        sub_command: sub_command.to_owned(),
        key_id: private_key_id.to_owned(),
        key_file: key_file.to_str().unwrap().to_owned(),
        ..Default::default()
    })?;

    let object = read_object_from_json_ttlv_file(&key_file)?;
    let key_bytes = if sub_command == "ec" {
        object.key_block()?.ec_raw_bytes()?
    } else if sub_command == "cc" {
        object.key_block()?.covercrypt_key_bytes()?
    } else {
        object.key_block()?.key_bytes()?
    };

    // wrap and unwrap using a password
    {
        let b64_wrapping_key = wrap(
            owner_client_conf_path,
            sub_command,
            &key_file,
            None,
            Some("password".to_owned()),
            None,
            None,
            None,
        )?;
        let wrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::TTLVEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.wrapped_key_bytes()?, key_bytes);
        unwrap(
            owner_client_conf_path,
            sub_command,
            &key_file,
            None,
            None,
            Some(b64_wrapping_key),
            None,
            None,
        )?;
        let unwrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(
            if sub_command == "ec" {
                unwrapped_object.key_block()?.ec_raw_bytes()?
            } else if sub_command == "cc" {
                unwrapped_object.key_block()?.covercrypt_key_bytes()?
            } else {
                unwrapped_object.key_block()?.key_bytes()?
            },
            key_bytes
        );
    }

    // wrap and unwrap using a base64 key
    {
        let mut rng = CsRng::from_entropy();
        let mut key = vec![0u8; 32];
        rng.fill_bytes(&mut key);
        let key_b64 = general_purpose::STANDARD.encode(&key);
        wrap(
            owner_client_conf_path,
            sub_command,
            &key_file,
            None,
            None,
            Some(key_b64.clone()),
            None,
            None,
        )?;
        let wrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(wrapped_object.key_wrapping_data().is_some());
        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().wrapping_method,
            WrappingMethod::Encrypt
        );

        assert_eq!(
            wrapped_object.key_wrapping_data().unwrap().encoding_option,
            Some(EncodingOption::TTLVEncoding)
        );
        assert_ne!(wrapped_object.key_block()?.wrapped_key_bytes()?, key_bytes);
        unwrap(
            owner_client_conf_path,
            sub_command,
            &key_file,
            None,
            None,
            Some(key_b64),
            None,
            None,
        )?;
        let unwrapped_object = read_object_from_json_ttlv_file(&key_file)?;
        assert!(unwrapped_object.key_wrapping_data().is_none());
        assert_eq!(
            if sub_command == "ec" {
                unwrapped_object.key_block()?.ec_raw_bytes()?
            } else if sub_command == "cc" {
                unwrapped_object.key_block()?.covercrypt_key_bytes()?
            } else {
                unwrapped_object.key_block()?.key_bytes()?
            },
            key_bytes
        );
    }

    // other wrap unwrap scenarios are covered by tests in utils/wrap_unwrap

    Ok(())
}
