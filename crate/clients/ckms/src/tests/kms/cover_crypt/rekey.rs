use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_cli::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    reexport::{
        cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::KeyUsage,
        cosmian_kms_crypto::{
            crypto::cover_crypt::access_structure::access_structure_from_json_file,
            reexport::{
                cosmian_cover_crypt::{
                    AccessPolicy, MasterSecretKey, UserSecretKey, api::Covercrypt,
                    encrypted_header::EncryptedHeader,
                },
                cosmian_crypto_core::bytes_ser_de::{
                    Deserializer, Serializable, test_serialization,
                },
            },
        },
    },
};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            cover_crypt::{
                SUB_COMMAND,
                encrypt_decrypt::{decrypt, encrypt},
                master_key_pair::create_cc_master_key_pair,
                user_decryption_keys::create_user_decryption_key,
            },
            shared::{ExportKeyParams, ImportKeyParams, export_key, import_key},
            symmetric::create_key::create_symmetric_key,
            utils::recover_cmd_logs,
        },
        save_kms_cli_config,
    },
};

pub(crate) fn rekey(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    access_policy: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "keys",
        "rekey",
        "--key-id",
        master_secret_key_id,
        access_policy,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("were rekeyed") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

pub(crate) fn prune(
    cli_conf_path: &str,
    master_secret_key_id: &str,
    access_policy: &str,
) -> CosmianResult<()> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    let args = vec![
        "keys",
        "prune",
        "--key-id",
        master_secret_key_id,
        access_policy,
    ];
    cmd.arg(KMS_SUBCOMMAND).arg(SUB_COMMAND).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() && std::str::from_utf8(&output.stdout)?.contains("were pruned") {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_rekey_error() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // generate a new master key pair
    let (master_secret_key_id, _master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    let _user_decryption_key = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    );

    // bad attributes
    assert!(
        rekey(
            &owner_client_conf_path,
            &master_secret_key_id,
            "bad_access_policy"
        )
        .is_err()
    );

    // bad keys
    assert!(
        rekey(
            &owner_client_conf_path,
            "bad_key",
            "Department::MKG || Department::FIN"
        )
        .is_err()
    );

    // Import a wrapped key

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();
    // create a symmetric key
    let symmetric_key_id =
        create_symmetric_key(&owner_client_conf_path, CreateKeyAction::default())?;
    // export a wrapped key
    let exported_wrapped_key_file = tmp_path.join("exported_wrapped_master_private.key");
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: master_secret_key_id,
        key_file: exported_wrapped_key_file.to_str().unwrap().to_string(),
        wrap_key_id: Some(symmetric_key_id),
        ..Default::default()
    })?;

    // import it wrapped
    let wrapped_key_id = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_string(),
        key_file: exported_wrapped_key_file.to_string_lossy().to_string(),
        replace_existing: true,
        ..Default::default()
    })?;

    // Rekeying wrapped keys is not allowed
    assert!(
        rekey(
            &owner_client_conf_path,
            &wrapped_key_id,
            "Department::MKG || Department::FIN"
        )
        .is_err()
    );

    Ok(())
}

#[test]
#[allow(clippy::similar_names)]
fn test_cc() -> CosmianResult<()> {
    let access_structure = access_structure_from_json_file(&PathBuf::from(
        "../../../test_data/access_structure_specifications.json",
    ))?;

    let cover_crypt = Covercrypt::default();
    let (mut msk, _mpk) = cover_crypt.setup()?;
    msk.access_structure = access_structure;
    let mpk = cover_crypt.update_msk(&mut msk)?;
    test_serialization(&msk).unwrap();

    let access_policy = "(Department::MKG || Department::FIN) && Security Level::Top Secret";
    let access_policy = AccessPolicy::parse(access_policy)?;
    let uk = cover_crypt.generate_user_secret_key(&mut msk, &access_policy)?;
    let uk_bytes = uk.serialize()?;
    let uk = UserSecretKey::deserialize(&uk_bytes)?;

    let encryption_policy = "Department::MKG && Security Level::Confidential";
    let ad = Some("myid".as_ref());
    let (_secret, encrypted_header) = EncryptedHeader::generate(
        &cover_crypt,
        &mpk,
        &AccessPolicy::parse(encryption_policy)?,
        None,
        ad,
    )?;
    let encrypted_header = encrypted_header.serialize()?.to_vec();

    let mut de = Deserializer::new(&encrypted_header);
    let encrypted_header = EncryptedHeader::read(&mut de)?;

    let _plaintext_header = encrypted_header.decrypt(&cover_crypt, &uk, ad)?;

    let ap = AccessPolicy::parse("Department::MKG || Department::FIN")?;
    let _mpk = cover_crypt.rekey(&mut msk, &ap)?;

    let msk_bytes = msk.serialize()?;
    let _my_msk = MasterSecretKey::deserialize(&msk_bytes)?;

    Ok(())
}

#[tokio::test]
async fn test_enc_dec_rekey() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure.json",
        &[],
        false,
    )?;
    let user_decryption_key_id = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::MKG || Department::FIN",
        &[],
        false,
    )?;

    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG",
        Some(output_file_before.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: user_decryption_key_id,
        key_file: exported_user_decryption_key_file
            .to_str()
            .unwrap()
            .to_string(),
        ..Default::default()
    })?;

    // rekey the attributes
    rekey(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::MKG || Department::FIN",
    )?;
    Ok(())
}

#[tokio::test]
async fn test_rekey_prune() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // create a temp dir
    let tmp_dir = TempDir::new()?;
    let tmp_path = tmp_dir.path();

    let input_file = PathBuf::from("../../../test_data/plain.txt");
    let output_file_before = tmp_path.join("plain.before.enc");
    let output_file_after = tmp_path.join("plain.after.enc");
    let recovered_file = tmp_path.join("plain.txt");

    // generate a new master key pair
    let (master_secret_key_id, master_public_key_id) = create_cc_master_key_pair(
        &owner_client_conf_path,
        "--specification",
        "../../../test_data/access_structure_specifications.json",
        &[],
        false,
    )?;
    let user_decryption_key_id = create_user_decryption_key(
        &owner_client_conf_path,
        &master_secret_key_id,
        "(Department::MKG || Department::FIN) && Security Level::Top Secret",
        &[],
        false,
    )?;

    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_before.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the file
    decrypt(
        &owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // export the user_decryption_key
    let exported_user_decryption_key_file = tmp_path.join("exported_user_decryption.key");
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_id: user_decryption_key_id.clone(),
        key_file: exported_user_decryption_key_file
            .to_str()
            .unwrap()
            .to_string(),
        ..Default::default()
    })?;

    // rekey the attributes
    rekey(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::MKG || Department::FIN",
    )?;

    // encrypt again after rekeying
    encrypt(
        &owner_client_conf_path,
        &[input_file.to_str().unwrap()],
        &master_public_key_id,
        "Department::MKG && Security Level::Confidential",
        Some(output_file_after.to_str().unwrap()),
        Some("myid"),
    )?;

    // the user key should be able to decrypt the new file
    decrypt(
        &owner_client_conf_path,
        &[output_file_after.to_str().unwrap()],
        &user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;
    // ... and the old file
    decrypt(
        &owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // import the non rotated user_decryption_key
    let old_user_decryption_key_id = import_key(ImportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: SUB_COMMAND.to_owned(),
        key_file: exported_user_decryption_key_file
            .to_string_lossy()
            .to_string(),
        replace_existing: false,
        key_usage_vec: Some(vec![KeyUsage::Unrestricted]),
        ..Default::default()
    })?;
    // the imported user key should not be able to decrypt the new file
    assert!(
        decrypt(
            &owner_client_conf_path,
            &[output_file_after.to_str().unwrap()],
            &old_user_decryption_key_id,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );
    // ... but should decrypt the old file
    decrypt(
        &owner_client_conf_path,
        &[output_file_before.to_str().unwrap()],
        &old_user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // prune the attributes
    prune(
        &owner_client_conf_path,
        &master_secret_key_id,
        "Department::MKG || Department::FIN",
    )?;

    // the user key should be able to decrypt the new file
    decrypt(
        &owner_client_conf_path,
        &[output_file_after.to_str().unwrap()],
        &user_decryption_key_id,
        Some(recovered_file.to_str().unwrap()),
        Some("myid"),
    )?;

    // but no longer the old file
    assert!(
        decrypt(
            &owner_client_conf_path,
            &[output_file_before.to_str().unwrap()],
            &user_decryption_key_id,
            Some(recovered_file.to_str().unwrap()),
            Some("myid"),
        )
        .is_err()
    );

    Ok(())
}
