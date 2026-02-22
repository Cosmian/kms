use std::{path::PathBuf, process::Command};

use assert_cmd::prelude::*;
use cosmian_kms_cli::actions::kms::{
    google::key_pairs::create::CreateKeyPairsAction, symmetric::keys::create_key::CreateKeyAction,
};
use cosmian_logger::log_init;
use test_kms_server::start_default_test_kms_server;

use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{
            KMS_SUBCOMMAND,
            certificates::certify::import_root_and_intermediate,
            utils::{extract_uids::extract_certificate_id, recover_cmd_logs},
        },
        save_kms_cli_config,
    },
};

fn create_keypairs(
    cli_conf_path: &str,
    action: CreateKeyPairsAction,
) -> Result<String, CosmianError> {
    // Create keypairs
    let mut args: Vec<String> = [
        "create".to_owned(),
        "--cse-key-id".to_owned(),
        action.cse_key_id.clone(),
        "--subject-name".to_owned(),
        action.subject_name.clone(),
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();

    if let Some(issuer_private_key_id) = action.issuer_private_key_id {
        args.push("--issuer-private-key-id".to_string());
        args.push(issuer_private_key_id);
    }
    if let Some(rsa_private_key_id) = action.rsa_private_key_id {
        args.push("--rsa-private-key-id".to_string());
        args.push(rsa_private_key_id);
    }
    if let Some(wrapping_key_id) = action.wrapping_key_id {
        args.push("--wrapping-key-id".to_string());
        args.push(wrapping_key_id);
    }
    if let Some(leaf_certificate_extensions) = action.leaf_certificate_extensions {
        args.push("--leaf-certificate-extensions".to_string());
        args.push(leaf_certificate_extensions.to_str().unwrap().to_string());
    }
    if let Some(leaf_certificate_id) = action.leaf_certificate_id {
        args.push("--leaf-certificate-id".to_string());
        args.push(leaf_certificate_id);
    }
    if let Some(leaf_certificate_pkcs12_file) = action.leaf_certificate_pkcs12_file {
        args.push("--leaf-certificate-pkcs12-file".to_string());
        args.push(leaf_certificate_pkcs12_file.to_str().unwrap().to_string());
    }
    if let Some(leaf_certificate_pkcs12_password) = action.leaf_certificate_pkcs12_password {
        args.push("--leaf-certificate-pkcs12-password".to_string());
        args.push(leaf_certificate_pkcs12_password);
    }
    if action.dry_run {
        args.push("--dry-run".to_string());
    }
    if action.sensitive {
        args.push("--sensitive".to_string());
    }

    // Finish with user id
    args.push(action.user_id);

    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.arg(KMS_SUBCOMMAND)
        .arg("google")
        .arg("key-pairs")
        .args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let stdout = std::str::from_utf8(&output.stdout)?;
        let certificate_id = extract_certificate_id(stdout)
            .ok_or_else(|| {
                CosmianError::Default("failed extracting the certificate id".to_owned())
            })?
            .to_owned();

        // Extract the certificate ID from the output or return a placeholder
        Ok(certificate_id)
    } else {
        Err(CosmianError::Default(
            std::str::from_utf8(&output.stderr)?.to_owned(),
        ))
    }
}

#[tokio::test]
async fn cli_create_google_key_pair() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create the Google CSE key
    let cse_key_id = CreateKeyAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // import signers
    let (_root_id, _intermediate_id, issuer_private_key_id) =
        import_root_and_intermediate(&owner_client_conf_path)?;

    // Create key pair without certificate extensions (must fail)
    let action = CreateKeyPairsAction {
        user_id: "john.doe@acme.com".to_string(),
        cse_key_id: cse_key_id.to_string(),
        issuer_private_key_id: None,
        subject_name: "CN=John Doe,OU=Org Unit,O=Org Name,L=City,ST=State,C=US".to_string(),
        rsa_private_key_id: None,
        sensitive: false,
        wrapping_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_id: None,
        leaf_certificate_pkcs12_file: None,
        leaf_certificate_pkcs12_password: None,
        number_of_days: 20,
        dry_run: true,
    };
    assert!(create_keypairs(&owner_client_conf_path, action.clone()).is_err());

    // Create key pair with certificate extensions (must succeed)
    let action = CreateKeyPairsAction {
        issuer_private_key_id: Some(issuer_private_key_id),
        leaf_certificate_extensions: Some(PathBuf::from(
            "../../../test_data/certificates/openssl/ext_leaf.cnf",
        )),
        ..action
    };
    let certificate_1 = create_keypairs(&owner_client_conf_path, action.clone()).unwrap();
    println!("Created key pair with certificate ID: {certificate_1}");

    // Create key pair with certificate id (must succeed)
    let action = CreateKeyPairsAction {
        user_id: "john.williams@acme.com".to_string(),
        issuer_private_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_id: Some(certificate_1),
        ..action
    };
    let _certificate_2 = create_keypairs(&owner_client_conf_path, action.clone()).unwrap();

    // Create key pair using a certificate file (must succeed)
    let action = CreateKeyPairsAction {
        user_id: "john.barry@acme.com".to_string(),
        leaf_certificate_id: None,
        issuer_private_key_id: None,
        leaf_certificate_extensions: None,
        leaf_certificate_pkcs12_file: Some(PathBuf::from(
            "../../../test_data/certificates/csr/leaf.p12",
        )),
        leaf_certificate_pkcs12_password: Some("secret".to_owned()),
        ..action
    };
    let _certificate_3 = create_keypairs(&owner_client_conf_path, action).unwrap();

    Ok(())
}
