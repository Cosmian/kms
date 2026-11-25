use cosmian_kms_cli_actions::reexport::{
    cosmian_kms_client::reexport::cosmian_kms_client_utils::import_utils::CertificateInputFormat,
};
use    test_kms_server::start_default_test_kms_server;
use cosmian_logger::info;

use crate::tests::utils::{ckms_bin, owner_config};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        certificates::import::{ImportCertificateInput, import_certificate},
        utils::recover_cmd_logs,
    },
};

/// A revoked leaf imported with its issuer must not be usable for encryption (#1461).
#[tokio::test]
#[cfg(all(feature = "non-fips", not(target_os = "windows")))]
async fn test_import_revoked_certificate_encrypt_prime256() -> CosmianResult<()> {
    use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::{
        certificate_utils::Algorithm, export_utils::CertificateExportFormat,
    };
    use std::path::PathBuf;

    use tempfile::TempDir;
    use test_kms_server::{TestClientOptions, start_test_server_with_patch, test_config_path};

    use crate::tests::{
        certificates::{
            certify::{CertifyOp, certify},
            encrypt::encrypt,
            export::export_certificate,
        },
        shared::revoke,
        utils::force_save_kms_cli_config,
    };

    // The CRL distribution point of the issued leaf is `kms_public_url`: the shared test
    // server advertises an unreachable port, so use a server that points at itself.
    let ctx = start_test_server_with_patch(
        &test_config_path("auth/plain.toml"),
        |config| config.kms_public_url = Some(format!("http://127.0.0.1:{}", config.http.port)),
        TestClientOptions::default(),
    )
    .await?;
    let (conf, _) = force_save_kms_cli_config(&ctx);
    let tmp_dir = TempDir::new()?;
    let leaf_pem = tmp_dir.path().join("leaf.pem");
    let leaf_pem = leaf_pem.to_str().unwrap();
    let output_file = tmp_dir.path().join("plain.enc");

    let ca_id = certify(
        &conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some("CN=Revoked Import CA,O=Cosmian".to_owned()),
            certificate_extensions: Some(PathBuf::from(
                "../../../test_data/certificates/chain/root/ca/ext_v3_ca_root.cnf",
            )),
            ..Default::default()
        },
    )?;
    let leaf_id = certify(
        &conf,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some("CN=Revoked Import Leaf,O=Cosmian".to_owned()),
            issuer_certificate_id: Some(ca_id.clone()),
            ..Default::default()
        },
    )?;
    // `revoke` is generic over the object type: the sub-command only selects the CLI family
    revoke(&conf, "ec", &leaf_id, "key compromise")?;
    export_certificate(
        &conf,
        &leaf_id,
        leaf_pem,
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;

    let imported_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &conf,
        sub_command: "certificates",
        key_file: leaf_pem,
        format: &CertificateInputFormat::Pem,
        issuer_certificate_id: Some(ca_id),
        ..Default::default()
    })?;
    assert_ne!(imported_id, leaf_id);

    assert!(
        encrypt(
            &conf,
            "../../../test_data/plain.txt",
            &imported_id,
            Some(output_file.to_str().unwrap()),
            None,
            None
        )
        .is_err()
    );
    ctx.stop_server().await?;
    Ok(())
}

pub(crate) fn validate_certificate(
    cli_conf_path: &str,
    sub_command: &str,
    uids: Vec<String>,
    date: Option<String>,
) -> CosmianResult<String> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    let mut args: Vec<String> = vec!["validate".to_owned()];
    for uid in uids {
        args.push("--certificate-id".to_owned());
        args.push(uid);
    }
    if let Some(d) = date {
        args.push("--validity-time".to_owned());
        args.push(d);
    }
    cmd.arg(sub_command).args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let validate_output = std::str::from_utf8(&output.stdout)?;
        return Ok(validate_output.to_owned());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[tokio::test]
async fn test_validate_cli() -> CosmianResult<()> {
    let ctx = start_default_test_kms_server().await;
    let owner_client_conf_path = owner_config(ctx);

    info!("importing root cert");
    let root_certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: "../../../test_data/certificates/chain/ca.cert.pem",
        format: &CertificateInputFormat::Pem,
        replace_existing: true,
        ..Default::default()
    })?;

    info!("importing intermediate cert");
    let intermediate_certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: "../../../test_data/certificates/chain/intermediate.cert.pem",
        format: &CertificateInputFormat::Pem,
        issuer_certificate_id: Some(root_certificate_id.clone()),
        replace_existing: true,
        ..Default::default()
    })?;

    let leaf1_certificate_id = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: "../../../test_data/certificates/chain/leaf1.cert.pem",
        format: &CertificateInputFormat::Pem,
        issuer_certificate_id: Some(intermediate_certificate_id.clone()),
        replace_existing: true,
        ..Default::default()
    })?;
    info!("leaf1 cert imported: {leaf1_certificate_id}");

    let test1_res = validate_certificate(
        &owner_client_conf_path,
        "certificates",
        vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
            leaf1_certificate_id,
        ],
        None,
    );
    info!(
        "Validate chain with leaf1: result supposed to be invalid, as leaf1 was revoked. \
         test1_res: {test1_res:?}"
    );
    assert!(
        format!("{test1_res:?}").contains("the certificate chain is not valid: Invalid"),
        "{test1_res:?}"
    );

    let test2_res = validate_certificate(
        &owner_client_conf_path,
        "certificates",
        vec![
            intermediate_certificate_id.clone(),
            root_certificate_id.clone(),
        ],
        None,
    )?;
    info!(
        "validate chain with leaf2: result supposed to be valid, as leaf2 was never revoked. \
         test2_res: {test2_res}"
    );
    assert!(test2_res.contains("Valid"));

    let test3_res = validate_certificate(
        &owner_client_conf_path,
        "certificates",
        vec![intermediate_certificate_id, root_certificate_id.clone()],
        // Date: 15/04/2048
        Some("20480415203000Z".to_owned()),
    );
    info!(
        "validate chain with leaf2: result supposed to be invalid, as date is posthumous to \
         leaf2's expiration date. test3_res: {test3_res:?}"
    );
    assert!(
        format!("{test3_res:?}").contains("the certificate chain is not valid: Invalid"),
        "{test3_res:?}"
    );

    let test4_res = validate_certificate(
        &owner_client_conf_path,
        "certificates",
        vec![root_certificate_id],
        None,
    )?;

    info!("validate chain only. Must be valid.");
    assert!(test4_res.contains("Valid"));

    info!("validate tests successfully passed");
    Ok(())
}
