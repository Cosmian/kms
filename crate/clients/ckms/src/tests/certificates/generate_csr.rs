use cosmian_logger::log_init;
use openssl::x509::{X509, X509Req};
use tempfile::TempDir;
use test_kms_server::start_default_test_kms_server;

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::CertificateExportFormat;

use super::{
    certify::{CertifyOp, certify, import_root_and_intermediate},
    export::export_certificate,
};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        rsa::create_key_pair::{RsaKeyPairOptions, create_rsa_key_pair},
        utils::{ckms_bin, owner_config, recover_cmd_logs},
    },
};

fn generate_csr(
    cli_conf_path: &str,
    private_key_id: &str,
    subject_name: &str,
    output_file: &std::path::Path,
) -> CosmianResult<()> {
    let mut cmd = ckms_bin();
    cmd.env(CKMS_CONF_ENV, cli_conf_path);
    cmd.args([
        "certificates",
        "generate-csr",
        "--private-key-id",
        private_key_id,
    ])
    .args(["--subject-name", subject_name])
    .arg("--output-file")
    .arg(output_file);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// A sub-CA CSR is generated for a key kept in the KMS, signed by a CA, and the resulting
/// certificate carries the key of the CSR.
#[tokio::test]
async fn test_generate_csr_for_kms_held_key_and_certify_it() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();

    let (private_key_id, _public_key_id) = create_rsa_key_pair(
        &conf,
        &RsaKeyPairOptions {
            number_of_bits: Some(2048),
            ..Default::default()
        },
    )?;
    let csr_file = tmp_dir.path().join("subca.csr");
    generate_csr(
        &conf,
        &private_key_id,
        "C=FR, O=Acme, CN=Acme Sub CA",
        &csr_file,
    )?;

    let csr = X509Req::from_pem(&std::fs::read(&csr_file).unwrap()).unwrap();
    assert!(csr.verify(csr.public_key().unwrap().as_ref()).unwrap());
    let cn = csr
        .subject_name()
        .entries()
        .last()
        .map(|e| String::from_utf8_lossy(e.data().as_slice()).into_owned());
    assert_eq!(cn.as_deref(), Some("Acme Sub CA"));

    // The "offline root" signs it.
    let (_root_id, _intermediate_id, issuer_private_key_id) = import_root_and_intermediate(&conf)?;
    let certificate_id = certify(
        &conf,
        CertifyOp {
            csr_file: Some(csr_file.to_string_lossy().into_owned()),
            issuer_private_key_id: Some(issuer_private_key_id),
            ..Default::default()
        },
    )?;
    let pem_file = tmp_dir.path().join("subca.pem");
    export_certificate(
        &conf,
        &certificate_id,
        pem_file.to_str().unwrap(),
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;
    let certificate = X509::from_pem(&std::fs::read(&pem_file).unwrap()).unwrap();
    assert!(
        certificate
            .public_key()
            .unwrap()
            .public_eq(csr.public_key().unwrap().as_ref())
    );
    Ok(())
}

#[tokio::test]
async fn test_generate_csr_rejects_a_public_key_and_a_bad_subject() -> CosmianResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let conf = owner_config(ctx);
    let tmp_dir = TempDir::new().unwrap();
    let (private_key_id, public_key_id) =
        create_rsa_key_pair(&conf, &RsaKeyPairOptions::default())?;
    let out = tmp_dir.path().join("x.csr");
    assert!(generate_csr(&conf, &public_key_id, "CN=x", &out).is_err());
    assert!(generate_csr(&conf, &private_key_id, "not a dn", &out).is_err());
    assert!(!out.exists(), "no CSR file is written on failure");
    Ok(())
}
