//! End-to-end tests for `ckms est` (RFC 7030 EST client commands).

use std::path::{Path, PathBuf};

use cosmian_kms_cli_actions::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::certificate_utils::Algorithm;
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509, X509NameBuilder, X509ReqBuilder},
};
use tempfile::TempDir;
use test_kms_server::{
    TestClientOptions, reexport::cosmian_kms_server::config::EstConfig,
    start_test_server_with_patch, test_config_path,
};

use crate::{
    error::result::CosmianResult,
    tests::{
        certificates::certify::{CertifyOp, certify},
        utils::{owner_config, run_ckms, run_ckms_expect_error},
    },
};

const CA_UID: &str = "est-test-ca";
const BOOT_USER: &str = "bootstrap";
const BOOT_PASS: &str = "bootstrap-secret";

fn write_device_csr(dir: &Path, cn: &str) -> PathBuf {
    let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let mut builder = X509ReqBuilder::new().unwrap();
    builder.set_subject_name(&name.build()).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let path = dir.join(format!("{cn}.csr.pem"));
    std::fs::write(&path, builder.build().to_pem().unwrap()).unwrap();
    path
}

#[tokio::test]
async fn test_est_cacerts_and_enroll() -> CosmianResult<()> {
    let ctx = start_test_server_with_patch(
        &test_config_path("auth/plain.toml"),
        |config| {
            config.est = EstConfig {
                est_enabled: true,
                est_ca_uid: Some(CA_UID.to_owned()),
                est_require_client_cert: false,
                est_bootstrap_username: Some(BOOT_USER.to_owned()),
                est_bootstrap_password: Some(BOOT_PASS.to_owned()),
                est_template: None,
            };
        },
        TestClientOptions::default(),
    )
    .await?;
    let owner_conf = owner_config(&ctx);

    let tmp = TempDir::new().unwrap();
    let ext_path = tmp.path().join("ca.ext");
    std::fs::write(
        &ext_path,
        "[ v3_ca ]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,crlSign,digitalSignature,keyEncipherment\n",
    )
    .unwrap();
    certify(
        &owner_conf,
        CertifyOp {
            certificate_id: Some(CA_UID.to_owned()),
            generate_keypair: true,
            algorithm: Some(Algorithm::RSA2048),
            subject_name: Some("CN=EST Test CA,O=Cosmian Test,C=FR".to_owned()),
            certificate_extensions: Some(ext_path),
            ..Default::default()
        },
    )?;

    // 1. `ckms est cacerts`
    let cacerts_path = tmp.path().join("cacerts.pem");
    run_ckms(
        &owner_conf,
        &["est", "cacerts", "--out", cacerts_path.to_str().unwrap()],
    )?;
    let cacerts_pem = std::fs::read(&cacerts_path).unwrap();
    assert!(cacerts_pem.starts_with(b"-----BEGIN CERTIFICATE-----"));
    let ca_cert = X509::from_pem(&cacerts_pem).unwrap();

    // 2. `ckms est enroll` with bootstrap Basic credentials
    let csr_path = write_device_csr(tmp.path(), "device1.iot.example");
    let cert_path = tmp.path().join("device1.crt.pem");
    run_ckms(
        &owner_conf,
        &[
            "est",
            "enroll",
            "--csr",
            csr_path.to_str().unwrap(),
            "--out",
            cert_path.to_str().unwrap(),
            "--user",
            BOOT_USER,
            "--password",
            BOOT_PASS,
        ],
    )?;
    let issued_cert = X509::from_pem(&std::fs::read(&cert_path).unwrap()).unwrap();
    assert_eq!(
        issued_cert.issuer_name().to_der().unwrap(),
        ca_cert.subject_name().to_der().unwrap(),
    );
    assert!(
        issued_cert
            .subject_name()
            .entries()
            .any(|e| e.data().as_utf8().unwrap().to_string() == "device1.iot.example")
    );

    // 3. Wrong bootstrap password is rejected (401).
    let stderr = run_ckms_expect_error(
        &owner_conf,
        &[
            "est",
            "enroll",
            "--csr",
            csr_path.to_str().unwrap(),
            "--out",
            tmp.path().join("rejected.pem").to_str().unwrap(),
            "--user",
            BOOT_USER,
            "--password",
            "wrong",
        ],
    )?;
    assert!(stderr.contains("401") || stderr.to_lowercase().contains("unauthorized"));

    ctx.stop_server().await?;
    Ok(())
}
