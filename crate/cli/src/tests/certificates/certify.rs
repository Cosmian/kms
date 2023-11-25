use std::{path::PathBuf, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, LinkType},
    ttlv::{deserializer::from_ttlv, TTLV},
};
use cosmian_logger::log_utils::log_init;
use openssl::{nid::Nid, x509::X509};
use uuid::Uuid;

use crate::{
    actions::{
        certificates::{CertificateExportFormat, CertificateInputFormat},
        shared::utils::{read_from_json_file, read_object_from_json_ttlv_file},
    },
    config::KMS_CLI_CONF_ENV,
    error::CliError,
    tests::{
        certificates::{export::export_certificate, import::import_certificate},
        elliptic_curve::create_key_pair::create_ec_key_pair,
        shared::export_key,
        utils::{extract_uids::extract_uid, recover_cmd_logs, start_default_test_kms_server, ONCE},
        PROG_NAME,
    },
};

#[allow(clippy::too_many_arguments)]
pub fn certify(
    cli_conf_path: &str,
    csr_file: Option<String>,
    public_key_id_to_certify: Option<String>,
    subject_name: Option<String>,
    issuer_private_key_id: &str,
    certificate_id: Option<String>,
    days: Option<usize>,
    tags: Option<&[&str]>,
) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=debug");
    let mut args: Vec<String> = vec!["certify".to_owned(), issuer_private_key_id.to_owned()];
    if let Some(csr_file) = csr_file {
        args.push("--certificate-signing-request".to_owned());
        args.push(csr_file);
    }
    if let Some(public_key_id_to_certify) = public_key_id_to_certify {
        args.push("--public-key-id-to-certify".to_owned());
        args.push(public_key_id_to_certify);
    }
    if let Some(subject_name) = subject_name {
        args.push("--subject-name".to_owned());
        args.push(subject_name);
    }
    if let Some(key_id) = certificate_id {
        args.push(key_id);
    }
    if let Some(days) = days {
        args.push("--days".to_owned());
        args.push(days.to_string());
    }
    if let Some(tags) = tags {
        for tag in tags {
            args.push("--tag".to_owned());
            args.push((*tag).to_string());
        }
    }
    cmd.arg("certificates").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        let import_output = std::str::from_utf8(&output.stdout)?;
        let imported_key_id = extract_certificate_id(import_output)
            .ok_or_else(|| CliError::Default("failed extracting the imported key id".to_owned()))?
            .to_owned();
        return Ok(imported_key_id)
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

/// Extract the imported key id
pub fn extract_certificate_id(text: &str) -> Option<&str> {
    extract_uid(text, ".*? was issued with id")
}

#[tokio::test]
async fn certify_a_csr_test() -> Result<(), CliError> {
    log_init("cosmian_kms_server=debug");
    // Create a test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // import Root CA
    import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/csr/ca.crt",
        CertificateInputFormat::Pem,
        None,
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["root_ca"]),
        false,
        true,
    )?;

    // import Intermediate p12
    let issuer_private_key_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/csr/intermediate.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["intermediate_ca"]),
        false,
        true,
    )?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_cli_conf_path,
        Some("test_data/certificates/csr/leaf.csr".to_owned()),
        None,
        None,
        &issuer_private_key_id,
        None,
        None,
        None,
    )?;

    // export the certificate
    export_certificate(
        &ctx.owner_cli_conf_path,
        &certificate_id,
        "/tmp/exported_cert.json",
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();
    let cert = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/exported_cert.json")).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => panic!("wrong object type"),
    };
    // check that the certificate is valid by parsing it using openssl
    let cert_x509 = X509::from_der(cert_x509_der).unwrap();
    // print the subject name
    assert_eq!(
        "Test Leaf",
        cert_x509
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
    );
    let ttlv: TTLV =
        read_from_json_file(&PathBuf::from("/tmp/exported_cert.attributes.json")).unwrap();
    let attributes: Attributes = from_ttlv(&ttlv).unwrap();
    // check that the attributes contain a certificate link to the intermediate
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    // export the intermediate certificate
    export_certificate(
        &ctx.owner_cli_conf_path,
        &certificate_link,
        "/tmp/exported_intermediate_cert.json",
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;
    // check that the attributes contain a certificate link to the private key
    let ttlv: TTLV = read_from_json_file(&PathBuf::from(
        "/tmp/exported_intermediate_cert.attributes.json",
    ))
    .unwrap();
    let attributes: Attributes = from_ttlv(&ttlv).unwrap();
    let private_key_link = attributes.get_link(LinkType::PrivateKeyLink).unwrap();
    assert_eq!(private_key_link, issuer_private_key_id);
    Ok(())
}

#[tokio::test]
async fn certify_a_public_key_test() -> Result<(), CliError> {
    log_init("cosmian_kms_server=debug");
    // Create a test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    // import Root CA
    import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/csr/ca.crt",
        CertificateInputFormat::Pem,
        None,
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["root_ca"]),
        false,
        true,
    )?;

    // import Intermediate p12
    let issuer_private_key_id = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/csr/intermediate.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["intermediate_ca"]),
        false,
        true,
    )?;

    // create a Ed25519 Key Pair
    let (_private_key_id, public_key_id) = create_ec_key_pair(&ctx.owner_cli_conf_path, &[])?;

    // Certify the public key with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_cli_conf_path,
        None,
        Some(public_key_id),
        Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = kmserver.acme.com".to_string()),
        &issuer_private_key_id,
        None,
        None,
        None,
    )?;

    // export the certificate
    export_certificate(
        &ctx.owner_cli_conf_path,
        &certificate_id,
        "/tmp/exported_cert.json",
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();
    let cert = read_object_from_json_ttlv_file(&PathBuf::from("/tmp/exported_cert.json")).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => panic!("wrong object type"),
    };
    // check that the certificate is valid by parsing it using openssl
    let cert_x509 = X509::from_der(cert_x509_der).unwrap();
    // print the subject name
    assert_eq!(
        "kmserver.acme.com",
        cert_x509
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
    );
    let ttlv: TTLV =
        read_from_json_file(&PathBuf::from("/tmp/exported_cert.attributes.json")).unwrap();
    let certificate_attributes: Attributes = from_ttlv(&ttlv).unwrap();

    // check that the attributes contain a certificate link to the intermediate
    let certificate_link = certificate_attributes
        .get_link(LinkType::CertificateLink)
        .unwrap();
    // export the intermediate certificate
    export_certificate(
        &ctx.owner_cli_conf_path,
        &certificate_link,
        "/tmp/exported_intermediate_cert.json",
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )?;

    // check that the certificate contains a link to the public key
    let public_key_link = certificate_attributes
        .get_link(LinkType::PublicKeyLink)
        .unwrap();
    export_key(
        &ctx.owner_cli_conf_path,
        "keys",
        &public_key_link,
        "/tmp/exported_public_key.json",
        None,
        false,
        None,
        false,
    )?;
    let public_key =
        read_object_from_json_ttlv_file(&PathBuf::from("/tmp/exported_public_key.json")).unwrap();
    //check that the public key contains a link to the certificate
    let certificate_link = public_key
        .attributes()?
        .get_link(LinkType::CertificateLink)
        .unwrap();
    assert_eq!(certificate_link, certificate_id);

    Ok(())
}
