use std::{path::PathBuf, process::Command};

use assert_cmd::cargo::CommandCargoExt;
use cosmian_kms_client::{
    cosmian_kmip::kmip::{
        kmip_objects::Object,
        kmip_types::{Attributes, LinkType},
        ttlv::{deserializer::from_ttlv, TTLV},
    },
    read_from_json_file, read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV,
};
use cosmian_logger::log_utils::log_init;
use kms_test_server::{start_default_test_kms_server, TestsContext, ONCE};
use openssl::{nid::Nid, x509::X509};
use tempfile::TempDir;
use uuid::Uuid;
use x509_parser::{der_parser::oid, prelude::*};

use crate::{
    actions::certificates::{Algorithm, CertificateExportFormat, CertificateInputFormat},
    error::CliError,
    tests::{
        certificates::{export::export_certificate, import::import_certificate},
        rsa::create_key_pair::create_rsa_4096_bits_key_pair,
        shared::export_key,
        utils::{extract_uids::extract_uid, recover_cmd_logs},
        PROG_NAME,
    },
};

#[derive(Debug, Default)]
pub struct CertifyOp {
    issuer_certificate_key_id: Option<String>,
    issuer_private_key_id: Option<String>,
    csr_file: Option<String>,
    public_key_id_to_certify: Option<String>,
    certificate_id_to_re_certify: Option<String>,
    generate_keypair: bool,
    subject_name: Option<String>,
    algorithm: Option<Algorithm>,
    certificate_id: Option<String>,
    days: Option<u32>,
    certificate_extensions: Option<PathBuf>,
    tags: Option<Vec<String>>,
}

pub fn certify(cli_conf_path: &str, certify_op: CertifyOp) -> Result<String, CliError> {
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    let mut args: Vec<String> = vec!["certify".to_owned()];
    if let Some(issuer_certificate_key_id) = certify_op.issuer_certificate_key_id {
        args.push("--issuer-certificate-id".to_owned());
        args.push(issuer_certificate_key_id);
    }
    if let Some(issuer_private_key_id) = certify_op.issuer_private_key_id {
        args.push("--issuer-private-key-id".to_owned());
        args.push(issuer_private_key_id);
    }
    if let Some(csr_file) = certify_op.csr_file {
        args.push("--certificate-signing-request".to_owned());
        args.push(csr_file);
    }
    if let Some(public_key_id_to_certify) = certify_op.public_key_id_to_certify {
        args.push("--public-key-id-to-certify".to_owned());
        args.push(public_key_id_to_certify);
    }
    if let Some(certificate_id_to_re_certify) = certify_op.certificate_id_to_re_certify {
        args.push("--certificate-id-to-re-certify".to_owned());
        args.push(certificate_id_to_re_certify);
    }
    if certify_op.generate_keypair {
        args.push("--generate-key-pair".to_owned());
    }
    if let Some(subject_name) = certify_op.subject_name {
        args.push("--subject-name".to_owned());
        args.push(subject_name);
    }
    if let Some(algorithm) = certify_op.algorithm {
        args.push("--algorithm".to_owned());
        args.push(algorithm.to_string());
    }
    if let Some(certificate_id) = certify_op.certificate_id {
        args.push("--certificate-id".to_owned());
        args.push(certificate_id);
    }
    if let Some(days) = certify_op.days {
        args.push("--days".to_owned());
        args.push(days.to_string());
    }
    if let Some(certificate_extensions) = certify_op.certificate_extensions {
        args.push("--certificate-extensions".to_owned());
        args.push(certificate_extensions.to_string_lossy().to_string());
    }
    if let Some(tags) = certify_op.tags {
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

fn import_root_and_intermediate(ctx: &TestsContext) -> Result<(String, String), CliError> {
    // import Root CA
    let root_ca_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/csr/ca.crt",
        CertificateInputFormat::Pem,
        None,
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["root_ca"]),
        None,
        false,
        true,
    )?;

    // import Intermediate p12
    let intermediate_ca_id = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/csr/intermediate.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["intermediate_ca"]),
        None,
        false,
        true,
    )?;

    Ok((root_ca_id, intermediate_ca_id))
}

/// Check a generated certificate and return its Object, attributes and der bytes
fn check_generated_certificate(
    ctx: &TestsContext,
    issuer_private_key_id: &str,
    certificate_id: &str,
) -> (Object, Attributes, Vec<u8>) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    // export the certificate
    let exported_cert_file = tmp_path.join("exported_cert.json");
    export_certificate(
        &ctx.owner_client_conf_path,
        certificate_id,
        exported_cert_file.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();
    let cert = read_object_from_json_ttlv_file(&exported_cert_file).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => panic!("wrong object type"),
    }
    .to_vec();
    // check that the certificate is valid by parsing it using openssl
    let cert_x509 = X509::from_der(&cert_x509_der).unwrap();
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
    let ttlv: TTLV = read_from_json_file(&tmp_path.join("exported_cert.attributes.json")).unwrap();
    let cert_attributes: Attributes = from_ttlv(&ttlv).unwrap();
    // check that the attributes contain a certificate link to the intermediate
    let certificate_link = cert_attributes.get_link(LinkType::CertificateLink).unwrap();
    // export the intermediate certificate
    let exported_intermediate_cert_file = tmp_path.join("exported_intermediate_cert.json");
    export_certificate(
        &ctx.owner_client_conf_path,
        &certificate_link.to_string(),
        exported_intermediate_cert_file.to_str().unwrap(),
        Some(CertificateExportFormat::Pem),
        None,
        true,
    )
    .unwrap();
    // check that the attributes contain a certificate link to the private key
    let ttlv: TTLV =
        read_from_json_file(&tmp_path.join("exported_intermediate_cert.attributes.json")).unwrap();
    let int_attributes: Attributes = from_ttlv(&ttlv).unwrap();
    let private_key_link = int_attributes.get_link(LinkType::PrivateKeyLink).unwrap();
    assert_eq!(private_key_link.to_string(), issuer_private_key_id);
    (cert, cert_attributes, cert_x509_der)
}

fn check_certificate_added_extensions(cert_x509_der: &Vec<u8>) {
    // check X509 extensions
    let (_, cert_x509) = X509Certificate::from_der(&cert_x509_der).unwrap();
    let exts_with_x509_parser = cert_x509.extensions();

    // BasicConstraints
    let bc = exts_with_x509_parser
        .iter()
        .find(|x| x.oid == oid!(2.5.29.19))
        .unwrap();
    assert!(!bc.critical);
    assert_eq!(
        bc.parsed_extension(),
        &ParsedExtension::BasicConstraints(BasicConstraints {
            ca: true,
            path_len_constraint: Some(0)
        })
    );

    // KeyUsage
    let ku: &X509Extension<'_> = exts_with_x509_parser
        .iter()
        .find(|x| x.oid == oid!(2.5.29.15))
        .unwrap();
    assert!(!ku.critical);
    assert_eq!(
        ku.parsed_extension(),
        &ParsedExtension::KeyUsage(KeyUsage { flags: 33 })
    );

    // ExtendedKeyUsage
    let eku: &X509Extension<'_> = exts_with_x509_parser
        .iter()
        .find(|x| x.oid == oid!(2.5.29.37))
        .unwrap();
    assert!(!eku.critical);
    assert_eq!(
        eku.parsed_extension(),
        &ParsedExtension::ExtendedKeyUsage(ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: true,
            time_stamping: false,
            ocsp_signing: false,
            other: vec![]
        })
    );

    // CRLDistributionPoints
    let crl_dp: &X509Extension<'_> = exts_with_x509_parser
        .iter()
        .find(|x| x.oid == oid!(2.5.29.31))
        .unwrap();
    assert!(!crl_dp.critical);
    assert_eq!(
        crl_dp.parsed_extension(),
        &ParsedExtension::CRLDistributionPoints(CRLDistributionPoints {
            points: vec![CRLDistributionPoint {
                distribution_point: Some(DistributionPointName::FullName(vec![GeneralName::URI(
                    "http://cse.example.com/crl.pem"
                )])),
                reasons: None,
                crl_issuer: None
            }]
        })
    );
}

fn check_certificate_and_public_key_linked(
    ctx: &TestsContext,
    certificate_id: &str,
    certificate_attributes: &Attributes,
) -> (String, Attributes) {
    // check that the certificate contains a link to the public key
    let public_key_link = certificate_attributes
        .get_link(LinkType::PublicKeyLink)
        .unwrap();
    // export the public key
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    let tmp_exported_pubkey = tmp_path.join("exported_pubkey.json");
    export_key(
        &ctx.owner_client_conf_path,
        "rsa",
        &public_key_link.to_string(),
        tmp_exported_pubkey.to_str().unwrap(),
        None,
        false,
        None,
        false,
    )
    .unwrap();
    let public_key = read_object_from_json_ttlv_file(&tmp_exported_pubkey).unwrap();
    //check that the public key contains a link to the certificate
    let public_key_attributes = public_key.attributes().unwrap();
    let certificate_link = public_key_attributes
        .get_link(LinkType::CertificateLink)
        .unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);
    (public_key_link.to_string(), public_key_attributes.clone())
}

fn check_public_and_private_key_linked(
    ctx: &TestsContext,
    public_key_id: &str,
    public_key_attributes: &Attributes,
) -> String {
    // check that the certificate contains a link to the public key
    let private_key_link = public_key_attributes
        .get_link(LinkType::PrivateKeyLink)
        .unwrap();
    // export the public key
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    let tmp_exported_privkey = tmp_path.join("exported_privkey.json");
    export_key(
        &ctx.owner_client_conf_path,
        "rsa",
        &private_key_link.to_string(),
        tmp_exported_privkey.to_str().unwrap(),
        None,
        false,
        None,
        false,
    )
    .unwrap();
    let private_key = read_object_from_json_ttlv_file(&tmp_exported_privkey).unwrap();
    //check that the private key contains a link to the public key
    let public_key_link = private_key
        .attributes()
        .unwrap()
        .get_link(LinkType::PublicKeyLink)
        .unwrap();
    assert_eq!(public_key_link.to_string(), public_key_id);
    private_key_link.to_string()
}

#[tokio::test]
async fn test_certify_a_csr() -> Result<(), CliError> {
    // log_init("cosmian_kms_server=debug");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            csr_file: Some("test_data/certificates/csr/leaf.csr".to_owned()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            tags: Some(vec!["certify_a_csr_test".to_owned()]),
            ..Default::default()
        },
    )?;

    let _ = check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);
    Ok(())
}

#[tokio::test]
async fn test_certify_a_csr_with_extensions() -> Result<(), CliError> {
    // log_init("cosmian_kms_server=info");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            csr_file: Some("test_data/certificates/csr/leaf.csr".to_owned()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            tags: Some(vec!["certify_a_csr_test".to_owned()]),
            certificate_extensions: Some(PathBuf::from("test_data/certificates/openssl/ext.cnf")),
            ..Default::default()
        },
    )?;

    // check the certificate
    let (_, _, cert_x509_der) =
        check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);

    // check the added extensions
    check_certificate_added_extensions(&cert_x509_der);

    Ok(())
}

#[tokio::test]
async fn certify_a_public_key_test() -> Result<(), CliError> {
    // log_init("cosmian_kms_server=info");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // create an RSA key pair
    let (_private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    // Certify the public key with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            public_key_id_to_certify: Some(public_key_id.clone()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_string(),
            ),
            ..Default::default()
        },
    )?;

    // check the certificate
    let (_, attributes, _) =
        check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);

    // check links to public key
    check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes);

    Ok(())
}

#[tokio::test]
async fn certify_a_public_key_test_with_extensions() -> Result<(), CliError> {
    // log_init("cosmian_kms_server=info");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;

    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // create an RSA key pair
    let (_private_key_id, public_key_id) =
        create_rsa_4096_bits_key_pair(&ctx.owner_client_conf_path, &[])?;

    // Certify the public key with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            public_key_id_to_certify: Some(public_key_id.clone()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_string(),
            ),
            certificate_extensions: Some(PathBuf::from("test_data/certificates/openssl/ext.cnf")),
            ..Default::default()
        },
    )?;

    // check the certificate
    let (_, attributes, cert_x509_der) =
        check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);

    // check the added extensions
    check_certificate_added_extensions(&cert_x509_der);

    // check links to public key
    check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes);

    Ok(())
}

#[tokio::test]
async fn test_renew_a_certificate() -> Result<(), CliError> {
    log_init("cosmian_kms_server=info");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            csr_file: Some("test_data/certificates/csr/leaf.csr".to_owned()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            tags: Some(vec!["certify_a_csr_test".to_owned()]),
            ..Default::default()
        },
    )?;

    let (_, _, der) = check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);
    let x509 = X509::from_der(&der).unwrap();
    let num_days = x509.not_before().diff(x509.not_after()).unwrap().days;
    assert_eq!(num_days, 365);

    // renew the certificate
    let renewed_certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            certificate_id_to_re_certify: Some(certificate_id.clone()),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            tags: Some(vec!["renew_a_certificate_test".to_owned()]),
            days: Some(42),
            ..Default::default()
        },
    )?;

    assert_eq!(renewed_certificate_id, certificate_id);

    let (_, _, der) = check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);
    let x509 = X509::from_der(&der).unwrap();
    let num_days = x509.not_before().diff(x509.not_after()).unwrap().days;
    assert_eq!(num_days, 42);

    Ok(())
}

#[tokio::test]
async fn test_issue_with_subject_name() -> Result<(), CliError> {
    // log_init("cosmian_kms_server=debug");
    // Create a test server
    let ctx = ONCE.get_or_try_init(start_default_test_kms_server).await?;
    // import signers
    let (_, issuer_private_key_id) = import_root_and_intermediate(ctx)?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &ctx.owner_client_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_string(),
            ),
            issuer_private_key_id: Some(issuer_private_key_id.clone()),
            tags: Some(vec!["certify_a_csr_test".to_owned()]),
            ..Default::default()
        },
    )?;

    let (_, attributes, _) =
        check_generated_certificate(ctx, &issuer_private_key_id, &certificate_id);
    println!("{:?}", attributes);

    // check links to public key
    let (public_key_id, public_key_attributes) =
        check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes);
    let _ = check_public_and_private_key_linked(ctx, &public_key_id, &public_key_attributes);
    Ok(())
}
