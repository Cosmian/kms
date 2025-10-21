use std::path::PathBuf;

use cosmian_kms_client::{
    cosmian_kmip::{
        kmip_2_1::{kmip_objects::Object, kmip_types::LinkType},
        ttlv::{TTLV, from_ttlv},
    },
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::Certificate, kmip_types::ValidityIndicator,
    },
    read_from_json_file, read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::CertificateExportFormat, import_utils::CertificateInputFormat,
    },
};
use cosmian_logger::{debug, info, log_init};
use openssl::{nid::Nid, x509::X509};
use tempfile::TempDir;
use test_kms_server::{TestsContext, start_default_test_kms_server};
use uuid::Uuid;
use x509_parser::{der_parser::oid, prelude::*};

use crate::{
    actions::kms::{
        certificates::{
            Algorithm, certify::CertifyAction, export_certificate::ExportCertificateAction,
            import_certificate::ImportCertificateAction,
            validate_certificate::ValidateCertificatesAction,
        },
        rsa::keys::create_key_pair::CreateKeyPairAction,
        shared::ExportSecretDataOrKeyAction,
    },
    error::result::KmsCliResult,
};

pub(crate) async fn import_root_and_intermediate(
    ctx: &TestsContext,
) -> KmsCliResult<(String, String, String)> {
    // import Root CA
    let root_ca_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from("../../test_data/certificates/csr/ca.crt")),
            input_format: CertificateInputFormat::Pem,
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    // import Intermediate CA
    let intermediate_ca_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/csr/intermediate.crt",
            )),
            input_format: CertificateInputFormat::Pem,
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["root_ca".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    // import Intermediate p12
    let intermediate_ca_private_key_id = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/csr/intermediate.p12",
            )),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["intermediate_ca".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?
    .unwrap();

    Ok((
        root_ca_id,
        intermediate_ca_id,
        intermediate_ca_private_key_id,
    ))
}

/// Fetch a certificate and return its Object, attributes and DER bytes
async fn fetch_certificate(
    ctx: &TestsContext,
    certificate_id: &str,
) -> (Object, Attributes, Vec<u8>) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    // export the certificate
    let exported_cert_file = tmp_path.join("new_cert.pem");
    debug!("exporting certificate: new_cert: {:?}", exported_cert_file);
    ExportCertificateAction {
        certificate_file: exported_cert_file.clone(),
        certificate_id: Some(certificate_id.to_owned()),
        output_format: CertificateExportFormat::JsonTtlv,
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    let cert = read_object_from_json_ttlv_file(&exported_cert_file).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => {
            // Write to disk
            // let pem_cert = openssl::x509::X509::from_der(certificate_value).unwrap();
            // let pem_cert = pem_cert.to_pem().unwrap();
            // std::fs::write("new_cert.pem", &pem_cert).unwrap();
            certificate_value
        }
        _ => panic!("wrong object type"),
    }
    .clone();
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
    let ttlv: TTLV = read_from_json_file(&tmp_path.join("new_cert.attributes.json")).unwrap();
    let cert_attributes: Attributes = from_ttlv(ttlv).unwrap();
    (cert, cert_attributes, cert_x509_der)
}

/// Check a generated certificate chain
/// and return its Object, attributes and DER bytes
async fn check_certificate_chain(
    ctx: &TestsContext,
    issuer_private_key_id: &str,
    certificate_id: &str,
) -> (Object, Attributes, Vec<u8>) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    // fetch generated certificate
    let (cert, cert_attributes, cert_x509_der) = fetch_certificate(ctx, certificate_id).await;
    // check that the attributes contain a certificate link to the intermediate
    let certificate_link = cert_attributes.get_link(LinkType::CertificateLink).unwrap();
    // export the intermediate certificate
    let signer_cert_file = tmp_path.join("signer_cert.pem");
    ExportCertificateAction {
        certificate_file: PathBuf::from(signer_cert_file.to_str().unwrap()),
        certificate_id: Some(certificate_link.to_string()),
        output_format: CertificateExportFormat::JsonTtlv,
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    // check that the attributes contain a certificate link to the private key
    let ttlv: TTLV = read_from_json_file(&tmp_path.join("signer_cert.attributes.json")).unwrap();
    let signer_attributes: Attributes = from_ttlv(ttlv).unwrap();
    let private_key_link = signer_attributes
        .get_link(LinkType::PrivateKeyLink)
        .unwrap();
    assert_eq!(private_key_link.to_string(), issuer_private_key_id);
    (cert, cert_attributes, cert_x509_der)
}

fn check_certificate_added_extensions(cert_x509_der: &[u8]) {
    // check X509 extensions
    let (_, cert_x509) = X509Certificate::from_der(cert_x509_der).unwrap();
    let exts_with_x509_parser = cert_x509.extensions();

    for ext in exts_with_x509_parser {
        info!("\next: {ext:?}");
        info!("value is: {:?}", String::from_utf8(ext.value.to_vec()));
    }

    // BasicConstraints
    let bc = exts_with_x509_parser
        .iter()
        .find(|x| x.oid == oid!(2.5.29.19))
        .unwrap();
    assert!(!bc.critical);
    assert_eq!(
        bc.parsed_extension(),
        &ParsedExtension::BasicConstraints(BasicConstraints {
            ca: false,
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
                    "https://package.cosmian.com/kms/crl_tests/intermediate.crl.pem"
                )])),
                reasons: None,
                crl_issuer: None
            }]
        })
    );
}

async fn check_certificate_and_public_key_linked(
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
    ExportSecretDataOrKeyAction {
        key_file: tmp_exported_pubkey.clone(),
        key_id: Some(public_key_link.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    let public_key = read_object_from_json_ttlv_file(&tmp_exported_pubkey).unwrap();
    // check that the public key contains a link to the certificate
    let public_key_attributes = public_key.attributes().unwrap();
    let certificate_link = public_key_attributes
        .get_link(LinkType::CertificateLink)
        .unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);
    (public_key_link.to_string(), public_key_attributes.clone())
}

async fn check_public_and_private_key_linked(
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
    ExportSecretDataOrKeyAction {
        key_file: tmp_exported_privkey.clone(),
        key_id: Some(private_key_link.to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    let private_key = read_object_from_json_ttlv_file(&tmp_exported_privkey).unwrap();
    // check that the private key contains a link to the public key
    let public_key_link = private_key
        .attributes()
        .unwrap()
        .get_link(LinkType::PublicKeyLink)
        .unwrap();
    assert_eq!(public_key_link.to_string(), public_key_id);
    private_key_link.to_string()
}

#[tokio::test]
async fn test_certify_a_csr_without_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await?;

    // Certify the CSR with the intermediate CA
    let certificate_id = CertifyAction {
        certificate_signing_request: Some(PathBuf::from(
            "../../test_data/certificates/csr/leaf.csr",
        )),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_we_test".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;

    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);

    Ok(())
}

#[tokio::test]
async fn test_certify_a_csr_with_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        import_root_and_intermediate(ctx).await?;

    // Certify the CSR with the intermediate CA
    let certificate_id = CertifyAction {
        certificate_signing_request: Some(PathBuf::from(
            "../../test_data/certificates/csr/leaf.csr",
        )),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_test".to_owned()],
        certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext.cnf",
        )),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // check the certificate
    let (_, _, cert_x509_der) =
        check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;

    // check the added extensions
    check_certificate_added_extensions(&cert_x509_der);

    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_a_public_key_test_without_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        import_root_and_intermediate(ctx).await?;

    // create an RSA key pair
    let (_private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Certify the public key with the intermediate CA
    let certificate_id = CertifyAction {
        public_key_id_to_certify: Some(public_key_id.to_string()),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // check the certificate
    let (_, attributes, _) =
        check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;

    // check links to public key
    check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes).await;

    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_a_public_key_test_with_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        import_root_and_intermediate(ctx).await?;

    // create an RSA key pair
    let (_private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Certify the public key with the intermediate CA
    let certificate_id = CertifyAction {
        public_key_id_to_certify: Some(public_key_id.to_string()),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/openssl/ext.cnf",
        )),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // check the certificate
    let (_, attributes, cert_x509_der) =
        check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;

    // check the added extensions
    check_certificate_added_extensions(&cert_x509_der);

    // check links to public key
    check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes).await;

    // validating generated certificate
    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_renew_a_certificate() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await?;

    // Certify the CSR with the intermediate CA
    let certificate_id = CertifyAction {
        certificate_signing_request: Some(PathBuf::from(
            "../../test_data/certificates/csr/leaf.csr",
        )),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_test".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, _, der) = check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;
    let x509 = X509::from_der(&der).unwrap();
    let num_days = x509.not_before().diff(x509.not_after()).unwrap().days;
    assert_eq!(num_days, 365);

    // renew the certificate
    let renewed_certificate_id = CertifyAction {
        certificate_id_to_re_certify: Some(certificate_id.clone()),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["renew_a_certificate_test".to_owned()],
        number_of_days: 42,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    assert_eq!(renewed_certificate_id, certificate_id);

    let (_, _, der) = check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;
    let x509 = X509::from_der(&der).unwrap();
    let num_days = x509.not_before().diff(x509.not_after()).unwrap().days;
    assert_eq!(num_days, 42);

    // validating generated certificate
    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_issue_with_subject_name() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // import signers
    let (root_id, intermediate_id, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await?;

    // Certify the CSR with the intermediate CA
    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_test".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) =
        check_certificate_chain(ctx, &issuer_private_key_id, &certificate_id).await;
    info!("{attributes}");

    // check links to public key
    let (public_key_id, public_key_attributes) =
        check_certificate_and_public_key_linked(ctx, &certificate_id, &attributes).await;
    check_public_and_private_key_linked(ctx, &public_key_id, &public_key_attributes).await;

    let validation = ValidateCertificatesAction {
        certificate_id: vec![root_id, intermediate_id, certificate_id],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_a_public_key_test_self_signed() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // create an RSA key pair
    let (_private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Certify the public key with the intermediate CA
    let certificate_id = CertifyAction {
        public_key_id_to_certify: Some(public_key_id.to_string()),
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) = fetch_certificate(ctx, &certificate_id).await;
    // since the certificate is self signed, the Certificate Link should point back to itself
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);

    let validation = ValidateCertificatesAction {
        certificate_id: vec![certificate_id.clone()],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

pub(crate) async fn create_self_signed_cert(ctx: &TestsContext) -> KmsCliResult<String> {
    // create an RSA key pair
    let (_private_key_id, public_key_id) = CreateKeyPairAction::default()
        .run(ctx.get_owner_client())
        .await?;

    // Certify the public key with the intermediate CA
    let certificate_id = CertifyAction {
        public_key_id_to_certify: Some(public_key_id.to_string()),
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    Ok(certificate_id)
}

#[tokio::test]
async fn test_certify_issue_with_subject_name_self_signed_without_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // create a self signed certificate
    let certificate_id = create_self_signed_cert(ctx).await?;

    let (_, attributes, _) = fetch_certificate(ctx, &certificate_id).await;
    // since the certificate is self signed, the Certificate Link should point back to itself
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);

    let validation = ValidateCertificatesAction {
        certificate_id: vec![certificate_id.clone()],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);
    Ok(())
}

#[tokio::test]
async fn test_certify_issue_with_subject_name_self_signed_with_extensions() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // Certify the CSR without issuer i.e. self signed
    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        tags: vec!["certify_self_signed".to_owned()],
        certificate_extensions: Some(PathBuf::from(
            "../../test_data/certificates/chain/root/ca/ext_v3_ca_root.cnf",
        )),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) = fetch_certificate(ctx, &certificate_id).await;
    // since the certificate is self signed, the Certificate Link should point back to itself
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);

    let validation = ValidateCertificatesAction {
        certificate_id: vec![certificate_id.clone()],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert!(validation == ValidityIndicator::Valid);

    Ok(())
}

#[tokio::test]
async fn test_certify_twice() -> KmsCliResult<()> {
    log_init(None);
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // Certify the CSR without issuer i.e. self signed
    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) = fetch_certificate(ctx, &certificate_id).await;
    let private_key_id = attributes.get_link(LinkType::PrivateKeyLink).unwrap();
    let public_key_id = attributes.get_link(LinkType::PublicKeyLink).unwrap();

    // Certify again with the same certificate id
    let certificate_id2 = CertifyAction {
        certificate_id: Some(certificate_id.clone()),
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes2, _) = fetch_certificate(ctx, &certificate_id2).await;
    let private_key_id2 = attributes2.get_link(LinkType::PrivateKeyLink).unwrap();
    let public_key_id2 = attributes2.get_link(LinkType::PublicKeyLink).unwrap();

    assert_eq!(certificate_id, certificate_id2);
    assert_ne!(private_key_id, private_key_id2);
    assert_ne!(public_key_id, public_key_id2);

    Ok(())
}
