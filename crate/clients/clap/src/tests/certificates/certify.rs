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
#[cfg(feature = "non-fips")]
use test_kms_server::start_test_kms_server_with_pqc_tls;
use test_kms_server::{TestsContext, start_default_test_kms_server};
use uuid::Uuid;
use x509_parser::{der_parser::oid, prelude::*};

use crate::{
    actions::{
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
            certificate_file: Some(PathBuf::from("../../../test_data/certificates/csr/ca.crt")),
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
                "../../../test_data/certificates/csr/intermediate.crt",
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
                "../../../test_data/certificates/csr/intermediate.p12",
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

/// Fetch a PQC certificate and return its Object, attributes and DER bytes.
///
/// Unlike `fetch_certificate`, this helper uses `x509_parser` (pure Rust) instead
/// of the OpenSSL Rust bindings so that ML-DSA and SLH-DSA certificates — whose
/// OIDs are only supported by OpenSSL 3.3+ — are parsed correctly in all build
/// environments.  The function asserts that the certificate subject contains the
/// expected Common Name.
#[cfg(feature = "non-fips")]
async fn fetch_pqc_certificate(
    ctx: &TestsContext,
    certificate_id: &str,
    expected_cn: &str,
) -> (Object, Attributes, Vec<u8>) {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    let exported_cert_file = tmp_path.join("pqc_cert.json");
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
        }) => certificate_value,
        _ => panic!("wrong object type"),
    }
    .clone();

    // Use x509_parser (pure Rust) — works for any algorithm including PQC.
    let (_, parsed) =
        X509Certificate::from_der(&cert_x509_der).expect("failed to parse PQC certificate DER");
    let cn = parsed
        .subject()
        .iter_common_name()
        .next()
        .expect("certificate has no Common Name")
        .as_str()
        .expect("CN is not valid UTF-8");
    assert_eq!(cn, expected_cn);

    let ttlv: TTLV = read_from_json_file(&tmp_path.join("pqc_cert.attributes.json")).unwrap();
    let cert_attributes: Attributes = from_ttlv(ttlv).unwrap();
    (cert, cert_attributes, cert_x509_der)
}

/// Shared helper: create a self-signed PQC certificate and verify its KMS
/// attributes.  Extracted to avoid repetition across the per-algorithm tests.
#[cfg(feature = "non-fips")]
async fn certify_pqc_self_signed(
    ctx: &TestsContext,
    algorithm: Algorithm,
    alg_label: &str,
) -> KmsCliResult<()> {
    let cn = format!("Test PQC {alg_label}");
    let subject_name = format!("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = {cn}");

    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm,
        subject_name: Some(subject_name),
        tags: vec![format!(
            "pqc_{}_cert",
            alg_label.to_lowercase().replace(['-', ' '], "_")
        )],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) = fetch_pqc_certificate(ctx, &certificate_id, &cn).await;

    // Self-signed: the certificate link must point back to the same certificate.
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);

    // Must be linked to a generated public key.
    let public_key_id = attributes.get_link(LinkType::PublicKeyLink).unwrap();
    assert!(!public_key_id.to_string().is_empty());

    Ok(())
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
            "../../../test_data/certificates/csr/leaf.csr",
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

    assert_eq!(validation, ValidityIndicator::Valid);

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
            "../../../test_data/certificates/csr/leaf.csr",
        )),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_test".to_owned()],
        certificate_extensions: Some(PathBuf::from(
            "../../../test_data/certificates/openssl/ext.cnf",
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

    assert_eq!(validation, ValidityIndicator::Valid);
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

    assert_eq!(validation, ValidityIndicator::Valid);
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
            "../../../test_data/certificates/openssl/ext.cnf",
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

    assert_eq!(validation, ValidityIndicator::Valid);
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
            "../../../test_data/certificates/csr/leaf.csr",
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

    assert_eq!(validation, ValidityIndicator::Valid);
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

    assert_eq!(validation, ValidityIndicator::Valid);
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

    assert_eq!(validation, ValidityIndicator::Valid);
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

    assert_eq!(validation, ValidityIndicator::Valid);
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
            "../../../test_data/certificates/chain/root/ca/ext_v3_ca_root.cnf",
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

    assert_eq!(validation, ValidityIndicator::Valid);

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

/// Test self-signed ML-DSA-44 X.509 certificate creation (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_ml_dsa_44_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Generate a self-signed certificate with an ML-DSA-44 key pair
    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test PQC ML-DSA-44".to_owned(),
        ),
        tags: vec!["pqc_ml_dsa_44_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attributes, _) =
        fetch_pqc_certificate(ctx, &certificate_id, "Test PQC ML-DSA-44").await;
    // Self-signed: the certificate link should point back to itself
    let certificate_link = attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(certificate_link.to_string(), certificate_id);
    // Certificate must be linked to a public key
    let public_key_id = attributes.get_link(LinkType::PublicKeyLink).unwrap();
    assert!(!public_key_id.to_string().is_empty());

    let validation = ValidateCertificatesAction {
        certificate_id: vec![certificate_id.clone()],
        validity_time: None,
    }
    .run(ctx.get_owner_client())
    .await?;

    assert_eq!(validation, ValidityIndicator::Valid);
    Ok(())
}

/// Test ML-DSA-65 certificate signed by an ML-DSA-44 CA (PQC issuer, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_ml_dsa_signed_by_pqc_ca() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Step 1: Create self-signed ML-DSA-44 root CA certificate
    let ca_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC Test CA".to_owned(),
        ),
        tags: vec!["pqc_ca_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, ca_attributes, _) = fetch_pqc_certificate(ctx, &ca_cert_id, "PQC Test CA").await;
    let ca_private_key_id = ca_attributes.get_link(LinkType::PrivateKeyLink).unwrap();

    // Step 2: Create ML-DSA-65 leaf certificate signed by the ML-DSA-44 CA
    let leaf_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa65,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC Test Leaf".to_owned(),
        ),
        issuer_private_key_id: Some(ca_private_key_id.to_string()),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["pqc_leaf_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, leaf_attributes, _) = fetch_pqc_certificate(ctx, &leaf_cert_id, "PQC Test Leaf").await;
    // Leaf certificate must link back to the CA certificate
    let cert_link = leaf_attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(cert_link.to_string(), ca_cert_id);
    // Leaf certificate must be linked to a public key
    let _leaf_pub_key_id = leaf_attributes.get_link(LinkType::PublicKeyLink).unwrap();
    Ok(())
}

// ── ML-KEM and hybrid KEM certificate tests ───────────────────────────────
//
// ML-KEM / X25519MLKEM768 / X448MLKEM1024 / ConfigurableKEM are KEM-only
// algorithms; they cannot self-sign.  MLKEM_* (PKCS8 format) can appear as the
// subject key in a CA-issued X.509 certificate because the public key is stored
// as SubjectPublicKeyInfo DER which OpenSSL 3.4+ understands.
//
// X25519MLKEM768, X448MLKEM1024, and the ConfigurableKEM variants (P-256 /
// Curve25519 hybrids) are stored in Raw or ConfigurableKEMPublicKey format;
// OpenSSL 3.6 cannot yet encode these as SPKI, so certifying them returns an
// unsupported-format error.

/// Helper: spin up a fresh ML-DSA-44 self-signed CA and return its cert id and
/// private key id.
#[cfg(feature = "non-fips")]
async fn create_ml_dsa_ca(ctx: &TestsContext) -> KmsCliResult<(String, String)> {
    let ca_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-KEM Test CA".to_owned(),
        ),
        tags: vec!["mlkem_ca_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();
    let (_, ca_attrs, _) = fetch_pqc_certificate(ctx, &ca_cert_id, "ML-KEM Test CA").await;
    let ca_sk_id = ca_attrs.get_link(LinkType::PrivateKeyLink).unwrap();
    Ok((ca_cert_id, ca_sk_id.to_string()))
}

/// ML-KEM-512 subject key issued by an ML-DSA-44 CA (non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_512_ca_issued() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await?;

    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem512,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-KEM-512 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["ml_kem_512_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attrs, _) = fetch_pqc_certificate(ctx, &cert_id, "ML-KEM-512 Subject").await;
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    assert!(
        !attrs
            .get_link(LinkType::PublicKeyLink)
            .unwrap()
            .to_string()
            .is_empty()
    );
    Ok(())
}

/// ML-KEM-768 subject key issued by an ML-DSA-44 CA (non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_768_ca_issued() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await?;

    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem768,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-KEM-768 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["ml_kem_768_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attrs, _) = fetch_pqc_certificate(ctx, &cert_id, "ML-KEM-768 Subject").await;
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    Ok(())
}

/// ML-KEM-1024 subject key issued by an ML-DSA-44 CA (non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_1024_ca_issued() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await?;

    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem1024,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-KEM-1024 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["ml_kem_1024_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, attrs, _) = fetch_pqc_certificate(ctx, &cert_id, "ML-KEM-1024 Subject").await;
    let issuer_link = attrs.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(issuer_link.to_string(), ca_cert_id);
    Ok(())
}

/// Self-signed ML-KEM-512 must fail with a clear KEM-cannot-sign error (non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_self_signed_is_rejected() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let err = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem512,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Self-Signed KEM".to_owned(),
        ),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap_err();

    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("kem") || msg.contains("sign"),
        "expected a KEM/signing error, got: {err}"
    );
    Ok(())
}

/// X25519MLKEM768 subject key — Raw format, not yet encodable as SPKI in OpenSSL 3.6
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_x25519_ml_kem_768_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::X25519MlKem768,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = X25519MLKEM768 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "X25519MLKEM768 subject key should not be encodable as X.509 SPKI in OpenSSL 3.6"
    );
}

/// X448MLKEM1024 subject key — Raw format, not yet encodable as SPKI in OpenSSL 3.6
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_x448_ml_kem_1024_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::X448MlKem1024,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = X448MLKEM1024 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "X448MLKEM1024 subject key should not be encodable as X.509 SPKI in OpenSSL 3.6"
    );
}

/// ML-KEM-512/P-256 (`ConfigurableKEM`) — custom format, not encodable as X.509 SPKI
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_512_p256_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem512P256,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = MlKem512P256 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "ConfigurableKEM subject key (ML-KEM-512/P-256) should not be encodable as X.509 SPKI"
    );
}

/// ML-KEM-768/P-256 (`ConfigurableKEM`) — custom format, not encodable as X.509 SPKI
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_768_p256_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem768P256,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = MlKem768P256 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "ConfigurableKEM subject key (ML-KEM-768/P-256) should not be encodable as X.509 SPKI"
    );
}

/// ML-KEM-512/Curve25519 (`ConfigurableKEM`) — custom format, not encodable as X.509 SPKI
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_512_curve25519_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem512Curve25519,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = MlKem512Curve25519 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "ConfigurableKEM subject key (ML-KEM-512/Curve25519) should not be encodable as X.509 SPKI"
    );
}

/// ML-KEM-768/Curve25519 (`ConfigurableKEM`) — custom format, not encodable as X.509 SPKI
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_ml_kem_768_curve25519_format_unsupported() {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    let (ca_cert_id, ca_sk_id) = create_ml_dsa_ca(ctx).await.expect("CA creation");

    let result = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlKem768Curve25519,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = MlKem768Curve25519 Subject".to_owned(),
        ),
        issuer_private_key_id: Some(ca_sk_id),
        issuer_certificate_id: Some(ca_cert_id),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await;

    assert!(
        result.is_err(),
        "ConfigurableKEM subject key (ML-KEM-768/Curve25519) should not be encodable as X.509 SPKI"
    );
}

/// ML-DSA-65 self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_ml_dsa_65_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::MlDsa65, "ML-DSA-65").await
}

/// ML-DSA-87 self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_ml_dsa_87_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::MlDsa87, "ML-DSA-87").await
}

/// SLH-DSA-SHA2-128s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_128s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2128s, "SLH-DSA-SHA2-128s").await
}

/// SLH-DSA-SHA2-128f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_128f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2128f, "SLH-DSA-SHA2-128f").await
}

/// SLH-DSA-SHA2-192s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_192s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2192s, "SLH-DSA-SHA2-192s").await
}

/// SLH-DSA-SHA2-192f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_192f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2192f, "SLH-DSA-SHA2-192f").await
}

/// SLH-DSA-SHA2-256s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_256s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2256s, "SLH-DSA-SHA2-256s").await
}

/// SLH-DSA-SHA2-256f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_sha2_256f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaSha2256f, "SLH-DSA-SHA2-256f").await
}

/// SLH-DSA-SHAKE-128s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_128s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake128s, "SLH-DSA-SHAKE-128s").await
}

/// SLH-DSA-SHAKE-128f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_128f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake128f, "SLH-DSA-SHAKE-128f").await
}

/// SLH-DSA-SHAKE-192s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_192s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake192s, "SLH-DSA-SHAKE-192s").await
}

/// SLH-DSA-SHAKE-192f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_192f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake192f, "SLH-DSA-SHAKE-192f").await
}

/// SLH-DSA-SHAKE-256s self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_256s_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake256s, "SLH-DSA-SHAKE-256s").await
}

/// SLH-DSA-SHAKE-256f self-signed certificate (PQC, non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_shake_256f_self_signed() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;
    certify_pqc_self_signed(ctx, Algorithm::SlhDsaShake256f, "SLH-DSA-SHAKE-256f").await
}

/// Cross-algorithm: SLH-DSA-SHA2-128s CA signs an ML-DSA-44 leaf (non-FIPS only)
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_certify_pqc_slh_dsa_ca_signs_ml_dsa_leaf() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create a self-signed SLH-DSA-SHA2-128s root CA
    let ca_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::SlhDsaSha2128s,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = SLH-DSA Test CA".to_owned(),
        ),
        tags: vec!["slh_dsa_ca_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, ca_attributes, _) = fetch_pqc_certificate(ctx, &ca_cert_id, "SLH-DSA Test CA").await;
    let ca_private_key_id = ca_attributes.get_link(LinkType::PrivateKeyLink).unwrap();

    // Issue an ML-DSA-44 leaf certificate signed by the SLH-DSA CA
    let leaf_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA Leaf".to_owned(),
        ),
        issuer_private_key_id: Some(ca_private_key_id.to_string()),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["ml_dsa_leaf_cert".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, leaf_attributes, _) = fetch_pqc_certificate(ctx, &leaf_cert_id, "ML-DSA Leaf").await;
    let cert_link = leaf_attributes.get_link(LinkType::CertificateLink).unwrap();
    assert_eq!(cert_link.to_string(), ca_cert_id);
    let leaf_pub_key_id = leaf_attributes.get_link(LinkType::PublicKeyLink).unwrap();
    assert!(!leaf_pub_key_id.to_string().is_empty());

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// PQC TLS + PKI compliance tests
// ─────────────────────────────────────────────────────────────────────────────

/// Verify that the KMS server can be configured with a PQC (ML-DSA-44) X.509 certificate
/// as its TLS server certificate, and that KMIP operations succeed over that HTTPS connection.
///
/// Requires a TLS client that supports the ML-DSA-44 TLS signature scheme
/// (draft-ietf-tls-mldsa). The `reqwest` crate with `native-tls` on macOS uses Apple's
/// Security.framework which does not yet implement PQC TLS signature algorithms. The test is
/// therefore `#[ignore]`d by default; run it explicitly with `-- --ignored` on a system where
/// the TLS client supports ML-DSA-44 (e.g. Linux with system OpenSSL ≥ 3.5).
#[cfg(feature = "non-fips")]
#[tokio::test]
#[ignore = "requires a TLS client that supports ML-DSA-44 (not available via native-tls on macOS)"]
async fn test_server_with_pqc_tls_cert() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_test_kms_server_with_pqc_tls().await;

    // Perform a KMIP Certify operation over the PQC TLS connection.
    // If the TLS handshake fails (unsupported PQC signature scheme), this will error.
    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC TLS Test Cert".to_owned(),
        ),
        tags: vec!["pqc_tls_test".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    assert!(!cert_id.is_empty(), "certificate ID must not be empty");
    Ok(())
}

/// Verify that a KMS-generated PQC (ML-DSA-44) certificate is fully X.509 v3 compliant:
///   - X.509 version 3
///   - Both outer and TBS `signatureAlgorithm` carry the `id-ml-dsa-44` OID
///     (2.16.840.1.101.3.4.3.17 per FIPS 204 / draft-ietf-lamps-dilithium-certificates)
///   - `subjectPublicKeyInfo.algorithm` carries the same OID
///   - Subject and Issuer are correctly encoded (self-signed ⇒ equal)
///   - Validity period is non-degenerate
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_pqc_x509_structural_compliance() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = PQC X509 Compliance Test".to_owned(),
        ),
        tags: vec!["pqc_x509_compliance".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, _, der) = fetch_pqc_certificate(ctx, &cert_id, "PQC X509 Compliance Test").await;

    // --- x509_parser structural checks ---
    let (_, cert) = X509Certificate::from_der(&der).expect("failed to parse DER as X.509");

    // Must be X.509 v3 (encoded as integer value 2 per RFC 5280)
    assert_eq!(
        cert.tbs_certificate.version,
        X509Version::V3,
        "certificate must be X.509 v3"
    );

    // id-ml-dsa-44 OID per FIPS 204 / draft-ietf-lamps-dilithium-certificates
    let ml_dsa_44 = oid!(2.16.840.1.101.3.4.3.17);

    // Outer signatureAlgorithm must use id-ml-dsa-44
    assert_eq!(
        cert.signature_algorithm.algorithm, ml_dsa_44,
        "outer signatureAlgorithm OID must be id-ml-dsa-44 (2.16.840.1.101.3.4.3.17)"
    );

    // TBS signatureAlgorithm must match outer (RFC 5280 §4.1.1.2)
    assert_eq!(
        cert.tbs_certificate.signature.algorithm, ml_dsa_44,
        "TBS signatureAlgorithm OID must be id-ml-dsa-44 and match outer signatureAlgorithm"
    );

    // SubjectPublicKeyInfo algorithm must use id-ml-dsa-44
    assert_eq!(
        cert.tbs_certificate.subject_pki.algorithm.algorithm, ml_dsa_44,
        "SubjectPublicKeyInfo algorithm OID must be id-ml-dsa-44"
    );

    // Common Name must match what we requested
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .expect("certificate has no Common Name")
        .as_str()
        .expect("CN is not valid UTF-8");
    assert_eq!(cn, "PQC X509 Compliance Test", "Subject CN mismatch");

    // Self-signed: Issuer DN must equal Subject DN
    assert_eq!(
        cert.tbs_certificate.issuer.to_string(),
        cert.tbs_certificate.subject.to_string(),
        "self-signed certificate: Issuer DN must equal Subject DN"
    );

    // Validity period must be non-degenerate (notBefore < notAfter)
    assert!(
        cert.tbs_certificate.validity.not_before < cert.tbs_certificate.validity.not_after,
        "notBefore must be earlier than notAfter"
    );

    Ok(())
}

/// Verify that a CA PQC certificate can issue a leaf certificate and that the
/// resulting signature is cryptographically valid.
///
/// Steps:
///   1. Generate a self-signed ML-DSA-44 CA certificate via the KMS.
///   2. Issue an ML-DSA-65 leaf certificate signed by the CA.
///   3. Check KMIP link consistency (issuer link, public key link).
///   4. Verify that `leaf.issuer == ca.subject` (DN match).
///   5. Use OpenSSL's `X509::verify()` (backed by OpenSSL 3.x EVP, which supports
///      PQC algorithms) to cryptographically verify the leaf's signature against the
///      CA's public key.
#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_pqc_ca_signature_verification() -> KmsCliResult<()> {
    log_init(None);
    let ctx = start_default_test_kms_server().await;

    // Create a self-signed ML-DSA-44 CA certificate
    let ca_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa44,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA-44 PQC Root CA".to_owned(),
        ),
        tags: vec!["pqc_sig_verify_ca".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, ca_attrs, ca_der) =
        fetch_pqc_certificate(ctx, &ca_cert_id, "ML-DSA-44 PQC Root CA").await;
    let ca_private_key_id = ca_attrs
        .get_link(LinkType::PrivateKeyLink)
        .expect("CA certificate must have a private key link");

    // Issue an ML-DSA-65 leaf certificate signed by the ML-DSA-44 CA
    let leaf_cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::MlDsa65,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = ML-DSA-65 PQC Leaf".to_owned(),
        ),
        issuer_private_key_id: Some(ca_private_key_id.to_string()),
        issuer_certificate_id: Some(ca_cert_id.clone()),
        tags: vec!["pqc_sig_verify_leaf".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let (_, leaf_attrs, leaf_der) =
        fetch_pqc_certificate(ctx, &leaf_cert_id, "ML-DSA-65 PQC Leaf").await;

    // KMIP link: the leaf's certificate link must point to the CA
    let issuer_link = leaf_attrs
        .get_link(LinkType::CertificateLink)
        .expect("leaf must have a CertificateLink pointing to its issuer");
    assert_eq!(
        issuer_link.to_string(),
        ca_cert_id,
        "leaf CertificateLink must point to the CA certificate"
    );

    // x509_parser: leaf Issuer DN must equal CA Subject DN
    let (_, ca_x509p) = X509Certificate::from_der(&ca_der).expect("failed to parse CA DER");
    let (_, leaf_x509p) = X509Certificate::from_der(&leaf_der).expect("failed to parse leaf DER");
    assert_eq!(
        leaf_x509p.tbs_certificate.issuer.to_string(),
        ca_x509p.tbs_certificate.subject.to_string(),
        "leaf Issuer DN must equal CA Subject DN"
    );

    // OpenSSL: cryptographic signature verification.
    // X509::verify() calls OpenSSL's X509_verify() which uses the EVP layer and
    // supports PQC algorithms (ML-DSA) via the OpenSSL 3.x non-FIPS provider.
    let ca_x509 = X509::from_der(&ca_der).expect("failed to load CA cert into OpenSSL");
    let leaf_x509 = X509::from_der(&leaf_der).expect("failed to load leaf cert into OpenSSL");
    let ca_pub_key = ca_x509
        .public_key()
        .expect("failed to extract CA public key");
    let signature_valid = leaf_x509
        .verify(&ca_pub_key)
        .expect("OpenSSL signature verification must not error for a well-formed PQC certificate");
    assert!(
        signature_valid,
        "leaf certificate signature must be cryptographically valid under the CA public key"
    );

    Ok(())
}
