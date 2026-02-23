use std::path::PathBuf;

use cosmian_kms_client::{
    cosmian_kmip::ttlv::{TTLV, from_ttlv},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, Object},
        kmip_types::{KeyFormatType, LinkType},
    },
    read_from_json_file, read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::{
        export_utils::{CertificateExportFormat, ExportKeyFormat::JsonTtlv},
        import_utils::CertificateInputFormat,
    },
};
use cosmian_logger::log_init;
use openssl::{
    pkcs7::Pkcs7,
    pkcs12::Pkcs12,
    stack::Stack,
    x509::{X509, store::X509StoreBuilder},
};
use tempfile::TempDir;
use test_kms_server::{init_openssl_providers_for_tests, start_default_test_kms_server};
use uuid::Uuid;

use crate::{
    actions::kms::{
        certificates::{
            Algorithm, certify::CertifyAction, export_certificate::ExportCertificateAction,
            import_certificate::ImportCertificateAction,
        },
        shared::ExportSecretDataOrKeyAction,
    },
    error::{KmsCliError, result::KmsCliResult},
    tests::kms::certificates::certify::{create_self_signed_cert, import_root_and_intermediate},
};

#[tokio::test]
async fn test_import_export_p12_25519() -> KmsCliResult<()> {
    log_init(option_env!("RUST_LOG"));
    init_openssl_providers_for_tests();

    // load the PKCS#12 file
    let p12_bytes =
        include_bytes!("../../../../../../test_data/certificates/another_p12/ed25519.p12");
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    // import the certificate
    let imported_p12_sk = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/another_p12/ed25519.p12",
            )),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["import_pkcs12".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    // export piece by piece
    //

    let tmp_dir = TempDir::new().unwrap();
    let tmp_exported_sk = tmp_dir.path().join("exported_p12_sk.json");
    let tmp_exported_cert = tmp_dir.path().join("exported_p12_cert.json");
    let tmp_exported_cert_attr = tmp_dir.path().join("exported_p12_cert.attributes.json");
    let tmp_exported_cert_p12 = tmp_dir.path().join("exported_p12_cert.p12");

    // export the private key
    ExportSecretDataOrKeyAction {
        key_file: tmp_exported_sk.clone(),
        key_id: imported_p12_sk.clone(),
        export_format: JsonTtlv,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let sk = read_object_from_json_ttlv_file(&tmp_exported_sk).unwrap();
    assert_eq!(
        sk.key_block().unwrap().ec_raw_bytes().unwrap().to_vec(),
        parsed_p12.pkey.as_ref().unwrap().raw_private_key().unwrap()
    );
    let certificate_id = sk
        .attributes()
        .unwrap()
        .get_link(LinkType::PKCS12CertificateLink)
        .unwrap();

    // export the certificate
    ExportCertificateAction {
        certificate_file: tmp_exported_cert.clone(),
        certificate_id: Some(certificate_id.to_string()),
        output_format: CertificateExportFormat::JsonTtlv,
        allow_revoked: true,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let cert = read_object_from_json_ttlv_file(&tmp_exported_cert).unwrap();
    let Object::Certificate(Certificate {
        certificate_value: cert_x509_der,
        ..
    }) = &cert
    else {
        panic!("wrong object type")
    };
    assert_eq!(
        cert_x509_der.clone(),
        parsed_p12.cert.as_ref().unwrap().to_der().unwrap()
    );
    let cert_attributes_ttlv: TTLV = read_from_json_file(&tmp_exported_cert_attr).unwrap();
    let cert_attributes: Attributes = from_ttlv(cert_attributes_ttlv).unwrap();
    let issuer_id = cert_attributes.get_link(LinkType::CertificateLink).unwrap();

    // export the chain - there should be only one certificate in the chain
    ExportCertificateAction {
        certificate_file: tmp_exported_cert.clone(),
        certificate_id: Some(issuer_id.to_string()),
        output_format: CertificateExportFormat::JsonTtlv,
        allow_revoked: true, // to get attributes
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let issuer_cert = read_object_from_json_ttlv_file(&tmp_exported_cert).unwrap();
    let Object::Certificate(Certificate {
        certificate_value: issuer_cert_x509_der,
        ..
    }) = &issuer_cert
    else {
        panic!("wrong object type")
    };
    assert_eq!(
        issuer_cert_x509_der.clone(),
        parsed_p12
            .ca
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap()
            .to_der()
            .unwrap()
    );
    // this test  is deactivated because another test imports this certificate with the same id
    // and a link to its issuer which may make this test fail. This test passes when run alone.
    let issuer_cert_attributes_ttlv: TTLV = read_from_json_file(&tmp_exported_cert_attr).unwrap();
    let issuer_cert_attributes: Attributes = from_ttlv(issuer_cert_attributes_ttlv).unwrap();
    assert!(
        issuer_cert_attributes
            .get_link(LinkType::CertificateLink)
            .is_none()
    );

    // export the pkcs12
    ExportCertificateAction {
        certificate_file: tmp_exported_cert_p12.clone(),
        certificate_id: imported_p12_sk,
        output_format: CertificateExportFormat::Pkcs12,
        allow_revoked: true, // to get attributes
        pkcs12_password: Some("secret".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let p12_bytes = std::fs::read(tmp_exported_cert_p12).unwrap();
    let p12_ = Pkcs12::from_der(p12_bytes.as_slice()).unwrap();
    let parsed_p12_ = p12_.parse2("secret").unwrap();

    assert_eq!(
        parsed_p12
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_der()
            .unwrap(),
        parsed_p12_
            .pkey
            .as_ref()
            .unwrap()
            .private_key_to_der()
            .unwrap()
    );
    assert_eq!(
        parsed_p12.cert.as_ref().unwrap().to_der().unwrap(),
        parsed_p12_.cert.as_ref().unwrap().to_der().unwrap()
    );
    assert_eq!(parsed_p12_.ca.as_ref().unwrap().len(), 1);
    assert_eq!(
        parsed_p12
            .ca
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap()
            .to_der()
            .unwrap(),
        parsed_p12_
            .ca
            .as_ref()
            .unwrap()
            .get(0)
            .unwrap()
            .to_der()
            .unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_import_p12_rsa() {
    init_openssl_providers_for_tests();

    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    // load the PKCS#12 file
    let p12_bytes = include_bytes!("../../../../../../test_data/certificates/csr/intermediate.p12");
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    // import the certificate
    let imported_p12_sk = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/csr/intermediate.p12",
            )),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            replace_existing: true,
            tags: vec!["import_pkcs12".to_owned()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await
    .unwrap();

    // export the private key
    let key_file = tmp_path.join("exported_p12_sk.json");
    ExportSecretDataOrKeyAction {
        key_file: key_file.clone(),
        key_id: imported_p12_sk,
        export_format: JsonTtlv,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await
    .unwrap();

    // export object by object
    let sk = read_object_from_json_ttlv_file(&key_file).unwrap();
    assert_eq!(
        sk.key_block().unwrap().key_format_type,
        KeyFormatType::PKCS1
    );
    assert_eq!(
        sk.key_block().unwrap().pkcs_der_bytes().unwrap().to_vec(),
        parsed_p12
            .pkey
            .unwrap()
            .rsa()
            .unwrap()
            .private_key_to_der()
            .unwrap()
    );
}

#[tokio::test]
async fn test_export_pkcs7() -> Result<(), KmsCliError> {
    let tmp_dir = TempDir::new().unwrap();

    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // import signers
    let (root_ca_id, _, issuer_private_key_id) =
        Box::pin(import_root_and_intermediate(ctx)).await?;

    // Certify the CSR with the intermediate CA
    let certificate_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::RSA4096,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_owned()),
        issuer_private_key_id: Some(issuer_private_key_id.clone()),
        tags: vec!["certify_a_csr_test".to_owned()],
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    let tmp_exported_pkcs7: std::path::PathBuf = tmp_dir.path().join("exported_p7.p7pem");

    // Export the pkcs7
    ExportCertificateAction {
        certificate_file: tmp_exported_pkcs7.clone(),
        certificate_id: Some(certificate_id.clone()),
        output_format: CertificateExportFormat::Pkcs7,
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    let p7_bytes = std::fs::read(tmp_exported_pkcs7).unwrap();
    let pkcs7 = Pkcs7::from_pem(p7_bytes.as_slice()).unwrap();

    // Build certs stack for verification
    let certs = Stack::new().unwrap();

    let mut store_builder = X509StoreBuilder::new().unwrap();
    let tmp_exported_int: std::path::PathBuf = tmp_dir.path().join("exported_int.pem");
    let tmp_exported_root: std::path::PathBuf = tmp_dir.path().join("exported_root.pem");

    // Export intermediate cert
    ExportCertificateAction {
        certificate_file: tmp_exported_int.clone(),
        certificate_id: Some(issuer_private_key_id.clone()),
        output_format: CertificateExportFormat::Pkcs12,
        pkcs12_password: Some("secret".to_owned()),
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let int_bytes = std::fs::read(tmp_exported_int).unwrap();
    let p12 = Pkcs12::from_der(int_bytes.as_slice()).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    let int_cert = parsed_p12.cert.unwrap();

    store_builder.add_cert(int_cert).unwrap();

    // Export root cert
    ExportCertificateAction {
        certificate_file: tmp_exported_root.clone(),
        certificate_id: Some(root_ca_id.clone()),
        output_format: CertificateExportFormat::Pem,
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;
    let root_bytes = std::fs::read(tmp_exported_root).unwrap();
    let root_ca = X509::from_pem(&root_bytes).unwrap();

    store_builder.add_cert(root_ca).unwrap();

    let store = store_builder.build();

    // Validate certificate
    let mut output = Vec::new();
    pkcs7
        .verify(
            &certs,
            &store,
            Some(&[]),
            Some(&mut output),
            openssl::pkcs7::Pkcs7Flags::empty(),
        )
        .unwrap();
    assert!(output.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_self_signed_export_loop() -> KmsCliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    // Create a self-signed certificate - the certificate link points to the certificate itself
    let certificate_id = create_self_signed_cert(ctx).await?;

    // export
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert.p12");
    ExportCertificateAction {
        certificate_file: tmp_exported_cert.clone(),
        certificate_id: Some(certificate_id.clone()),
        output_format: CertificateExportFormat::Pkcs12,
        pkcs12_password: Some(String::from("secret")),
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // try re-importing the PKCS#12
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(tmp_exported_cert.clone()),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_export_root_and_intermediate_pkcs12() -> KmsCliResult<()> {
    init_openssl_providers_for_tests();

    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // Generate a self-signed root CA
    let ca_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test CA".to_owned()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // Certify an intermediate CA with the root CA
    let intermediate_id = CertifyAction {
        issuer_certificate_id: Some(ca_id),
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some(
            "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Intermediate".to_owned(),
        ),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // export the intermediate CA to PKCS#12
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert.p12");
    ExportCertificateAction {
        certificate_file: tmp_exported_cert.clone(),
        certificate_id: Some(intermediate_id.clone()),
        output_format: CertificateExportFormat::Pkcs12,
        pkcs12_password: Some(String::from("secret")),
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // try re-importing the PKCS#12
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(tmp_exported_cert.clone()),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn test_export_import_legacy_p12() -> KmsCliResult<()> {
    init_openssl_providers_for_tests();

    // Create a test server
    let ctx = start_default_test_kms_server().await;

    // Generate a self-signed root CA
    let cert_id = CertifyAction {
        generate_key_pair: true,
        algorithm: Algorithm::NistP256,
        subject_name: Some("C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Cert".to_string()),
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?
    .to_string();

    // export the certificate to legacy PKCS#12
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert_legacy.p12");
    ExportCertificateAction {
        certificate_file: tmp_exported_cert.clone(),
        certificate_id: Some(cert_id.clone()),
        output_format: CertificateExportFormat::Pkcs12Legacy,
        pkcs12_password: Some(String::from("secret")),
        allow_revoked: false,
        ..Default::default()
    }
    .run(ctx.get_owner_client())
    .await?;

    // try re-importing the PKCS#12
    Box::pin(
        ImportCertificateAction {
            certificate_file: Some(tmp_exported_cert.clone()),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some(Uuid::new_v4().to_string()),
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    Ok(())
}
