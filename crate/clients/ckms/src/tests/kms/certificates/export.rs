use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_cli::reexport::cosmian_kms_client::reexport::cosmian_kms_client_utils::export_utils::CertificateExportFormat;
#[cfg(feature = "non-fips")]
use cosmian_kms_cli::reexport::cosmian_kms_client::{
    cosmian_kmip::ttlv::{TTLV, from_ttlv},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::{Certificate, Object},
        kmip_types::{KeyFormatType, LinkType},
    },
    read_from_json_file, read_object_from_json_ttlv_file,
    reexport::cosmian_kms_client_utils::{
        certificate_utils::Algorithm,
        export_utils::ExportKeyFormat::JsonTtlv,
        import_utils::CertificateInputFormat,
    },
};
#[cfg(feature = "non-fips")]
use cosmian_logger::log_init;
#[cfg(feature = "non-fips")]
use openssl::{
    pkcs7::Pkcs7,
    pkcs12::Pkcs12,
    stack::Stack,
    x509::{X509, store::X509StoreBuilder},
};
#[cfg(feature = "non-fips")]
use tempfile::TempDir;
#[cfg(feature = "non-fips")]
use test_kms_server::start_default_test_kms_server;
#[cfg(feature = "non-fips")]
use uuid::Uuid;

#[cfg(feature = "non-fips")]
use crate::tests::kms::certificates::certify::create_self_signed_cert;
#[cfg(feature = "non-fips")]
use crate::tests::{
    kms::{
        certificates::{
            certify::{CertifyOp, certify, import_root_and_intermediate},
            import::{ImportCertificateInput, import_certificate},
        },
        shared::{ExportKeyParams, export_key},
    },
    save_kms_cli_config,
};
use crate::{
    config::CKMS_CONF_ENV,
    error::{CosmianError, result::CosmianResult},
    tests::{
        PROG_NAME,
        kms::{KMS_SUBCOMMAND, utils::recover_cmd_logs},
    },
};

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_import_export_p12_25519() {
    log_init(option_env!("RUST_LOG"));
    // load the PKCS#12 file
    let p12_bytes =
        include_bytes!("../../../../../../../test_data/certificates/another_p12/ed25519.p12");
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    // import the certificate
    let imported_p12_sk = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: "../../../test_data/certificates/another_p12/ed25519.p12",
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: Some(Uuid::new_v4().to_string()),
        replace_existing: true,
        tags: Some(&["import_pkcs12"]),
        ..Default::default()
    })
    .unwrap();

    // export piece by piece
    //

    let tmp_dir = TempDir::new().unwrap();
    let tmp_exported_sk = tmp_dir.path().join("exported_p12_sk.json");
    let tmp_exported_cert = tmp_dir.path().join("exported_p12_cert.json");
    let tmp_exported_cert_attr = tmp_dir.path().join("exported_p12_cert.attributes.json");
    let tmp_exported_cert_p12 = tmp_dir.path().join("exported_p12_cert.p12");

    // export the private key
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path.clone(),
        sub_command: "ec".to_owned(),
        key_id: imported_p12_sk.clone(),
        key_file: tmp_exported_sk.to_str().unwrap().to_string(),
        key_format: Some(JsonTtlv),
        ..Default::default()
    })
    .unwrap();

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
    export_certificate(
        &owner_client_conf_path,
        &certificate_id.to_string(),
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();
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
    export_certificate(
        &owner_client_conf_path,
        &issuer_id.to_string(),
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true, // to get attributes
    )
    .unwrap();
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
    export_certificate(
        &owner_client_conf_path,
        &imported_p12_sk,
        tmp_exported_cert_p12.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12),
        Some("secret".to_owned()),
        true, // to get attributes
    )
    .unwrap();
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
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_import_p12_rsa() {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    // load the PKCS#12 file
    let p12_bytes =
        include_bytes!("../../../../../../../test_data/certificates/csr/intermediate.p12");
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    // import the certificate
    let imported_p12_sk = import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: "../../../test_data/certificates/csr/intermediate.p12",
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        replace_existing: true,
        tags: Some(&["import_pkcs12"]),
        ..Default::default()
    })
    .unwrap();

    // export the private key
    let key_file = tmp_path.join("exported_p12_sk.json");
    export_key(ExportKeyParams {
        cli_conf_path: owner_client_conf_path,
        sub_command: "ec".to_owned(),
        key_id: imported_p12_sk,
        key_file: key_file.to_str().unwrap().to_string(),
        key_format: Some(JsonTtlv),
        ..Default::default()
    })
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

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_export_pkcs7() -> Result<(), CosmianError> {
    let tmp_dir = TempDir::new().unwrap();

    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // import signers
    let (root_ca_id, intermediate_ca_id, issuer_private_key_id) =
        import_root_and_intermediate(&owner_client_conf_path)?;

    // Certify the CSR with the intermediate CA
    let certificate_id = certify(
        &owner_client_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::RSA4096),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Leaf".to_string(),
            ),
            issuer_private_key_id: Some(issuer_private_key_id),
            tags: Some(vec!["certify_a_csr_test".to_owned()]),
            ..CertifyOp::default()
        },
    )?;

    let tmp_exported_pkcs7: std::path::PathBuf = tmp_dir.path().join("exported_p7.p7pem");

    // Export the pkcs7
    export_certificate(
        &owner_client_conf_path,
        &certificate_id,
        tmp_exported_pkcs7.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs7),
        None,
        false,
    )?;

    let p7_bytes = std::fs::read(tmp_exported_pkcs7).unwrap();
    let pkcs7 = Pkcs7::from_pem(p7_bytes.as_slice()).unwrap();

    // Build certs stack for verification
    let certs = Stack::new().unwrap();

    let mut store_builder = X509StoreBuilder::new().unwrap();
    let tmp_exported_int: std::path::PathBuf = tmp_dir.path().join("exported_int.pem");
    let tmp_exported_root: std::path::PathBuf = tmp_dir.path().join("exported_root.pem");

    // Export intermediate cert
    export_certificate(
        &owner_client_conf_path,
        &intermediate_ca_id,
        tmp_exported_int.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12),
        Some("secret".to_owned()),
        false,
    )?;
    let int_bytes = std::fs::read(tmp_exported_int).unwrap();
    let p12 = Pkcs12::from_der(int_bytes.as_slice()).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    let int_cert = parsed_p12.cert.unwrap();

    store_builder.add_cert(int_cert).unwrap();

    // Export root cert
    export_certificate(
        &owner_client_conf_path,
        &root_ca_id,
        tmp_exported_root.to_str().unwrap(),
        Some(CertificateExportFormat::Pem),
        None,
        false,
    )?;
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

pub(crate) fn export_certificate(
    cli_conf_path: &str,
    certificate_id: &str,
    certificate_file: &str,
    certificate_format: Option<CertificateExportFormat>,
    pkcs_12_password: Option<String>,
    allow_revoked: bool,
) -> CosmianResult<()> {
    let mut args: Vec<String> = [
        "export",
        "--certificate-id",
        certificate_id,
        certificate_file,
    ]
    .iter()
    .map(std::string::ToString::to_string)
    .collect();
    if let Some(certificate_format) = certificate_format {
        args.push("--format".to_owned());
        #[cfg(feature = "non-fips")]
        let arg_value = match certificate_format {
            CertificateExportFormat::JsonTtlv => "json-ttlv",
            CertificateExportFormat::Pem => "pem",
            CertificateExportFormat::Pkcs12 => "pkcs12",
            CertificateExportFormat::Pkcs12Legacy => "pkcs12-legacy",
            CertificateExportFormat::Pkcs7 => "pkcs7",
        };
        #[cfg(not(feature = "non-fips"))]
        let arg_value = match certificate_format {
            CertificateExportFormat::JsonTtlv => "json-ttlv",
            CertificateExportFormat::Pem => "pem",
            CertificateExportFormat::Pkcs12 => "pkcs12",
            CertificateExportFormat::Pkcs7 => "pkcs7",
        };
        args.push(arg_value.to_owned());
    }
    if let Some(pkcs_12_password) = pkcs_12_password {
        args.push("--pkcs12-password".to_owned());
        args.push(pkcs_12_password);
    }
    if allow_revoked {
        args.push("--allow-revoked".to_owned());
    }
    let mut cmd = Command::cargo_bin(PROG_NAME)?;
    cmd.env(CKMS_CONF_ENV, cli_conf_path);

    cmd.arg(KMS_SUBCOMMAND).arg("certificates").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(());
    }
    Err(CosmianError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_self_signed_export_loop() -> CosmianResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Create a self-signed certificate - the certificate link points to the certificate itself
    let certificate_id = create_self_signed_cert(&owner_client_conf_path)?;

    // export
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert.p12");
    export_certificate(
        &owner_client_conf_path,
        &certificate_id,
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12),
        Some(String::from("secret")),
        false, // to get attributes
    )?;

    // try re-importing the PKCS#12
    import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: tmp_exported_cert.to_str().unwrap(),
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: Some(Uuid::new_v4().to_string()),
        ..Default::default()
    })?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_export_root_and_intermediate_pkcs12() -> CosmianResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Generate a self-signed root CA
    let ca_id = certify(
        &owner_client_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test CA".to_string(),
            ),
            ..Default::default()
        },
    )?;

    // Certify an intermediate CA with the root CA
    let intermediate_id = certify(
        &owner_client_conf_path,
        CertifyOp {
            issuer_certificate_id: Some(ca_id),
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Intermediate".to_string(),
            ),
            ..Default::default()
        },
    )?;

    // export the intermediate CA to PKCS#12
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert.p12");
    export_certificate(
        &owner_client_conf_path,
        &intermediate_id,
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12),
        Some(String::from("secret")),
        false,
    )?;

    // try re-importing the PKCS#12
    import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: tmp_exported_cert.to_str().unwrap(),
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: Some(Uuid::new_v4().to_string()),
        ..Default::default()
    })?;

    Ok(())
}

#[cfg(feature = "non-fips")]
#[tokio::test]
async fn test_export_import_legacy_p12() -> CosmianResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;
    let (owner_client_conf_path, _) = save_kms_cli_config(ctx);

    // Generate a self-signed root CA
    let cert_id = certify(
        &owner_client_conf_path,
        CertifyOp {
            generate_keypair: true,
            algorithm: Some(Algorithm::NistP256),
            subject_name: Some(
                "C = FR, ST = IdF, L = Paris, O = AcmeTest, CN = Test Cert".to_string(),
            ),
            ..Default::default()
        },
    )?;

    // export the certificate to legacy PKCS#12
    let tmp_dir = TempDir::new()?;
    let tmp_exported_cert = tmp_dir.path().join("cert_legacy.p12");
    export_certificate(
        &owner_client_conf_path,
        &cert_id,
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12Legacy),
        Some(String::from("secret")),
        false,
    )?;

    // try re-importing the PKCS#12
    import_certificate(ImportCertificateInput {
        cli_conf_path: &owner_client_conf_path,
        sub_command: "certificates",
        key_file: tmp_exported_cert.to_str().unwrap(),
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: Some(Uuid::new_v4().to_string()),
        ..Default::default()
    })?;

    Ok(())
}
