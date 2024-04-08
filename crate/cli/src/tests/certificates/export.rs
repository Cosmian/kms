use std::process::Command;

use assert_cmd::prelude::CommandCargoExt;
use cosmian_kms_client::{
    kmip::{
        kmip_objects::Object,
        kmip_types::{Attributes, KeyFormatType, LinkType},
        ttlv::{deserializer::from_ttlv, TTLV},
    },
    read_from_json_file, read_object_from_json_ttlv_file, KMS_CLI_CONF_ENV,
};
use kms_test_server::{start_default_test_kms_server, ONCE};
use openssl::pkcs12::Pkcs12;
use tempfile::TempDir;
use uuid::Uuid;

use crate::{
    actions::{
        certificates::{CertificateExportFormat, CertificateInputFormat},
        shared::ExportKeyFormat::JsonTtlv,
    },
    error::CliError,
    tests::{
        certificates::import::import_certificate, shared::export_key, utils::recover_cmd_logs,
        PROG_NAME,
    },
};

#[tokio::test]
async fn test_import_export_p12_25519() {
    //load the PKCS#12 file
    let p12_bytes = include_bytes!("../../../test_data/certificates/another_p12/server.p12");
    // Create a test server
    let ctx = ONCE
        .get_or_try_init(start_default_test_kms_server)
        .await
        .unwrap();

    //parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    //import the certificate
    let imported_p12_sk = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/another_p12/server.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        Some(Uuid::new_v4().to_string()),
        None,
        None,
        Some(&["import_pkcs12"]),
        None,
        false,
        true,
    )
    .unwrap();

    //
    // export piece by piece
    //

    let tmp_dir = TempDir::new().unwrap();
    let tmp_exported_sk = tmp_dir.path().join("exported_p12_sk.json");
    let tmp_exported_cert = tmp_dir.path().join("exported_p12_cert.json");
    let tmp_exported_cert_attr = tmp_dir.path().join("exported_p12_cert.attributes.json");
    let tmp_exported_cert_p12 = tmp_dir.path().join("exported_p12_cert.p12");

    // export the private key
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &imported_p12_sk,
        tmp_exported_sk.to_str().unwrap(),
        Some(JsonTtlv),
        false,
        None,
        false,
    )
    .unwrap();
    let sk = read_object_from_json_ttlv_file(&tmp_exported_sk).unwrap();
    assert_eq!(
        sk.key_block().unwrap().key_bytes().unwrap().to_vec(),
        parsed_p12.pkey.as_ref().unwrap().raw_private_key().unwrap()
    );
    let certificate_id = sk
        .attributes()
        .unwrap()
        .get_link(LinkType::PKCS12CertificateLink)
        .unwrap();

    // export the certificate
    export_certificate(
        &ctx.owner_client_conf_path,
        &certificate_id,
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true,
    )
    .unwrap();
    let cert = read_object_from_json_ttlv_file(&tmp_exported_cert).unwrap();
    let cert_x509_der = match &cert {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => panic!("wrong object type"),
    };
    assert_eq!(
        cert_x509_der.clone(),
        parsed_p12.cert.as_ref().unwrap().to_der().unwrap()
    );
    let cert_attributes_ttlv: TTLV = read_from_json_file(&tmp_exported_cert_attr).unwrap();
    let cert_attributes: Attributes = from_ttlv(&cert_attributes_ttlv).unwrap();
    let issuer_id = cert_attributes.get_link(LinkType::CertificateLink).unwrap();

    // export the chain - there should be only one certificate in the chain
    export_certificate(
        &ctx.owner_client_conf_path,
        &issuer_id,
        tmp_exported_cert.to_str().unwrap(),
        Some(CertificateExportFormat::JsonTtlv),
        None,
        true, //to get attributes
    )
    .unwrap();
    let issuer_cert = read_object_from_json_ttlv_file(&tmp_exported_cert).unwrap();
    let issuer_cert_x509_der = match &issuer_cert {
        Object::Certificate {
            certificate_value, ..
        } => certificate_value,
        _ => panic!("wrong object type"),
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
    let issuer_cert_attributes: Attributes = from_ttlv(&issuer_cert_attributes_ttlv).unwrap();
    assert!(
        issuer_cert_attributes
            .get_link(LinkType::CertificateLink)
            .is_none()
    );

    // export the pkcs12
    export_certificate(
        &ctx.owner_client_conf_path,
        &imported_p12_sk,
        tmp_exported_cert_p12.to_str().unwrap(),
        Some(CertificateExportFormat::Pkcs12),
        Some("secret".to_owned()),
        true, //to get attributes
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

#[tokio::test]
async fn test_import_p12_rsa() {
    let tmp_dir = TempDir::new().unwrap();
    let tmp_path = tmp_dir.path();
    //load the PKCS#12 file
    let p12_bytes = include_bytes!("../../../test_data/certificates/csr/intermediate.p12");
    // Create a test server
    let ctx = ONCE
        .get_or_try_init(start_default_test_kms_server)
        .await
        .unwrap();

    //parse the PKCS#12 with openssl
    let p12 = Pkcs12::from_der(p12_bytes).unwrap();
    let parsed_p12 = p12.parse2("secret").unwrap();
    //import the certificate
    let imported_p12_sk = import_certificate(
        &ctx.owner_client_conf_path,
        "certificates",
        "test_data/certificates/csr/intermediate.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        None,
        None,
        None,
        Some(&["import_pkcs12"]),
        None,
        false,
        true,
    )
    .unwrap();

    // export the private key
    let key_file = tmp_path.join("exported_p12_sk.json");
    export_key(
        &ctx.owner_client_conf_path,
        "ec",
        &imported_p12_sk,
        key_file.to_str().unwrap(),
        Some(JsonTtlv),
        false,
        None,
        false,
    )
    .unwrap();
    // export object by object
    let sk = read_object_from_json_ttlv_file(&key_file).unwrap();
    assert_eq!(
        sk.key_block().unwrap().key_format_type,
        KeyFormatType::PKCS1
    );
    assert_eq!(
        sk.key_block().unwrap().key_bytes().unwrap().to_vec(),
        parsed_p12
            .pkey
            .unwrap()
            .rsa()
            .unwrap()
            .private_key_to_der()
            .unwrap()
    );
}

#[allow(clippy::too_many_arguments)]
pub fn export_certificate(
    cli_conf_path: &str,
    certificate_id: &str,
    certificate_file: &str,
    certificate_format: Option<CertificateExportFormat>,
    pkcs_12_password: Option<String>,
    allow_revoked: bool,
) -> Result<(), CliError> {
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
        let arg_value = match certificate_format {
            CertificateExportFormat::JsonTtlv => "json-ttlv",
            CertificateExportFormat::Pem => "pem",
            CertificateExportFormat::Pkcs12 => "pkcs12",
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
    cmd.env(KMS_CLI_CONF_ENV, cli_conf_path);
    cmd.env("RUST_LOG", "cosmian_kms_cli=info");
    cmd.arg("certificates").args(args);
    let output = recover_cmd_logs(&mut cmd);
    if output.status.success() {
        return Ok(())
    }
    Err(CliError::Default(
        std::str::from_utf8(&output.stderr)?.to_owned(),
    ))
}
