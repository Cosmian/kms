use cosmian_kms_client::kmip::kmip_types::{LinkType, Tag};
use kms_test_server::start_default_test_kms_server;
use tracing::debug;

use crate::{
    actions::certificates::CertificateInputFormat,
    error::result::CliResult,
    tests::{
        attributes::get_attributes,
        certificates::import::{import_certificate, ImportCertificateInput},
    },
};

#[tokio::test]
async fn test_get_attributes_p12() -> CliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    //import the certificate
    let imported_p12_sk_uid = import_certificate(ImportCertificateInput {
        cli_conf_path: &ctx.owner_client_conf_path,
        sub_command: "certificates",
        key_file: "test_data/certificates/csr/intermediate.p12",
        format: &CertificateInputFormat::Pkcs12,
        pkcs12_password: Some("secret"),
        certificate_id: Some("get_attributes_test_p12_cert".to_string()),
        tags: Some(&["import_pkcs12"]),
        replace_existing: true,
        ..Default::default()
    })?;

    //get the attributes of the private key and check that they are correct
    let pkcs12_attributes = get_attributes(
        &ctx.owner_client_conf_path,
        &imported_p12_sk_uid,
        &[Tag::KeyFormatType, Tag::LinkType],
        &[],
    )?;

    debug!("test_get_attributes_p12: pkcs12_attributes: {pkcs12_attributes:?}");
    assert!(!pkcs12_attributes.contains_key(&LinkType::PublicKeyLink.to_string()));
    assert_eq!(
        pkcs12_attributes
            .get(&Tag::KeyFormatType.to_string())
            .unwrap(),
        &serde_json::json!("PKCS1")
    );
    let intermediate_certificate_id: String = serde_json::from_value(
        pkcs12_attributes
            .get(&LinkType::PKCS12CertificateLink.to_string())
            .unwrap()
            .clone(),
    )?;

    //get the attributes of the certificate and check that they are correct
    let intermediate_attributes = get_attributes(
        &ctx.owner_client_conf_path,
        &intermediate_certificate_id,
        &[Tag::KeyFormatType, Tag::LinkType],
        &[],
    )?;

    debug!("test_get_attributes_p12: intermediate_attributes: {intermediate_attributes:?}");

    assert_eq!(
        intermediate_attributes
            .get(&Tag::KeyFormatType.to_string())
            .unwrap(),
        &serde_json::json!("X509")
    );
    assert_eq!(
        intermediate_attributes
            .get(&LinkType::PrivateKeyLink.to_string())
            .unwrap(),
        &serde_json::json!(imported_p12_sk_uid)
    );
    assert!(!intermediate_attributes.contains_key(&LinkType::CertificateLink.to_string()));

    Ok(())
}
