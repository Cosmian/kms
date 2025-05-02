use std::path::PathBuf;

use cosmian_kms_client::{
    kmip_2_1::kmip_types::{LinkType, Tag},
    reexport::cosmian_kms_client_utils::import_utils::CertificateInputFormat,
};
use test_kms_server::start_default_test_kms_server;
use tracing::debug;

use crate::{
    actions::kms::{
        attributes::GetAttributesAction, certificates::import_certificate::ImportCertificateAction,
    },
    error::result::KmsCliResult,
};

#[tokio::test]
async fn test_get_attributes_p12() -> KmsCliResult<()> {
    // Create a test server
    let ctx = start_default_test_kms_server().await;

    //import the certificate
    let imported_p12_sk_uid = Box::pin(
        ImportCertificateAction {
            certificate_file: Some(PathBuf::from(
                "../../test_data/certificates/csr/intermediate.p12",
            )),
            input_format: CertificateInputFormat::Pkcs12,
            pkcs12_password: Some("secret".to_owned()),
            certificate_id: Some("get_attributes_test_p12_cert".to_string()),
            replace_existing: true,
            tags: vec!["import_pkcs12".to_string()],
            ..Default::default()
        }
        .run(ctx.get_owner_client()),
    )
    .await?;

    //get the attributes of the private key and check that they are correct
    let pkcs12_attributes = GetAttributesAction {
        id: imported_p12_sk_uid.clone(),
        tags: None,
        attribute_tags: vec![Tag::KeyFormatType, Tag::LinkType],
        attribute_link_types: vec![],
        output_file: None,
    }
    .process(ctx.get_owner_client())
    .await?;

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
    let intermediate_attributes = GetAttributesAction {
        id: Some(intermediate_certificate_id.clone()),
        tags: None,
        attribute_tags: vec![Tag::KeyFormatType, Tag::LinkType],
        attribute_link_types: vec![],
        output_file: None,
    }
    .process(ctx.get_owner_client())
    .await?;

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
