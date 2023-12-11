use crate::{
    actions::{certificates::CertificateInputFormat, shared::AttributeTag},
    tests::{
        certificates::import::import_certificate,
        shared::get_attributes,
        utils::{start_default_test_kms_server, ONCE},
    },
};

#[tokio::test]
async fn test_get_attributes_p12() {
    // Create a test server
    let ctx = ONCE.get_or_init(start_default_test_kms_server).await;

    //import the certificate
    let imported_p12_sk = import_certificate(
        &ctx.owner_cli_conf_path,
        "certificates",
        "test_data/certificates/csr/intermediate.p12",
        CertificateInputFormat::Pkcs12,
        Some("secret"),
        Some("get_attributes_test_p12_cert".to_string()),
        None,
        None,
        Some(&["import_pkcs12"]),
        false,
        true,
    )
    .unwrap();

    //get the attributes of the private key and check that they are correct
    let attributes = get_attributes(
        &ctx.owner_cli_conf_path,
        &imported_p12_sk,
        &[
            AttributeTag::KeyFormatType,
            AttributeTag::LinkedPublicKeyId,
            AttributeTag::LinkedCertificateId,
        ],
    )
    .unwrap();
    assert!(attributes.get(&AttributeTag::LinkedPublicKeyId).is_none());
    assert_eq!(
        attributes.get(&AttributeTag::KeyFormatType).unwrap(),
        &serde_json::json!("PKCS1")
    );
    let intermediate_certificate_id = attributes
        .get(&AttributeTag::LinkedCertificateId)
        .unwrap()
        .as_str()
        .unwrap();

    //get the attributes of the certificate and check that they are correct
    let attributes = get_attributes(
        &ctx.owner_cli_conf_path,
        intermediate_certificate_id,
        &[
            AttributeTag::KeyFormatType,
            AttributeTag::LinkedPrivateKeyId,
            AttributeTag::LinkedIssuerCertificateId,
        ],
    )
    .unwrap();
    assert_eq!(
        attributes.get(&AttributeTag::KeyFormatType).unwrap(),
        &serde_json::json!("X509")
    );
    assert_eq!(
        attributes.get(&AttributeTag::LinkedPrivateKeyId).unwrap(),
        &serde_json::json!(imported_p12_sk)
    );
    assert!(
        attributes
            .get(&AttributeTag::LinkedIssuerCertificateId)
            .is_none()
    );
}
