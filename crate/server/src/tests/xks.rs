use base64::{engine::general_purpose::STANDARD, Engine};
use cosmian_kmip::{
    crypto::symmetric::create_symmetric_key_kmip_object,
    kmip::{
        kmip_operations::{Import, ImportResponse},
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
    },
};
use cosmian_kms_client::access::{Access, ObjectOperationType, SuccessResponse};

use crate::{
    result::KResult,
    routes::xks::{
        CdivAlgorithm, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
        EncrytionAlgorithm, GetHealthStatusRequest, GetHealthStatusResponse, GetKeyMetadataRequest,
        GetKeyMetadataResponse, HealthMetaData, KeyRequestMetadata, KeyUsage, RequestMetadata,
    },
    tests::test_utils,
};

#[tokio::test]
async fn test_encrypt_decrypt() -> KResult<()> {
    // cosmian_logger::log_utils::log_init("debug,cosmian_kms_server=trace");
    let app = test_utils::test_app(Some("http://127.0.0.1/".to_string())).await;

    // health status
    let health_request = GetHealthStatusRequest {
        requestMetadata: HealthMetaData {
            kmsRequestId: "00".to_string(),
            kmsOperation: "ConnectKmsKeystore".to_string(),
        },
    };
    let response: GetHealthStatusResponse =
        test_utils::post_with_uri(&app, health_request, "/kms/xks/v1/health").await?;
    assert_eq!(response.xksProxyFleetSize, 1);
    assert_eq!(response.xksProxyVendor, "Cosmian".to_string());
    assert!(response.xksProxyModel.contains("Cosmian KMS"));
    assert_eq!(response.ekmVendor, "Cosmian".to_string());
    assert_eq!(response.ekmFleetDetails.len(), 1);
    assert_eq!(response.ekmFleetDetails[0].id, "1".to_string());
    assert!(response.ekmFleetDetails[0].model.contains("Cosmian KMS"));
    assert_eq!(
        response.ekmFleetDetails[0].healthStatus,
        "ACTIVE".to_string()
    );

    let unique_identifier = UniqueIdentifier::TextString("xks_test".to_string());
    let object = create_symmetric_key_kmip_object(
        b"12345678901234567890123456789012",
        CryptographicAlgorithm::AES,
    );

    // Import the key
    let import_request = Import {
        unique_identifier: unique_identifier.clone(),
        object_type: object.object_type(),
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: object.attributes().cloned().unwrap_or_default(),
        object,
    };

    let response: ImportResponse = test_utils::post(&app, import_request).await?;
    let key_id = response.unique_identifier.to_string();

    // Grant access to the key
    tracing::debug!("grant post");
    let access = Access {
        unique_identifier: Some(unique_identifier),
        user_id: "*".to_string(),
        operation_types: vec![
            ObjectOperationType::Create,
            ObjectOperationType::Destroy,
            ObjectOperationType::Get,
            ObjectOperationType::Encrypt,
            ObjectOperationType::Decrypt,
        ],
    };

    let access_response: SuccessResponse =
        test_utils::post_with_uri(&app, access, "/access/grant").await?;
    tracing::debug!("grant response post: {access_response:?}");

    let message = b"The plaintext";
    let aead = b"aead";

    // generate XKS encryption
    let encrypt_request = EncryptRequest {
        requestMetadata: RequestMetadata {
            awsPrincipalArn: "whoami".to_string(),
            awsSourceVpc: None,
            awsSourceVpce: None,
            kmsKeyArn: "".to_string(),
            kmsOperation: "Encrypt".to_string(),
            kmsRequestId: "01".to_string(),
            kmsViaService: None,
        },
        plaintext: STANDARD.encode(&message),
        encryptionAlgorithm: EncrytionAlgorithm::AES_GCM,
        additionalAuthenticatedData: Some(STANDARD.encode(&aead)),
        ciphertextDataIntegrityValueAlgorithm: Some(CdivAlgorithm::SHA_256),
    };
    let uri = format!("/kms/xks/v1/keys/{}/encrypt", key_id);
    let response: EncryptResponse = test_utils::post_with_uri(&app, encrypt_request, &uri).await?;
    let ciphertext = STANDARD.decode(response.ciphertext)?;
    let nonce = STANDARD.decode(response.initializationVector)?;
    let tag = STANDARD.decode(response.authenticationTag)?;
    let ciphertext_metadata = response.ciphertextMetadata;
    assert!(ciphertext_metadata.is_none());
    assert_eq!(ciphertext.len(), message.len());
    assert_eq!(nonce.len(), 12);
    assert_eq!(tag.len(), 16);

    // decrypt
    let decrypt_request = DecryptRequest {
        requestMetadata: RequestMetadata {
            awsPrincipalArn: "whoami".to_string(),
            awsSourceVpc: None,
            awsSourceVpce: None,
            kmsKeyArn: "".to_string(),
            kmsOperation: "Decrypt".to_string(),
            kmsRequestId: "02".to_string(),
            kmsViaService: None,
        },
        ciphertext: STANDARD.encode(ciphertext),
        ciphertextMetadata: None,
        encryptionAlgorithm: EncrytionAlgorithm::AES_GCM,
        additionalAuthenticatedData: Some(STANDARD.encode(&aead)),
        initializationVector: STANDARD.encode(&nonce),
        authenticationTag: STANDARD.encode(&tag),
    };
    let uri = format!("/kms/xks/v1/keys/{}/decrypt", key_id);
    let response: DecryptResponse = test_utils::post_with_uri(&app, decrypt_request, &uri).await?;
    let plaintext = STANDARD.decode(response.plaintext)?;

    assert_eq!(plaintext, message);

    // Key Meta Data
    let key_metadata_request = GetKeyMetadataRequest {
        requestMetadata: KeyRequestMetadata {
            awsPrincipalArn: "whoami".to_string(),
            awsSourceVpc: None,
            awsSourceVpce: None,
            kmsOperation: "GetKeyMetadata".to_string(),
            kmsRequestId: "03".to_string(),
        },
    };
    let uri = format!("/kms/xks/v1/keys/{}/metadata", key_id);
    let response: GetKeyMetadataResponse =
        test_utils::post_with_uri(&app, key_metadata_request, &uri).await?;
    assert!(response.keyUsage.contains(&KeyUsage::ENCRYPT));
    assert!(response.keyUsage.contains(&KeyUsage::DECRYPT));
    assert!(response.keyUsage.contains(&KeyUsage::WRAP));
    assert!(response.keyUsage.contains(&KeyUsage::UNWRAP));
    assert_eq!(response.keySpec, "AES_256".to_string());
    assert_eq!(response.keyStatus, "ENABLED".to_string());

    Ok(())
}
