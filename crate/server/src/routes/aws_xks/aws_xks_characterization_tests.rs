//! Characterization of the AWS XKS wire types and error mapping at BASE.

use actix_web::{ResponseError, error::JsonPayloadError, test as actix_test};
use serde_json::json;

use super::{
    encrypt_decrypt::{DecryptRequest, EncryptRequest, EncryptResponse, RequestMetadata},
    error::{XksErrorName, XksErrorReply, xks_json_error_handler, xks_path_not_found_handler},
    health_status::{EkmFleetDetails, GetHealthStatusResponse},
    key_metadata::{GetKeyMetadataResponse, KeyUsage},
};

fn reply(name: XksErrorName, message: Option<&str>) -> XksErrorReply {
    XksErrorReply {
        errorName: name,
        errorMessage: message.map(str::to_owned),
    }
}

#[test]
fn characterization_xks_error_reply_status_and_body_per_variant() {
    let cases = [
        (
            XksErrorName::ValidationException,
            401_u16,
            "ValidationException",
        ),
        (
            XksErrorName::InvalidStateException,
            401,
            "InvalidStateException",
        ),
        (
            XksErrorName::InvalidCiphertextException,
            401,
            "InvalidCiphertextException",
        ),
        (
            XksErrorName::InvalidKeyUsageException,
            401,
            "InvalidKeyUsageException",
        ),
        (
            XksErrorName::AuthenticationFailedException,
            401,
            "AuthenticationFailedException",
        ),
        (
            XksErrorName::AccessDeniedException,
            403,
            "AccessDeniedException",
        ),
        (
            XksErrorName::KeyNotFoundException,
            418,
            "KeyNotFoundException",
        ),
        (
            XksErrorName::InvalidUriPathException,
            404,
            "InvalidUriPathException",
        ),
        (
            XksErrorName::ThrottlingException,
            429,
            "ThrottlingException",
        ),
        (
            XksErrorName::UnsupportedOperationException,
            501,
            "UnsupportedOperationException",
        ),
        (
            XksErrorName::DependencyTimeoutException,
            503,
            "DependencyTimeoutException",
        ),
        (XksErrorName::InternalException, 500, "InternalException"),
    ];
    for (name, status, label) in cases {
        let r = reply(name, Some("msg"));
        assert_eq!(r.error_response().status().as_u16(), status, "{label}");
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            format!(r#"{{"errorName":"{label}","errorMessage":"msg"}}"#)
        );
        assert_eq!(
            r.to_string(),
            format!(r#"XksErrorReply {{ errorName: {label}, errorMessage: Some("msg") }}"#)
        );
    }
    let none = reply(XksErrorName::InternalException, None);
    assert_eq!(
        serde_json::to_string(&none).unwrap(),
        r#"{"errorName":"InternalException","errorMessage":null}"#
    );
}

#[test]
fn characterization_xks_json_error_handler_deserialize_and_other() {
    let req = actix_test::TestRequest::default().to_http_request();
    let de = JsonPayloadError::Deserialize(serde_json::from_str::<u8>("x").unwrap_err());
    let err = xks_json_error_handler(de, &req);
    assert_eq!(err.as_response_error().status_code().as_u16(), 500);
    assert_eq!(err.error_response().status().as_u16(), 401);
    assert_eq!(
        err.to_string(),
        r#"XksErrorReply { errorName: ValidationException, errorMessage: Some("JSON deserialize error: expected value at line 1 column 1") }"#
    );
    let err = xks_json_error_handler(JsonPayloadError::ContentType, &req);
    assert_eq!(
        err.to_string(),
        r#"XksErrorReply { errorName: ValidationException, errorMessage: Some("Unknown error") }"#
    );
}

#[tokio::test]
async fn characterization_xks_path_not_found_handler_reports_path() {
    let req = actix_test::TestRequest::get()
        .uri("/kms/xks/v1/nope")
        .to_http_request();
    let err = xks_path_not_found_handler(req).await.unwrap_err();
    assert_eq!(err.error_response().status().as_u16(), 404);
    assert_eq!(
        err.to_string(),
        r#"XksErrorReply { errorName: InvalidUriPathException, errorMessage: Some("Resource not found: /kms/xks/v1/nope") }"#
    );
}

const METADATA_JSON: &str = r#"{"awsPrincipalArn":"arn:p","awsSourceVpc":null,"awsSourceVpce":"vpce","kmsKeyArn":"arn:k","kmsOperation":"Encrypt","kmsRequestId":"rid","kmsViaService":null}"#;

#[test]
fn characterization_xks_wire_types_json() {
    let metadata: RequestMetadata = serde_json::from_str(METADATA_JSON).unwrap();
    assert_eq!(serde_json::to_string(&metadata).unwrap(), METADATA_JSON);
    let request: EncryptRequest = serde_json::from_value(json!({
        "requestMetadata": serde_json::to_value(&metadata).unwrap(),
        "plaintext": "AAEC",
        "encryptionAlgorithm": "AES_GCM",
        "additionalAuthenticatedData": "QUFE",
        "ciphertextDataIntegrityValueAlgorithm": "SHA_256"
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_string(&request).unwrap(),
        format!(
            r#"{{"requestMetadata":{METADATA_JSON},"plaintext":"AAEC","encryptionAlgorithm":"AES_GCM","additionalAuthenticatedData":"QUFE","ciphertextDataIntegrityValueAlgorithm":"SHA_256"}}"#
        )
    );
    let decrypt: DecryptRequest = serde_json::from_value(json!({
        "requestMetadata": serde_json::to_value(&metadata).unwrap(),
        "ciphertext": "c",
        "encryptionAlgorithm": "AES_GCM",
        "initializationVector": "iv",
        "authenticationTag": "tag"
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_string(&decrypt).unwrap(),
        format!(
            r#"{{"requestMetadata":{METADATA_JSON},"ciphertext":"c","ciphertextMetadata":null,"encryptionAlgorithm":"AES_GCM","additionalAuthenticatedData":null,"initializationVector":"iv","authenticationTag":"tag"}}"#
        )
    );
    assert_eq!(
        serde_json::to_string(&EncryptResponse::default()).unwrap(),
        r#"{"ciphertext":"","ciphertextMetadata":null,"initializationVector":"","authenticationTag":"","ciphertextDataIntegrityValue":null}"#
    );
    let keys = GetKeyMetadataResponse {
        keySpec: "AES_256".to_owned(),
        keyUsage: vec![
            KeyUsage::ENCRYPT,
            KeyUsage::DECRYPT,
            KeyUsage::SIGN,
            KeyUsage::VERIFY,
            KeyUsage::WRAP,
            KeyUsage::UNWRAP,
        ],
        keyStatus: "ENABLED".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&keys).unwrap(),
        r#"{"keySpec":"AES_256","keyUsage":["ENCRYPT","DECRYPT","SIGN","VERIFY","WRAP","UNWRAP"],"keyStatus":"ENABLED"}"#
    );
    let health = GetHealthStatusResponse {
        xksProxyFleetSize: 1,
        xksProxyVendor: "V".to_owned(),
        xksProxyModel: "M".to_owned(),
        ekmVendor: "E".to_owned(),
        ekmFleetDetails: vec![EkmFleetDetails {
            id: "1".to_owned(),
            model: "m".to_owned(),
            healthStatus: "ACTIVE".to_owned(),
        }],
    };
    assert_eq!(
        serde_json::to_string(&health).unwrap(),
        r#"{"xksProxyFleetSize":1,"xksProxyVendor":"V","xksProxyModel":"M","ekmVendor":"E","ekmFleetDetails":[{"id":"1","model":"m","healthStatus":"ACTIVE"}]}"#
    );
}
