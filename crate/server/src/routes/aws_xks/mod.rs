mod aws_xks_config;
mod encrypt_decrypt;
mod error;
mod health_status;
mod key_metadata;
mod sigv4_middleware;

pub use aws_xks_config::AwsXksConfig;
pub(crate) use encrypt_decrypt::{decrypt, encrypt};
pub(crate) use error::{xks_json_error_handler, xks_path_not_found_handler};
pub(crate) use health_status::get_health_status;
pub(crate) use key_metadata::get_key_metadata;
pub use sigv4_middleware::Sigv4MWare;

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Result-returning tests assert with assert!/assert_eq!"
)]
mod tests;

use crate::{error::KmsError, result::KResultHelper};

/// Reserved KMS identity under which every AWS XKS operation is executed.
///
/// The AWS XKS proxy authenticates the caller (AWS KMS) through the shared `SigV4` secret in
/// [`Sigv4MWare`]; that signature — not the `awsPrincipalArn` carried in the request body —
/// is the real trust boundary, matching AWS's documented "the AWS key policy is the source
/// of truth" model. All XKS-triggered KMS operations therefore run under this single,
/// stable identity rather than the transient caller ARN, so any correctly-signed request can
/// use the key regardless of which IAM role AWS used.
///
/// XKS keys remain **owned by `default_username`** so operators keep full administrative
/// control (list, revoke, destroy, export) and so key creation still satisfies the
/// `privileged_users` policy. This identity is merely *granted* `Encrypt`, `Decrypt`, and
/// `GetAttributes` on each XKS key: it is a least-privilege delegate that can perform the
/// cryptographic operations XKS needs and nothing else.
///
/// The value is deliberately wrapped in square brackets so it cannot collide with any
/// identity a client could authenticate as: JWT `email`/subject, TLS certificate Common
/// Names, AWS principal ARNs, and API-token user names can never contain the bracket
/// framing. Combined with the grant-based model, the set of objects reachable through the
/// XKS endpoints is exactly the set of XKS keys — no other object can be touched.
pub(crate) const AWS_XKS_SERVICE_USER: &str = "[aws-xks-service]";

#[derive(Debug, Clone)]
pub struct AwsXksParams {
    pub region: String,
    pub service: String,
    pub sigv4_access_key_id: String,
    pub sigv4_secret_access_key: String,
}

impl TryFrom<AwsXksConfig> for AwsXksParams {
    type Error = KmsError;

    fn try_from(config: AwsXksConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            region: config.region.context("AWS XKS region is required")?,
            service: config.service.context("AWS XKS service is required")?,
            sigv4_access_key_id: config
                .sigv4_access_key_id
                .context("AWS XKS SigV4 access key ID is required")?,
            sigv4_secret_access_key: config
                .sigv4_secret_access_key
                .context("AWS XKS SigV4 secret access key is required")?,
        })
    }
}

#[cfg(test)]
mod characterization_tests {
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
            (XksErrorName::Validation, 401_u16, "ValidationException"),
            (XksErrorName::InvalidState, 401, "InvalidStateException"),
            (
                XksErrorName::InvalidCiphertext,
                401,
                "InvalidCiphertextException",
            ),
            (
                XksErrorName::InvalidKeyUsage,
                401,
                "InvalidKeyUsageException",
            ),
            (
                XksErrorName::AuthenticationFailed,
                401,
                "AuthenticationFailedException",
            ),
            (XksErrorName::AccessDenied, 403, "AccessDeniedException"),
            (XksErrorName::KeyNotFound, 418, "KeyNotFoundException"),
            (XksErrorName::InvalidUriPath, 404, "InvalidUriPathException"),
            (XksErrorName::Throttling, 429, "ThrottlingException"),
            (
                XksErrorName::UnsupportedOperation,
                501,
                "UnsupportedOperationException",
            ),
            (
                XksErrorName::DependencyTimeout,
                503,
                "DependencyTimeoutException",
            ),
            (XksErrorName::Internal, 500, "InternalException"),
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
        let none = reply(XksErrorName::Internal, None);
        assert_eq!(
            serde_json::to_string(&none).unwrap(),
            r#"{"errorName":"InternalException","errorMessage":null}"#
        );
    }

    #[test]
    fn characterization_xks_json_error_handler_deserialize_and_other() {
        let req = actix_test::TestRequest::default().to_http_request();
        let de = JsonPayloadError::Deserialize(serde_json::from_str::<u8>("x").unwrap_err());
        let err = xks_json_error_handler(&de, &req);
        assert_eq!(err.as_response_error().status_code().as_u16(), 500);
        assert_eq!(err.error_response().status().as_u16(), 401);
        assert_eq!(
            err.to_string(),
            r#"XksErrorReply { errorName: ValidationException, errorMessage: Some("JSON deserialize error: expected value at line 1 column 1") }"#
        );
        let err = xks_json_error_handler(&JsonPayloadError::ContentType, &req);
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
                KeyUsage::Encrypt,
                KeyUsage::Decrypt,
                KeyUsage::Sign,
                KeyUsage::Verify,
                KeyUsage::Wrap,
                KeyUsage::Unwrap,
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
}
