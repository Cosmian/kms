//! GetKeyMetaData
//! ----------------
//! This API fetches metadata associated with the external key including its type,
//! supported cryptographic operations and status.
use std::sync::Arc;

use actix_web::{
    post,
    web::{Data, Json, Path},
    HttpRequest, HttpResponse,
};
use cosmian_kmip::kmip::{
    kmip_operations::GetAttributes,
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{error::KmsError, kms_bail, result::KResult, KMSServer};

/// Request Payload Parameters: The HTTP body of the request contains the requestMetadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub struct RequestMetadata {
    /// This is the ARN of the principal that invoked KMS CreateKey (see aws:PrincipalArn).
    /// When the caller is another AWS service, this field will contain either
    /// the service principal ending in amazonaws.com, such as ec2.amazonaws.com or
    /// “AWS Internal”. This field is REQUIRED.
    pub awsPrincipalArn: String,
    /// This field is OPTIONAL. It is present if and only if the KMS API request was made using
    /// a VPC endpoint.
    /// When present, this field indicates the VPC where the request originated (see aws:SourceVpc).
    pub awsSourceVpc: Option<String>,
    /// This field is OPTIONAL. It is present if and only if the KMS API request was made using
    /// a VPC endpoint.
    /// When present, this field indicates the VPC endpoint used for the request (see aws:SourceVpce)
    pub awsSourceVpce: Option<String>,
    /// This is the KMS API call that resulted in the XKS Proxy API request,
    /// e.g. CreateKey can result in a GetKeyMetadata call. This field is REQUIRED.
    /// The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation
    /// other than those listed for this API call.
    /// In the future, KMS may introduce a new API that can be satisfied
    /// by calling one of the XKS APIs listed in this document.
    /// For proxies that implement secondary authorization,
    /// it is acceptable for XKS API requests made as part of the new KMS API to fail authorization.
    /// It is easier for a customer to update their XKS Proxy authorization policy
    /// than to update their XKS Proxy software.
    pub kmsOperation: String,
    /// This is the requestId of the call made to KMS which is visible in AWS CloudTrail.
    /// The XKS proxy SHOULD log this field to allow a customer
    /// to correlate AWS CloudTrail entries with log entries in the XKS Proxy.
    /// This field typically follows the format for UUIDs
    /// but the XKS Proxy MUST treat this as an opaque string
    /// and MUST NOT perform any validation on its structure.
    /// This field is REQUIRED.
    pub kmsRequestId: String,
}

/// The HTTP body of the request contains requestMetadata fields
/// that provide additional context on the request being made.
/// This information is helpful for auditing and for implementing
/// an optional secondary layer of authorization at the XKS Proxy
/// (see a later section on Authorization).
/// There is no expectation for the XKS Proxy to validate any information
/// included in the requestMetadata beyond validating the signature
/// that covers the entire request payload.
///
/// Example:
/// ```json
/// {
///     "requestMetadata": {
///         "awsPrincipalArn": "arn:aws:iam::123456789012:user/Alice",
///         "kmsOperation": "CreateKey",
///         "kmsRequestId": "4112f4d6-db54-4af4-ae30-c55a22a8dfae"
///     }
/// }
/// ```
#[derive(Deserialize, Debug, Serialize)]
#[allow(non_snake_case)]
pub struct GetKeyMetadataRequest {
    pub requestMetadata: RequestMetadata,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Debug, PartialEq, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum KeyUsage {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    WRAP,
    UNWRAP,
}

/// The HTTP response body contains the keySpec, keyUsage, and keyStatus fields.
/// ```json
/// {
///     "keySpec": "AES_256",
///     "keyUsage": ["ENCRYPT", "DECRYPT"],
///     "keyStatus": "ENABLED"
/// }
/// ```
#[derive(Serialize, Default, Deserialize)]
#[allow(non_snake_case)]
pub struct GetKeyMetadataResponse {
    /// Specifies the type of external key.
    /// This field is REQUIRED.
    /// The XKS Proxy must use the string AES_256 to indicate a 256-bit AES key.
    pub keySpec: String,
    /// Specifies an array of cryptographic operations for which external key can be used.
    /// This field is REQUIRED.
    /// The XKS Proxy must use the strings ENCRYPT and DECRYPT (all uppercase)
    /// to indicate when an external key supports encrypt and decrypt operations, respectively.
    /// The XKS Proxy response MAY include additional values supported by that external key,
    /// e.g. PKCS11-based HSMs additionally support DERIVE, SIGN, VERIFY, WRAP, UNWRAP.
    /// The response MUST NOT contain more than ten keyUsage values.
    pub keyUsage: Vec<KeyUsage>,
    /// Specifies the state of the external key.
    /// The supported values are ENABLED and DISABLED. This field is REQUIRED.
    /// If neither the external key manager nor the XKS Proxy support disabling individual keys,
    /// the XKS Proxy MUST return ENABLED for this field.
    pub keyStatus: String,
}

#[post("keys/{key_id}/metadata")]
pub async fn get_key_metadata(
    req_http: HttpRequest,
    key_id: Path<String>,
    request: Json<GetKeyMetadataRequest>,
    kms: Data<Arc<KMSServer>>,
) -> HttpResponse {
    let request = request.into_inner();
    let key_id = key_id.into_inner();
    info!(
        "POST /kms/xks/v1/keys/{key_id}/metadata - operation: {} - id: {} - user: {}",
        request.requestMetadata.kmsOperation,
        request.requestMetadata.kmsRequestId,
        request.requestMetadata.awsPrincipalArn
    );
    debug!("get metadata request: {:?}", request.requestMetadata);
    let kms = kms.into_inner();
    match _get_key_metadata(req_http, request, key_id, &kms)
        .await
        .map(Json)
    {
        Ok(wrap_response) => HttpResponse::Ok().json(wrap_response),
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn _get_key_metadata(
    req_http: HttpRequest,
    request: GetKeyMetadataRequest,
    key_id: String,
    kms: &Arc<KMSServer>,
) -> KResult<GetKeyMetadataResponse> {
    let user = request.requestMetadata.awsPrincipalArn;
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let response = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(key_id)),
                attribute_references: None,
            },
            &user,
            database_params.as_ref(),
        )
        .await?;
    let cryptographic_algorithm = response.attributes.cryptographic_algorithm.ok_or_else(|| {
        KmsError::CryptographicError("No cryptographic algorithm found".to_string())
    })?;
    let key_size = response
        .attributes
        .cryptographic_length
        .ok_or_else(|| KmsError::CryptographicError("No cryptographic length found".to_string()))?;
    let (key_spec, key_usage) = match cryptographic_algorithm {
        CryptographicAlgorithm::AES => (
            format!("AES_{}", key_size),
            vec![
                KeyUsage::ENCRYPT,
                KeyUsage::DECRYPT,
                KeyUsage::WRAP,
                KeyUsage::UNWRAP,
            ],
        ),
        CryptographicAlgorithm::RSA => {
            let key_spec = format!("RSA_{}", key_size);
            if response.attributes.get_tags().contains("_sk") {
                // a private key
                (
                    key_spec,
                    vec![KeyUsage::DECRYPT, KeyUsage::SIGN, KeyUsage::UNWRAP],
                )
            } else {
                (
                    key_spec,
                    vec![KeyUsage::ENCRYPT, KeyUsage::VERIFY, KeyUsage::WRAP],
                )
            }
        }
        xc => {
            kms_bail!("XKS: Unsupported cryptographic algorithm: {:?}", xc);
        }
    };

    let key_status = "ENABLED".to_string();
    Ok(GetKeyMetadataResponse {
        keySpec: key_spec,
        keyUsage: key_usage,
        keyStatus: key_status,
    })
}
