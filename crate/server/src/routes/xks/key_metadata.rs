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
use clap::crate_version;
use cosmian_kmip::kmip::{kmip_operations::GetAttributes, kmip_types::UniqueIdentifier};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace};

use crate::{
    error::KmsError,
    result::KResult,
    routes::google_cse::{operations, GoogleCseConfig},
    KMSServer,
};

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
    pub kmsOperation: String,
    pub kmsRequestId: String,
    pub awsSourceVpc: Option<String>,
    pub awsSourceVpce: Option<String>,
    pub kmsKeyArn: Option<String>,
    pub kmsViaService: Option<String>,
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
#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct GetKeyMetadataRequest {
    requestMetadata: RequestMetadata,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Debug)]
#[allow(clippy::upper_case_acronyms)]
enum KeyUsage {
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
#[derive(Serialize, Default)]
#[allow(non_snake_case)]
struct GetKeyMetadataResponse {
    /// Specifies the type of external key.
    /// This field is REQUIRED.
    /// The XKS Proxy must use the string AES_256 to indicate a 256-bit AES key.
    keySpec: String,
    /// Specifies an array of cryptographic operations for which external key can be used.
    /// This field is REQUIRED.
    /// The XKS Proxy must use the strings ENCRYPT and DECRYPT (all uppercase)
    /// to indicate when an external key supports encrypt and decrypt operations, respectively.
    /// The XKS Proxy response MAY include additional values supported by that external key,
    /// e.g. PKCS11-based HSMs additionally support DERIVE, SIGN, VERIFY, WRAP, UNWRAP.
    /// The response MUST NOT contain more than ten keyUsage values.
    keyUsage: Vec<KeyUsage>,
    /// Specifies the state of the external key.
    /// The supported values are ENABLED and DISABLED. This field is REQUIRED.
    /// If neither the external key manager nor the XKS Proxy support disabling individual keys,
    /// the XKS Proxy MUST return ENABLED for this field.
    keyStatus: String,
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
        "POST /kms/xks/v1/keys/{key_id}/metadata - id {}",
        request.requestMetadata.kmsRequestId
    );
    debug!("get metadata request: {:?}", request.requestMetadata);
    let kms = kms.into_inner();
    match _get_key_metadata(req_http, request, key_id, &kms)
        .await
        .map(Json)
    {
        Ok(wrap_response) => HttpResponse::Ok().json(wrap_response),
        Err(e) => e.into(),
    }
}

async fn _get_key_metadata(
    req_http: HttpRequest,
    request: GetKeyMetadataRequest,
    key_id: String,
    kms: &Arc<KMSServer>,
) -> KResult<GetKeyMetadataResponse> {
    let user = kms.get_user(req_http)?;
    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let attributes = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(key_id)),
                attribute_references: None,
            },
            &user,
            database_params.as_ref(),
        )
        .await?;
    let cryptographic_algorithm =
        attributes
            .attributes
            .cryptographic_algorithm
            .ok_or_else(|| {
                KmsError::CryptographicError("No cryptographic algorithm found".to_string())
            })?;
    // .map(|attributes| {
    //     let key_spec = attributes
    //         .cryptographic_algorithm
    //         .as_ref()
    //         .map(|algorithm| algorithm.to_string())
    //         .unwrap_or_else(|| "AES_256".to_string());
    //     let key_usage = attributes
    //         .cryptographic_usage_mask
    //         .as_ref()
    //         .map(|mask| {
    //             mask.iter()
    //                 .filter_map(|usage| match usage {
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::ENCRYPT => {
    //                         Some(KeyUsage::ENCRYPT)
    //                     }
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::DECRYPT => {
    //                         Some(KeyUsage::DECRYPT)
    //                     }
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::SIGN => {
    //                         Some(KeyUsage::SIGN)
    //                     }
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::VERIFY => {
    //                         Some(KeyUsage::VERIFY)
    //                     }
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::WRAP => {
    //                         Some(KeyUsage::WRAP)
    //                     }
    //                     cosmian_kmip::kmip::kmip_enums::CryptographicUsageMask::UNWRAP => {
    //                         Some(KeyUsage::UNWRAP)
    //                     }
    //                     _ => None,
    //                 })
    //                 .collect()
    //         })
    //         .unwrap_or_default();
    let key_status = "ENABLED".to_string();
    Ok(GetKeyMetadataResponse {
        keySpec: key_spec,
        keyUsage: key_usage,
        keyStatus: key_status,
    })
}
