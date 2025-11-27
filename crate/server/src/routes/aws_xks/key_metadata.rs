//! `GetKeyMetaData`
//! ----------------
//! This API is called by KMS to get metadata about an external key or create a new external key.
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json, Path},
};
use cosmian_kms_access::access::Access;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, GetAttributes},
        kmip_types::{CryptographicAlgorithm, KeyFormatType, UniqueIdentifier},
    },
};
use cosmian_logger::warn;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing::{debug, info};

use crate::{
    core::KMS,
    routes::aws_xks::error::{XksErrorName, XksErrorReply},
};

/// Returns the current UTC time with milliseconds set to zero.
///
/// This function is used to normalize timestamps across the KMIP implementation,
/// ensuring consistent time representations without millisecond precision.
///
/// # Returns
///
/// Returns the current `OffsetDateTime` with milliseconds set to 0.
///
/// # Errors
///
/// Returns a `KmipError::Default` if the millisecond replacement fails.
fn time_normalize() -> Result<OffsetDateTime, XksErrorReply> {
    OffsetDateTime::now_utc()
        .replace_millisecond(0)
        .map_err(|e| XksErrorReply {
            errorName: XksErrorName::InternalException,
            errorMessage: Some(format!("Failed to normalize time: {e}")),
        })
}

/// Request Payload Parameters: The HTTP body of the request contains the requestMetadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) struct RequestMetadata {
    /// This is the ARN of the principal that invoked KMS `CreateKey` (see aws:PrincipalArn).
    /// When the caller is another AWS service, this field will contain either
    /// the service principal ending in amazonaws.com, such as ec2.amazonaws.com or
    /// "AWS Internal". This field is REQUIRED.
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
    /// e.g. `CreateKey` can result in a `GetKeyMetadata` call. This field is REQUIRED.
    /// The XKS Proxy MUST NOT reject a request as invalid if it sees a kmsOperation
    /// other than those listed for this API call.
    /// In the future, KMS may introduce a new API that can be satisfied
    /// by calling one of the XKS APIs listed in this document.
    /// For proxies that implement secondary authorization,
    /// it is acceptable for XKS API requests made as part of the new KMS API to fail authorization.
    /// It is easier for a customer to update their XKS Proxy authorization policy
    /// than to update their XKS Proxy software.
    pub kmsOperation: String,
    /// This is the requestId of the call made to KMS which is visible in AWS `CloudTrail`.
    /// The XKS proxy SHOULD log this field to allow a customer
    /// to correlate AWS `CloudTrail` entries with log entries in the XKS Proxy.
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
pub(crate) struct GetKeyMetadataRequest {
    pub requestMetadata: RequestMetadata,
}

// Defined per XKS Proxy API spec.
#[derive(Serialize, Debug, PartialEq, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum KeyUsage {
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
pub(crate) struct GetKeyMetadataResponse {
    /// Specifies the type of external key.
    /// This field is REQUIRED.
    /// The XKS Proxy must use the string `AES_256` to indicate a 256-bit AES key.
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

#[post("/kms/xks/v1/keys/{key_id}/metadata")]
pub(crate) async fn get_key_metadata(
    req_http: HttpRequest,
    key_id: Path<String>,
    request: Json<GetKeyMetadataRequest>,
    kms: Data<Arc<KMS>>,
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
    let response = match request.requestMetadata.kmsOperation.as_str() {
        "GetKeyMetadata" | "DescribeKey" => get_key_metadata_inner(req_http, request, key_id, &kms)
            .await
            .map(Json),
        "CreateKey" => create_key(req_http, request, key_id, &kms).await.map(Json),
        x => Err(XksErrorReply {
            errorName: XksErrorName::UnsupportedOperationException,
            errorMessage: Some(format!("Unsupported kmsOperation: {x}")),
        }),
    };
    match response {
        Ok(wrap_response) => HttpResponse::Ok().json(wrap_response),
        Err(e) => HttpResponse::from_error(e),
    }
}

async fn get_key_metadata_inner(
    _req_http: HttpRequest,
    request: GetKeyMetadataRequest,
    key_id: String,
    kms: &Arc<KMS>,
) -> Result<GetKeyMetadataResponse, XksErrorReply> {
    let user = request.requestMetadata.awsPrincipalArn;

    let response = kms
        .get_attributes(
            GetAttributes {
                unique_identifier: Some(UniqueIdentifier::TextString(key_id)),
                attribute_reference: None,
            },
            &user,
        )
        .await
        .map_err(|e| XksErrorReply {
            errorName: XksErrorName::KeyNotFoundException,
            errorMessage: Some(e.to_string()),
        })?;
    let cryptographic_algorithm =
        response
            .attributes
            .cryptographic_algorithm
            .ok_or_else(|| XksErrorReply {
                errorName: XksErrorName::InternalException,
                errorMessage: Some("No cryptographic algorithm found".to_owned()),
            })?;
    let key_size = response
        .attributes
        .cryptographic_length
        .ok_or_else(|| XksErrorReply {
            errorName: XksErrorName::InternalException,
            errorMessage: Some("No cryptographic length found".to_owned()),
        })?;
    let (key_spec, key_usage) = match cryptographic_algorithm {
        CryptographicAlgorithm::AES => (
            format!("AES_{key_size}"),
            vec![
                KeyUsage::ENCRYPT,
                KeyUsage::DECRYPT,
                KeyUsage::WRAP,
                KeyUsage::UNWRAP,
            ],
        ),
        CryptographicAlgorithm::RSA => {
            let key_spec = format!("RSA_{key_size}");
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
            return Err(XksErrorReply {
                errorName: XksErrorName::UnsupportedOperationException,
                errorMessage: Some(format!("Unsupported cryptographic algorithm: {xc:?}")),
            });
        }
    };

    let key_status = "ENABLED".to_owned();
    Ok(GetKeyMetadataResponse {
        keySpec: key_spec,
        keyUsage: key_usage,
        keyStatus: key_status,
    })
}

async fn create_key(
    _req_http: HttpRequest,
    request: GetKeyMetadataRequest,
    key_id: String,
    kms: &Arc<KMS>,
) -> Result<GetKeyMetadataResponse, XksErrorReply> {
    let aws_user = request.requestMetadata.awsPrincipalArn;
    let uid = UniqueIdentifier::TextString(key_id);
    // Set the activation date  in the past to have the key immediately active
    let activation_date = time_normalize().map_err(|e| XksErrorReply {
        errorName: XksErrorName::InternalException,
        errorMessage: Some(format!("Failed to get current time: {e}")),
    })? - time::Duration::minutes(1);

    let mut attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        cryptographic_length: Some(256),
        cryptographic_usage_mask: Some(
            CryptographicUsageMask::Encrypt
                | CryptographicUsageMask::Decrypt
                | CryptographicUsageMask::WrapKey
                | CryptographicUsageMask::UnwrapKey,
        ),
        key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
        object_type: Some(ObjectType::SymmetricKey),
        unique_identifier: Some(uid.clone()),
        activation_date: Some(activation_date),
        ..Attributes::default()
    };
    attributes
        .set_tags(["aws-xks"])
        .map_err(|e| XksErrorReply {
            errorName: XksErrorName::InternalException,
            errorMessage: Some(format!("Failed to set tags: {e}")),
        })?;
    let create = Create {
        object_type: ObjectType::SymmetricKey,
        attributes,
        protection_storage_masks: None,
    };

    if let Err(e) = kms.create(create, &kms.params.default_username, None).await {
        // If the key already exists, ignore the creation error (idempotent CreateKey).
        let get_att_response = kms
            .get_attributes(
                GetAttributes {
                    unique_identifier: Some(uid.clone()),
                    attribute_reference: None,
                },
                &kms.params.default_username,
            )
            .await
            .map_err(|e| XksErrorReply {
                errorName: XksErrorName::InternalException,
                errorMessage: Some(format!("Failed to check prior existence of key {uid}: {e}")),
            })?;
        if get_att_response.attributes.object_type == Some(ObjectType::SymmetricKey) {
            warn!("AWS XKS create: key {uid} already exists (ignoring creation).");
        } else {
            return Err(XksErrorReply {
                errorName: XksErrorName::InternalException,
                errorMessage: Some(format!("Failed to create XKS key {uid}: {e}")),
            });
        }
    } else {
        // Grant Encrypt and Decrypt usage for the created key to the AWS user
        kms.grant_access(
            &Access {
                unique_identifier: Some(uid.clone()),
                user_id: aws_user.clone(),
                operation_types: vec![
                    KmipOperation::Encrypt,
                    KmipOperation::Decrypt,
                    KmipOperation::GetAttributes,
                ],
            },
            &kms.params.default_username,
            None,
        )
        .await
        .map_err(|e| XksErrorReply {
            errorName: XksErrorName::InternalException,
            errorMessage: Some(format!(
                "Failed to grant access to key {uid}, to user {aws_user}: {e}"
            )),
        })?;
    }

    // Return the key metadata
    let key_spec = "AES_256".to_owned();
    let key_usage = vec![
        KeyUsage::ENCRYPT,
        KeyUsage::DECRYPT,
        KeyUsage::WRAP,
        KeyUsage::UNWRAP,
    ];
    let key_status = "ENABLED".to_owned();
    Ok(GetKeyMetadataResponse {
        keySpec: key_spec,
        keyUsage: key_usage,
        keyStatus: key_status,
    })
}
