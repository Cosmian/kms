#!allow(dead_code, unused_imports)]
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json, Path, Query},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyMaterial,
    kmip_objects::Object,
    kmip_operations::Get,
    kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
};
use cosmian_logger::{debug, info, trace};
use serde::{Deserialize, Serialize};

use crate::{core::KMS, error::KmsError, routes::azure_ekm::error::AzureEkmErrorReply};

pub(crate) mod error;

/// List of API versions supported by this implementation
pub(crate) const SUPPORTED_API_VERSIONS: [&str; 1] = [
    "0.1-preview",
    // Add future versions here.
];

pub(crate) const HIGHEST_API_VERSION: &str = "0.1-preview";

pub(crate) fn is_api_version_supported(version: &str) -> bool {
    SUPPORTED_API_VERSIONS.contains(&version)
}

/// Validate API version for all requests
fn validate_api_version(version: &str) -> Result<(), AzureEkmErrorReply> {
    if !SUPPORTED_API_VERSIONS.contains(&version) {
        return Err(AzureEkmErrorReply::unsupported_api_version(version));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AzureEkmQueryParams {
    #[serde(rename = "api-version")]
    pub(crate) api_version: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestContext {
    request_id: String,
    correlation_id: String,
    pool_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProxyInfoRequest {
    request_context: RequestContext,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProxyInfoResponse {
    pub api_version: String,
    pub proxy_vendor: String,
    pub proxy_name: String,
    pub ekm_vendor: String,
    pub ekm_product: String,
}

// Post request handlers below
#[post("/info")]
pub(crate) async fn get_proxy_info(
    req: HttpRequest,
    query: Query<AzureEkmQueryParams>,
    request: Json<ProxyInfoRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    info!(
        "POST /ekm/info api-version={} user={}",
        query.api_version,
        kms.get_user(&req)
    );
    trace!("Request: {:?}", request);

    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }
    let conf = kms.params.azure_ekm.clone(); // it's an Arc, so cheap clone

    HttpResponse::Ok().json(ProxyInfoResponse {
        api_version: query.api_version.clone(),
        proxy_vendor: conf.azure_ekm_proxy_vendor,
        proxy_name: conf.azure_ekm_proxy_name,
        ekm_vendor: conf.azure_ekm_ekm_vendor,
        ekm_product: conf.azure_ekm_ekm_product,
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyMetadataRequest {
    request_context: RequestContext,
}

#[derive(Debug, Serialize)]
struct KeyMetadataResponse {
    key_type: String,
    key_size: u32,
    key_ops: [&'static str; 2],
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>, // base64url encoded RSA modulus (only for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>, // base64url encoded RSA public exponent (only for RSA keys)
}

impl KeyMetadataResponse {
    fn aes() -> Self {
        Self {
            key_type: "oct".to_string(),
            key_size: 256,
            key_ops: ["wrapKey", "unwrapKey"],
            n: None,
            e: None,
        }
    }

    fn rsa(key_size: u32, modulus_base64url: String, exponent_base64url: String) -> Self {
        Self {
            key_type: "RSA".to_string(),
            key_size,
            key_ops: ["wrapKey", "unwrapKey"],
            n: Some(modulus_base64url),
            e: Some(exponent_base64url),
        }
    }
}

#[post("/{key_name}/metadata")]
pub(crate) async fn get_key_metadata(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<KeyMetadataRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&req);

    info!(
        "POST /ekm/{}/metadata api-version={} user={}",
        key_name, query.api_version, user,
    );
    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }

    debug!("retrieving key from KMS");
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name)),
        key_format_type: None,
        key_wrap_type: None,
        key_compression_type: None,
        key_wrapping_specification: None,
    };

    match kms.get(get_request, &user, None).await {
        Ok(resp) => match resp.object {
            Object::SymmetricKey(_) | Object::PublicKey(_) | Object::PrivateKey(_) => {
                let object = resp.object;

                // Get the key block
                let key_block = match object.key_block() {
                    Ok(kb) => kb,
                    Err(e) => {
                        return AzureEkmErrorReply::from(&KmsError::from(e)).into();
                    }
                };

                // Get the cryptographic algorithm
                let algorithm = match key_block.cryptographic_algorithm() {
                    Some(alg) => alg,
                    None => {
                        return AzureEkmErrorReply::from(&KmsError::ServerError(
                            "key has no cryptographic algorithm".to_string(),
                        ))
                        .into();
                    }
                };

                // Get the cryptographic length
                let key_length = match key_block.cryptographic_length {
                    Some(len) => len as u32,
                    None => {
                        return AzureEkmErrorReply::from(&KmsError::ServerError(
                            "key has no cryptographic length".to_string(),
                        ))
                        .into();
                    }
                };

                // Check algorithm and build response
                match algorithm {
                    CryptographicAlgorithm::AES => {
                        if key_length == 256 {
                            HttpResponse::Ok().json(KeyMetadataResponse::aes())
                        } else {
                            AzureEkmErrorReply::from(&KmsError::ServerError(format!(
                                "unsupported AES key length: {}. Only 256 is supported",
                                key_length
                            )))
                            .into()
                        }
                    }
                    CryptographicAlgorithm::RSA => {
                        let key_material = match key_block.key_material() {
                            Ok(km) => km,
                            Err(e) => {
                                return AzureEkmErrorReply::from(&KmsError::from(e)).into();
                            }
                        };

                        let (modulus, public_exponent) = match key_material {
                            KeyMaterial::TransparentRSAPublicKey {
                                modulus,
                                public_exponent,
                            } => (modulus, public_exponent),
                            KeyMaterial::TransparentRSAPrivateKey {
                                modulus,
                                public_exponent: Some(public_exponent),
                                ..
                            } => (modulus, public_exponent),
                            _ => {
                                return AzureEkmErrorReply::from(&KmsError::ServerError(
                                    "RSA key has missing metadata parameters".to_string(),
                                ))
                                .into();
                            }
                        };

                        let modulus_bytes = modulus.to_bytes_be().1; // Get big-endian bytes, .1 to skip sign
                        let exponent_bytes = public_exponent.to_bytes_be().1;

                        let n_base64url = URL_SAFE_NO_PAD.encode(&modulus_bytes);
                        let e_base64url = URL_SAFE_NO_PAD.encode(&exponent_bytes);
                        // TODO: Extract RSA modulus and exponent from key_block
                        // For now, return an error indicating incomplete implementation
                        HttpResponse::Ok().json(KeyMetadataResponse::rsa(
                            key_length,
                            n_base64url,
                            e_base64url,
                        ))
                    }
                    _ => AzureEkmErrorReply::from(&KmsError::ServerError(format!(
                        "unsupported key algorithm: {:?}. Only AES and RSA are supported",
                        algorithm
                    )))
                    .into(),
                }
            }
            _ => {
                return AzureEkmErrorReply::operation_not_allowed("metadata", &key_name).into();
            }
        },
        Err(e) => {
            if matches!(e, KmsError::ItemNotFound(_)) || e.to_string().contains("not found") {
                return AzureEkmErrorReply::key_not_found(&key_name).into(); // as required by Azure EKM specs
            }
            // Otherwise, it's an internal error
            return AzureEkmErrorReply::internal_error(format!("Failed to retrieve key: {}", e))
                .into();
        }
    }
}

// struct WrapKeyRequest {
//     // TODO: stub
// }

// #[post("/{key_name}/wrapkey")]
// pub(crate) async fn wrap_key(
//     req: HttpRequest,
//     key_name: Path<String>,
//     query: Query<AzureEkmQueryParams>,
//     request: Json<WrapKeyRequest>,
//     kms: Data<Arc<KMS>>,
// ) -> HttpResponse {
//     let key_name = key_name.into_inner();
//     info!(
//         "POST /ekm/{}/wrapkey alg={} api-version={} user={}",
//         key_name,
//         request.alg,
//         query.api_version,
//         kms.get_user(&req)
//     );

//     if let Err(e) = validate_api_version(&query.api_version) {
//         return e.into();
//     }
//     if let Err(e) = validate_key_name(&key_name) {
//         return e.into();
//     }

//     match operations::wrap_key(&key_name, request.into_inner(), &kms)
//         .await
//         .map(Json)
//     {
//         Ok(response) => HttpResponse::Ok().json(response),
//         Err(e) => AzureEkmErrorReply::from(&e).into(),
//     }
// }

// struct UnwrapKeyRequest {
//     // TODO: stub
// }

// #[post("/{key_name}/unwrapkey")]
// pub(crate) async fn unwrap_key(
//     req: HttpRequest,
//     key_name: Path<String>,
//     query: Query<AzureEkmQueryParams>,
//     request: Json<UnwrapKeyRequest>,
//     kms: Data<Arc<KMS>>,
// ) -> HttpResponse {
//     let key_name = key_name.into_inner();
//     info!(
//         "POST /ekm/{}/unwrapkey alg={} api-version={} user={}",
//         key_name,
//         request.alg,
//         query.api_version,
//         kms.get_user(&req)
//     );

//     if let Err(e) = validate_api_version(&query.api_version) {
//         return e.into();
//     }
//     if let Err(e) = validate_key_name(&key_name) {
//         return e.into();
//     }

//     match operations::unwrap_key(&key_name, request.into_inner(), &kms)
//         .await
//         .map(Json)
//     {
//         Ok(response) => HttpResponse::Ok().json(response),
//         Err(e) => AzureEkmErrorReply::from(&e).into(),
//     }
// }
