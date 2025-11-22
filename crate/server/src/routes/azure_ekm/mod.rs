#!allow(dead_code, unused_imports)]
use std::sync::Arc;

use actix_web::{
    HttpRequest, HttpResponse, post,
    web::{Data, Json, Path, Query},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
// TODO : do not import from client utiles, use cosmian_kms_server like below
use cosmian_kms_client_utils::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::CryptographicParameters,
    },
};
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_data_structures::{KeyBlock, KeyMaterial},
    kmip_objects::Object,
    kmip_operations::Get,
    kmip_types::{CryptographicAlgorithm, LinkType::PublicKeyLink, UniqueIdentifier},
};
use cosmian_logger::{info, trace};
use num_bigint_dig::BigInt;
use serde::{Deserialize, Serialize};

use crate::{
    core::KMS, error::KmsError, result::KResult, routes::azure_ekm::error::AzureEkmErrorReply,
};

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
    key_size: i32,
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

    fn rsa(key_size: i32, modulus_base64url: String, exponent_base64url: String) -> Self {
        Self {
            key_type: "RSA".to_string(),
            key_size,
            key_ops: ["wrapKey", "unwrapKey"],
            n: Some(modulus_base64url),
            e: Some(exponent_base64url),
        }
    }
}

const SUPPORTED_RSA_LENGTHS: [i32; 3] = [2048, 3072, 4096]; // the KMS key lengths are i32

#[post("/{key_name}/metadata")]
pub(crate) async fn get_key_metadata(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
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

    match get_key_metadata_from_kms(key_name, user, kms).await {
        Ok(response) => response,
        Err(e) => AzureEkmErrorReply::from(e).into(),
    }
}

pub(crate) async fn get_key_metadata_from_kms(
    key_name: String,
    user: String,
    kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.clone())),
        ..Default::default()
    };
    match kms.get(get_request, &user, None).await {
        Ok(resp) => {
            match resp.object {
                Object::SymmetricKey(_) | Object::PublicKey(_) | Object::PrivateKey(_) => {
                    let object = resp.object;

                    let key_block = object.key_block()?;

                    let algorithm = key_block.cryptographic_algorithm().ok_or_else(|| {
                        KmsError::ServerError("Cryptographic algorithm not set.".to_string())
                    })?;
                    let key_length = key_block
                        .cryptographic_length
                        .ok_or_else(|| KmsError::ServerError("Key length not set.".to_string()))?;
                    // Check algorithm and build response
                    match algorithm {
                        CryptographicAlgorithm::AES => {
                            if key_length == 256 {
                                Ok(HttpResponse::Ok().json(KeyMetadataResponse::aes()))
                            } else {
                                // It's indeed uncommon to see an error wrapped in an Ok() - this was done in purpose to reduce useless conversions
                                // Returning an Err() will be interpreted as an internal server error by the caller, which is not what we want here
                                // since the key exists but its length is unsupported. The specs is not very clear on this particular case.
                                return Ok(AzureEkmErrorReply::operation_not_allowed(
                                    &format!(
                                        "AES key has length {}, only 256 is supported for now.",
                                        key_length
                                    ),
                                    &key_name,
                                )
                                .into());
                            }
                        }
                        CryptographicAlgorithm::RSA => Ok({
                            if !SUPPORTED_RSA_LENGTHS.contains(&key_length) {
                                return Ok(AzureEkmErrorReply::operation_not_allowed(
                                    &format!(
                                        "RSA key has length {}. Only {:?} are supported for now.",
                                        key_length, SUPPORTED_RSA_LENGTHS,
                                    ),
                                    &key_name,
                                )
                                .into());
                            }
                            let key_material = key_block.key_material()?;

                            let modulus;
                            let public_exponent: Box<BigInt>; // solves ownership issues - strongly typed on purpose

                            match key_material {
                                KeyMaterial::TransparentRSAPublicKey {
                                    modulus: m,
                                    public_exponent: pe,
                                } => {
                                    modulus = m;
                                    public_exponent = pe.clone();
                                }
                                KeyMaterial::TransparentRSAPrivateKey {
                                    modulus: m,
                                    public_exponent: pe,
                                    ..
                                } => {
                                    modulus = m;
                                    let pub_exp = if let Some(exp) = pe {
                                        exp.clone()
                                    } else {
                                        // Fetch and store in outer scope
                                        // This function is not called in the other branches, which makes the cloning
                                        // mandatory - I do not think there's a more efficient way to this
                                        let fetched = get_public_exponent_from_linked_key(
                                            &key_block, &user, &kms,
                                        )
                                        .await?;
                                        fetched.clone()
                                    };
                                    public_exponent = pub_exp;
                                }
                                _ => {
                                    return Err(KmsError::ServerError(
                                        "RSA key has missing metadata parameters".to_string(),
                                    ));
                                }
                            };

                            let modulus_bytes = modulus.to_bytes_be().1; // .1 to skip sign
                            let exponent_bytes = &public_exponent.to_bytes_be().1;

                            let n_base64url = URL_SAFE_NO_PAD.encode(&modulus_bytes);
                            let e_base64url = URL_SAFE_NO_PAD.encode(&exponent_bytes);
                            HttpResponse::Ok().json(KeyMetadataResponse::rsa(
                                key_length,
                                n_base64url,
                                e_base64url,
                            ))
                        }),
                        _ => Err(KmsError::ServerError(format!(
                            "Unsupported key algorithm: {:?}. Only AES and RSA are supported",
                            algorithm
                        ))),
                    }
                }
                _ => {
                    return Ok(
                        AzureEkmErrorReply::operation_not_allowed("metadata", &key_name).into(),
                    );
                }
            }
        }
        Err(e) => {
            if matches!(e, KmsError::ItemNotFound(_)) || e.to_string().contains("not found") {
                return Ok(AzureEkmErrorReply::key_not_found(&key_name).into()); // as required by Azure EKM specs
            }
            // Otherwise, it's an internal error
            return Ok(AzureEkmErrorReply::internal_error(format!(
                "Failed to retrieve key: {}",
                e
            ))
            .into());
        }
    }
}

/// If the public exponent is missing from the private key, fetch it from a linked RSA public key
async fn get_public_exponent_from_linked_key(
    key_block: &KeyBlock,
    user: &str,
    kms: &KMS,
) -> KResult<Box<num_bigint_dig::BigInt>> {
    let public_key_id = key_block
        .get_linked_object_id(PublicKeyLink)?
        .ok_or_else(|| {
            KmsError::ServerError(
                "RSA private key has no linked public key to get public exponent from.".to_string(),
            )
        })?;

    let public_key_response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(public_key_id)),
                ..Default::default()
            },
            user,
            None,
        )
        .await?;

    match public_key_response.object {
        Object::PublicKey(pub_key) => match pub_key.key_block.key_material()? {
            KeyMaterial::TransparentRSAPublicKey {
                public_exponent, ..
            } => Ok(public_exponent.clone()),
            _ => Err(KmsError::ServerError(
                "Failed to retrieve public exponent from linked public key".to_string(),
            )),
        },
        _ => Err(KmsError::ServerError(
            "Failed to retrieve public exponent from linked public key".to_string(),
        )),
    }
}

// code above this line has been re-read and verified (not tested)

// code below is incomplete and is a work going on

#[derive(Debug, Deserialize)]
pub(crate) enum WrapAlgorithm {
    A256KW,
    A256KWP,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
}
#[derive(Debug, Deserialize)]
pub(crate) struct WrapKeyRequest {
    request_context: RequestContext,
    alg: WrapAlgorithm,
    value: String, // base64url encoded key to wrap
}

#[derive(Debug, Serialize)]
pub(crate) struct WrapKeyResponse {
    value: String, // base64url encoded wrapped key
}

#[post("/{key_name}/wrapkey")]
pub(crate) async fn wrap_key(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<WrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&req);

    info!(
        "POST /ekm/{}/wrapkey alg={:?} api-version={} user={}",
        key_name, request.alg, query.api_version, user
    );

    // Validate API version
    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }

    // Call inner implementation
    match wrap_key_handler(&kms, &key_name, &user, request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => e.into(),
    }
}

async fn wrap_key_handler(
    kms: &KMS,
    key_name: &str,
    user: &str,
    request: WrapKeyRequest,
) -> Result<WrapKeyResponse, AzureEkmErrorReply> {
    // Decode the input key from base64url
    let dek_bytes = URL_SAFE_NO_PAD.decode(&request.value).map_err(|_| {
        AzureEkmErrorReply::invalid_request("Invalid base64url encoding in 'value' field")
    })?;

    let wrapping_key_object = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
                ..Default::default()
            },
            user,
            None,
        )
        .await
        .map_err(|e| match e {
            KmsError::ItemNotFound(_) => AzureEkmErrorReply::key_not_found(key_name),
            _ => e.into(),
        })?
        .object;

    // Validation
    match &wrapping_key_object {
        Object::SymmetricKey(_) | Object::PublicKey(_) => {}
        _ => {
            return Err(AzureEkmErrorReply::operation_not_allowed(
                "wrapkey", key_name,
            ));
        }
    }

    let key_block = wrapping_key_object.key_block().unwrap(); // TODO no unwrap
    let key_algorithm = key_block.cryptographic_algorithm().ok_or_else(|| {
        AzureEkmErrorReply::internal_error("Wrapping key has no cryptographic algorithm")
    })?;

    // Validate algorithm matches key type
    validate_wrapping_algorithm(&request.alg, &key_algorithm)?;

    // Perform the wrap operation based on key type
    let wrapped_key_bytes = match key_algorithm {
        CryptographicAlgorithm::AES => {
            // AES Key Wrap using KMIP Encrypt operation
            wrap_with_aes(kms, key_name, user, &dek_bytes, &request.alg).await?
        }
        CryptographicAlgorithm::RSA => {
            // RSA-OAEP wrap using KMIP Encrypt operation
            wrap_with_rsa(kms, key_name, user, &dek_bytes, &request.alg).await?
        }
        _ => {
            return Err(AzureEkmErrorReply::internal_error(format!(
                "Unsupported key algorithm: {:?}",
                key_algorithm
            )));
        }
    };

    // Encode wrapped key as base64url
    let wrapped_base64url = URL_SAFE_NO_PAD.encode(&wrapped_key_bytes);

    Ok(WrapKeyResponse {
        value: wrapped_base64url,
    })
}

/// Validate that the wrap algorithm is compatible with the key type
fn validate_wrapping_algorithm(
    alg: &WrapAlgorithm,
    key_algorithm: &CryptographicAlgorithm,
) -> Result<(), AzureEkmErrorReply> {
    match (key_algorithm, alg) {
        (CryptographicAlgorithm::AES, WrapAlgorithm::A256KW | WrapAlgorithm::A256KWP) => Ok(()),
        (CryptographicAlgorithm::RSA, WrapAlgorithm::RsaOaep256) => Ok(()),
        (CryptographicAlgorithm::AES, _) => Err(AzureEkmErrorReply::unsupported_algorithm(
            &format!("{:?}", alg),
            "AES",
        )),
        (CryptographicAlgorithm::RSA, _) => Err(AzureEkmErrorReply::unsupported_algorithm(
            &format!("{:?}", alg),
            "RSA",
        )),
        _ => Err(AzureEkmErrorReply::internal_error(format!(
            "Unsupported key algorithm: {:?}",
            key_algorithm
        ))),
    }
}

async fn wrap_with_aes(
    _kms: &KMS,
    _key_name: &str,
    _user: &str,
    _dek_bytes: &[u8],
    _alg: &WrapAlgorithm,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    todo!("Implement wrap_with_aes function")
    // Ok(wrapped_data)
}

/// Wrap DEK with RSA public key using KMIP Encrypt (OAEP padding)
async fn wrap_with_rsa(
    kms: &KMS,
    key_name: &str,
    user: &str,
    dek_bytes: &[u8],
    _alg: &WrapAlgorithm,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    // does not work ?
    // if alg != WrapAlgorithm::RsaOaep256 {
    //     return Err(AzureEkmErrorReply::internal_error(
    //         "Invalid RSA wrap algorithm",
    //     ));
    // }

    let encrypt_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        data: Some(dek_bytes.to_vec().into()),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
        i_v_counter_nonce: None,
    };

    let response = kms.encrypt(encrypt_request, user, None).await?;

    let wrapped_data = response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Encrypt response missing data"))?;

    Ok(wrapped_data)
}

#[derive(Debug, Deserialize)]
pub(crate) struct UnwrapKeyRequest {
    request_context: RequestContext,
    alg: WrapAlgorithm, // (A256KW, A256KWP, RSA-OAEP-256)
    value: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct UnwrapKeyResponse {
    value: String, // base64url encoded unwrapped DEK
}

#[post("/{key_name}/unwrapkey")]
pub(crate) async fn unwrap_key(
    req: HttpRequest,
    key_name: Path<String>,
    query: Query<AzureEkmQueryParams>,
    request: Json<UnwrapKeyRequest>,
    kms: Data<Arc<KMS>>,
) -> HttpResponse {
    let key_name = key_name.into_inner();
    let user = kms.get_user(&req);

    info!(
        "POST /ekm/{}/unwrapkey alg={} api-version={} user={}",
        key_name, request.alg, query.api_version, user
    );

    // Validate API version
    if let Err(e) = validate_api_version(&query.api_version) {
        return e.into();
    }

    // Call inner implementation
    match unwrap_key_handler(&kms, &key_name, &user, request.into_inner()).await {
        Ok(response) => HttpResponse::Ok().json(response),
        Err(e) => e.into(),
    }
}

async fn unwrap_key_handler(
    kms: &KMS,
    key_name: &str,
    user: &str,
    request: UnwrapKeyRequest,
) -> Result<UnwrapKeyResponse, AzureEkmErrorReply> {
    let wrapped_dek_bytes = URL_SAFE_NO_PAD.decode(&request.value).map_err(|_| {
        AzureEkmErrorReply::invalid_request("Invalid base64url encoding in 'value' field")
    })?;

    let unwrapping_key_object = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
                ..Default::default()
            },
            user,
            None,
        )
        .await
        .map_err(|e| match e {
            KmsError::ItemNotFound(_) => AzureEkmErrorReply::key_not_found(key_name),
            _ => e.into(),
        })?
        .object;
    match &unwrapping_key_object {
        Object::SymmetricKey(_) | Object::PrivateKey(_) => {}
        _ => {
            return Err(AzureEkmErrorReply::operation_not_allowed(
                "unwrapkey",
                key_name,
            ));
        }
    }

    let key_block = unwrapping_key_object.key_block()?;
    let key_algorithm = key_block.cryptographic_algorithm().ok_or_else(|| {
        AzureEkmErrorReply::internal_error("Unwrapping key has no cryptographic algorithm")
    })?;

    validate_wrapping_algorithm(&request.alg, &key_algorithm)?;

    let unwrapped_dek_bytes = match key_algorithm {
        CryptographicAlgorithm::AES => {
            unwrap_with_aes(kms, key_name, user, &wrapped_dek_bytes, &request.alg).await?
        }
        CryptographicAlgorithm::RSA => {
            unwrap_with_rsa(kms, key_name, user, &wrapped_dek_bytes, &request.alg).await?
        }
        _ => {
            return Err(AzureEkmErrorReply::internal_error(format!(
                "Unsupported key algorithm: {:?}",
                key_algorithm
            )));
        }
    };
    let unwrapped_base64url = URL_SAFE_NO_PAD.encode(&unwrapped_dek_bytes);
    Ok(UnwrapKeyResponse {
        value: unwrapped_base64url,
    })
}
async fn unwrap_with_aes(
    _kms: &KMS,
    _key_name: &str,
    _user: &str,
    _wrapped_dek_bytes: &[u8],
    _alg: &WrapAlgorithm,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    todo!("Implement unwrap_with_aes function")
}

async fn unwrap_with_rsa(
    _kms: &KMS,
    _key_name: &str,
    _user: &str,
    _wrapped_dek_bytes: &[u8],
    _alg: &WrapAlgorithm,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    todo!("Implement unwrap_with_rsa function")
}
