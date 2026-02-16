#![allow(clippy::panic)]

use actix_web::{HttpResponse, web::Data};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::KeyWrapType,
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::KeyFormatType,
    kmip_2_1::{
        kmip_data_structures::{KeyBlock, KeyMaterial},
        kmip_objects::Object,
        kmip_operations::{Decrypt, Encrypt, Get},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, LinkType::PublicKeyLink,
            UniqueIdentifier,
        },
    },
};
use cosmian_logger::trace;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    error::KmsError,
    result::KResult,
    routes::azure_ekm::{
        SUPPORTED_RSA_LENGTHS,
        error::AzureEkmErrorReply,
        models::{
            KeyMetadataResponse, UnwrapKeyRequest, UnwrapKeyResponse, WrapAlgorithm,
            WrapKeyRequest, WrapKeyResponse,
        },
    },
};

#[allow(clippy::manual_let_else)] // debug
pub(crate) async fn get_key_metadata_handler(
    key_name: String,
    user: String,
    kms: Data<Arc<KMS>>,
) -> KResult<HttpResponse> {
    let get_request = Get {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.clone())),
        ..Default::default()
    };
    match kms.get(get_request, &user).await {
        Ok(resp) => {
            match resp.object {
                Object::SymmetricKey(_) | Object::PublicKey(_) | Object::PrivateKey(_) => {
                    let object = resp.object;

                    let key_block = object.key_block()?;

                    let algorithm = key_block.cryptographic_algorithm().ok_or_else(|| {
                        KmsError::ServerError("Cryptographic algorithm not set.".to_owned())
                    })?;
                    let key_length = key_block
                        .cryptographic_length
                        .ok_or_else(|| KmsError::ServerError("Key length not set.".to_owned()))?;
                    // Check algorithm and build response
                    match algorithm {
                        CryptographicAlgorithm::AES => {
                            if key_length == 256 {
                                Ok(HttpResponse::Ok().json(KeyMetadataResponse::aes()))
                            } else {
                                // It's indeed uncommon to see an error wrapped in an Ok() - this was done in purpose to reduce useless conversions
                                // Returning an Err() will be interpreted as an internal server error by the caller, which is not what we want here
                                // since the key exists but its length is unsupported. The specs is not very clear on this particular case.
                                Ok(AzureEkmErrorReply::operation_not_allowed(
                                    &format!(
                                        "AES key has length {key_length}, only 256 is supported for now."
                                    ),
                                    &key_name,
                                )
                                .into())
                            }
                        }
                        CryptographicAlgorithm::RSA => {
                            if !SUPPORTED_RSA_LENGTHS.contains(&key_length) {
                                return Ok(AzureEkmErrorReply::operation_not_allowed(
                                    &format!(
                                        "RSA key has length {key_length}. Only {SUPPORTED_RSA_LENGTHS:?} are supported for now.",
                                    ),
                                    &key_name,
                                )
                                .into());
                            }
                            let key_material = key_block.key_material()?;

                            let (mod_bytes, exp_bytes) = match key_material {
                                // In the best case, the private key contains both modulus and public exponent, and we can directly return them
                                KeyMaterial::TransparentRSAPrivateKey {
                                    modulus: m,
                                    public_exponent: Some(pe),
                                    ..
                                } => (m.to_bytes_be().1, pe.to_bytes_be().1),
                                // However, like in the ms dke route, we will most likely fallback to fetching them from the associated public key
                                _ => {
                                    get_rsa_key_metadata_from_public_key(&kms, &key_name, &user)
                                        .await?
                                }
                            };

                            let n_base64url = URL_SAFE_NO_PAD.encode(&mod_bytes);
                            let e_base64url = URL_SAFE_NO_PAD.encode(&exp_bytes);

                            Ok(HttpResponse::Ok().json(KeyMetadataResponse::rsa(
                                key_length,
                                n_base64url,
                                e_base64url,
                            )))
                        }
                        _ => Err(KmsError::ServerError(format!(
                            "Unsupported key algorithm: {algorithm:?}. Only AES and RSA are supported"
                        ))),
                    }
                }
                _ => Ok(AzureEkmErrorReply::operation_not_allowed("metadata", &key_name).into()),
            }
        }
        Err(e) => {
            if (matches!(e, KmsError::ItemNotFound(_)) || e.to_string().contains("not found")) {
                return Ok(AzureEkmErrorReply::key_not_found(&key_name).into()); // as required by Azure EKM specs
            }
            if matches!(e, KmsError::Unauthorized(_)) {
                return Ok(AzureEkmErrorReply::unauthorized(&key_name).into());
            }
            // Otherwise, it's an internal error
            Ok(AzureEkmErrorReply::internal_error(format!("Failed to retrieve key: {e}")).into())
        }
    }
}

/// Extract RSA public key metadata (modulus and exponent) for Azure EKM response
async fn get_rsa_key_metadata_from_public_key(
    kms: &KMS,
    key_name: &str,
    user: &str,
) -> KResult<(Vec<u8>, Vec<u8>)> {
    let public_key_name = format!("{key_name}_pk");
    trace!(
        "Fetching public key: {public_key_name} and attempting to extract RSA modulus and public exponent from key material"
    );
    let public_key_response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(public_key_name.clone())),
                key_format_type: Some(KeyFormatType::TransparentRSAPublicKey),
                key_wrap_type: Some(KeyWrapType::NotWrapped),
                ..Default::default()
            },
            user,
        )
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to retrieve public key {public_key_name}: {e}"
            ))
        })?;

    let pub_key_block = public_key_response.object.key_block()?;
    let key_material = pub_key_block.key_material()?;

    match key_material {
        KeyMaterial::TransparentRSAPublicKey {
            modulus,
            public_exponent,
        } => {
            let mod_bytes = modulus.to_bytes_be().1;
            let exp_bytes = public_exponent.to_bytes_be().1;

            Ok((mod_bytes, exp_bytes))
        }
        _ => Err(KmsError::ServerError(
            "Public key does not contain RSA public key material".to_owned(),
        )),
    }
}

/// Retrieve and validate a wrapping/unwrapping key from KMS (the kek)
/// Simply refactored because we need it in both wrap and unwrap handlers
///
/// Returns the cryptographic algorithm after validation
async fn get_and_validate_kek_algorithm(
    kms: &KMS,
    key_name: &str,
    user: &str,
    request_alg: &WrapAlgorithm,
) -> Result<CryptographicAlgorithm, AzureEkmErrorReply> {
    let key_object = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
                ..Default::default()
            },
            user,
        )
        .await
        .map_err(|e| match e {
            KmsError::ItemNotFound(_) => AzureEkmErrorReply::key_not_found(key_name),
            _ => e.into(),
        })?
        .object;

    let kek_algorithm = *key_object
        .key_block()
        .map_err(KmsError::from)?
        .cryptographic_algorithm()
        .ok_or_else(|| {
            AzureEkmErrorReply::internal_error("Key has no cryptographic algorithm set".to_owned())
        })?;

    // According to KMS docs, if the algorithm is present the length is also present, so if we reach this line, there is no more error risk
    match (&kek_algorithm, request_alg) {
        (CryptographicAlgorithm::AES, WrapAlgorithm::A256KW | WrapAlgorithm::A256KWP) => {
            // Specs mention only the usage of 256 bits keys
            let key_length = key_object
                .key_block()
                .map_err(KmsError::from)?
                .cryptographic_length
                .ok_or_else(|| {
                    AzureEkmErrorReply::internal_error("Key has no cryptographic length.")
                })?;
            if key_length != 256 {
                return Err(AzureEkmErrorReply::invalid_request(format!(
                    "AES KEK must be 256 bits, found {key_length} bits"
                )));
            }
            Ok(kek_algorithm)
        }
        (CryptographicAlgorithm::RSA, WrapAlgorithm::RsaOaep256) => Ok(kek_algorithm),
        (CryptographicAlgorithm::AES, _) => Err(AzureEkmErrorReply::unsupported_algorithm(
            &format!("{request_alg:?}"),
            "AES",
        )),
        (CryptographicAlgorithm::RSA, _) => Err(AzureEkmErrorReply::unsupported_algorithm(
            &format!("{request_alg:?}"),
            "RSA",
        )),
        _ => Err(AzureEkmErrorReply::internal_error(format!(
            "Unsupported key algorithm: {kek_algorithm:?}",
        ))),
    }
}

pub(crate) async fn wrap_key_handler(
    kms: &KMS,
    key_name: &str,
    user: &str,
    request: WrapKeyRequest,
) -> Result<WrapKeyResponse, AzureEkmErrorReply> {
    // Decode the input key from base64url
    let dek_bytes = Zeroizing::new(URL_SAFE_NO_PAD.decode(&request.value).map_err(|e| {
        AzureEkmErrorReply::invalid_request(format!(
            "Invalid base64url encoding in 'value' field : {e}"
        ))
    })?);

    // Validate input length - this is critical because the KMS panics if handed non valid data !
    if dek_bytes.is_empty() {
        return Err(AzureEkmErrorReply::invalid_request(
            "Cannot wrap empty key data",
        ));
    }
    match request.alg {
        WrapAlgorithm::A256KW | WrapAlgorithm::A256KWP => {
            // NIST Key Wrap requires at least 8 bytes (64 bits)
            if dek_bytes.len() < 8 {
                return Err(AzureEkmErrorReply::invalid_request(format!(
                    "Key data too short for AES Key Wrap: {} bytes (minimum 8 bytes required)",
                    dek_bytes.len()
                )));
            }
        }
        WrapAlgorithm::RsaOaep256 => {
            // We only check for reasonable bounds here
            if dek_bytes.len() > 512 {
                return Err(AzureEkmErrorReply::invalid_request(format!(
                    "Key data too large for RSA wrapping: {} bytes (maximum ~512 bytes)",
                    dek_bytes.len()
                )));
            }
        }
    }

    let kek_algorithm = get_and_validate_kek_algorithm(kms, key_name, user, &request.alg).await?;

    // Perform the wrap operation based on key type
    let wrapped_key_bytes = match kek_algorithm {
        CryptographicAlgorithm::AES => {
            // AES Key Wrap using KMIP Encrypt operation
            wrap_with_aes(
                kms,
                key_name,
                user,
                dek_bytes,
                &request.alg,
                request.request_context.correlation_id,
            )
            .await?
        }
        CryptographicAlgorithm::RSA => {
            // RSA-OAEP-256 wrap using KMIP Encrypt operation
            wrap_with_rsa(
                kms,
                key_name,
                user,
                dek_bytes,
                request.request_context.correlation_id,
            )
            .await?
        }
        _ => {
            return Err(AzureEkmErrorReply::internal_error(format!(
                "Unsupported key algorithm: {kek_algorithm:?}",
            )));
        }
    };

    // Encode wrapped key as base64url
    let wrapped_base64url = URL_SAFE_NO_PAD.encode(&wrapped_key_bytes);

    Ok(WrapKeyResponse {
        value: wrapped_base64url,
    })
}

async fn wrap_with_aes(
    kms: &KMS,
    key_name: &str,
    user: &str,
    dek_bytes: Zeroizing<Vec<u8>>,
    alg: &WrapAlgorithm,
    correlation_id: String, // for logging purposes
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    // Determine block cipher mode and IV/nonce based on algorithm
    let block_cipher_mode = match alg {
        WrapAlgorithm::A256KWP => BlockCipherMode::AESKeyWrapPadding,
        WrapAlgorithm::A256KW => BlockCipherMode::NISTKeyWrap,
        WrapAlgorithm::RsaOaep256 => {
            return Err(AzureEkmErrorReply::invalid_request(
                "Invalid AES wrap algorithm",
            ));
        }
    };

    let encrypt_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            ..Default::default()
        }),
        data: Some(dek_bytes),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };

    let response = kms.encrypt(encrypt_request, user).await?;

    let wrapped_data = response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Encrypt response missing data."))?;

    Ok(wrapped_data)
}

/// Wrap DEK with RSA public key using KMIP Encrypt (OAEP padding)
async fn wrap_with_rsa(
    kms: &KMS,
    key_name: &str,
    user: &str,
    dek_bytes: Zeroizing<Vec<u8>>,
    correlation_id: String, // for logging purposes
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    let encrypt_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(format!("{key_name}_pk"))),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        data: Some(dek_bytes),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };

    let response = kms.encrypt(encrypt_request, user).await?;

    let wrapped_data = response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Encrypt response missing data."))?;

    Ok(wrapped_data)
}

pub(crate) async fn unwrap_key_handler(
    kms: &KMS,
    key_name: &str,
    user: &str,
    request: UnwrapKeyRequest,
) -> Result<UnwrapKeyResponse, AzureEkmErrorReply> {
    let wrapped_dek_bytes = URL_SAFE_NO_PAD.decode(&request.value).map_err(|e| {
        AzureEkmErrorReply::invalid_request(format!(
            "Invalid base64url encoding in 'value' field: {e}"
        ))
    })?;

    let kek_algorithm = get_and_validate_kek_algorithm(kms, key_name, user, &request.alg).await?;

    let unwrapped_dek_bytes = match kek_algorithm {
        CryptographicAlgorithm::AES => {
            unwrap_with_aes(
                kms,
                key_name,
                user,
                wrapped_dek_bytes,
                &request.alg,
                request.request_context.correlation_id,
            )
            .await?
        }
        CryptographicAlgorithm::RSA => {
            unwrap_with_rsa(
                kms,
                key_name,
                user,
                wrapped_dek_bytes,
                request.request_context.correlation_id,
            )
            .await?
        }
        _ => {
            return Err(AzureEkmErrorReply::internal_error(format!(
                "Unsupported key algorithm: {kek_algorithm:?}",
            )));
        }
    };
    let unwrapped_base64url = URL_SAFE_NO_PAD.encode(&unwrapped_dek_bytes);
    Ok(UnwrapKeyResponse {
        value: unwrapped_base64url,
    })
}

async fn unwrap_with_aes(
    kms: &KMS,
    key_name: &str,
    user: &str,
    wrapped_dek_bytes: Vec<u8>,
    alg: &WrapAlgorithm,
    correlation_id: String, // for logging purposes
) -> Result<Zeroizing<Vec<u8>>, AzureEkmErrorReply> {
    let block_cipher_mode = match alg {
        WrapAlgorithm::A256KWP => BlockCipherMode::AESKeyWrapPadding,
        WrapAlgorithm::A256KW => BlockCipherMode::NISTKeyWrap,
        WrapAlgorithm::RsaOaep256 => {
            return Err(AzureEkmErrorReply::invalid_request(
                "Invalid AES wrap algorithm",
            ));
        }
    };

    let decrypt_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            ..Default::default()
        }),
        data: Some(wrapped_dek_bytes),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };

    let response = kms.decrypt(decrypt_request, user).await?;

    let unwrapped_data = response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Decrypt response missing data."))?;

    Ok(unwrapped_data)
}

/// Unwrap DEK with RSA private key using KMIP Decrypt (OAEP padding)
async fn unwrap_with_rsa(
    kms: &KMS,
    key_name: &str,
    user: &str,
    wrapped_dek_bytes: Vec<u8>,
    correlation_id: String, // for logging purposes
) -> Result<Zeroizing<Vec<u8>>, AzureEkmErrorReply> {
    let decrypt_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_name.to_owned())),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        data: Some(wrapped_dek_bytes),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };

    let response = kms.decrypt(decrypt_request, user).await?;

    let unwrapped_data = response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Decrypt response missing data."))?;

    Ok(unwrapped_data)
}

/// If the public exponent is missing from the private key, fetch it from a linked RSA public key
#[allow(dead_code)]
async fn get_public_exponent_from_linked_key(
    key_block: &KeyBlock,
    user: &str,
    kms: &KMS,
) -> KResult<Box<num_bigint_dig::BigInt>> {
    let public_key_id = key_block
        .get_linked_object_id(PublicKeyLink)?
        .ok_or_else(|| {
            KmsError::ServerError(
                "RSA private key has no linked public key to get public exponent from.".to_owned(),
            )
        })?;

    let public_key_response = kms
        .get(
            Get {
                unique_identifier: Some(UniqueIdentifier::TextString(public_key_id)),
                ..Default::default()
            },
            user,
        )
        .await?;

    match public_key_response.object {
        Object::PublicKey(pub_key) => match pub_key.key_block.key_material()? {
            KeyMaterial::TransparentRSAPublicKey {
                public_exponent, ..
            } => Ok(public_exponent.clone()),
            _ => Err(KmsError::ServerError(
                "Failed to retrieve public exponent from linked public key".to_owned(),
            )),
        },
        _ => Err(KmsError::ServerError(
            "Failed to retrieve public exponent from linked public key".to_owned(),
        )),
    }
}
