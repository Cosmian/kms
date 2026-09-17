use std::sync::Arc;

use actix_web::{HttpResponse, web::Data};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_data_structures::KeyMaterial,
        kmip_objects::Object,
        kmip_operations::{Decrypt, Encrypt, Get},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
};
use zeroize::Zeroizing;

use crate::{
    core::KMS,
    error::KmsError,
    middlewares::UserId,
    result::KResult,
    routes::{
        azure_ekm::{
            SUPPORTED_RSA_LENGTHS,
            error::AzureEkmErrorReply,
            models::{
                KeyMetadataResponse, UnwrapKeyRequest, UnwrapKeyResponse, WrapAlgorithm,
                WrapKeyRequest, WrapKeyResponse,
            },
        },
        utils::get_rsa_key_metadata_from_public_key,
    },
};

const AZURE_EKM_REQUIRED_AES_KEY_LENGTH: i32 = 256;

pub(crate) async fn get_key_metadata_handler(
    key_name: String,
    user: UserId,
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
                            if key_length == AZURE_EKM_REQUIRED_AES_KEY_LENGTH {
                                Ok(HttpResponse::Ok().json(KeyMetadataResponse::aes()))
                            } else {
                                // It's indeed uncommon to see an error wrapped in an Ok() - this was done in purpose to reduce useless conversions
                                // Returning an Err() will be interpreted as an internal server error by the caller, which is not what we want here
                                // since the key exists but its length is unsupported. The specs is not very clear on this particular case.
                                Ok(AzureEkmErrorReply::operation_not_allowed(
                                    &format!(
                                        "AES key has length {key_length}, only {AZURE_EKM_REQUIRED_AES_KEY_LENGTH} is supported for now."
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

                            let (mod_bytes, exp_bytes) =
                                if let KeyMaterial::TransparentRSAPrivateKey {
                                    modulus: m,
                                    public_exponent: Some(pe),
                                    ..
                                } = key_material
                                {
                                    (m.to_bytes_be().1, pe.to_bytes_be().1)
                                } else {
                                    let (m, e) = get_rsa_key_metadata_from_public_key(
                                        &kms, &key_name, &user,
                                    )
                                    .await?;
                                    (m.to_bytes_be().1, e.to_bytes_be().1)
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

/// Retrieve and validate a wrapping/unwrapping key from KMS (the kek)
/// Simply refactored because we need it in both wrap and unwrap handlers
///
/// Returns the cryptographic algorithm after validation
async fn get_and_validate_kek_algorithm(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
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
            let key_length = key_object
                .key_block()
                .map_err(KmsError::from)?
                .cryptographic_length
                .ok_or_else(|| {
                    AzureEkmErrorReply::internal_error("Key has no cryptographic length.")
                })?;
            if key_length != AZURE_EKM_REQUIRED_AES_KEY_LENGTH {
                return Err(AzureEkmErrorReply::invalid_request(format!(
                    "AES KEK must be {AZURE_EKM_REQUIRED_AES_KEY_LENGTH} bits, found {key_length} bits"
                )));
            }
            Ok(kek_algorithm)
        }
        (CryptographicAlgorithm::RSA, WrapAlgorithm::RsaOaep256 | WrapAlgorithm::RsaOaep) => {
            Ok(kek_algorithm)
        }
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
    user: &UserId,
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
        WrapAlgorithm::RsaOaep256 | WrapAlgorithm::RsaOaep => {
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
            // RSA-OAEP wrap using KMIP Encrypt operation
            let hashing_algorithm = match request.alg {
                WrapAlgorithm::RsaOaep => HashingAlgorithm::SHA1,
                _ => HashingAlgorithm::SHA256,
            };
            wrap_with_rsa(
                kms,
                key_name,
                user,
                dek_bytes,
                hashing_algorithm,
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

/// Pivot: encrypt `dek_bytes` with the key identified by `key_uid` using KMIP Encrypt.
///
/// Both `wrap_with_aes` and `wrap_with_rsa` share this pattern — they differ only in
/// the `key_uid` (the AES key uses the name as-is; RSA appends `"_pk"`) and the
/// `crypto_params` (AES uses `block_cipher_mode`; RSA uses algorithm/padding/hash).
async fn kmip_encrypt_dek(
    kms: &KMS,
    key_uid: String,
    user: &UserId,
    dek_bytes: Zeroizing<Vec<u8>>,
    crypto_params: CryptographicParameters,
    correlation_id: String,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    let encrypt_request = Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid)),
        cryptographic_parameters: Some(crypto_params),
        data: Some(dek_bytes),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };
    let response = kms.encrypt(encrypt_request, user).await?;
    response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Encrypt response missing data."))
}

async fn wrap_with_aes(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
    dek_bytes: Zeroizing<Vec<u8>>,
    alg: &WrapAlgorithm,
    correlation_id: String,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    let block_cipher_mode = match alg {
        WrapAlgorithm::A256KWP => BlockCipherMode::AESKeyWrapPadding,
        WrapAlgorithm::A256KW => BlockCipherMode::NISTKeyWrap,
        WrapAlgorithm::RsaOaep256 | WrapAlgorithm::RsaOaep => {
            return Err(AzureEkmErrorReply::invalid_request(
                "Invalid AES wrap algorithm",
            ));
        }
    };
    kmip_encrypt_dek(
        kms,
        key_name.to_owned(),
        user,
        dek_bytes,
        CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            ..Default::default()
        },
        correlation_id,
    )
    .await
}

/// Wrap DEK with RSA public key using KMIP Encrypt (OAEP padding)
///
/// `hashing_algorithm` selects the OAEP hash: `SHA256` for `RSA-OAEP-256`, `SHA1` for `RSA-OAEP`.
async fn wrap_with_rsa(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
    dek_bytes: Zeroizing<Vec<u8>>,
    hashing_algorithm: HashingAlgorithm,
    correlation_id: String,
) -> Result<Vec<u8>, AzureEkmErrorReply> {
    kmip_encrypt_dek(
        kms,
        format!("{key_name}_pk"),
        user,
        dek_bytes,
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(hashing_algorithm),
            ..Default::default()
        },
        correlation_id,
    )
    .await
}

pub(crate) async fn unwrap_key_handler(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
    request: UnwrapKeyRequest,
) -> Result<UnwrapKeyResponse, AzureEkmErrorReply> {
    let wrapped_dek_bytes = URL_SAFE_NO_PAD.decode(&request.value).map_err(|e| {
        AzureEkmErrorReply::invalid_request(format!(
            "Invalid base64url encoding in 'value' field: {e}"
        ))
    })?;

    if wrapped_dek_bytes.is_empty() {
        return Err(AzureEkmErrorReply::invalid_request(
            "Cannot unwrap empty data",
        ));
    }
    // No other length validation here: Invalid lengths produce clean crypto errors.

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
            let hashing_algorithm = match request.alg {
                WrapAlgorithm::RsaOaep => HashingAlgorithm::SHA1,
                _ => HashingAlgorithm::SHA256,
            };
            unwrap_with_rsa(
                kms,
                key_name,
                user,
                wrapped_dek_bytes,
                hashing_algorithm,
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

/// Pivot: decrypt `data` with the key identified by `key_uid` using KMIP Decrypt.
///
/// Both `unwrap_with_aes` and `unwrap_with_rsa` share this pattern — they differ only in
/// the `crypto_params` (AES uses `block_cipher_mode`; RSA uses algorithm/padding/hash).
async fn kmip_decrypt_dek(
    kms: &KMS,
    key_uid: String,
    user: &UserId,
    data: Vec<u8>,
    crypto_params: CryptographicParameters,
    correlation_id: String,
) -> Result<Zeroizing<Vec<u8>>, AzureEkmErrorReply> {
    let decrypt_request = Decrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid)),
        cryptographic_parameters: Some(crypto_params),
        data: Some(data),
        correlation_value: Some(correlation_id.into_bytes()),
        ..Default::default()
    };
    let response = kms.decrypt(decrypt_request, user).await?;
    response
        .data
        .ok_or_else(|| AzureEkmErrorReply::internal_error("Decrypt response missing data."))
}

async fn unwrap_with_aes(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
    wrapped_dek_bytes: Vec<u8>,
    alg: &WrapAlgorithm,
    correlation_id: String,
) -> Result<Zeroizing<Vec<u8>>, AzureEkmErrorReply> {
    let block_cipher_mode = match alg {
        WrapAlgorithm::A256KWP => BlockCipherMode::AESKeyWrapPadding,
        WrapAlgorithm::A256KW => BlockCipherMode::NISTKeyWrap,
        WrapAlgorithm::RsaOaep256 | WrapAlgorithm::RsaOaep => {
            return Err(AzureEkmErrorReply::invalid_request(
                "Invalid AES wrap algorithm",
            ));
        }
    };
    kmip_decrypt_dek(
        kms,
        key_name.to_owned(),
        user,
        wrapped_dek_bytes,
        CryptographicParameters {
            block_cipher_mode: Some(block_cipher_mode),
            ..Default::default()
        },
        correlation_id,
    )
    .await
}

/// Unwrap DEK with RSA private key using KMIP Decrypt (OAEP padding)
///
/// `hashing_algorithm` selects the OAEP hash: `SHA256` for `RSA-OAEP-256`, `SHA1` for `RSA-OAEP`.
async fn unwrap_with_rsa(
    kms: &KMS,
    key_name: &str,
    user: &UserId,
    wrapped_dek_bytes: Vec<u8>,
    hashing_algorithm: HashingAlgorithm,
    correlation_id: String,
) -> Result<Zeroizing<Vec<u8>>, AzureEkmErrorReply> {
    kmip_decrypt_dek(
        kms,
        key_name.to_owned(),
        user,
        wrapped_dek_bytes,
        CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(hashing_algorithm),
            ..Default::default()
        },
        correlation_id,
    )
    .await
}
