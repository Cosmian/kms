use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::CryptographicUsageMask,
        kmip_2_1::{
            KmipOperation,
            kmip_objects::{Object, ObjectType},
            kmip_operations::{SignatureVerify, SignatureVerifyResponse},
            kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
        },
    },
    cosmian_kms_crypto::{
        crypto::{
            elliptic_curves::verify::{ecdsa_verify, ed_verify},
            rsa::{default_cryptographic_parameters, verify::rsa_verify},
        },
        openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{debug, trace};
use openssl::pkey::{Id, PKey, Public};

use crate::{
    core::{
        KMS,
        operations::{CryptoOpSpec, KeysetMode, has_usage_mask, perform_crypto_operation},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Marker type for the `SignatureVerify` operation's key selection requirements.
pub(crate) struct SignatureVerifyOp;

impl CryptoOpSpec for SignatureVerifyOp {
    type Request = SignatureVerify;
    type Response = SignatureVerifyResponse;

    const KMIP_OP: KmipOperation = KmipOperation::SignatureVerify;
    const OP_NAME: &'static str = "SignatureVerify";

    fn unique_identifier(request: &Self::Request) -> Option<&UniqueIdentifier> {
        request.unique_identifier.as_ref()
    }

    fn keyset_mode() -> KeysetMode {
        KeysetMode::TryEach
    }

    fn usage_data_len(request: &Self::Request) -> usize {
        request
            .data
            .as_ref()
            .map_or(0, Vec::len)
            .max(request.digested_data.as_ref().map_or(0, Vec::len))
    }

    fn is_key_eligible(owm: &ObjectWithMetadata, _vendor_id: &str) -> bool {
        match owm.object() {
            // Accept both public and private keys for verification.
            // Private keys are supported for imported keys that may lack a paired public key;
            // the public component is extracted at execution time.
            // Use Verify mask with lenient=true so imported keys without an explicit mask
            // still work.
            Object::PublicKey { .. } | Object::PrivateKey { .. } => {
                has_usage_mask(owm, CryptographicUsageMask::Verify, true)
            }
            _ => false,
        }
    }

    async fn execute_local(
        _kms: &KMS,
        owm: &ObjectWithMetadata,
        request: &Self::Request,
        _user: &str,
    ) -> KResult<Self::Response> {
        let verification_key = extract_verification_key(owm.object())?;

        // Resolve cryptographic parameters: prefer request values, but fall back to
        // the stored key Attributes when the request omits them.
        let effective_crypto_params = CryptographicParameters::merged_with_object(
            request.cryptographic_parameters.clone(),
            owm.object(),
        );

        // Handle streaming verification
        if request.init_indicator == Some(true) || request.correlation_value.is_some() {
            return handle_streaming_verification(request, owm.id().to_owned(), &verification_key);
        }

        // For final verification, signature_data is required
        let signature_data = request
            .signature_data
            .as_ref()
            .ok_or_else(|| KmsError::InvalidRequest("Missing signature_data".to_owned()))?;

        // Validate input data
        let data_to_verify = match (&request.data, &request.digested_data) {
            (Some(data), None) => data.clone(),
            (None, Some(digested_data)) => digested_data.clone(),
            (Some(_), Some(_)) => {
                return Err(KmsError::InvalidRequest(
                    "Cannot provide both data and digested_data".to_owned(),
                ));
            }
            (None, None) => {
                return Err(KmsError::InvalidRequest(
                    "Must provide either data or digested_data".to_owned(),
                ));
            }
        };

        let crypto_params = effective_crypto_params;
        debug!(
            "signature_verify: effective CP => alg={:?} pad={:?} hash={:?} dsa={:?} mgf1_hash={:?}",
            crypto_params.cryptographic_algorithm,
            crypto_params.padding_method,
            crypto_params.hashing_algorithm,
            crypto_params.digital_signature_algorithm,
            crypto_params.mask_generator_hashing_algorithm
        );

        // ML-DSA: check the key's algorithm; if PQC, use ml_dsa_verify directly
        #[cfg(feature = "non-fips")]
        {
            if owm
                .resolve_key_algorithm()
                .is_some_and(|a| a.is_pqc_signature())
            {
                use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::pqc::ml_dsa::ml_dsa_verify;
                let valid = ml_dsa_verify(&verification_key, &data_to_verify, signature_data)?;
                let vi = if valid {
                    ValidityIndicator::Valid
                } else {
                    ValidityIndicator::Invalid
                };
                return Ok(SignatureVerifyResponse {
                    unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
                    validity_indicator: Some(vi),
                    data: None,
                    correlation_value: request.correlation_value.clone(),
                });
            }
        }

        let validity_indicator = verify_signature(
            &verification_key,
            &data_to_verify,
            signature_data,
            &crypto_params,
            request.digested_data.is_some(),
        )?;

        debug!("Signature verification result: {validity_indicator:?}");

        Ok(SignatureVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
            validity_indicator: Some(validity_indicator),
            data: None,
            correlation_value: request.correlation_value.clone(),
        })
    }

    async fn execute_oracle(
        kms: &KMS,
        request: &Self::Request,
        uid: &str,
        prefix: &str,
    ) -> KResult<Self::Response> {
        let data: &[u8] = request
            .data
            .as_deref()
            .or(request.digested_data.as_deref())
            .ok_or_else(|| {
                KmsError::InvalidRequest(
                    "SignatureVerify: must provide data or digested_data".to_owned(),
                )
            })?;
        let signature = request.signature_data.as_deref().ok_or_else(|| {
            KmsError::InvalidRequest("SignatureVerify: missing signature_data".to_owned())
        })?;
        let lock = kms.crypto_oracles.read().await;
        let crypto_oracle = lock.get(prefix).ok_or_else(|| {
            KmsError::InvalidRequest(format!(
                "SignatureVerify: unknown crypto oracle prefix: {prefix}"
            ))
        })?;
        let valid = crypto_oracle
            .signature_verify(
                uid,
                data,
                signature,
                request.cryptographic_parameters.as_ref(),
            )
            .await?;
        Ok(SignatureVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(uid.to_owned()),
            validity_indicator: Some(if valid {
                ValidityIndicator::Valid
            } else {
                ValidityIndicator::Invalid
            }),
            data: None,
            correlation_value: request.correlation_value.clone(),
        })
    }
}

pub(crate) async fn signature_verify(
    kms: &KMS,
    request: SignatureVerify,
    user: &str,
) -> KResult<SignatureVerifyResponse> {
    trace!("{request}");

    // Validate streaming indicators
    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        return Err(KmsError::InvalidRequest(
            "Invalid request: init_indicator and final_indicator cannot both be true".to_owned(),
        ));
    }

    Box::pin(perform_crypto_operation::<SignatureVerifyOp>(
        kms, request, user,
    ))
    .await
}

/// Extract the verification key from a managed object.
///
/// # Arguments
///
/// * `object` - The managed object that should contain a verification key.
///
/// # Returns
///
/// A `KResult` containing the extracted public key for verification.
///
/// # Errors
///
/// Returns an error if the object is not a valid key type for verification.
fn extract_verification_key(object: &Object) -> KResult<PKey<Public>> {
    match object.object_type() {
        ObjectType::PublicKey => Ok(kmip_public_key_to_openssl(object)?),
        ObjectType::PrivateKey => {
            // Extract the public component from a private key (covers imported keys
            // that have no paired public key object in the store).
            let pkey = kmip_private_key_to_openssl(object)?;
            // openssl PKey<Private> can be converted to its public component via raw bytes
            let pub_der = pkey.public_key_to_der()?;
            Ok(PKey::public_key_from_der(&pub_der)?)
        }
        _ => Err(KmsError::InvalidRequest(format!(
            "Object type {} is not valid for signature verification",
            object.object_type()
        ))),
    }
}

/// Perform the actual signature verification.
///
/// # Arguments
///
/// * `verification_key` - The public key to use for verification.
/// * `data` - The data that was signed.
/// * `signature` - The signature to verify.
/// * `crypto_params` - The cryptographic parameters specifying algorithms.
/// * `is_digested` - Whether the data is already digested.
///
/// # Returns
///
/// A `KResult` containing the validity indicator.
///
/// # Errors
///
/// Returns an error if the verification process fails due to cryptographic errors.
fn verify_signature(
    verification_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
    crypto_params: &CryptographicParameters,
    is_digested: bool,
) -> KResult<ValidityIndicator> {
    let res = match verification_key.id() {
        Id::RSA => rsa_verify(
            verification_key,
            data,
            signature,
            crypto_params,
            is_digested,
        ),
        Id::EC => ecdsa_verify(
            verification_key,
            data,
            signature,
            crypto_params,
            is_digested,
        ),
        Id::ED25519 | Id::ED448 => ed_verify(verification_key, data, signature),
        _ => kms_bail!(KmsError::NotSupported(format!(
            "verify_signature: key type not supported: {:?}",
            verification_key.id()
        ))),
    }?;
    Ok(res)
}

/// Handle streaming signature verification operations.
///
/// # Arguments
///
/// * `request` - The signature verification request with streaming indicators.
/// * `unique_identifier` - The unique identifier of the verification key.
/// * `verification_key` - The public key to use for verification.
///
/// # Returns
///
/// A `KResult` containing a `SignatureVerifyResponse` for streaming operations.
fn handle_streaming_verification(
    request: &SignatureVerify,
    unique_identifier: String,
    verification_key: &PKey<Public>,
) -> KResult<SignatureVerifyResponse> {
    // Extract cryptographic parameters (no key Attributes available in this helper),
    // defaulting when omitted. For multi-part flows, callers should ensure consistency
    // across calls if parameters are required.
    let crypto_params = request.cryptographic_parameters.clone().unwrap_or_default();
    let (_, _, _, _signature_algorithm) = default_cryptographic_parameters(Some(&crypto_params));

    // For streaming, we need to maintain state in correlation_value
    let correlation_data = if let Some(correlation_value) = &request.correlation_value {
        correlation_value.clone()
    } else if request.init_indicator == Some(true) {
        // Initial call - create new verifier state
        Vec::new()
    } else {
        return Err(KmsError::InvalidRequest(
            "Correlation value required for non-initial streaming operations".to_owned(),
        ));
    };

    // Get data to process
    let data_to_process = match (&request.data, &request.digested_data) {
        (Some(data), None) => data.clone(),
        (None, Some(digested_data)) => digested_data.clone(),
        (Some(_), Some(_)) => {
            return Err(KmsError::InvalidRequest(
                "Cannot provide both data and digested_data".to_owned(),
            ));
        }
        (None, None) if request.final_indicator == Some(true) => {
            // Final call may have no data if all data was processed in previous calls
            Vec::new()
        }
        (None, None) => {
            return Err(KmsError::InvalidRequest(
                "Must provide either data or digested_data".to_owned(),
            ));
        }
    };

    if request.final_indicator == Some(true) {
        // Final call - perform verification
        let signature_data = request.signature_data.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest("Missing signature_data for final verification".to_owned())
        })?;

        // Combine all accumulated data with current data
        let mut all_data = correlation_data;
        all_data.extend_from_slice(&data_to_process);

        let validity_indicator = verify_signature(
            verification_key,
            &all_data,
            signature_data,
            &crypto_params,
            request.digested_data.is_some(),
        )?;

        Ok(SignatureVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(unique_identifier),
            validity_indicator: Some(validity_indicator),
            data: None,
            correlation_value: None, // No correlation value needed for final response
        })
    } else {
        // Intermediate call - accumulate data
        let mut accumulated_data = correlation_data;
        accumulated_data.extend_from_slice(&data_to_process);

        Ok(SignatureVerifyResponse {
            unique_identifier: UniqueIdentifier::TextString(unique_identifier),
            validity_indicator: None, // No verification result until final call
            data: None,
            correlation_value: Some(accumulated_data),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use hex::FromHex;
    use openssl::{hash::MessageDigest, rsa::Padding, sign::Verifier};

    use super::*;

    #[test]
    fn verify_cs_ac_m_2_21_step1_openssl() {
        // Public key from XML (PKCS1 DER, hex-encoded)
        let pk_hex = "3082010a0282010100ab7f161c0042496ccd6c6d4dadb919973435357776003acf54b7af1e440afb80b64a8755f8002cfeba6b184540a2d66086d74648346d75b8d71812b205387c0f6583bc4d7dc7ec114f3b176b7957c422e7d03fc6267fa2a6f89b9bee9e60a1d7c2d833e5a5f4bb0b1434f4e795a41100f8aa214900df8b65089f98135b1c67b701675abdbc7d5721aac9d14a7f081fcec80b64e8a0ecc8295353c795328abf70e1b42e7bb8b7f4e8ac8c810cdb66e3d21126eba8da7d0ca34142cb76f91f013da809e9c1b7ae64c54130fbc21d80e9c2cb06c5c8d7cce8946a9ac99b1c2815c3612a29a82d73a1f99374fe30e54951662a6eda29c6fc411335d5dc7426b0f6050203010001";
        let sig_hex = "2925ebf8c6c9d0585c36a44491dd28f8ffd1098d2275a505a0eba7af452e9496472fd5c4a515d1c0db16c7c59ef76863b571cbf498fb8178ffeb75667e6e51b9b9bbf09d55bba54b42acb947aa5a81dc62751727d7cad4616c0c0bf1dd666f8266f24262c5fa9cbbdc424ef5f5e345e633d111e66eb4afc4001bb02e158b2d5d4573c614655f21a688bee0e9dbde6a58324c08f42ae69697e0c51803f9de6b3df242d2915d9b1a8110ad28143ab7855ef92ede48971b484172de3b0b8957f493a74b3372ee2200f2233607735f90d0b180968ab20d74841fd3dba4fb1f225ea5c6c87f99c2a238db72a536e68be202a092cd032337d451477e568f9a48b638cb";
        let data = <[u8; 16]>::from_hex("01020304050607080910111213141516").unwrap();

        let pk_der = Vec::from_hex(pk_hex).unwrap();
        let sig = Vec::from_hex(sig_hex).unwrap();

        let rsa = openssl::rsa::Rsa::public_key_from_der_pkcs1(&pk_der).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        // Try SHA-256, MGF1=SHA-256, saltlen=DIGEST_LENGTH
        let mut v = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        v.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
        v.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
        if !v.verify_oneshot(&sig, &data).unwrap() {
            let mut v2 = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
            v2.set_rsa_padding(Padding::PKCS1_PSS).unwrap();
            v2.set_rsa_mgf1_md(MessageDigest::sha1()).unwrap();
            assert!(v2.verify_oneshot(&sig, &data).unwrap());
        }
    }

    #[test]
    fn verify_cs_ac_m_2_21_step1_kms_path() {
        let pk_hex = "3082010a0282010100ab7f161c0042496ccd6c6d4dadb919973435357776003acf54b7af1e440afb80b64a8755f8002cfeba6b184540a2d66086d74648346d75b8d71812b205387c0f6583bc4d7dc7ec114f3b176b7957c422e7d03fc6267fa2a6f89b9bee9e60a1d7c2d833e5a5f4bb0b1434f4e795a41100f8aa214900df8b65089f98135b1c67b701675abdbc7d5721aac9d14a7f081fcec80b64e8a0ecc8295353c795328abf70e1b42e7bb8b7f4e8ac8c810cdb66e3d21126eba8da7d0ca34142cb76f91f013da809e9c1b7ae64c54130fbc21d80e9c2cb06c5c8d7cce8946a9ac99b1c2815c3612a29a82d73a1f99374fe30e54951662a6eda29c6fc411335d5dc7426b0f6050203010001";
        let sig_hex = "2925ebf8c6c9d0585c36a44491dd28f8ffd1098d2275a505a0eba7af452e9496472fd5c4a515d1c0db16c7c59ef76863b571cbf498fb8178ffeb75667e6e51b9b9bbf09d55bba54b42acb947aa5a81dc62751727d7cad4616c0c0bf1dd666f8266f24262c5fa9cbbdc424ef5f5e345e633d111e66eb4afc4001bb02e158b2d5d4573c614655f21a688bee0e9dbde6a58324c08f42ae69697e0c51803f9de6b3df242d2915d9b1a8110ad28143ab7855ef92ede48971b484172de3b0b8957f493a74b3372ee2200f2233607735f90d0b180968ab20d74841fd3dba4fb1f225ea5c6c87f99c2a238db72a536e68be202a092cd032337d451477e568f9a48b638cb";
        let data = <[u8; 16]>::from_hex("01020304050607080910111213141516").unwrap();

        let pk_der = Vec::from_hex(pk_hex).unwrap();
        let sig = Vec::from_hex(sig_hex).unwrap();

        let rsa = openssl::rsa::Rsa::public_key_from_der_pkcs1(&pk_der).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        // imports moved to module top to satisfy clippy::items-after-statements
        let cp = CryptographicParameters {
            cryptographic_algorithm: Some(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::RSA),
            padding_method: Some(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::PaddingMethod::PSS),
            hashing_algorithm: Some(cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::HashingAlgorithm::SHA256),
            digital_signature_algorithm: None,
            mask_generator: None,
            mask_generator_hashing_algorithm: None,
            p_source: None,
            // other fields default
            ..Default::default()
        };

        let v = super::verify_signature(&pkey, &data, &sig, &cp, false).unwrap();
        assert!(matches!(v, ValidityIndicator::Valid));
    }
}
