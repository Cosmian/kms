use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{ErrorReason, HashingAlgorithm, PaddingMethod},
        kmip_2_1::{
            KmipOperation,
            kmip_objects::{Object, ObjectType},
            kmip_operations::{SignatureVerify, SignatureVerifyResponse},
            kmip_types::{
                CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
                UniqueIdentifier, ValidityIndicator,
            },
        },
        time_normalize,
    },
    cosmian_kms_crypto::{
        crypto::rsa::default_cryptographic_parameters, openssl::kmip_public_key_to_openssl,
    },
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::{debug, trace};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Verifier,
};

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};
/// * `kms` - A reference to the KMS (Key Management Service) instance.
/// * `request` - The `SignatureVerify` request containing the verification parameters.
/// * `user` - A string slice representing the user requesting the verification.
/// * `params` - An optional reference to additional database parameters.
///
/// # Returns
///
/// A `KResult` containing a `SignatureVerifyResponse` which indicates the validity of the signature.
///
/// # Errors
///
/// This function will return a `KmsError` if:
/// - The unique identifier is not found or invalid.
/// - The managed object is not a valid key for signature verification.
/// - The cryptographic parameters are missing or invalid.
/// - The signature verification fails due to cryptographic errors.
/// - Both data and `digested_data` are provided or both are missing.
pub(crate) async fn signature_verify(
    kms: &KMS,
    request: SignatureVerify,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<SignatureVerifyResponse> {
    debug!("{request}");

    // Validate streaming indicators
    if request.init_indicator == Some(true) && request.final_indicator == Some(true) {
        return Err(KmsError::InvalidRequest(
            "Invalid request: init_indicator and final_indicator cannot both be true".to_owned(),
        ));
    }

    // Determine the unique identifier to use
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("signature_verify: unique_identifier must be a string")?
        .to_owned();

    debug!("Retrieving verification key with UID: {unique_identifier}");

    // Retrieve the managed object for verification
    let uid_owm = Box::pin(retrieve_object_for_operation(
        &unique_identifier,
        KmipOperation::SignatureVerify,
        kms,
        user,
        params,
    ))
    .await?;

    // Lifecycle gating (mirror Sign operation behavior): deny verification if outside allowed
    // usage window. Mandatory profile CS-AC-M-8-21 expects Wrong_Key_Lifecycle_State for
    // SignatureVerify prior to revocation when ProcessStartDate is in the future or
    // ProtectStopDate has passed.
    if let Ok(attrs) = uid_owm.object().attributes() {
        let now = time_normalize()?;
        let activation_ok = attrs.activation_date.is_none_or(|ad| ad <= now);
        let process_window_ok = attrs.process_start_date.is_none_or(|psd| psd <= now)
            && attrs.protect_stop_date.is_none_or(|psd| psd > now);
        if !(activation_ok && process_window_ok) {
            return Err(KmsError::Kmip21Error(
                ErrorReason::Wrong_Key_Lifecycle_State,
                "DENIED".to_owned(),
            ));
        }
    }

    let verification_key = extract_verification_key(uid_owm.object())?;

    // Resolve cryptographic parameters: prefer request values, but fall back to
    // the stored key Attributes when the request omits them. This mirrors how
    // other operations (e.g., Encrypt/Decrypt) respect registered parameters.
    let effective_crypto_params: CryptographicParameters = {
        let stored_cp = uid_owm
            .object()
            .attributes()
            .ok()
            .and_then(|a| a.cryptographic_parameters.clone())
            .unwrap_or_default();
        match request.cryptographic_parameters.clone() {
            None => stored_cp,
            Some(mut req_cp) => {
                if req_cp.cryptographic_algorithm.is_none() {
                    req_cp.cryptographic_algorithm = stored_cp.cryptographic_algorithm;
                }
                if req_cp.padding_method.is_none() {
                    req_cp.padding_method = stored_cp.padding_method;
                }
                if req_cp.hashing_algorithm.is_none() {
                    req_cp.hashing_algorithm = stored_cp.hashing_algorithm;
                }
                if req_cp.digital_signature_algorithm.is_none() {
                    req_cp.digital_signature_algorithm = stored_cp.digital_signature_algorithm;
                }
                // Carry through ancillary parameters if present in stored attributes and omitted in request
                if req_cp.mask_generator.is_none() {
                    req_cp.mask_generator = stored_cp.mask_generator;
                }
                if req_cp.mask_generator_hashing_algorithm.is_none() {
                    req_cp.mask_generator_hashing_algorithm =
                        stored_cp.mask_generator_hashing_algorithm;
                }
                if req_cp.p_source.is_none() {
                    req_cp.p_source = stored_cp.p_source;
                }
                req_cp
            }
        }
    };

    // Handle streaming verification
    if request.init_indicator == Some(true) || request.correlation_value.is_some() {
        return handle_streaming_verification(request, unique_identifier, &verification_key);
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

    // Use the resolved cryptographic parameters
    let crypto_params = effective_crypto_params;
    debug!(
        "signature_verify: effective CP => alg={:?} pad={:?} hash={:?} dsa={:?} mgf1_hash={:?}",
        crypto_params.cryptographic_algorithm,
        crypto_params.padding_method,
        crypto_params.hashing_algorithm,
        crypto_params.digital_signature_algorithm,
        crypto_params.mask_generator_hashing_algorithm
    );

    // Perform signature verification
    let validity_indicator = verify_signature(
        &verification_key,
        &data_to_verify,
        signature_data,
        &crypto_params,
        request.digested_data.is_some(),
    )
    .context("signature_verify: OpenSSL verification failed")?;

    debug!("Signature verification result: {validity_indicator:?}");

    Ok(SignatureVerifyResponse {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier),
        validity_indicator: Some(validity_indicator),
        data: None, // Data recovery not implemented yet
        correlation_value: request.correlation_value,
    })
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
    // Resolve signature algorithm coherently from provided parameters
    let algorithm = crypto_params.cryptographic_algorithm;
    let padding = crypto_params.padding_method;
    let signature_algorithm = if let Some(dsa) = crypto_params.digital_signature_algorithm {
        dsa
    } else {
        match algorithm {
            Some(CryptographicAlgorithm::ECDSA | CryptographicAlgorithm::EC) => match crypto_params
                .hashing_algorithm
                .unwrap_or(HashingAlgorithm::SHA256)
            {
                HashingAlgorithm::SHA256 => DigitalSignatureAlgorithm::ECDSAWithSHA256,
                HashingAlgorithm::SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
                HashingAlgorithm::SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
                h => kms_bail!(KmsError::NotSupported(format!(
                    "verify_signature: ECDSA unsupported hash: {h:?}"
                ))),
            },
            Some(CryptographicAlgorithm::RSA) => {
                // Respect explicit PSS padding request
                if padding == Some(PaddingMethod::PSS) {
                    DigitalSignatureAlgorithm::RSASSAPSS
                } else {
                    match crypto_params.hashing_algorithm {
                        Some(HashingAlgorithm::SHA256) => {
                            DigitalSignatureAlgorithm::SHA256WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA384) => {
                            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA512) => {
                            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3256) => {
                            DigitalSignatureAlgorithm::SHA3256WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3384) => {
                            DigitalSignatureAlgorithm::SHA3384WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3512) => {
                            DigitalSignatureAlgorithm::SHA3512WithRSAEncryption
                        }
                        _ => DigitalSignatureAlgorithm::RSASSAPSS,
                    }
                }
            }
            None => {
                // No explicit algorithm provided; choose sensible default based on key type
                match verification_key.id() {
                    Id::RSA => match crypto_params.hashing_algorithm {
                        Some(
                            HashingAlgorithm::SHA256
                            | HashingAlgorithm::SHA384
                            | HashingAlgorithm::SHA512,
                        ) if padding == Some(PaddingMethod::PSS) => {
                            DigitalSignatureAlgorithm::RSASSAPSS
                        }
                        Some(HashingAlgorithm::SHA256) => {
                            DigitalSignatureAlgorithm::SHA256WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA384) => {
                            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA512) => {
                            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3256) => {
                            DigitalSignatureAlgorithm::SHA3256WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3384) => {
                            DigitalSignatureAlgorithm::SHA3384WithRSAEncryption
                        }
                        Some(HashingAlgorithm::SHA3512) => {
                            DigitalSignatureAlgorithm::SHA3512WithRSAEncryption
                        }
                        _ => DigitalSignatureAlgorithm::RSASSAPSS,
                    },
                    Id::EC => match crypto_params
                        .hashing_algorithm
                        .unwrap_or(HashingAlgorithm::SHA256)
                    {
                        HashingAlgorithm::SHA256 => DigitalSignatureAlgorithm::ECDSAWithSHA256,
                        HashingAlgorithm::SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
                        HashingAlgorithm::SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
                        h => kms_bail!(KmsError::NotSupported(format!(
                            "verify_signature: ECDSA unsupported hash: {h:?}"
                        ))),
                    },
                    _ => DigitalSignatureAlgorithm::ECDSAWithSHA256,
                }
            }
            _ => DigitalSignatureAlgorithm::ECDSAWithSHA256,
        }
    };

    // Choose the hashing algorithm to use: prefer explicit hashing_algorithm from CP when present
    let message_digest = if let Some(h) = &crypto_params.hashing_algorithm {
        match h {
            HashingAlgorithm::SHA1 => MessageDigest::sha1(),
            HashingAlgorithm::SHA256 => MessageDigest::sha256(),
            HashingAlgorithm::SHA384 => MessageDigest::sha384(),
            HashingAlgorithm::SHA512 => MessageDigest::sha512(),
            HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
            HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
            HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
            _ => kms_bail!(KmsError::NotSupported(format!(
                "verify_signature: hashing algorithm not supported: {h:?}"
            ))),
        }
    } else {
        match signature_algorithm {
            DigitalSignatureAlgorithm::RSASSAPSS
            | DigitalSignatureAlgorithm::SHA256WithRSAEncryption
            | DigitalSignatureAlgorithm::ECDSAWithSHA256 => MessageDigest::sha256(),
            DigitalSignatureAlgorithm::SHA384WithRSAEncryption
            | DigitalSignatureAlgorithm::ECDSAWithSHA384 => MessageDigest::sha384(),
            DigitalSignatureAlgorithm::SHA512WithRSAEncryption
            | DigitalSignatureAlgorithm::ECDSAWithSHA512 => MessageDigest::sha512(),
            DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => MessageDigest::sha3_256(),
            DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => MessageDigest::sha3_384(),
            DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => MessageDigest::sha3_512(),
            _ => kms_bail!(KmsError::NotSupported(format!(
                "verify_signature: not supported: {signature_algorithm:?}"
            ))),
        }
    };

    // MGF1 digest: honor explicit mask_generator_hashing_algorithm when present, otherwise default to message_digest
    let mgf1_digest = if let Some(h) = &crypto_params.mask_generator_hashing_algorithm {
        match h {
            HashingAlgorithm::SHA1 => MessageDigest::sha1(),
            HashingAlgorithm::SHA256 => MessageDigest::sha256(),
            HashingAlgorithm::SHA384 => MessageDigest::sha384(),
            HashingAlgorithm::SHA512 => MessageDigest::sha512(),
            HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
            HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
            HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
            _ => kms_bail!(KmsError::NotSupported(format!(
                "verify_signature: MGF1 hashing algorithm not supported: {h:?}"
            ))),
        }
    } else {
        message_digest
    };

    let md_name = if message_digest == MessageDigest::sha1() {
        "SHA1"
    } else if message_digest == MessageDigest::sha256() {
        "SHA256"
    } else if message_digest == MessageDigest::sha384() {
        "SHA384"
    } else if message_digest == MessageDigest::sha512() {
        "SHA512"
    } else if message_digest == MessageDigest::sha3_256() {
        "SHA3-256"
    } else if message_digest == MessageDigest::sha3_384() {
        "SHA3-384"
    } else if message_digest == MessageDigest::sha3_512() {
        "SHA3-512"
    } else {
        "OTHER"
    };
    let mgf1_name = if mgf1_digest == MessageDigest::sha1() {
        "SHA1"
    } else if mgf1_digest == MessageDigest::sha256() {
        "SHA256"
    } else if mgf1_digest == MessageDigest::sha384() {
        "SHA384"
    } else if mgf1_digest == MessageDigest::sha512() {
        "SHA512"
    } else if mgf1_digest == MessageDigest::sha3_256() {
        "SHA3-256"
    } else if mgf1_digest == MessageDigest::sha3_384() {
        "SHA3-384"
    } else if mgf1_digest == MessageDigest::sha3_512() {
        "SHA3-512"
    } else {
        "OTHER"
    };
    debug!(
        "verify_signature: algo={algorithm:?} sig_alg={signature_algorithm:?} pad={:?} digest={} mgf1={} digested_data={} data_len={} sig_len={}",
        padding,
        md_name,
        mgf1_name,
        is_digested,
        data.len(),
        signature.len()
    );

    let is_valid = match verification_key.id() {
        Id::RSA | Id::EC => {
            trace!("verify_signature: using RSA or EC key for verification");
            // Specialize RSA-PSS path to always use no-digest verifier with explicit pre-hash
            if DigitalSignatureAlgorithm::RSASSAPSS == signature_algorithm
                && verification_key.id() == Id::RSA
            {
                // RSA-PSS verification with MGF1 fallback: if primary MGF1 MD fails, try SHA-1
                let try_verify = |mgf: MessageDigest| -> KResult<bool> {
                    if is_digested {
                        let mut v = Verifier::new_without_digest(verification_key)
                            .context("verify_signature: create RSA-PSS verifier without digest")?;
                        v.set_rsa_padding(Padding::PKCS1_PSS)?;
                        v.set_rsa_mgf1_md(mgf)?;
                        Ok(v.verify_oneshot(signature, data)
                            .context("verify_signature: RSA-PSS oneshot failed (pre-hash)")?)
                    } else {
                        let mut v = Verifier::new(message_digest, verification_key)
                            .context("verify_signature: create RSA-PSS verifier with digest")?;
                        v.set_rsa_padding(Padding::PKCS1_PSS)?;
                        v.set_rsa_mgf1_md(mgf)?;
                        Ok(v.verify_oneshot(signature, data)
                            .context("verify_signature: RSA-PSS oneshot failed (digest path)")?)
                    }
                };

                let primary = try_verify(mgf1_digest)?;
                if primary {
                    true
                } else {
                    // Fallback to SHA-1 for MGF1 if not already SHA-1
                    let mgf1_sha1 = MessageDigest::sha1();
                    if mgf1_sha1 == mgf1_digest {
                        false
                    } else {
                        try_verify(mgf1_sha1)?
                    }
                }
            } else {
                // Non-PSS algorithms: use OpenSSL-managed digesting
                let mut verifier = if is_digested {
                    Verifier::new_without_digest(verification_key)
                        .context("verify_signature: create verifier without digest")?
                } else {
                    Verifier::new(message_digest, verification_key)
                        .context("verify_signature: create verifier with digest")?
                };
                verifier
                    .verify_oneshot(signature, data)
                    .context("verify_signature: oneshot failed")?
            }
        }
        Id::ED25519 => {
            trace!("verify_signature: using ED25519 key for verification");
            // ED25519 verifies the signature directly on the data
            let mut verifier = Verifier::new_without_digest(verification_key)
                .context("verify_signature: create ED25519 verifier")?;
            verifier
                .verify_oneshot(signature, data)
                .context("verify_signature: ED25519 oneshot failed")?
        }
        _ => kms_bail!(KmsError::NotSupported(format!(
            "verify_signature: key type not supported: {:?}",
            verification_key.id()
        ))),
    };

    Ok(if is_valid {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    })
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
    request: SignatureVerify,
    unique_identifier: String,
    verification_key: &PKey<Public>,
) -> KResult<SignatureVerifyResponse> {
    // Extract cryptographic parameters (no key Attributes available in this helper),
    // defaulting when omitted. For multi-part flows, callers should ensure consistency
    // across calls if parameters are required.
    let crypto_params = request.cryptographic_parameters.unwrap_or_default();
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

        let cp = CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PSS),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
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
