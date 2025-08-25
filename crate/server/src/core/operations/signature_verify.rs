use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{SignatureVerify, SignatureVerifyResponse},
        kmip_types::{
            CryptographicParameters, DigitalSignatureAlgorithm, UniqueIdentifier, ValidityIndicator,
        },
    },
    cosmian_kms_crypto::{
        crypto::rsa::default_cryptographic_parameters, openssl::kmip_public_key_to_openssl,
    },
    cosmian_kms_interfaces::SessionParams,
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::Verifier,
};
use tracing::{debug, trace};

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// This operation requests the server to verify a signature on data using a managed object.
///
/// The request contains information about the verification key, the signature algorithm,
/// the data that was signed, and the signature to be verified.
///
/// # Arguments
///
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
    trace!("signature_verify: {request}");

    // Return error if the signature is absent
    let signature_data = request
        .signature_data
        .as_ref()
        .ok_or_else(|| KmsError::InvalidRequest("Missing signature_data".to_owned()))?;

    // Determine the unique identifier to use
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("signature_verify: unique_identifier must be a string")?;

    debug!("signature_verify: Retrieving verification key with UID: {unique_identifier}");

    // Retrieve the managed object for verification
    let uid_owm = retrieve_object_for_operation(
        unique_identifier,
        KmipOperation::SignatureVerify,
        kms,
        user,
        params,
    )
    .await?;

    let verification_key = extract_verification_key(uid_owm.object())?;

    // Validate input data
    let data_to_verify = match (&request.data, &request.digested_data) {
        (Some(data), None) => data.clone(),
        (None, Some(digested_data)) => digested_data.clone(),
        (Some(_), Some(_)) => {
            return Err(KmsError::InvalidRequest(
                "Cannot provide both data and digested_data".to_owned(),
            ))
        }
        (None, None) => {
            return Err(KmsError::InvalidRequest(
                "Must provide either data or digested_data".to_owned(),
            ))
        }
    };

    // Extract cryptographic parameters
    let crypto_params = request.cryptographic_parameters.unwrap_or_default();

    // Perform signature verification
    let validity_indicator = verify_signature(
        &verification_key,
        &data_to_verify,
        signature_data,
        &crypto_params,
        request.digested_data.is_some(),
    )?;

    debug!("Signature verification result: {validity_indicator:?}");

    Ok(SignatureVerifyResponse {
        unique_identifier: UniqueIdentifier::TextString(unique_identifier.to_owned()),
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
    // Determine the message digest algorithm
    let (_algorithm, _padding, _hashing_fn, digital_signature_algorithm) =
        default_cryptographic_parameters(Some(crypto_params));

    // Matches the hashing algorithm to use
    let message_digest = match digital_signature_algorithm {
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
            "verify_signature: not supported: {digital_signature_algorithm:?}"
        ))),
    };

    debug!("verify_signature: using digital_signature_algorithm: {digital_signature_algorithm}");

    if is_digested {
        // Data is already digested, verify directly
        let mut verifier = Verifier::new_without_digest(verification_key)?;
        if DigitalSignatureAlgorithm::RSASSAPSS == digital_signature_algorithm
            && verification_key.id() == Id::RSA
        {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        let is_valid = verifier.verify_oneshot(signature, data)?;
        Ok(if is_valid {
            ValidityIndicator::Valid
        } else {
            ValidityIndicator::Invalid
        })
    } else {
        // Data needs to be hashed during verification
        let mut verifier = Verifier::new(message_digest, verification_key)?;
        if DigitalSignatureAlgorithm::RSASSAPSS == digital_signature_algorithm
            && verification_key.id() == Id::RSA
        {
            verifier.set_rsa_padding(Padding::PKCS1_PSS)?;
            verifier.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
        }
        verifier.update(data)?;
        let is_valid = verifier.verify(signature)?;
        Ok(if is_valid {
            ValidityIndicator::Valid
        } else {
            ValidityIndicator::Invalid
        })
    }
}
