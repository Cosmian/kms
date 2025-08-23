use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, ErrorReason, HashingAlgorithm, State},
        kmip_2_1::{
            KmipOperation,
            extra::BulkData,
            kmip_objects::Object,
            kmip_operations::{Sign, SignResponse},
            kmip_types::{
                CryptographicParameters, KeyFormatType, UniqueIdentifier,
            },
        },
    },
    cosmian_kms_crypto::{
        crypto::rsa::default_cryptographic_parameters,
        openssl::kmip_private_key_to_openssl,
    },
    cosmian_kms_interfaces::{ObjectWithMetadata, SessionParams},
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private},
    rsa::Padding,
    sign::Signer,
};
use tracing::{debug, info, trace};
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS,
        uid_utils::uids_from_unique_identifier,
    },
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn sign(
    kms: &KMS,
    request: Sign,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<SignResponse> {
    trace!("Sign: {}", serde_json::to_string(&request)?);

    // Get the data to sign - either data or digested_data must be provided
    let data_to_sign = if let Some(data) = request.data.as_ref() {
        data.as_slice()
    } else if let Some(digested_data) = request.digested_data.as_ref() {
        digested_data.as_slice()
    } else {
        return Err(KmsError::InvalidRequest(
            "Sign: either data or digested_data must be provided".to_owned(),
        ))
    };

    // Get the uids from the unique identifier
    let unique_identifier = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?;
    let uids = uids_from_unique_identifier(unique_identifier, kms, params.clone())
        .await
        .context("Sign")?;
    trace!("Sign: candidate uids: {uids:?}");

    // Find a suitable private key for signing
    let mut selected_owm = None;
    for uid in uids {
        let owm = kms
            .database
            .retrieve_object(&uid, params.clone())
            .await?
            .ok_or_else(|| {
                KmsError::InvalidRequest(format!("Sign: failed to retrieve key: {uid}"))
            })?;
        if owm.state() != State::Active {
            continue
        }
        //check user permissions - owner can always sign
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(&uid, user, false, params.clone())
                .await?;
            if !ops.iter().any(|p| *p == KmipOperation::Sign) {
                continue
            }
        }
        trace!("Sign: user: {user} is authorized to sign using: {uid}");
        
        // Only private keys can be used for signing
        if let Object::PrivateKey { .. } = owm.object() {
            // Check that the private key is authorized for signing
            let attributes = owm
                .object()
                .attributes()
                .unwrap_or_else(|_| owm.attributes());
            trace!("sign: attributes: {attributes:#?}");
            if !attributes.is_usage_authorized_for(CryptographicUsageMask::Sign)? {
                continue
            }
            selected_owm = Some(owm);
            break
        }
    }
    let mut owm = selected_owm.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Item_Not_Found,
            format!("Sign: no valid private key for id: {unique_identifier}"),
        )
    })?;

    // unwrap if wrapped
    owm.set_object(
        kms.get_unwrapped(owm.id(), owm.object(), user, params.clone())
            .await?,
    );

    // data length for logging
    let data_len = data_to_sign.len();

    // It may be a bulk signing request; if not, fallback to single signing
    let res = match BulkData::deserialize(data_to_sign) {
        Ok(bulk_data) => {
            // It is a bulk signing request
            sign_bulk(&owm, request, bulk_data)
        }
        Err(_) => {
            // fallback to single signing
            sign_single(&owm, &request)
        }
    }?;

    info!(
        uid = owm.id(),
        user = user,
        "Signed data of: {} bytes -> signature length: {}",
        data_len,
        res.signature_data.as_ref().map_or(0, Vec::len),
    );
    Ok(res)
}

fn sign_single(owm: &ObjectWithMetadata, request: &Sign) -> KResult<SignResponse> {
    match owm.object() {
        Object::PrivateKey { .. } => sign_with_private_key(request, owm),
        other => kms_bail!(KmsError::NotSupported(format!(
            "sign: signing with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

/// Sign multiple data with the same key
/// and return the corresponding signatures.
///
/// This is a hack where `request.data` is a serialized `BulkData` object.
/// The `BulkData` object is deserialized and each data is signed.
/// The signatures are concatenated and returned as a single `BulkData` object.
/// # Arguments
/// * `owm` - the object with metadata of the key
/// * `request` - the sign request
/// * `bulk_data` - the bulk data to sign
/// # Returns
/// * the sign response
pub(crate) fn sign_bulk(
    owm: &ObjectWithMetadata,
    mut request: Sign,
    bulk_data: BulkData,
) -> KResult<SignResponse> {
    debug!("sign_bulk: ==> signing {} data items", bulk_data.len());
    let mut signatures = Vec::with_capacity(bulk_data.len());

    match owm.object() {
        Object::PrivateKey { .. } => {
            for data in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(data.clone());
                let response = sign_with_private_key(&request, owm)?;
                if let Some(signature) = response.signature_data {
                    signatures.push(Zeroizing::new(signature));
                }
            }
        }
        other => {
            kms_bail!(KmsError::NotSupported(format!(
                "sign_bulk: signing with keys of type: {} is not supported",
                other.object_type()
            )))
        }
    }

    let bulk_signatures = BulkData::from(signatures);
    Ok(SignResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id().to_owned()),
        signature_data: Some(bulk_signatures.serialize()?.to_vec()),
        correlation_value: request.correlation_value.clone(),
    })
}

fn sign_with_private_key(
    request: &Sign,
    owm: &ObjectWithMetadata,
) -> KResult<SignResponse> {
    // Make sure that the key used to sign can be used to sign.
    if !owm
        .object()
        .attributes()
        .unwrap_or_else(|_| owm.attributes())
        .is_usage_authorized_for(CryptographicUsageMask::Sign)?
    {
        return Err(KmsError::Kmip21Error(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Sign".to_owned(),
        ))
    }

    let key_block = owm.object().key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::TransparentECPrivateKey
        | KeyFormatType::TransparentRSAPrivateKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            // Get the data to sign - either data or digested_data must be provided
            let data_to_sign = if let Some(data) = request.data.as_ref() {
                data.as_slice()
            } else if let Some(digested_data) = request.digested_data.as_ref() {
                digested_data.as_slice()
            } else {
                return Err(KmsError::InvalidRequest(
                    "Sign: either data or digested_data must be provided".to_owned(),
                ))
            };

            trace!(
                "sign_with_private_key: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let private_key = kmip_private_key_to_openssl(owm.object())?;
            trace!("sign_with_private_key: OpenSSL Private Key instantiated before signing");
            sign_with_pkey(request, owm.id(), data_to_sign, &private_key)
        }
        other => Err(KmsError::NotSupported(format!(
            "signing with private keys of format: {other}"
        ))),
    }
}

fn sign_with_pkey(
    request: &Sign,
    key_id: &str,
    data_to_sign: &[u8],
    private_key: &PKey<Private>,
) -> KResult<SignResponse> {
    let signature = match private_key.id() {
        Id::RSA => sign_with_rsa(
            private_key,
            request.cryptographic_parameters.as_ref(),
            data_to_sign,
        )?,
        Id::EC => sign_with_ecdsa(
            private_key,
            request.cryptographic_parameters.as_ref(),
            data_to_sign,
        )?,
        other => {
            kms_bail!("Sign: private key type not supported: {other:?}")
        }
    };
    Ok(SignResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_owned()),
        signature_data: Some(signature),
        correlation_value: request.correlation_value.clone(),
    })
}

fn sign_with_rsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    data_to_sign: &[u8],
) -> KResult<Vec<u8>> {
    let (_algorithm, _padding, hashing_fn) =
        default_cryptographic_parameters(cryptographic_parameters);
    debug!("sign_with_rsa: signing with RSA PSS {hashing_fn:?}");

    // For RSA signatures, we use RSASSA-PSS
    let digest = match hashing_fn {
        HashingAlgorithm::SHA1 => MessageDigest::sha1(),
        HashingAlgorithm::SHA224 => MessageDigest::sha224(),
        HashingAlgorithm::SHA256 => MessageDigest::sha256(),
        HashingAlgorithm::SHA384 => MessageDigest::sha384(),
        HashingAlgorithm::SHA512 => MessageDigest::sha512(),
        HashingAlgorithm::SHA3224 => MessageDigest::sha3_224(),
        HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
        HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
        HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
        _ => MessageDigest::sha256(),
    };

    let mut signer = Signer::new(digest, private_key)?;
    signer.set_rsa_padding(Padding::PKCS1_PSS)?;
    signer.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
    signer.update(data_to_sign)?;
    let signature = signer.sign_to_vec()?;
    
    debug!(
        "sign_with_rsa: signed {} bytes, signature length: {}",
        data_to_sign.len(),
        signature.len()
    );
    
    Ok(signature)
}

fn sign_with_ecdsa(
    private_key: &PKey<Private>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    data_to_sign: &[u8],
) -> KResult<Vec<u8>> {
    let (_algorithm, _padding, hashing_fn) =
        default_cryptographic_parameters(cryptographic_parameters);
    debug!("sign_with_ecdsa: signing with ECDSA {hashing_fn:?}");

    // For ECDSA signatures, we use the appropriate hash function
    let digest = match hashing_fn {
        HashingAlgorithm::SHA1 => MessageDigest::sha1(),
        HashingAlgorithm::SHA224 => MessageDigest::sha224(),
        HashingAlgorithm::SHA256 => MessageDigest::sha256(),
        HashingAlgorithm::SHA384 => MessageDigest::sha384(),
        HashingAlgorithm::SHA512 => MessageDigest::sha512(),
        HashingAlgorithm::SHA3224 => MessageDigest::sha3_224(),
        HashingAlgorithm::SHA3256 => MessageDigest::sha3_256(),
        HashingAlgorithm::SHA3384 => MessageDigest::sha3_384(),
        HashingAlgorithm::SHA3512 => MessageDigest::sha3_512(),
        _ => MessageDigest::sha256(),
    };

    let mut signer = Signer::new(digest, private_key)?;
    signer.update(data_to_sign)?;
    let signature = signer.sign_to_vec()?;
    
    debug!(
        "sign_with_ecdsa: signed {} bytes, signature length: {}",
        data_to_sign.len(),
        signature.len()
    );
    
    Ok(signature)
}