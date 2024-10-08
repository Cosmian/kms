use cloudproof::reexport::cover_crypt::Covercrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::elliptic_curves::ecies::ecies_encrypt;
#[cfg(not(feature = "fips"))]
use cosmian_kmip::crypto::rsa::ckm_rsa_pkcs::ckm_rsa_pkcs_encrypt;
use cosmian_kmip::{
    crypto::{
        cover_crypt::encryption::CoverCryptEncryption,
        rsa::{
            ckm_rsa_aes_key_wrap::ckm_rsa_aes_key_wrap,
            ckm_rsa_pkcs_oaep::ckm_rsa_pkcs_oaep_encrypt, default_cryptographic_parameters,
        },
        symmetric::symmetric_ciphers::{encrypt as sym_encrypt, random_nonce, SymCipher},
        EncryptionSystem,
    },
    kmip::{
        extra::BulkData,
        kmip_objects::{Object, ObjectType},
        kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, CryptographicUsageMask, KeyFormatType,
            PaddingMethod, StateEnumeration, UniqueIdentifier,
        },
    },
    openssl::kmip_public_key_to_openssl,
    KmipError,
};
use cosmian_kms_client::access::ObjectOperationType;
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::unwrap_key, KMS},
    database::object_with_metadata::ObjectWithMetadata,
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

const EMPTY_SLICE: &[u8] = &[];

pub(crate) async fn encrypt(
    kms: &KMS,
    request: Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<EncryptResponse> {
    trace!("Encrypt: {}", serde_json::to_string(&request)?);

    let owm = get_key(kms, &request, user, params).await?;

    // we do not (yet) support continuation cases
    let data = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;

    // it may be a bulk encryption request, if not, fallback to single encryption
    match BulkData::deserialize(data) {
        Ok(bulk_data) => {
            // it is a bulk encryption request
            encrypt_bulk(&owm, request, bulk_data)
        }
        Err(_) => {
            // fallback to single encryption
            encrypt_single(&owm, &request)
        }
    }
}

fn encrypt_single(owm: &ObjectWithMetadata, request: &Encrypt) -> KResult<EncryptResponse> {
    match &owm.object {
        Object::SymmetricKey { .. } => encrypt_with_symmetric_key(request, owm),
        Object::PublicKey { .. } => encrypt_with_public_key(request, owm),
        Object::Certificate {
            certificate_value, ..
        } => encrypt_with_certificate(request, &owm.id, certificate_value),
        other => kms_bail!(KmsError::NotSupported(format!(
            "encrypt: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    }
}

/// Encrypt multiple plaintexts with the same key
/// and return the corresponding ciphertexts.
///
/// This is a hack where `request.data` is a serialized `BulkData` object.
// TODO: Covercrypt already has a bulk encryption method; maybe this should be merged here
pub(crate) fn encrypt_bulk(
    owm: &ObjectWithMetadata,
    mut request: Encrypt,
    bulk_data: BulkData,
) -> KResult<EncryptResponse> {
    debug!(
        "encrypt_bulk: ==> encrypting {} clear texts",
        bulk_data.len()
    );
    let mut ciphertexts = Vec::with_capacity(bulk_data.len());

    match &owm.object {
        Object::SymmetricKey { .. } => {
            let aad = request
                .authenticated_encryption_additional_data
                .as_deref()
                .unwrap_or(EMPTY_SLICE);
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let (key_bytes, cipher) = get_cipher_and_key(&request, owm)?;
                let nonce = request
                    .iv_counter_nonce
                    .clone()
                    .unwrap_or(random_nonce(cipher)?);
                let (ciphertext, tag) = sym_encrypt(cipher, &key_bytes, &nonce, aad, &plaintext)?;
                // concatenate nonce || ciphertext || tag
                let nct = [nonce.as_slice(), ciphertext.as_slice(), tag.as_slice()].concat();
                ciphertexts.push(Zeroizing::new(nct));
            }
        }
        Object::PublicKey { .. } => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response = encrypt_with_public_key(&request, owm)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        Object::Certificate {
            certificate_value, ..
        } => {
            for plaintext in <BulkData as Into<Vec<Zeroizing<Vec<u8>>>>>::into(bulk_data) {
                request.data = Some(plaintext.clone());
                let response = encrypt_with_certificate(&request, &owm.id, certificate_value)?;
                ciphertexts.push(Zeroizing::new(response.data.unwrap_or_default()));
            }
        }
        other => kms_bail!(KmsError::NotSupported(format!(
            "Encrypt bulk: encryption with keys of type: {} is not supported",
            other.object_type()
        ))),
    };

    debug!(
        "encrypt_bulk: <== encrypted {} ciphertexts",
        ciphertexts.len()
    );
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id.clone()),
        data: Some(BulkData::new(ciphertexts).serialize()?.to_vec()),
        iv_counter_nonce: None,
        correlation_value: request.correlation_value,
        authenticated_encryption_tag: None,
    })
}

async fn get_key(
    kms: &KMS,
    request: &Encrypt,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ObjectWithMetadata> {
    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Encrypt: the unique identifier or tags must be a string")?
        .to_owned();
    trace!("operations::encrypt: key uid_or_tags: {uid_or_tags}");

    // retrieve from tags or use passed identifier
    let mut owm_s = kms
        .db
        .retrieve(&uid_or_tags, user, ObjectOperationType::Encrypt, params)
        .await?
        .into_values()
        .filter(|owm| {
            let object_type = owm.object.object_type();
            owm.state == StateEnumeration::Active
                && (object_type == ObjectType::PublicKey
                    || object_type == ObjectType::SymmetricKey
                    || object_type == ObjectType::Certificate)
        })
        .collect::<Vec<ObjectWithMetadata>>();

    trace!(
        "operations::encrypt: key owm_s: number of results: {}",
        owm_s.len()
    );
    // there can only be one key
    let mut owm = owm_s
        .pop()
        .ok_or_else(|| KmsError::KmipError(ErrorReason::Item_Not_Found, uid_or_tags.clone()))?;

    if !owm_s.is_empty() {
        return Err(KmsError::InvalidRequest(format!(
            "get: too many objects for key {uid_or_tags}",
        )));
    }

    // the key must be active
    if owm.state != StateEnumeration::Active {
        kms_bail!(KmsError::InconsistentOperation(
            "encrypt: the server cannot if the key is not active".to_owned()
        ));
    }

    // unwrap if wrapped
    match &mut owm.object {
        Object::Certificate { .. } => {}
        _ => {
            if owm.object.key_wrapping_data().is_some() {
                let key_block = owm.object.key_block_mut()?;
                unwrap_key(key_block, kms, &owm.owner, params).await?;
            }
        }
    }
    Ok(owm)
}

fn encrypt_with_symmetric_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    let (key_bytes, aead) = get_cipher_and_key(request, owm)?;
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let nonce = request
        .iv_counter_nonce
        .clone()
        .unwrap_or(random_nonce(aead)?);
    let aad = request
        .authenticated_encryption_additional_data
        .as_deref()
        .unwrap_or(EMPTY_SLICE);
    let (ciphertext, tag) = sym_encrypt(aead, &key_bytes, &nonce, aad, plaintext)?;
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(owm.id.clone()),
        data: Some(ciphertext),
        iv_counter_nonce: Some(nonce),
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: Some(tag),
    })
}

fn get_cipher_and_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<(Zeroizing<Vec<u8>>, SymCipher)> {
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ))
    }
    let key_block = owm.object.key_block()?;
    let key_bytes = key_block.key_bytes()?;
    let aead = match key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey | KeyFormatType::Raw => {
            // recover the cryptographic algorithm from the request or the key block or default to AES
            let cryptographic_algorithm = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.cryptographic_algorithm)
                .unwrap_or_else(|| {
                    key_block
                        .cryptographic_algorithm()
                        .copied()
                        .unwrap_or(CryptographicAlgorithm::AES)
                });
            let block_cipher_mode = request
                .cryptographic_parameters
                .as_ref()
                .and_then(|cp| cp.block_cipher_mode);
            SymCipher::from_algorithm_and_key_size(
                cryptographic_algorithm,
                block_cipher_mode,
                key_bytes.len(),
            )?
        }
        other => {
            return Err(KmsError::NotSupported(format!(
                "symmetric encryption with keys of format: {other}"
            )))
        }
    };
    Ok((key_bytes, aead))
}

fn encrypt_with_public_key(
    request: &Encrypt,
    owm: &ObjectWithMetadata,
) -> KResult<EncryptResponse> {
    // Make sure that the key used to encrypt can be used to encrypt.
    if !owm
        .object
        .attributes()?
        .is_usage_authorized_for(CryptographicUsageMask::Encrypt)?
    {
        return Err(KmsError::KmipError(
            ErrorReason::Incompatible_Cryptographic_Usage_Mask,
            "CryptographicUsageMask not authorized for Encrypt".to_owned(),
        ))
    }

    let key_block = owm.object.key_block()?;
    match &key_block.key_format_type {
        KeyFormatType::CoverCryptPublicKey => {
            CoverCryptEncryption::instantiate(Covercrypt::default(), &owm.id, &owm.object)?
                .encrypt(request)
                .map_err(Into::into)
        }
        KeyFormatType::TransparentECPublicKey
        | KeyFormatType::TransparentRSAPublicKey
        | KeyFormatType::PKCS1
        | KeyFormatType::PKCS8 => {
            let plaintext = request.data.as_ref().ok_or_else(|| {
                KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
            })?;
            trace!(
                "get_encryption_system: matching on key format type: {:?}",
                key_block.key_format_type
            );
            let public_key = kmip_public_key_to_openssl(&owm.object)?;
            trace!("get_encryption_system: OpenSSL Public Key instantiated before encryption");
            encrypt_with_pkey(request, &owm.id, plaintext, &public_key)
        }
        other => Err(KmsError::NotSupported(format!(
            "encryption with public keys of format: {other}"
        ))),
    }
}

fn encrypt_with_pkey(
    request: &Encrypt,
    key_id: &str,
    plaintext: &[u8],
    public_key: &PKey<Public>,
) -> KResult<EncryptResponse> {
    let ciphertext = match public_key.id() {
        Id::RSA => encrypt_with_rsa(
            public_key,
            request.cryptographic_parameters.as_ref(),
            plaintext,
        )?,
        #[cfg(not(feature = "fips"))]
        Id::EC | Id::X25519 | Id::ED25519 => ecies_encrypt(public_key, plaintext)?,
        other => {
            kms_bail!("Encrypt: public key type not supported: {other:?}")
        }
    };
    Ok(EncryptResponse {
        unique_identifier: UniqueIdentifier::TextString(key_id.to_owned()),
        data: Some(ciphertext),
        iv_counter_nonce: None,
        correlation_value: request.correlation_value.clone(),
        authenticated_encryption_tag: None,
    })
}

fn encrypt_with_rsa(
    public_key: &PKey<Public>,
    cryptographic_parameters: Option<&CryptographicParameters>,
    plaintext: &[u8],
) -> KResult<Vec<u8>> {
    let (algorithm, padding, hashing_fn) =
        default_cryptographic_parameters(cryptographic_parameters);

    let ciphertext = match algorithm {
        CryptographicAlgorithm::AES => match padding {
            PaddingMethod::OAEP => ckm_rsa_aes_key_wrap(public_key, hashing_fn, plaintext)?,
            _ => kms_bail!(
                "Unable to encrypt with RSA AES KEY WRAP: padding method not supported: \
                 {padding:?}"
            ),
        },
        CryptographicAlgorithm::RSA => match padding {
            PaddingMethod::OAEP => ckm_rsa_pkcs_oaep_encrypt(public_key, hashing_fn, plaintext)?,
            #[cfg(not(feature = "fips"))]
            PaddingMethod::PKCS1v15 => ckm_rsa_pkcs_encrypt(public_key, plaintext)?,
            _ => kms_bail!("Unable to encrypt with RSA: padding method not supported: {padding:?}"),
        },
        x => {
            kms_bail!("Unable to encrypt with RSA: algorithm not supported for encrypting: {x:?}")
        }
    };
    Ok(ciphertext)
}

fn encrypt_with_certificate(
    request: &Encrypt,
    key_id: &str,
    certificate_value: &[u8],
) -> KResult<EncryptResponse> {
    let plaintext = request.data.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest("Encrypt: data to encrypt must be provided".to_owned())
    })?;
    let cert = X509::from_der(certificate_value)
        .map_err(|e| KmipError::ConversionError(format!("invalid X509 DER: {e:?}")))?;
    let public_key = cert.public_key().map_err(|e| {
        KmipError::ConversionError(format!("invalid certificate public key: error: {e:?}"))
    })?;
    encrypt_with_pkey(request, key_id, plaintext, &public_key)
}
