use cosmian_kmip::{
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptedData, Encrypt},
        kmip_types::KeyFormatType,
    },
    openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
};
use openssl::pkey::{PKey, Private, Public};
use tracing::debug;

use crate::{
    crypto::{
        hybrid_encryption::{HybridDecryptionSystem, HybridEncryptionSystem},
        wrap::rfc5649::{key_unwrap, key_wrap},
    },
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail, DecryptionSystem, EncryptionSystem,
};

/// Encrypt bytes using the wrapping key
pub fn encrypt_bytes(wrapping_key: &Object, plaintext: &[u8]) -> Result<Vec<u8>, KmipUtilsError> {
    debug!(
        "encrypt_bytes: with object: {:?}",
        wrapping_key.object_type()
    );
    match wrapping_key {
        Object::Certificate {
            certificate_value, ..
        } => {
            // TODO(ECSE): cert should be verified before anything
            //verify_certificate(certificate_value, kms, owner, params).await?;
            debug!("encrypt_bytes: Encryption with certificate: certificate OK");
            let encrypt_system =
                HybridEncryptionSystem::instantiate_with_certificate("id", certificate_value)?;
            let request = Encrypt {
                data: Some(plaintext.to_vec()),
                ..Encrypt::default()
            };
            let encrypt_response = encrypt_system.encrypt(&request)?;
            let ciphertext = encrypt_response.data.ok_or(KmipUtilsError::Default(
                "Encrypt response does not contain ciphertext".to_string(),
            ))?;
            debug!(
                "encrypt_bytes: succeeded: ciphertext length: {}",
                ciphertext.len()
            );
            Ok(ciphertext)
        }
        Object::PGPKey { key_block, .. }
        | Object::SecretData { key_block, .. }
        | Object::SplitKey { key_block, .. }
        | Object::PrivateKey { key_block }
        | Object::PublicKey { key_block }
        | Object::SymmetricKey { key_block } => {
            // wrap the wrapping key if necessary
            if key_block.key_wrapping_data.is_some() {
                kmip_utils_bail!(
                    "unable to wrap keys: wrapping key is wrapped and that is not supported"
                )
            }
            let ciphertext = match key_block.key_format_type {
                KeyFormatType::TransparentSymmetricKey => {
                    // wrap using rfc_5649
                    let wrap_secret = key_block.key_bytes()?;
                    let ciphertext = key_wrap(plaintext, &wrap_secret)?;
                    Ok(ciphertext)
                }
                KeyFormatType::TransparentECPublicKey | KeyFormatType::TransparentRSAPublicKey => {
                    //convert to transparent key and wrap
                    // note: when moving to full openssl this double conversion will be unnecessary
                    let p_key = kmip_public_key_to_openssl(wrapping_key)?;
                    encrypt_with_public_key(p_key, plaintext)
                }
                // this really is SPKI
                KeyFormatType::PKCS8 => {
                    let p_key = PKey::public_key_from_der(&key_block.key_bytes()?)?;
                    encrypt_with_public_key(p_key, plaintext)
                }
                x => {
                    kmip_utils_bail!(
                        "Unable to wrap key: wrapping key: key format not supported for wrapping: \
                         {x:?}"
                    )
                }
            }?;
            Ok(ciphertext)
        }
        _ => Err(KmipUtilsError::NotSupported(format!(
            "Wrapping key type not supported: {:?}",
            wrapping_key.object_type()
        ))),
    }
}

fn encrypt_with_public_key(
    wrapping_key: PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    // wrap using ECIES/RSA
    let encrypt_system = HybridEncryptionSystem::new("public_key_uid", wrapping_key);
    let request = Encrypt {
        data: Some(plaintext.to_vec()),
        ..Encrypt::default()
    };
    let encrypt_response = encrypt_system.encrypt(&request)?;
    let ciphertext = encrypt_response.data.ok_or(KmipUtilsError::Default(
        "Encrypt response does not contain ciphertext".to_string(),
    ))?;
    debug!(
        "encrypt_bytes: succeeded: ciphertext length: {}",
        ciphertext.len()
    );
    Ok(ciphertext)
}

/// Decrypt bytes using the unwrapping key
pub fn decrypt_bytes(
    unwrapping_key: &Object,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    debug!(
        "decrypt_bytes: with object: {:?} on ciphertext length: {}",
        unwrapping_key,
        ciphertext.len()
    );

    let unwrapping_key_block = unwrapping_key
        .key_block()
        .context("Unable to unwrap: unwrapping key is not a key")?;
    // unwrap the unwrapping key if necessary
    if unwrapping_key_block.key_wrapping_data.is_some() {
        kmip_utils_bail!(
            "unable to unwrap key: unwrapping key is wrapped and that is not supported"
        )
    }
    let plaintext = match unwrapping_key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey => {
            // unwrap using rfc_5649
            let unwrap_secret = unwrapping_key_block.key_bytes()?;
            let plaintext = key_unwrap(ciphertext, &unwrap_secret)?;
            Ok(plaintext)
        }
        KeyFormatType::TransparentECPrivateKey | KeyFormatType::TransparentRSAPrivateKey => {
            // convert to an openssl private key
            let p_key = kmip_private_key_to_openssl(unwrapping_key)?;
            decrypt_with_private_key(p_key, ciphertext)
        }
        KeyFormatType::PKCS8 => {
            let p_key = PKey::private_key_from_der(&unwrapping_key_block.key_bytes()?)?;
            decrypt_with_private_key(p_key, ciphertext)
        }
        x => {
            kmip_utils_bail!(
                "Unable to unwrap key: unwrapping key: format not supported for unwrapping: {x:?}"
            )
        }
    }?;
    Ok(plaintext)
}

fn decrypt_with_private_key(
    p_key: PKey<Private>,
    ciphertext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    let decrypt_system = HybridDecryptionSystem::new(None, p_key);
    let request = Decrypt {
        data: Some(ciphertext.to_vec()),
        ..Decrypt::default()
    };
    let decrypt_response = decrypt_system.decrypt(&request)?;
    let plaintext = decrypt_response.data.ok_or(KmipUtilsError::Default(
        "Decrypt response does not contain plaintext".to_string(),
    ))?;
    debug!(
        "decrypt_bytes: succeeded: plaintext length: {}",
        plaintext.len()
    );
    let decrypted_data = DecryptedData::try_from(plaintext.as_ref())?;
    Ok(decrypted_data.plaintext)
}

#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;
    use openssl::rand::rand_bytes;

    use crate::crypto::{
        curve_25519::operation::create_x25519_key_pair, symmetric::create_symmetric_key,
    };

    #[test]
    fn test_encrypt_decrypt_rfc_5649() {
        let mut symmetric_key = vec![0; 32];
        rand_bytes(&mut symmetric_key).unwrap();
        let wrap_key = create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let plaintext = b"plaintext";
        let ciphertext = super::encrypt_bytes(&wrap_key, plaintext).unwrap();
        let decrypted_plaintext = super::decrypt_bytes(&wrap_key, &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }
    #[test]
    fn test_encrypt_decrypt_rfc_ecies() {
        let wrap_key_pair = create_x25519_key_pair("sk_uid", "pk_uid").unwrap();
        let plaintext = b"plaintext";
        let ciphertext = super::encrypt_bytes(wrap_key_pair.public_key(), plaintext).unwrap();
        let decrypted_plaintext =
            super::decrypt_bytes(wrap_key_pair.private_key(), &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }
}
