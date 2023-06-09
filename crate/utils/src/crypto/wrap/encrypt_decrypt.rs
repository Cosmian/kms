use cloudproof::reexport::crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519PrivateKey, X25519PublicKey},
        DhKeyPair,
    },
    reexport::rand_core::CryptoRngCore,
    KeyTrait,
};
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyMaterial,
    kmip_objects::Object,
    kmip_types::{CryptographicAlgorithm, KeyFormatType, RecommendedCurve},
};

use crate::{
    crypto::{
        ecies::{ecies_decrypt, ecies_encrypt},
        error::{result::CryptoResultHelper, CryptoError},
        key_wrapping_rfc_5649,
    },
    crypto_bail,
};

/// Encrypt bytes using the wrapping key
pub fn encrypt_bytes<R>(
    rng: &mut R,
    wrapping_key: &Object,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError>
where
    R: CryptoRngCore,
{
    let wrapping_key_block = wrapping_key
        .key_block()
        .context("unable to wrap: wrapping key is not a key")?;
    // wrap the wrapping key if necessary
    if wrapping_key_block.key_wrapping_data.is_some() {
        crypto_bail!("unable to wrap keys: wrapping key is wrapped and that is not supported")
    }
    let ciphertext = match wrapping_key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey => {
            // wrap using rfc_5649
            let wrap_secret = wrapping_key_block.key_bytes()?;
            key_wrapping_rfc_5649::wrap(plaintext, &wrap_secret)
        }
        KeyFormatType::TransparentECPublicKey => {
            // wrap using ECIES
            match wrapping_key_block.cryptographic_algorithm {
                CryptographicAlgorithm::ECDH => match &wrapping_key_block.key_value.key_material {
                    KeyMaterial::TransparentECPublicKey {
                        recommended_curve,
                        q_string,
                    } => match recommended_curve {
                        RecommendedCurve::CURVE25519 => {
                            let public_key = X25519PublicKey::try_from_bytes(q_string).context(
                                "Unable to wrap key: wrapping key: failed to parse X25519 public \
                                 key",
                            )?;
                            ecies_encrypt::<
                                R,
                                X25519KeyPair,
                                { X25519KeyPair::PUBLIC_KEY_LENGTH },
                                { X25519KeyPair::PRIVATE_KEY_LENGTH },
                            >(rng, &public_key, plaintext, None, None)
                        }
                        x => {
                            crypto_bail!(
                                "Unable to wrap key: wrapping key: recommended curve not \
                                 supported for wrapping: {x:?}"
                            )
                        }
                    },
                    x => {
                        crypto_bail!(
                            "Unable to wrap key: wrapping key: key material not supported for \
                             wrapping: {x:?}"
                        )
                    }
                },
                x => {
                    crypto_bail!(
                        "Unable to wrap key: wrapping key: cryptographic algorithm not supported \
                         for wrapping: {x:?}"
                    )
                }
            }
        }
        x => {
            crypto_bail!(
                "Unable to wrap key: wrapping key: format not supported for wrapping: {x:?}"
            )
        }
    }?;
    Ok(ciphertext)
}

/// Decrypt bytes using the unwrapping key
pub fn decrypt_bytes(unwrapping_key: &Object, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let unwrapping_key_block = unwrapping_key
        .key_block()
        .context("Unable to unwrap: unwrapping key is not a key")?;
    // unwrap the unwrapping key if necessary
    if unwrapping_key_block.key_wrapping_data.is_some() {
        crypto_bail!("unable to unwrap key: unwrapping key is wrapped and that is not supported")
    }
    let plaintext = match unwrapping_key_block.key_format_type {
        KeyFormatType::TransparentSymmetricKey => {
            // unwrap using rfc_5649
            let unwrap_secret = unwrapping_key_block.key_bytes()?;
            key_wrapping_rfc_5649::unwrap(ciphertext, &unwrap_secret)
        }
        KeyFormatType::TransparentECPrivateKey => {
            match unwrapping_key_block.cryptographic_algorithm {
                CryptographicAlgorithm::ECDH => {
                    match &unwrapping_key_block.key_value.key_material {
                        KeyMaterial::TransparentECPrivateKey {
                            recommended_curve,
                            d,
                        } => match recommended_curve {
                            RecommendedCurve::CURVE25519 => {
                                let private_key =
                                    X25519PrivateKey::try_from_bytes(&d.to_bytes_be()).context(
                                        "Unable to unwrap: unwrapping key: failed to parse X25519 \
                                         private key",
                                    )?;
                                ecies_decrypt::<
                                    X25519KeyPair,
                                    { X25519KeyPair::PUBLIC_KEY_LENGTH },
                                    { X25519KeyPair::PRIVATE_KEY_LENGTH },
                                >(
                                    &private_key, ciphertext, None, None
                                )
                            }
                            x => {
                                crypto_bail!(
                                    "Unable to unwrap key: unwrapping key: recommended curve not \
                                     supported for unwrapping: {x:?}"
                                )
                            }
                        },
                        x => {
                            crypto_bail!(
                                "Unable to unwrap key: unwrapping key: key material not supported \
                                 for unwrapping: {x:?}"
                            )
                        }
                    }
                }
                x => {
                    crypto_bail!(
                        "Unable to unwrap key: unwrapping key: cryptographic algorithm not \
                         supported for unwrapping: {x:?}"
                    )
                }
            }
        }

        x => {
            crypto_bail!(
                "Unable to unwrap key: unwrapping key: format not supported for unwrapping: {x:?}"
            )
        }
    }?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {

    use cloudproof::reexport::crypto_core::{
        reexport::rand_core::{RngCore, SeedableRng},
        CsRng,
    };
    use cosmian_kmip::kmip::kmip_types::CryptographicAlgorithm;

    use crate::crypto::{
        curve_25519::operation::create_ec_key_pair, symmetric::create_symmetric_key,
    };

    #[test]
    fn test_encrypt_decrypt_rfc_5649() {
        let mut rng = CsRng::from_entropy();

        let mut symmetric_key = vec![0; 32];
        rng.fill_bytes(&mut symmetric_key);
        let wrap_key = create_symmetric_key(symmetric_key.as_slice(), CryptographicAlgorithm::AES);

        let plaintext = b"plaintext";
        let ciphertext = super::encrypt_bytes(&mut rng, &wrap_key, plaintext).unwrap();
        let decrypted_plaintext = super::decrypt_bytes(&wrap_key, &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }
    #[test]
    fn test_encrypt_decrypt_rfc_ecies() {
        let mut rng = CsRng::from_entropy();
        let wrap_key_pair = create_ec_key_pair(&mut rng, "sk_uid", "pk_uid").unwrap();

        let plaintext = b"plaintext";
        let ciphertext =
            super::encrypt_bytes(&mut rng, wrap_key_pair.public_key(), plaintext).unwrap();
        let decrypted_plaintext =
            super::decrypt_bytes(wrap_key_pair.private_key(), &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted_plaintext[..]);
    }
}
