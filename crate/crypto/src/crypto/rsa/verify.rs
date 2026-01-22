use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm as KmipHash, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm, ValidityIndicator},
};
use cosmian_logger::error;
use openssl::{
    hash::MessageDigest,
    md::MdRef,
    pkey::{PKey, Public},
    pkey_ctx::PkeyCtx,
    rsa::Padding,
    sign::Verifier,
};

use crate::{
    error::{CryptoError, result::CryptoResult},
    openssl::hashing_algorithm_to_openssl_ref,
};

fn kmip_hash_to_message_digest(hash: KmipHash) -> CryptoResult<MessageDigest> {
    Ok(match hash {
        KmipHash::SHA1 => MessageDigest::sha1(),
        KmipHash::SHA256 => MessageDigest::sha256(),
        KmipHash::SHA384 => MessageDigest::sha384(),
        KmipHash::SHA512 => MessageDigest::sha512(),
        KmipHash::SHA3256 => MessageDigest::sha3_256(),
        KmipHash::SHA3384 => MessageDigest::sha3_384(),
        KmipHash::SHA3512 => MessageDigest::sha3_512(),
        other => {
            return Err(CryptoError::NotSupported(format!(
                "Hash not supported: {other:?}"
            )));
        }
    })
}

fn default_digest_for_signature_algorithm(
    signature_algorithm: DigitalSignatureAlgorithm,
) -> CryptoResult<MessageDigest> {
    Ok(match signature_algorithm {
        DigitalSignatureAlgorithm::RSASSAPSS
        | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::SHA384WithRSAEncryption => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::SHA512WithRSAEncryption => MessageDigest::sha512(),
        DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => MessageDigest::sha3_256(),
        DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => MessageDigest::sha3_384(),
        DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => MessageDigest::sha3_512(),
        other => {
            return Err(CryptoError::NotSupported(format!(
                "RSA verify not supported: {other:?}"
            )));
        }
    })
}

fn message_digest_to_md_ref(digest: MessageDigest) -> CryptoResult<&'static MdRef> {
    // `hashing_algorithm_to_openssl_ref` is the canonical mapping to OpenSSL's `MdRef`.
    // Convert from MessageDigest by re-mapping from KMIP where possible.
    // Since this module already reasons in KMIP hashes, we keep a small bridge.
    //
    // Note: `MessageDigest` doesn't expose a safe way to obtain an `&MdRef`.
    // Use the existing safe helper by mapping via KMIP.
    let kmip = if digest == MessageDigest::sha1() {
        KmipHash::SHA1
    } else if digest == MessageDigest::sha256() {
        KmipHash::SHA256
    } else if digest == MessageDigest::sha384() {
        KmipHash::SHA384
    } else if digest == MessageDigest::sha512() {
        KmipHash::SHA512
    } else if digest == MessageDigest::sha3_256() {
        KmipHash::SHA3256
    } else if digest == MessageDigest::sha3_384() {
        KmipHash::SHA3384
    } else if digest == MessageDigest::sha3_512() {
        KmipHash::SHA3512
    } else {
        return Err(CryptoError::NotSupported(
            "Unsupported OpenSSL digest in RSA verify".to_owned(),
        ));
    };
    hashing_algorithm_to_openssl_ref(kmip)
}

pub fn rsa_verify(
    verification_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
    crypto_params: &CryptographicParameters,
    is_digested: bool,
) -> CryptoResult<ValidityIndicator> {
    let signature_algorithm = crypto_params
        .digital_signature_algorithm
        .unwrap_or_else(|| {
            if crypto_params.padding_method == Some(PaddingMethod::PSS) {
                DigitalSignatureAlgorithm::RSASSAPSS
            } else {
                match crypto_params.hashing_algorithm {
                    Some(KmipHash::SHA256) => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
                    Some(KmipHash::SHA384) => DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
                    Some(KmipHash::SHA512) => DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
                    Some(KmipHash::SHA3256) => DigitalSignatureAlgorithm::SHA3256WithRSAEncryption,
                    Some(KmipHash::SHA3384) => DigitalSignatureAlgorithm::SHA3384WithRSAEncryption,
                    Some(KmipHash::SHA3512) => DigitalSignatureAlgorithm::SHA3512WithRSAEncryption,
                    _ => DigitalSignatureAlgorithm::RSASSAPSS,
                }
            }
        });

    let message_digest = match crypto_params.hashing_algorithm {
        Some(h) => kmip_hash_to_message_digest(h)?,
        None => default_digest_for_signature_algorithm(signature_algorithm)?,
    };

    let mgf1_digest = match crypto_params.mask_generator_hashing_algorithm {
        Some(h) => kmip_hash_to_message_digest(h)?,
        None => message_digest,
    };

    let is_valid = if signature_algorithm == DigitalSignatureAlgorithm::RSASSAPSS {
        // Try primary MGF1, then fallback to SHA-1
        let try_verify = |mgf: MessageDigest| -> CryptoResult<bool> {
            if is_digested {
                let mut ctx = PkeyCtx::new(verification_key)?;
                ctx.verify_init()?;
                // Set signature digest first so OpenSSL doesn't initialize PSS with SHA-1 defaults
                // (disallowed in FIPS provider).
                ctx.set_signature_md(message_digest_to_md_ref(message_digest)?)?;
                ctx.set_rsa_padding(Padding::PKCS1_PSS)?;
                ctx.set_rsa_mgf1_md(message_digest_to_md_ref(mgf)?)?;
                ctx.set_rsa_pss_saltlen(openssl::sign::RsaPssSaltlen::DIGEST_LENGTH)?;
                match ctx.verify(data, signature) {
                    Ok(verified) => Ok(verified),
                    Err(err) => {
                        error!(
                            "Error verifying digest ({:?}) signature: {:?}, data: {:?}, error: {err:?}",
                            signature_algorithm,
                            hex::encode_upper(signature),
                            hex::encode_upper(data)
                        );
                        Ok(false)
                    }
                }
            } else {
                let mut v = Verifier::new(message_digest, verification_key)?;
                v.set_rsa_padding(Padding::PKCS1_PSS)?;
                v.set_rsa_mgf1_md(mgf)?;
                match v.verify_oneshot(signature, data) {
                    Ok(verified) => Ok(verified),
                    Err(err) => {
                        error!(
                            "Error verifying raw ({:?}) signature: {:?}, data: {:?}, error: {err:?}",
                            signature_algorithm,
                            hex::encode_upper(signature),
                            hex::encode_upper(data)
                        );
                        Ok(false)
                    }
                }
            }
        };
        let primary = try_verify(mgf1_digest)?;
        if primary {
            true
        } else {
            #[cfg(not(feature = "non-fips"))]
            {
                // In FIPS mode, don't attempt SHA-1 fallback
                false
            }
            #[cfg(feature = "non-fips")]
            {
                let mgf1_sha1 = MessageDigest::sha1();
                if mgf1_sha1 == mgf1_digest {
                    false
                } else {
                    try_verify(mgf1_sha1)?
                }
            }
        }
    } else {
        // RSASSA-PKCS1 v1.5
        if is_digested {
            // For pre-digested data, use PkeyCtx to explicitly set the digest algorithm
            let mut ctx = PkeyCtx::new(verification_key)?;
            ctx.verify_init()?;
            ctx.set_rsa_padding(Padding::PKCS1)?;
            ctx.set_signature_md(message_digest_to_md_ref(message_digest)?)?;
            match ctx.verify(data, signature) {
                Ok(verified) => verified,
                Err(err) => {
                    error!(
                        "Error verifying digest ({:?}) signature: {:?}, data: {:?}, error: {err:?}",
                        signature_algorithm,
                        hex::encode_upper(signature),
                        hex::encode_upper(data)
                    );
                    false
                }
            }
        } else {
            // For raw data, use high-level Verifier API
            let mut verifier = Verifier::new(message_digest, verification_key)?;
            verifier.set_rsa_padding(Padding::PKCS1)?;
            match verifier.verify_oneshot(signature, data) {
                Ok(verified) => verified,
                Err(err) => {
                    error!(
                        "Error verifying ({:?}) signature: {:?}, data: {:?}, error: {err:?}",
                        signature_algorithm,
                        hex::encode_upper(signature),
                        hex::encode_upper(data)
                    );
                    false
                }
            }
        }
    };

    Ok(if is_valid {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    })
}
