use cosmian_kmip::{
    kmip_0::kmip_types::{HashingAlgorithm as KmipHash, PaddingMethod},
    kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm, ValidityIndicator},
};
use cosmian_logger::error;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    rsa::Padding,
    sign::Verifier,
};

use crate::error::{CryptoError, result::CryptoResult};

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
        Some(KmipHash::SHA1) => MessageDigest::sha1(),
        Some(KmipHash::SHA256) => MessageDigest::sha256(),
        Some(KmipHash::SHA384) => MessageDigest::sha384(),
        Some(KmipHash::SHA512) => MessageDigest::sha512(),
        Some(KmipHash::SHA3256) => MessageDigest::sha3_256(),
        Some(KmipHash::SHA3384) => MessageDigest::sha3_384(),
        Some(KmipHash::SHA3512) => MessageDigest::sha3_512(),
        None => match signature_algorithm {
            DigitalSignatureAlgorithm::RSASSAPSS
            | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => MessageDigest::sha256(),
            DigitalSignatureAlgorithm::SHA384WithRSAEncryption => MessageDigest::sha384(),
            DigitalSignatureAlgorithm::SHA512WithRSAEncryption => MessageDigest::sha512(),
            DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => MessageDigest::sha3_256(),
            DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => MessageDigest::sha3_384(),
            DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => MessageDigest::sha3_512(),
            _ => {
                return Err(CryptoError::NotSupported(format!(
                    "RSA verify not supported: {signature_algorithm:?}"
                )));
            }
        },
        Some(other) => {
            return Err(CryptoError::NotSupported(format!(
                "Hash not supported: {other:?}"
            )));
        }
    };

    let mgf1_digest = match crypto_params.mask_generator_hashing_algorithm {
        Some(KmipHash::SHA1) => MessageDigest::sha1(),
        Some(KmipHash::SHA256) => MessageDigest::sha256(),
        Some(KmipHash::SHA384) => MessageDigest::sha384(),
        Some(KmipHash::SHA512) => MessageDigest::sha512(),
        Some(KmipHash::SHA3256) => MessageDigest::sha3_256(),
        Some(KmipHash::SHA3384) => MessageDigest::sha3_384(),
        Some(KmipHash::SHA3512) => MessageDigest::sha3_512(),
        None => message_digest,
        Some(other) => {
            return Err(CryptoError::NotSupported(format!(
                "MGF1 hashing algorithm not supported: {other:?}"
            )));
        }
    };

    let is_valid = if signature_algorithm == DigitalSignatureAlgorithm::RSASSAPSS {
        // Try primary MGF1, then fallback to SHA-1
        let try_verify = |mgf: MessageDigest| -> CryptoResult<bool> {
            if is_digested {
                use openssl::pkey_ctx::PkeyCtx;
                let mut ctx = PkeyCtx::new(verification_key)?;
                ctx.verify_init()?;
                ctx.set_rsa_padding(Padding::PKCS1_PSS)?;
                #[allow(unsafe_code)]
                ctx.set_rsa_mgf1_md(unsafe { &*(mgf.as_ptr().cast::<openssl::md::MdRef>()) })?;
                #[allow(unsafe_code)]
                ctx.set_signature_md(unsafe {
                    &*(message_digest.as_ptr().cast::<openssl::md::MdRef>())
                })?;
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
            let mgf1_sha1 = MessageDigest::sha1();
            if mgf1_sha1 == mgf1_digest {
                false
            } else {
                try_verify(mgf1_sha1)?
            }
        }
    } else {
        // For RSASSA-PKCS1 v1.5, always use digest-managed verifier; pre-digested input
        // is not supported in the OpenSSL high-level API for PKCS1.
        let mut verifier = Verifier::new(message_digest, verification_key)?;
        // Explicitly set PKCS1 padding for non-PSS RSA signatures
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
    };

    Ok(if is_valid {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    })
}
