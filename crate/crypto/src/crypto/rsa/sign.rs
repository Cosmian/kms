use base64::{Engine, engine::general_purpose};
use cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm as KmipHash,
    kmip_2_1::{kmip_operations::Sign, kmip_types::DigitalSignatureAlgorithm},
};
use openssl::{
    hash::MessageDigest,
    md::Md,
    pkey::{PKey, Private},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::{RsaPssSaltlen, Signer},
};

use crate::{
    CryptoError, crypto::rsa::default_cryptographic_parameters, error::result::CryptoResult,
};

/// Attempt to sign a digest using an RSA private key and the provided algorithm name.
///
/// Supported algorithms:
/// - `SHA1withRSA`
/// - `SHA256withRSA`
/// - `SHA512withRSA`
/// - `SHA1withRSA/PSS`
/// - `SHA256withRSA/PSS`
/// - `SHA512withRSA/PSS`
pub fn sign_rsa_digest_with_algorithm(
    raw_private_key: &[u8],
    algorithm: &str,
    digest_b64: &str,
    _rsa_pss_salt_length: Option<i32>,
) -> CryptoResult<Vec<u8>> {
    // Validate the DER is a loadable private key (accept PKCS#8). If it fails, try PKCS#1.
    let private_key = match PKey::private_key_from_der(raw_private_key) {
        Ok(key) => key,
        Err(_) => {
            // For already uploaded Gmail CSE wrapped private keys, need to also handle PKCS#1 format.
            PKey::from_rsa(Rsa::<Private>::private_key_from_der(raw_private_key)?).map_err(|e| {
                CryptoError::ConversionError(format!(
                    "Neither PKCS#8 nor PKCS#1 could load RSA private key: {e}"
                ))
            })?
        }
    };

    let mut ctx = PkeyCtx::new(&private_key)?;
    ctx.sign_init()?;
    let (padding, md) = match algorithm {
        "SHA1withRSA" => (Padding::PKCS1, Md::sha1()),
        "SHA256withRSA" => (Padding::PKCS1, Md::sha256()),
        "SHA512withRSA" => (Padding::PKCS1, Md::sha512()),
        "SHA1withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha1()),
        "SHA256withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha256()),
        "SHA512withRSA/PSS" => (Padding::PKCS1_PSS, Md::sha512()),
        _ => {
            return Err(crate::error::CryptoError::Default(
                "Padding algorithm not handled.".to_owned(),
            ));
        }
    };
    ctx.set_rsa_padding(padding)?;
    ctx.set_signature_md(md)?;

    let digest = general_purpose::STANDARD
        .decode(digest_b64)
        .map_err(|e| crate::error::CryptoError::Default(e.to_string()))?;
    let allocation_size = ctx.sign(&digest, None)?;
    let mut signature = vec![0_u8; allocation_size];
    let signature_size = ctx.sign(&digest, Some(&mut *signature))?;
    if allocation_size != signature_size {
        return Err(crate::error::CryptoError::Default(
            "allocation_size MUST be equal to signature_size".to_owned(),
        ));
    }
    Ok(signature)
}

/// Sign using RSA with KMIP `Sign` request semantics (PKCS#1 v1.5 and RSASSA-PSS).
/// - Honors `cryptographic_parameters.hashing_algorithm` when provided
/// - For RSASSA-PSS, aligns MGF1 digest and optional salt length
/// - Supports pre-digested data via `digested_data` and correlation buffer via `correlation_value`
pub fn sign_rsa_with_pkey(request: &Sign, private_key: &PKey<Private>) -> CryptoResult<Vec<u8>> {
    let (_algorithm, _padding, default_hash, digital_signature_algorithm) =
        default_cryptographic_parameters(request.cryptographic_parameters.as_ref());

    // Determine effective message digest
    let digest = if let Some(cp) = request.cryptographic_parameters.as_ref() {
        if let Some(h) = &cp.hashing_algorithm {
            match h {
                KmipHash::SHA1 => MessageDigest::sha1(),
                KmipHash::SHA256 => MessageDigest::sha256(),
                KmipHash::SHA384 => MessageDigest::sha384(),
                KmipHash::SHA512 => MessageDigest::sha512(),
                KmipHash::SHA3256 => MessageDigest::sha3_256(),
                KmipHash::SHA3384 => MessageDigest::sha3_384(),
                KmipHash::SHA3512 => MessageDigest::sha3_512(),
                _ => {
                    return Err(CryptoError::Default(
                        "sign_rsa_with_pkey: hashing algorithm not supported".to_owned(),
                    ));
                }
            }
        } else {
            match digital_signature_algorithm {
                DigitalSignatureAlgorithm::RSASSAPSS
                | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => MessageDigest::sha256(),
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption => MessageDigest::sha384(),
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption => MessageDigest::sha512(),
                DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => MessageDigest::sha3_256(),
                DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => MessageDigest::sha3_384(),
                DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => MessageDigest::sha3_512(),
                _ => {
                    return Err(CryptoError::Default(format!(
                        "sign_rsa_with_pkey: not supported: {digital_signature_algorithm:?}"
                    )));
                }
            }
        }
    } else {
        map_kmip_hash_to_openssl(default_hash)
    };

    // RSASSA-PSS: pre-hash path when digested_data provided
    if digital_signature_algorithm == DigitalSignatureAlgorithm::RSASSAPSS
        && request.digested_data.is_some()
    {
        // We use PkeyCtx because Signer::new_without_digest often loses the MD context, needed for PSS padding parameters
        use openssl::pkey_ctx::PkeyCtx;

        let mut buffer = Vec::new();
        if let Some(corr) = &request.correlation_value {
            buffer.extend_from_slice(corr);
        }
        let mut ctx = PkeyCtx::new(private_key)?;
        ctx.sign_init()?;
        ctx.set_rsa_padding(Padding::PKCS1_PSS)?;

        if let Some(cp) = request.cryptographic_parameters.as_ref() {
            if let Some(h) = cp.mask_generator_hashing_algorithm {
                let mgf1 = map_kmip_hash_to_openssl(h);
                #[allow(unsafe_code)]
                ctx.set_rsa_mgf1_md(unsafe { &*(mgf1.as_ptr().cast::<openssl::md::MdRef>()) })?;
            } else {
                #[allow(unsafe_code)]
                ctx.set_rsa_mgf1_md(unsafe { &*(digest.as_ptr().cast::<openssl::md::MdRef>()) })?;
            }
        } else {
            #[allow(unsafe_code)]
            ctx.set_rsa_mgf1_md(unsafe { &*(digest.as_ptr().cast::<openssl::md::MdRef>()) })?;
        }
        //Tell OpenSSL what the hash type is
        #[allow(unsafe_code)]
        ctx.set_signature_md(unsafe { &*(digest.as_ptr().cast::<openssl::md::MdRef>()) })?;

        let salt_len = request
            .cryptographic_parameters
            .as_ref()
            .and_then(|cp| cp.salt_length)
            .map_or(RsaPssSaltlen::DIGEST_LENGTH, RsaPssSaltlen::custom);
        ctx.set_rsa_pss_saltlen(salt_len)?;

        let digested_data = request.digested_data.as_ref().ok_or_else(|| {
            CryptoError::ObjectNotFound("Missing digested data for PSS operation".to_owned())
        })?;
        buffer.extend_from_slice(digested_data);

        // First call: Pass None to get the required buffer size
        let required_len = ctx.sign(&buffer, None)?;
        // Second call: Pass a buffer of the correct size
        let mut signature = vec![0_u8; required_len];
        ctx.sign(&buffer, Some(&mut signature))?;
        return Ok(signature);
    }

    let mut signer = Signer::new(digest, private_key)?;
    if DigitalSignatureAlgorithm::RSASSAPSS == digital_signature_algorithm {
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        if let Some(cp) = request.cryptographic_parameters.as_ref() {
            if let Some(h) = cp.mask_generator_hashing_algorithm {
                let mgf1 = map_kmip_hash_to_openssl(h);
                signer.set_rsa_mgf1_md(mgf1)?;
            } else {
                signer.set_rsa_mgf1_md(digest)?;
            }
            if let Some(salt_len) = cp.salt_length {
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::custom(salt_len))?;
            } else {
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            }
        } else {
            signer.set_rsa_mgf1_md(digest)?;
            signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
        }
    }
    if let Some(corr) = request.correlation_value.clone() {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)
    } else {
        let data_to_sign = request.data.clone().unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)
    }?;
    Ok(signature)
}

fn map_kmip_hash_to_openssl(kmip_hash: KmipHash) -> MessageDigest {
    match kmip_hash {
        KmipHash::SHA1 => MessageDigest::sha1(),
        KmipHash::SHA384 => MessageDigest::sha384(),
        KmipHash::SHA512 => MessageDigest::sha512(),
        KmipHash::SHA3256 => MessageDigest::sha3_256(),
        KmipHash::SHA3384 => MessageDigest::sha3_384(),
        KmipHash::SHA3512 => MessageDigest::sha3_512(),
        _ => MessageDigest::sha256(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use cosmian_kmip::kmip_2_1::kmip_types::CryptographicParameters;

    use super::*;
    use crate::crypto::rsa::verify::rsa_verify;

    fn sign_twice_and_compare(sign_req: &Sign, pkey: &PKey<Private>) -> (Vec<u8>, Vec<u8>) {
        let sig1 = sign_rsa_with_pkey(sign_req, pkey).expect("first signature");
        let sig2 = sign_rsa_with_pkey(sign_req, pkey).expect("second signature");
        (sig1, sig2)
    }

    #[test]
    fn rsa_pkcs1_v15_deterministic() {
        // Generate RSA key
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Prepare Sign request for PKCS#1 v1.5 with SHA-256
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let req = Sign {
            unique_identifier: None,
            data: Some(b"deterministic test".to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey);
        assert_eq!(sig1, sig2, "RSA PKCS#1 signatures must be deterministic");
    }

    #[test]
    fn rsa_pss_zero_salt_deterministic() {
        // Generate RSA key
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // RSASSA-PSS with SHA-256 and salt_length = 0 should be deterministic
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            salt_length: Some(0),
            ..Default::default()
        };
        let req = Sign {
            unique_identifier: None,
            data: Some(b"deterministic PSS".to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey);
        assert_eq!(sig1, sig2, "RSA-PSS with zero salt must be deterministic");
    }

    #[test]
    fn rsa_pkcs1_v15_sign_prehashed_and_verify() {
        // Generate RSA key
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Compute SHA-256 digest of the message
        let message = b"rsa pkcs1 prehashed test";
        let digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // Prepare Sign request with digested_data for PKCS#1 v1.5 + SHA256
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let req = Sign {
            unique_identifier: None,
            data: None,
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };

        let sig = sign_rsa_with_pkey(&req, &pkey).expect("signature");

        // Verify signature using rsa_verify helper
        let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
        let cp_verify = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let valid = rsa_verify(&public_key, &digest, &sig, &cp_verify, true).expect("rsa_verify");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature must verify for prehashed PKCS#1 v1.5"
        );
    }

    #[test]
    fn rsa_pss_sign_prehashed_and_verify() {
        // Generate RSA key
        let rsa = openssl::rsa::Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Compute SHA-256 digest of the message
        let message = b"rsa pss prehashed test";
        let digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // RSASSA-PSS with explicit hashing + MGF1 and DIGEST_LENGTH salt
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            salt_length: None,
            ..Default::default()
        };
        let req = Sign {
            unique_identifier: None,
            data: None,
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };

        let sig = sign_rsa_with_pkey(&req, &pkey).expect("signature");

        // Verify signature using rsa_verify helper for RSASSA-PSS
        let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
        let cp_verify = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let valid = rsa_verify(&public_key, &digest, &sig, &cp_verify, true).expect("rsa_verify");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature must verify for prehashed RSASSA-PSS"
        );
    }

    #[test]
    fn rsa_pss_sign_raw_digest_verify() {
        // Generate RSA key
        let rsa = Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Compute SHA-256 digest of the message
        let message = b"rsa pss raw/digest test";
        let message_digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // RSASSA-PSS with explicit hashing + MGF1 and DIGEST_LENGTH salt
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            salt_length: None,
            ..Default::default()
        };
        let req_raw = Sign {
            unique_identifier: None,
            data: Some(message.to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp.clone()),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };
        let req_digest = Sign {
            unique_identifier: None,
            data: None,
            digested_data: Some(message_digest.to_vec()),
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
        };
        // Sign raw and digest data
        let sig_raw = sign_rsa_with_pkey(&req_raw, &pkey).expect("signature raw");
        let sig_digest = sign_rsa_with_pkey(&req_digest, &pkey).expect("signature digest");
        assert_ne!(
            sig_raw, sig_digest,
            "Signature raw and digest match error - non deterministic - should be different"
        );
        // Verify signature
        let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
        let cp_verify = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        // raw data verification - raw data, raw signature
        let valid = rsa_verify(&public_key, message, &sig_raw, &cp_verify, false)
            .expect("rsa_verify signature raw");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature raw must verify for RSASSA-PSS"
        );
        // raw data verification - raw data, digest signature
        let valid = rsa_verify(&public_key, message, &sig_digest, &cp_verify, false)
            .expect("rsa_verify signature digest");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature digest, raw data must verify for RSASSA-PSS"
        );
        // digest data verification - digest data, digest signature
        let valid = rsa_verify(&public_key, &message_digest, &sig_digest, &cp_verify, true)
            .expect("rsa_verify signature digest");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature digest must verify for prehashed RSASSA-PSS"
        );
        // digest data verification - digest data, raw signature
        let valid = rsa_verify(&public_key, &message_digest, &sig_raw, &cp_verify, true)
            .expect("rsa_verify signature digest");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "Signature raw, digest data verify for prehashed RSASSA-PSS"
        );
    }
}
