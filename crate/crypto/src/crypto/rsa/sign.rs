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
    openssl::hashing_algorithm_to_openssl_ref,
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
            return Err(CryptoError::Default(
                "Padding algorithm not handled.".to_owned(),
            ));
        }
    };
    ctx.set_rsa_padding(padding)?;
    ctx.set_signature_md(md)?;

    let digest = general_purpose::STANDARD
        .decode(digest_b64)
        .map_err(|e| CryptoError::Default(e.to_string()))?;
    let allocation_size = ctx.sign(&digest, None)?;
    let mut signature = vec![0_u8; allocation_size];
    let signature_size = ctx.sign(&digest, Some(&mut *signature))?;
    if allocation_size != signature_size {
        return Err(CryptoError::Default(
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

    // Determine effective hashing algorithm (KMIP) first, then map to OpenSSL.
    let mut effective_hash: KmipHash = if let Some(cp) = request.cryptographic_parameters.as_ref() {
        if let Some(h) = cp.hashing_algorithm {
            h
        } else {
            match digital_signature_algorithm {
                DigitalSignatureAlgorithm::RSASSAPSS
                | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => KmipHash::SHA256,
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption => KmipHash::SHA384,
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption => KmipHash::SHA512,
                DigitalSignatureAlgorithm::SHA3256WithRSAEncryption => KmipHash::SHA3256,
                DigitalSignatureAlgorithm::SHA3384WithRSAEncryption => KmipHash::SHA3384,
                DigitalSignatureAlgorithm::SHA3512WithRSAEncryption => KmipHash::SHA3512,
                other => {
                    return Err(CryptoError::Default(format!(
                        "sign_rsa_with_pkey: not supported: {other:?}"
                    )));
                }
            }
        }
    } else if let Some(digested_data) = &request.digested_data {
        // When no cryptographic parameters are provided but we have digested data,
        // infer the digest algorithm from the size of the digest
        match digested_data.len() {
            20 => KmipHash::SHA1,
            32 => KmipHash::SHA256,
            48 => KmipHash::SHA384,
            64 => KmipHash::SHA512,
            _ => default_hash,
        }
    } else {
        default_hash
    };

    // If the caller provided pre-digested data, prefer inferring the hash from the digest length.
    // This avoids accidentally selecting SHA-1 (disallowed in FIPS) when the digest is clearly
    // SHA-256/384/512.
    if let Some(digested_data) = &request.digested_data {
        effective_hash = match digested_data.len() {
            20 => KmipHash::SHA1,
            32 => KmipHash::SHA256,
            48 => KmipHash::SHA384,
            64 => KmipHash::SHA512,
            _ => effective_hash,
        };
    }

    // OpenSSL FIPS provider forbids SHA-1 for RSA signing.
    #[cfg(not(feature = "non-fips"))]
    if effective_hash == KmipHash::SHA1 {
        return Err(CryptoError::Default(
            "RSA signing with SHA-1 is not supported in FIPS mode".to_owned(),
        ));
    }

    let digest = map_kmip_hash_to_openssl(effective_hash);

    // RSASSA-PSS: pre-hash path when digested_data provided
    if digital_signature_algorithm == DigitalSignatureAlgorithm::RSASSAPSS
        && request.digested_data.is_some()
    {
        let mut buffer = Vec::new();
        if let Some(corr) = &request.correlation_value {
            buffer.extend_from_slice(corr);
        }
        let mut ctx = PkeyCtx::new(private_key)?;
        ctx.sign_init()?;
        let mgf1_hash = request
            .cryptographic_parameters
            .as_ref()
            .and_then(|cp| cp.mask_generator_hashing_algorithm)
            .unwrap_or(effective_hash);

        #[cfg(not(feature = "non-fips"))]
        let mgf1_hash = if mgf1_hash == KmipHash::SHA1 {
            effective_hash
        } else {
            mgf1_hash
        };

        // OpenSSL FIPS provider forbids SHA-1 for RSA PSS MGF1.
        // KMIP says the default MGF1 hash is SHA-1 when omitted, so we must
        // override that default to match the signature hash (typically SHA-256)
        // for FIPS compatibility.
        // Set the signature digest first so OpenSSL doesn't initialize RSA-PSS
        // with SHA-1 defaults (disallowed in FIPS).
        ctx.set_signature_md(hashing_algorithm_to_openssl_ref(effective_hash)?)?;
        // Then select PSS padding; the digest is already configured.
        ctx.set_rsa_padding(Padding::PKCS1_PSS)?;
        // MGF1 digest is a PSS-only parameter, so set it after PSS is selected.
        ctx.set_rsa_mgf1_md(hashing_algorithm_to_openssl_ref(mgf1_hash)?)?;

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
        let required_len = ctx.sign(&buffer, None).map_err(|e| {
            CryptoError::Default(format!(
                "rsa pss prehash sign init failed (hash={effective_hash:?}, mgf1={mgf1_hash:?}, payload_len={}): {e}",
                buffer.len()
            ))
        })?;
        // Second call: Pass a buffer of the correct size
        let mut signature = vec![0_u8; required_len];
        ctx.sign(&buffer, Some(&mut signature)).map_err(|e| {
            CryptoError::Default(format!(
                "rsa pss prehash sign failed (hash={effective_hash:?}, mgf1={mgf1_hash:?}, payload_len={}): {e}",
                buffer.len()
            ))
        })?;
        return Ok(signature);
    }

    // PKCS#1 v1.5: pre-hash path when digested_data provided
    // Use PkeyCtx for FIPS compatibility with pre-digested data
    if request.digested_data.is_some() {
        let digested_data = request
            .digested_data
            .as_ref()
            .ok_or_else(|| CryptoError::ObjectNotFound("Missing digested data".to_owned()))?;

        let mut buffer = Vec::new();
        if let Some(corr) = &request.correlation_value {
            buffer.extend_from_slice(corr);
        }
        buffer.extend_from_slice(digested_data);

        let mut ctx = PkeyCtx::new(private_key)?;
        ctx.sign_init()?;
        ctx.set_signature_md(hashing_algorithm_to_openssl_ref(effective_hash)?)?;
        // Tell OpenSSL what the hash type is for the pre-digested data.
        // Set it before padding so OpenSSL doesn't use SHA-1 defaults.
        ctx.set_rsa_padding(Padding::PKCS1)?;

        // First call: Pass None to get the required buffer size
        let required_len = ctx.sign(&buffer, None).map_err(|e| {
            CryptoError::Default(format!(
                "rsa pkcs1 prehash sign init failed (hash={effective_hash:?}, payload_len={}): {e}",
                buffer.len()
            ))
        })?;
        // Second call: Pass a buffer of the correct size
        let mut signature = vec![0_u8; required_len];
        ctx.sign(&buffer, Some(&mut signature)).map_err(|e| {
            CryptoError::Default(format!(
                "rsa pkcs1 prehash sign failed (hash={effective_hash:?}, payload_len={}): {e}",
                buffer.len()
            ))
        })?;
        return Ok(signature);
    }

    // Standard path for non-digested data
    let mut signer = Signer::new(digest, private_key)?;
    if DigitalSignatureAlgorithm::RSASSAPSS == digital_signature_algorithm {
        signer.set_rsa_padding(Padding::PKCS1_PSS)?;
        if let Some(cp) = request.cryptographic_parameters.as_ref() {
            if let Some(h) = cp.mask_generator_hashing_algorithm {
                let mgf1_hash = h;

                #[cfg(not(feature = "non-fips"))]
                let mgf1_hash = if mgf1_hash == KmipHash::SHA1 {
                    effective_hash
                } else {
                    mgf1_hash
                };
                let mgf1 = map_kmip_hash_to_openssl(mgf1_hash);
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
        let rsa = Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Prepare Sign request for PKCS#1 v1.5 with SHA-256
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let req = Sign {
            data: Some(b"deterministic test".to_vec().into()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey);
        assert_eq!(sig1, sig2, "RSA PKCS#1 signatures must be deterministic");
    }

    #[test]
    fn rsa_pss_zero_salt_deterministic() {
        // Generate RSA key
        let rsa = Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
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
            data: Some(b"deterministic PSS".to_vec().into()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey);
        assert_eq!(sig1, sig2, "RSA-PSS with zero salt must be deterministic");
    }

    #[test]
    fn rsa_pkcs1_v15_sign_prehashed_and_verify() {
        // Generate RSA key
        let rsa = Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
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
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
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
    #[cfg(feature = "non-fips")]
    fn rsa_pss_sign_prehashed_and_verify() {
        // Generate RSA key
        let rsa = Rsa::generate(2048).unwrap_or_else(|e| panic!("rsa gen: {e}"));
        let pkey = PKey::from_rsa(rsa).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Compute SHA-256 digest of the message
        let message = b"rsa pss prehashed test";
        let digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // RSASSA-PSS with explicit hashing + MGF1 and DIGEST_LENGTH salt
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(KmipHash::SHA256),
            mask_generator_hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let req = Sign {
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
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
    #[cfg(feature = "non-fips")]
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
            ..Default::default()
        };
        let req_raw = Sign {
            data: Some(message.to_vec().into()),
            cryptographic_parameters: Some(cp.clone()),
            ..Default::default()
        };
        let req_digest = Sign {
            digested_data: Some(message_digest.to_vec()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
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
