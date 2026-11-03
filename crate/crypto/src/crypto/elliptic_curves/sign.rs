#[cfg(feature = "non-fips")]
use std::ffi::c_uint;

use cosmian_kmip::kmip_2_1::{kmip_operations::Sign, kmip_types::DigitalSignatureAlgorithm};
#[cfg(feature = "non-fips")]
use foreign_types::ForeignTypeRef as _;
#[cfg(feature = "non-fips")]
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey,
    signature::{Signer as _, hazmat::PrehashSigner as _},
};
#[cfg(feature = "non-fips")]
use openssl::{
    hash::Hasher,
    md::Md,
    pkey_ctx::{PkeyCtx, PkeyCtxRef},
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};

#[cfg(feature = "non-fips")]
use crate::crypto::elliptic_curves::ECDSA_256_D_PRIVATE_KEY_LENGTH;
use crate::error::CryptoError;

/// ECDSA signature helper: in non-fips builds P-256 and secp256k1 are signed deterministically
/// (RFC 6979) — P-256 via OpenSSL's deterministic nonce mode (when the digest has the hash
/// length), secp256k1 via k256 with low-S, which is ~3x faster than OpenSSL on that curve.
/// Everything else uses OpenSSL's randomised signer.
pub fn ecdsa_sign(request: &Sign, private_key: &PKey<Private>) -> Result<Vec<u8>, CryptoError> {
    let digital_signature_algorithm = request.cryptographic_parameters.as_ref().map_or(
        DigitalSignatureAlgorithm::ECDSAWithSHA256,
        |cp| {
            cp.digital_signature_algorithm
                .unwrap_or(DigitalSignatureAlgorithm::ECDSAWithSHA256)
        },
    );

    let digest = match digital_signature_algorithm {
        DigitalSignatureAlgorithm::ECDSAWithSHA256 => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::ECDSAWithSHA384 => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::ECDSAWithSHA512 => MessageDigest::sha512(),
        _ => {
            return Err(CryptoError::NotSupported(format!(
                "ecdsa_sign: not supported: {digital_signature_algorithm:?}"
            )));
        }
    };

    // RFC6979 deterministic ECDSA for P-256 (OpenSSL) and secp256k1 (k256) in non-fips builds
    #[cfg(feature = "non-fips")]
    {
        if let Ok(ec_key) = private_key.ec_key() {
            let curve_nid = ec_key.group().curve_name();

            if curve_nid == Some(openssl::nid::Nid::X9_62_PRIME256V1) {
                // `None` (digest length != hash length) falls through to the randomised
                // OpenSSL path below.
                if let Some(signature) = ecdsa_sign_rfc6979_openssl(request, private_key, digest)? {
                    return Ok(signature);
                }
            } else if curve_nid == Some(openssl::nid::Nid::SECP256K1) {
                let mut msg_bytes = Vec::new();
                if let Some(corr) = request.correlation_value.clone() {
                    msg_bytes.extend_from_slice(&corr);
                }
                if let Some(digested_data) = &request.digested_data {
                    msg_bytes.extend_from_slice(digested_data);
                } else if let Some(data) = &request.data {
                    msg_bytes.extend_from_slice(data.as_ref());
                }

                // Private scalar d
                let mut d_bytes = ec_key.private_key().to_vec();
                if d_bytes.len() < ECDSA_256_D_PRIVATE_KEY_LENGTH {
                    let mut padded = vec![0_u8; ECDSA_256_D_PRIVATE_KEY_LENGTH - d_bytes.len()];
                    padded.extend_from_slice(&d_bytes);
                    d_bytes = padded;
                } else if d_bytes.len() > ECDSA_256_D_PRIVATE_KEY_LENGTH {
                    let start = d_bytes.len().saturating_sub(ECDSA_256_D_PRIVATE_KEY_LENGTH);
                    d_bytes = d_bytes.get(start..).unwrap_or(&d_bytes[..]).to_vec();
                }
                let key = K256SigningKey::from_slice(&d_bytes)
                    .map_err(|e| CryptoError::NotSupported(format!("K256 key error: {e}")))?;
                let sig: K256Signature = if request.digested_data.is_some() {
                    key.sign_prehash(&msg_bytes)
                        .map_err(|e| CryptoError::NotSupported(format!("Sign (K256) error: {e}")))?
                } else {
                    // k256 `Signer` hashes with SHA-256 (RFC 6979).
                    key.sign(&msg_bytes)
                };
                // Apply Low-S normalization
                return Ok(sig.normalize_s().to_der().as_bytes().to_vec());
            }
        }
    }

    // Default OpenSSL path.
    //
    // CRITICAL: when `digested_data` is set the caller already hashed the data
    // (prehashed == true).  Using `Signer::new(digest, key)` followed by
    // `sign_oneshot_to_vec(digested_data)` would call `EVP_DigestSign`, which
    // hashes the input AGAIN before signing — producing a signature over
    // hash(hash(data)) that never verifies.
    //
    // For the prehashed path we therefore use `EcdsaSig::sign`, which maps
    // directly to `ECDSA_sign(0, dgst, dgstlen, ...)` — it takes a raw digest
    // and produces a DER-encoded (r,s) signature without any extra hashing.
    //
    // NOTE: `correlation_value` is only applied in the unhashed branch (below).
    // This is intentional — when `digested_data` is present the data has already
    // been hashed by the caller, so there is nothing to prepend or correlate.
    // Per the KMIP spec, `CorrelationValue` is the "data to be correlated" and
    // is only meaningful when the server performs the hashing.

    let signature = if let Some(digested_data) = &request.digested_data {
        let ec_key = private_key.ec_key().map_err(|e| {
            CryptoError::Kmip(format!(
                "ecdsa_sign: cannot extract EC key for prehashed sign: {e}"
            ))
        })?;
        let ecdsa_sig = openssl::ecdsa::EcdsaSig::sign(digested_data, &ec_key).map_err(|e| {
            CryptoError::Kmip(format!("ecdsa_sign: prehashed ECDSA sign failed: {e}"))
        })?;
        ecdsa_sig
            .to_der()
            .map_err(|e| CryptoError::Kmip(format!("ecdsa_sign: DER serialization failed: {e}")))?
    } else {
        // Unhashed data: use OpenSSL's full digest-then-sign path.
        let mut signer = Signer::new(digest, private_key)?;
        if let Some(corr) = request.correlation_value.clone() {
            signer.update(&corr)?;
        }
        let data_to_sign = request.data.clone().unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)?
    };
    Ok(signature)
}

/// RFC 6979 deterministic ECDSA computed by OpenSSL (`nonce-type` = 1), which uses its
/// optimised curve arithmetic (~20x faster than the pure-Rust `p256` crate).
/// Returns `Ok(None)` when `digested_data` is not exactly `digest.size()` bytes: OpenSSL
/// rejects such inputs, so the caller falls back to the randomised OpenSSL signer.
#[cfg(feature = "non-fips")]
fn ecdsa_sign_rfc6979_openssl(
    request: &Sign,
    private_key: &PKey<Private>,
    digest: MessageDigest,
) -> Result<Option<Vec<u8>>, CryptoError> {
    let hashed;
    let tbs: &[u8] = if let Some(digested_data) = &request.digested_data {
        if digested_data.len() != digest.size() {
            return Ok(None);
        }
        digested_data
    } else {
        let mut hasher = Hasher::new(digest)?;
        if let Some(corr) = &request.correlation_value {
            hasher.update(corr)?;
        }
        if let Some(data) = &request.data {
            hasher.update(data.as_ref())?;
        }
        hashed = hasher.finish()?;
        &hashed
    };
    let md = Md::from_nid(digest.type_()).ok_or_else(|| {
        CryptoError::NotSupported(format!(
            "ecdsa_sign: no OpenSSL MD for {:?}",
            digest.type_()
        ))
    })?;
    let mut ctx = PkeyCtx::new(private_key)?;
    ctx.sign_init()?;
    ctx.set_signature_md(md)?;
    if !set_deterministic_nonce(&mut ctx) {
        return Ok(None);
    }
    let mut signature = Vec::new();
    ctx.sign_to_vec(tbs, &mut signature)?;
    Ok(Some(signature))
}

/// Switches `ctx` to RFC 6979 deterministic nonces via the `nonce-type` signature parameter.
///
/// `openssl::pkey_ctx::NonceType` is gated on `ossl320`, which is off whenever `openssl-sys`
/// is built against older headers (e.g. system 3.0.x) while the final binary links the
/// 3.6.2 libcrypto from `build.rs`. The raw `OSSL_PARAM` call only needs `ossl300`.
/// Returns `false` when the linked libcrypto does not honour the parameter (OpenSSL < 3.2
/// silently ignores unknown parameters), so the caller never mistakes a random-nonce
/// signature for an RFC 6979 one and falls back to the default OpenSSL signer instead.
#[cfg(feature = "non-fips")]
#[allow(unsafe_code)] // reason: raw OSSL_PARAM FFI; openssl's safe `set_nonce_type` is gated on ossl320, off when openssl-sys is built against 3.0.x headers
fn set_deterministic_nonce(ctx: &mut PkeyCtxRef<Private>) -> bool {
    let key = c"nonce-type";
    let mut requested: c_uint = 1; // 1 = RFC 6979 deterministic k
    // SAFETY: `key` is a NUL-terminated static, `requested` outlives the call, and the params
    // array is terminated by `OSSL_PARAM_construct_end`. `ctx.as_ptr()` is a live EVP_PKEY_CTX.
    let set_ok = unsafe {
        let params = [
            openssl_sys::OSSL_PARAM_construct_uint(key.as_ptr(), &raw mut requested),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        openssl_sys::EVP_PKEY_CTX_set_params(ctx.as_ptr(), params.as_ptr())
    };
    if set_ok <= 0 {
        return false;
    }
    let mut effective: c_uint = 0;
    // SAFETY: same invariants as above; `effective` outlives the call.
    let get_ok = unsafe {
        let mut params = [
            openssl_sys::OSSL_PARAM_construct_uint(key.as_ptr(), &raw mut effective),
            openssl_sys::OSSL_PARAM_construct_end(),
        ];
        openssl_sys::EVP_PKEY_CTX_get_params(ctx.as_ptr(), params.as_mut_ptr())
    };
    get_ok > 0 && effective == 1
}

/// `EdDSA` (e.g., `Ed25519`) signing helper. Uses OpenSSL's one-shot signer without digest.
pub fn eddsa_sign(request: &Sign, private_key: &PKey<Private>) -> Result<Vec<u8>, CryptoError> {
    let mut signer = Signer::new_without_digest(private_key)?;

    if let Some(corr) = request.correlation_value.clone() {
        signer.update(&corr)?;
    }
    let signature = if let Some(digested_data) = &request.digested_data {
        signer.sign_oneshot_to_vec(digested_data)?
    } else {
        let data_to_sign = request.data.clone().unwrap_or_default();
        signer.sign_oneshot_to_vec(&data_to_sign)?
    };
    Ok(signature)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm as KmipHash,
        kmip_2_1::kmip_types::CryptographicParameters,
    };
    use openssl::pkey::PKey;

    use super::*;
    use crate::crypto::elliptic_curves::verify::ecdsa_verify;

    fn sign_twice_and_compare<F>(sign_req: &Sign, pkey: &PKey<Private>, f: F) -> (Vec<u8>, Vec<u8>)
    where
        F: Fn(&Sign, &PKey<Private>) -> Result<Vec<u8>, CryptoError>,
    {
        let sig1 = f(&sign_req.clone(), pkey).expect("first signature");
        let sig2 = f(&sign_req.clone(), pkey).expect("second signature");
        (sig1, sig2)
    }

    #[test]
    fn ed25519_deterministic() {
        // Generate Ed25519 key
        let pkey = PKey::generate_ed25519().unwrap_or_else(|e| panic!("ed25519 gen: {e}"));
        let cp: CryptographicParameters = CryptographicParameters::default();
        let req = Sign {
            data: Some(b"ed25519 deterministic".to_vec().into()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey, eddsa_sign);
        assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn ed448_deterministic() {
        // Generate Ed448 key
        let pkey = PKey::generate_ed448().unwrap_or_else(|e| panic!("ed448 gen: {e}"));
        let cp: CryptographicParameters = CryptographicParameters::default();
        let req = Sign {
            data: Some(b"ed448 deterministic".to_vec().into()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey, eddsa_sign);
        assert_eq!(sig1, sig2, "Ed448 signatures must be deterministic");
    }

    #[test]
    fn ecdsa_is_nondeterministic() {
        // Generate ECDSA key on NIST P-256
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let ec_key =
            openssl::ec::EcKey::generate(&group).unwrap_or_else(|e| panic!("ec key gen: {e}"));
        let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey: {e}"));

        // Prepare ECDSA with SHA-256
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        };
        let req = Sign {
            data: Some(b"ecdsa nondeterminism test".to_vec().into()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let (sig1, sig2) = sign_twice_and_compare(&req, &pkey, ecdsa_sign);
        #[cfg(feature = "non-fips")]
        {
            assert_eq!(
                sig1, sig2,
                "ECDSA signatures must be deterministic under RFC6979 path"
            );
        }
        #[cfg(not(feature = "non-fips"))]
        {
            assert_ne!(
                sig1, sig2,
                "ECDSA signatures should not be deterministic under OpenSSL"
            );
        }
    }

    #[test]
    fn ecdsa_sign_supported_recommended_curves() {
        // List of supported curves for signature in server sign path
        #[allow(unused_mut)]
        let mut curves = vec![
            openssl::nid::Nid::SECP224R1,        // P224
            openssl::nid::Nid::X9_62_PRIME256V1, // P256
            openssl::nid::Nid::SECP384R1,        // P384
            openssl::nid::Nid::SECP521R1,        // P521
        ];
        #[cfg(feature = "non-fips")]
        {
            // Additional non-FIPS curves
            curves.push(openssl::nid::Nid::X9_62_PRIME192V1); // P192
            curves.push(openssl::nid::Nid::SECP256K1); // SECP256K1
            curves.push(openssl::nid::Nid::SECP224K1); // SECP224K1
        }

        for nid in curves {
            let group = openssl::ec::EcGroup::from_curve_name(nid)
                .unwrap_or_else(|e| panic!("group({nid:?}): {e}"));
            let ec_key = openssl::ec::EcKey::generate(&group)
                .unwrap_or_else(|e| panic!("ec_key({nid:?}): {e}"));
            let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey({nid:?}): {e}"));

            // Choose digest based on curve (SHA-256 works for all ECDSA here)
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                ..Default::default()
            };
            let req = Sign {
                data: Some(b"supported curves signing".to_vec().into()),
                cryptographic_parameters: Some(cp),
                ..Default::default()
            };

            let sig = ecdsa_sign(&req, &pkey).expect("ecdsa signature");
            assert!(!sig.is_empty(), "signature must not be empty for {nid:?}");
        }
        // Mapping check removed to satisfy clippy pedantic (no-effect bindings)
    }

    #[test]
    fn ecdsa_sign_prehashed_and_verify_sha256() {
        // Generate ECDSA key on NIST P-256
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let ec_key =
            openssl::ec::EcKey::generate(&group).unwrap_or_else(|e| panic!("ec key gen: {e}"));
        let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey: {e}"));

        let message = b"ecdsa prehashed test";
        let digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // Prepare ECDSA with SHA-256 using digested_data
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        };
        let req = Sign {
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };

        let sig = ecdsa_sign(&req, &pkey).expect("ecdsa signature");

        // Verify signature using ecdsa_verify helper with prehashed input
        let cp_verify = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            hashing_algorithm: Some(KmipHash::SHA256),
            ..Default::default()
        };
        let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
        let valid =
            ecdsa_verify(&public_key, &digest, &sig, &cp_verify, true).expect("ecdsa_verify");
        assert_eq!(
            valid,
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid,
            "ECDSA signature must verify for prehashed SHA-256"
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn ecdsa_sign_raw_digest_sha256() {
        let group_p256 = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let group_k256 = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let groups = vec![group_p256, group_k256];
        let mut results = Vec::with_capacity(groups.len());
        for group in groups {
            let ec_key =
                openssl::ec::EcKey::generate(&group).unwrap_or_else(|e| panic!("ec key gen: {e}"));
            let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey: {e}"));

            let message = b"banana";
            let message_digest =
                openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

            // Prepare ECDSA with SHA-256 using digested_data
            let cp = CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
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

            // raw data -> sha256(raw data)
            let sig_raw = ecdsa_sign(&req_raw, &pkey).expect("ecdsa signature raw");
            // sha256 is provided
            let sig_digest = ecdsa_sign(&req_digest, &pkey).expect("ecdsa signature digest");

            // Verify signature - signature must be same raw data and digest data
            assert_eq!(
                sig_raw, sig_digest,
                "ECDSA signature must be same for raw and digest data"
            );
            results.push((sig_raw.clone(), sig_digest.clone()));
            assert_eq!(
                hex::encode(sig_raw),
                hex::encode(sig_digest),
                "ECDSA (sha256k) signature must be same for raw and digest data - hex"
            );
        }
        assert_eq!(2, results.len());
        let pair_result0 = results.first().expect("Pair results expected");
        let pair_result1 = results.last().expect("Pair results expected");
        assert_eq!(pair_result0.0, pair_result0.1);
        assert_eq!(pair_result1.0, pair_result1.1);
        // should not be the same p256 != k256
        assert_ne!(pair_result0.0, pair_result1.0);
        assert_ne!(pair_result0.0, pair_result1.1);
        assert_ne!(pair_result0.1, pair_result1.0);
        assert_ne!(pair_result0.1, pair_result1.1);
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn p256_rfc6979_matches_known_answer() {
        // RFC 6979 A.2.5 (P-256, SHA-256, message "sample").
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCDJr6nYRbp1FmtcIVdnsdaTTlDD2zbo\n\
                   mxJ7imIrEg9nIQ==\n\
                   -----END PRIVATE KEY-----";
        let ec_key = openssl::ec::EcKey::private_key_from_pem(pem.as_bytes()).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        // The linked libcrypto (3.6.2) must honour `nonce-type`; otherwise `ecdsa_sign`
        // would silently take the slow pure-Rust fallback.
        let mut ctx = PkeyCtx::new(&pkey).unwrap();
        ctx.sign_init().unwrap();
        assert!(set_deterministic_nonce(&mut ctx));
        let expected = hex::decode(
            "3046022100EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716022100F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
        )
        .unwrap();
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        };

        let req_data = Sign {
            data: Some(b"sample".to_vec().into()),
            cryptographic_parameters: Some(cp.clone()),
            ..Default::default()
        };
        assert_eq!(ecdsa_sign(&req_data, &pkey).unwrap(), expected);
        // The OpenSSL fast path itself (not the randomised fallback) must produce the KAT.
        assert_eq!(
            ecdsa_sign_rfc6979_openssl(&req_data, &pkey, MessageDigest::sha256()).unwrap(),
            Some(expected.clone())
        );

        let sha256 = openssl::hash::hash(MessageDigest::sha256(), b"sample").unwrap();
        let req_digest = Sign {
            digested_data: Some(sha256.to_vec()),
            cryptographic_parameters: Some(cp.clone()),
            ..Default::default()
        };
        assert_eq!(ecdsa_sign(&req_digest, &pkey).unwrap(), expected);

        // 20-byte digest: not a SHA-256 length, so OpenSSL's deterministic mode rejects it and
        // `ecdsa_sign` falls back to the randomised OpenSSL signer; the signature must verify.
        let sha1 = openssl::hash::hash(MessageDigest::sha1(), b"sample").unwrap();
        let req_sha1 = Sign {
            digested_data: Some(sha1.to_vec()),
            cryptographic_parameters: Some(cp),
            ..Default::default()
        };
        let sig1 = ecdsa_sign(&req_sha1, &pkey).unwrap();
        let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
        let cp_verify = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        };
        assert_eq!(
            ecdsa_verify(&public_key, &sha1, &sig1, &cp_verify, true).unwrap(),
            cosmian_kmip::kmip_2_1::kmip_types::ValidityIndicator::Valid
        );
    }
}
