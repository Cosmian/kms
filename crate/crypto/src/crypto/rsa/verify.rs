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
        // Mirrors sign_rsa_with_pkey's hash inference (crate/crypto/src/crypto/rsa/sign.rs):
        // non-FIPS builds support SHA-1 RSA-PKCS1v1.5 verification (FIPS providers reject
        // SHA-1 at the OpenSSL layer regardless).
        DigitalSignatureAlgorithm::SHA1WithRSAEncryption => MessageDigest::sha1(),
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
                            "Error verifying digest ({:?}) signature: {} bytes, data: {} bytes, error: {err:?}",
                            signature_algorithm,
                            signature.len(),
                            data.len()
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
                            "Error verifying raw ({:?}) signature: {} bytes, data: {} bytes, error: {err:?}",
                            signature_algorithm,
                            signature.len(),
                            data.len()
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
                        "Error verifying digest ({:?}) signature: {} bytes, data: {} bytes, error: {err:?}",
                        signature_algorithm,
                        signature.len(),
                        data.len()
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
                        "Error verifying ({:?}) signature: {} bytes, data: {} bytes, error: {err:?}",
                        signature_algorithm,
                        signature.len(),
                        data.len()
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

#[cfg(test)]
mod tests {
    use cosmian_kmip::{
        kmip_0::kmip_types::PaddingMethod,
        kmip_2_1::kmip_types::{CryptographicParameters, ValidityIndicator},
    };
    use openssl::{bn::BigNum, pkey::PKey, rsa::Rsa};

    use super::rsa_verify;

    /// RSA PKCS#1 v1.5 and RSASSA-PSS verification against Wycheproof and NIST ACVP vectors.
    #[test]
    fn test_rsa_verify_official_vectors() {
        #[cfg(not(feature = "non-fips"))]
        openssl::provider::Provider::load(None, "fips").unwrap();

        for g in crate::kat_vectors::rsa_verify_groups().unwrap() {
            let pk = PKey::from_rsa(
                Rsa::from_public_components(
                    BigNum::from_slice(&g.n).unwrap(),
                    BigNum::from_slice(&g.e).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
            let params = CryptographicParameters {
                padding_method: g.pss.then_some(PaddingMethod::PSS),
                hashing_algorithm: Some(g.hash),
                mask_generator_hashing_algorithm: g.pss.then_some(g.hash),
                ..Default::default()
            };
            for t in &g.tests {
                let verdict = rsa_verify(&pk, &t.msg, &t.sig, &params, false);
                if t.valid {
                    assert_eq!(
                        verdict.unwrap(),
                        ValidityIndicator::Valid,
                        "{} ({})",
                        t.id,
                        g.source
                    );
                } else {
                    assert!(
                        matches!(verdict, Err(_) | Ok(ValidityIndicator::Invalid)),
                        "{} ({})",
                        t.id,
                        g.source
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod log_tests {
    use std::{
        fmt::{Debug, Write as _},
        sync::{Arc, Mutex},
    };

    use cosmian_kmip::{
        kmip_0::kmip_types::HashingAlgorithm,
        kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm},
    };
    use cosmian_logger::reexport::tracing::{
        self, Event, Metadata,
        field::{Field, Visit},
        span::{Attributes, Id, Record},
    };
    use openssl::{pkey::PKey, rsa::Rsa};

    use super::rsa_verify;

    /// Collects every event field, formatted as `tracing` would record it.
    struct Capture(Arc<Mutex<String>>);

    struct Fields<'a>(&'a mut String);

    impl Visit for Fields<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _span: &Id, _values: &Record<'_>) {}

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            if let Ok(mut out) = self.0.lock() {
                event.record(&mut Fields(&mut out));
                out.push('\n');
            }
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn verify_error_log_has_no_signature_bytes() {
        let rsa = Rsa::generate(2048).unwrap();
        let public_key = PKey::public_key_from_pem(&rsa.public_key_to_pem().unwrap()).unwrap();
        let params = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        };
        let out = Arc::new(Mutex::new(String::new()));
        // wrong signature length: OpenSSL reports an error rather than a mismatch
        let verdict = tracing::subscriber::with_default(Capture(out.clone()), || {
            rsa_verify(&public_key, &[0xCD; 32], &[0xAB; 10], &params, true)
        });
        assert!(verdict.is_ok(), "{verdict:?}");
        let logs = out.lock().map(|l| l.clone()).unwrap_or_default();
        assert!(!logs.contains("ABABAB"), "signature bytes logged: {logs}");
        assert!(!logs.contains("CDCDCD"), "data bytes logged: {logs}");
        assert!(logs.contains("10 bytes"), "no length log: {logs}");
    }
}
