use cosmian_kmip::kmip_2_1::{kmip_operations::Sign, kmip_types::DigitalSignatureAlgorithm};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
};

use crate::error::CryptoError;

/// ECDSA signature helper implementing RFC6979 determinism for NIST P-256 + SHA-256 in non-fips builds,
/// falling back to OpenSSL Signer otherwise.
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

    // RFC6979 path for non-fips builds
    #[cfg(feature = "non-fips")]
    {
        if digital_signature_algorithm == DigitalSignatureAlgorithm::ECDSAWithSHA256 {
            if let Ok(ec_key) = private_key.ec_key() {
                if matches!(
                    ec_key.group().curve_name(),
                    Some(openssl::nid::Nid::X9_62_PRIME256V1)
                ) {
                    use cosmian_crypto_core::reexport::signature::hazmat::PrehashSigner;
                    use p256::ecdsa::{Signature, SigningKey, signature::DigestSigner};
                    use sha2::{Digest, Sha256};

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
                    if d_bytes.len() < 32 {
                        let mut padded = vec![0_u8; 32 - d_bytes.len()];
                        padded.extend_from_slice(&d_bytes);
                        d_bytes = padded;
                    } else if d_bytes.len() > 32 {
                        let start = d_bytes.len().saturating_sub(32);
                        d_bytes = d_bytes.get(start..).unwrap_or(&d_bytes[..]).to_vec();
                    }

                    let signing_key = SigningKey::from_slice(&d_bytes).map_err(|e| {
                        CryptoError::NotSupported(format!("p256 SigningKey error: {e}"))
                    })?;

                    let signature: Signature = if request.digested_data.is_some() {
                        signing_key.sign_prehash(&msg_bytes).map_err(|e| {
                            CryptoError::NotSupported(format!("Sign data pre hash error: {e}"))
                        })?
                    } else if request.data.is_some() {
                        let mut hasher = Sha256::new();
                        hasher.update(&msg_bytes);
                        signing_key.sign_digest(hasher)
                    } else {
                        return Err(CryptoError::NotSupported(
                            "Request data not supported".to_owned(),
                        ));
                    };
                    let sig_der = signature.to_der();
                    return Ok(sig_der.as_bytes().to_vec());
                }
            }
        }
    }

    // Default OpenSSL path
    let mut signer = Signer::new(digest, private_key)?;
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
            unique_identifier: None,
            data: Some(b"ed25519 deterministic".to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
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
            unique_identifier: None,
            data: Some(b"ed448 deterministic".to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
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
            unique_identifier: None,
            data: Some(b"ecdsa nondeterminism test".to_vec().into()),
            digested_data: None,
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
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
                unique_identifier: None,
                data: Some(b"supported curves signing".to_vec().into()),
                digested_data: None,
                cryptographic_parameters: Some(cp.clone()),
                init_indicator: None,
                final_indicator: None,
                correlation_value: None,
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
            unique_identifier: None,
            data: None,
            digested_data: Some(digest.to_vec()),
            cryptographic_parameters: Some(cp),
            init_indicator: None,
            final_indicator: None,
            correlation_value: None,
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
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let ec_key =
            openssl::ec::EcKey::generate(&group).unwrap_or_else(|e| panic!("ec key gen: {e}"));
        let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey: {e}"));

        let message = b"banana";
        let message_digest = openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

        // Prepare ECDSA with SHA-256 using digested_data
        let cp = CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
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

        // raw data -> sha256(raw data)
        let sig_raw = ecdsa_sign(&req_raw, &pkey).expect("ecdsa signature raw");
        // sha256 is provided
        let sig_digest = ecdsa_sign(&req_digest, &pkey).expect("ecdsa signature digest");

        // Verify signature - signature must be same raw data and digest data
        assert_eq!(
            sig_raw, sig_digest,
            "ECDSA signature must be same for raw and digest data"
        );
    }
}
