use cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm as KmipHash,
    kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm, ValidityIndicator},
};
#[cfg(feature = "non-fips")]
use k256::ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey};
#[cfg(feature = "non-fips")]
use openssl::bn::BigNumContext;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sign::Verifier,
};
#[cfg(feature = "non-fips")]
use p256::ecdsa::{
    Signature as P256Signature, VerifyingKey as P256VerifyingKey,
    signature::hazmat::PrehashVerifier as _,
};

#[cfg(feature = "non-fips")]
use crate::crypto::elliptic_curves::VERIFY_256_DATA_LENGTH;
use crate::error::{CryptoError, result::CryptoResult};

pub fn ecdsa_verify(
    verification_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
    crypto_params: &CryptographicParameters,
    is_digested: bool,
) -> CryptoResult<ValidityIndicator> {
    let dsa = if let Some(dsa) = crypto_params.digital_signature_algorithm {
        dsa
    } else {
        match crypto_params.hashing_algorithm.unwrap_or(KmipHash::SHA256) {
            KmipHash::SHA256 => DigitalSignatureAlgorithm::ECDSAWithSHA256,
            KmipHash::SHA384 => DigitalSignatureAlgorithm::ECDSAWithSHA384,
            KmipHash::SHA512 => DigitalSignatureAlgorithm::ECDSAWithSHA512,
            h => {
                return Err(CryptoError::NotSupported(format!(
                    "ECDSA unsupported hash: {h:?}"
                )));
            }
        }
    };

    let md = match dsa {
        DigitalSignatureAlgorithm::ECDSAWithSHA256 => MessageDigest::sha256(),
        DigitalSignatureAlgorithm::ECDSAWithSHA384 => MessageDigest::sha384(),
        DigitalSignatureAlgorithm::ECDSAWithSHA512 => MessageDigest::sha512(),
        _ => {
            return Err(CryptoError::NotSupported(format!(
                "ECDSA verify not supported: {dsa:?}"
            )));
        }
    };

    // RFC6979 path for non-fips builds
    #[cfg(feature = "non-fips")]
    {
        if dsa == DigitalSignatureAlgorithm::ECDSAWithSHA256 {
            if let Ok(ec_key) = verification_key.ec_key() {
                let curve_nid = ec_key.group().curve_name();
                let is_p256 = curve_nid == Some(openssl::nid::Nid::X9_62_PRIME256V1);
                let is_k256 = curve_nid == Some(openssl::nid::Nid::SECP256K1);
                if is_digested && (is_p256 || is_k256) {
                    if data.len() != VERIFY_256_DATA_LENGTH {
                        return Err(CryptoError::InvalidSize(format!(
                            "SHA-256 digest for verify must be exactly {} bytes, is {} bytes.",
                            VERIFY_256_DATA_LENGTH,
                            data.len()
                        )));
                    }
                    let mut ctx = BigNumContext::new()?;
                    let pub_key_sec1 = ec_key.public_key().to_bytes(
                        ec_key.group(),
                        openssl::ec::PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )?;
                    let is_valid = if is_p256 {
                        let verifying_key = P256VerifyingKey::from_sec1_bytes(&pub_key_sec1)
                            .map_err(|e| {
                                CryptoError::ConversionError(format!(
                                    "Verify - invalid P256 public key: {e}"
                                ))
                            })?;
                        let signature = P256Signature::from_der(signature).map_err(|e| {
                            CryptoError::ConversionError(format!(
                                "Verify - invalid ECDSA P256 signature: {e}"
                            ))
                        })?;
                        verifying_key.verify_prehash(data, &signature).is_ok()
                    } else {
                        let verifying_key = K256VerifyingKey::from_sec1_bytes(&pub_key_sec1)
                            .map_err(|e| {
                                CryptoError::ConversionError(format!(
                                    "Verify - invalid K256 public key: {e}"
                                ))
                            })?;
                        let signature = K256Signature::from_der(signature).map_err(|e| {
                            CryptoError::ConversionError(format!(
                                "Verify - invalid ECDSA K256 signature: {e}"
                            ))
                        })?;
                        verifying_key.verify_prehash(data, &signature).is_ok()
                    };
                    return Ok(if is_valid {
                        ValidityIndicator::Valid
                    } else {
                        ValidityIndicator::Invalid
                    });
                }
            }
        }
    }

    let mut verifier = if is_digested {
        Verifier::new_without_digest(verification_key)?
    } else {
        Verifier::new(md, verification_key)?
    };
    let ok = verifier.verify_oneshot(signature, data)?;
    Ok(if ok {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    })
}

pub fn ed_verify(
    verification_key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
) -> CryptoResult<ValidityIndicator> {
    let mut verifier = Verifier::new_without_digest(verification_key)?;
    let ok = verifier.verify_oneshot(signature, data)?;
    Ok(if ok {
        ValidityIndicator::Valid
    } else {
        ValidityIndicator::Invalid
    })
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    #[cfg(feature = "non-fips")]
    use {
        super::*, crate::crypto::elliptic_curves::operation::ecdsa_sign,
        cosmian_kmip::kmip_2_1::kmip_operations::Sign,
    };

    #[cfg(feature = "non-fips")]
    #[test]
    fn ecdsa_sign_verify_raw_digest_sha256() {
        let group_p256 = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let group_k256 = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)
            .unwrap_or_else(|e| panic!("ec group: {e}"));
        let groups = vec![group_p256, group_k256];
        for group in groups {
            let ec_key =
                openssl::ec::EcKey::generate(&group).unwrap_or_else(|e| panic!("ec key gen: {e}"));
            let pkey = PKey::from_ec_key(ec_key).unwrap_or_else(|e| panic!("pkey: {e}"));

            let message = b"ecdsa raw/digest testing - both P256 and K256";
            let message_digest =
                openssl::hash::hash(MessageDigest::sha256(), message).expect("digest");

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
            let signature_raw = ecdsa_sign(&req_raw, &pkey).expect("ecdsa signature raw");
            // sha256 is provided
            let signature_digest = ecdsa_sign(&req_digest, &pkey).expect("ecdsa signature digest");

            // Verify signature - signature must be same raw data and digest data
            assert_eq!(
                signature_raw, signature_digest,
                "ECDSA signature must be same for raw and digest data"
            );

            // Verify signature using ecdsa_verify helper with prehashed input
            let cp_verify = CryptographicParameters {
                digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
                hashing_algorithm: Some(KmipHash::SHA256),
                ..Default::default()
            };
            let public_key = PKey::public_key_from_pem(&pkey.public_key_to_pem().unwrap()).unwrap();
            let valid_raw = ecdsa_verify(
                &public_key,
                message.as_ref(),
                &signature_raw,
                &cp_verify,
                false,
            )
            .expect("ecdsa_verify raw");

            let valid_digest = ecdsa_verify(
                &public_key,
                &message_digest,
                &signature_digest,
                &cp_verify,
                true,
            )
            .expect("ecdsa_verify digest");

            assert_eq!(
                valid_raw,
                ValidityIndicator::Valid,
                "ECDSA signature must verify for raw"
            );
            assert_eq!(
                valid_digest,
                ValidityIndicator::Valid,
                "ECDSA signature must verify for digest data"
            );
        }
    }
}
