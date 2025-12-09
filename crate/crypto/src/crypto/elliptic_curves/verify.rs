use cosmian_kmip::{
    kmip_0::kmip_types::HashingAlgorithm as KmipHash,
    kmip_2_1::kmip_types::{CryptographicParameters, DigitalSignatureAlgorithm, ValidityIndicator},
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sign::Verifier,
};

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

pub fn ed25519_verify(
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
