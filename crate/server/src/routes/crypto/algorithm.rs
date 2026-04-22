use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
    },
};

use super::CryptoApiError;

/// Derive KMIP `CryptographicParameters` from JOSE algorithm identifiers.
///
/// For encrypt/decrypt, pass both `alg` and `enc`.
/// For sign/verify, pass only `alg` (set `enc = None`).
/// For MAC, pass only `alg` (set `enc = None`).
pub(crate) fn jose_to_kmip_params(
    alg: &str,
    enc: Option<&str>,
) -> Result<CryptographicParameters, CryptoApiError> {
    match enc {
        Some(enc_val) => build_enc_params(alg, enc_val),
        None => build_alg_params(alg),
    }
}

/// Build KMIP parameters for content-encryption operations (encrypt/decrypt).
fn build_enc_params(alg: &str, enc: &str) -> Result<CryptographicParameters, CryptoApiError> {
    if alg != "dir" {
        return Err(CryptoApiError::UnsupportedAlgorithm(format!(
            "Unsupported key management algorithm '{alg}'. Phase 1 supports only 'dir'."
        )));
    }

    let block_cipher_mode = match enc {
        "A128GCM" | "A192GCM" | "A256GCM" => BlockCipherMode::GCM,
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Unsupported content-encryption algorithm '{other}'. Phase 1 supports: A128GCM, A192GCM, A256GCM."
            )));
        }
    };

    Ok(CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(block_cipher_mode),
        padding_method: Some(PaddingMethod::None),
        // tag_length is in bytes; JOSE GCM always uses 128-bit (16-byte) authentication tag
        tag_length: Some(16),
        ..Default::default()
    })
}

/// Build KMIP parameters for sign/verify operations.
fn build_alg_params(alg: &str) -> Result<CryptographicParameters, CryptoApiError> {
    // MAC algorithms
    if let Some(params) = try_mac_params(alg) {
        return Ok(params);
    }

    // Signature algorithms
    let digital_signature_algorithm = match alg {
        "RS256" => DigitalSignatureAlgorithm::SHA256WithRSAEncryption,
        "RS384" => DigitalSignatureAlgorithm::SHA384WithRSAEncryption,
        "RS512" => DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
        "PS256" => DigitalSignatureAlgorithm::RSASSAPSS,
        "PS384" => DigitalSignatureAlgorithm::RSASSAPSS,
        "PS512" => DigitalSignatureAlgorithm::RSASSAPSS,
        "ES256" => DigitalSignatureAlgorithm::ECDSAWithSHA256,
        "ES384" => DigitalSignatureAlgorithm::ECDSAWithSHA384,
        "ES512" => DigitalSignatureAlgorithm::ECDSAWithSHA512,
        #[cfg(feature = "non-fips")]
        "EdDSA" | "MLDSA44" => {
            // These use CryptographicAlgorithm directly, not DigitalSignatureAlgorithm
            return build_pqc_params(alg);
        }
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Unknown JOSE alg identifier '{other}'. Supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA (non-FIPS), MLDSA44 (non-FIPS), HS256, HS384, HS512."
            )));
        }
    };

    // PSS variants need an explicit hashing_algorithm
    let hashing_algorithm = match alg {
        "PS256" => Some(HashingAlgorithm::SHA256),
        "PS384" => Some(HashingAlgorithm::SHA384),
        "PS512" => Some(HashingAlgorithm::SHA512),
        _ => None,
    };

    Ok(CryptographicParameters {
        digital_signature_algorithm: Some(digital_signature_algorithm),
        hashing_algorithm,
        ..Default::default()
    })
}

/// Build KMIP parameters for MAC operations.
fn try_mac_params(alg: &str) -> Option<CryptographicParameters> {
    let (crypto_alg, hashing_alg) = match alg {
        "HS256" => (CryptographicAlgorithm::HMACSHA256, HashingAlgorithm::SHA256),
        "HS384" => (CryptographicAlgorithm::HMACSHA384, HashingAlgorithm::SHA384),
        "HS512" => (CryptographicAlgorithm::HMACSHA512, HashingAlgorithm::SHA512),
        _ => return None,
    };

    Some(CryptographicParameters {
        cryptographic_algorithm: Some(crypto_alg),
        hashing_algorithm: Some(hashing_alg),
        ..Default::default()
    })
}

/// Build KMIP parameters for post-quantum / EdDSA algorithms (non-FIPS only).
#[cfg(feature = "non-fips")]
fn build_pqc_params(alg: &str) -> Result<CryptographicParameters, CryptoApiError> {
    let crypto_alg = match alg {
        "EdDSA" => CryptographicAlgorithm::Ed25519,
        "MLDSA44" => CryptographicAlgorithm::MLDSA_44,
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Unknown PQC/EdDSA alg identifier '{other}'."
            )));
        }
    };

    Ok(CryptographicParameters {
        cryptographic_algorithm: Some(crypto_alg),
        ..Default::default()
    })
}
