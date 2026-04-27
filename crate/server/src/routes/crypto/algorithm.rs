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
    enc.map_or_else(
        || build_alg_params(alg),
        |enc_val| build_enc_params(alg, enc_val),
    )
}

/// Build KMIP parameters for content-encryption operations (encrypt/decrypt).
fn build_enc_params(alg: &str, enc: &str) -> Result<CryptographicParameters, CryptoApiError> {
    if alg != "dir" {
        return Err(CryptoApiError::UnsupportedAlgorithm(format!(
            "Unsupported key management algorithm '{alg}'. /v1/crypto supports only 'dir'."
        )));
    }

    // padding_method is co-located with block_cipher_mode intentionally:
    // GCM is a stream-cipher mode and requires PaddingMethod::None; CBC-like modes
    // require PKCS5 padding.  Adding a new enc here without also setting the right
    // padding_method would be a silent crypto error.
    let (block_cipher_mode, padding_method) = match enc {
        "A128GCM" | "A192GCM" | "A256GCM" => (BlockCipherMode::GCM, PaddingMethod::None),
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Unsupported content-encryption algorithm '{other}'. /v1/crypto supports: A128GCM, A192GCM, A256GCM."
            )));
        }
    };

    Ok(CryptographicParameters {
        cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
        block_cipher_mode: Some(block_cipher_mode),
        padding_method: Some(padding_method),
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

    // Signature algorithms — returns (DigitalSignatureAlgorithm, Option<HashingAlgorithm>).
    //
    // hashing_algorithm is co-located with the DSA variant intentionally:
    // PSS requires an explicit hash; splitting into two separate match arms risks a
    // new PSS variant silently inheriting `None` and making the KMS pick an
    // undefined default hash.  Never split this into two separate match arms.
    let (digital_signature_algorithm, hashing_algorithm) = match alg {
        "RS256" => (DigitalSignatureAlgorithm::SHA256WithRSAEncryption, None),
        "RS384" => (DigitalSignatureAlgorithm::SHA384WithRSAEncryption, None),
        "RS512" => (DigitalSignatureAlgorithm::SHA512WithRSAEncryption, None),
        "PS256" => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA256),
        ),
        "PS384" => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA384),
        ),
        "PS512" => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA512),
        ),
        "ES256" => (DigitalSignatureAlgorithm::ECDSAWithSHA256, None),
        "ES384" => (DigitalSignatureAlgorithm::ECDSAWithSHA384, None),
        "ES512" => (DigitalSignatureAlgorithm::ECDSAWithSHA512, None),
        #[cfg(feature = "non-fips")]
        "EdDSA" | "MLDSA44" => {
            // These use CryptographicAlgorithm directly, not DigitalSignatureAlgorithm
            return build_pqc_params(alg);
        }
        other => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Unknown JOSE alg identifier '{other}'. /v1/crypto supports: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA (non-FIPS), MLDSA44 (non-FIPS), HS256, HS384, HS512."
            )));
        }
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

/// Build KMIP parameters for post-quantum / `EdDSA` algorithms (non-FIPS only).
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
