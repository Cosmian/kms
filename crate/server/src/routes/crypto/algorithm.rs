use std::{fmt, str::FromStr};

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
    },
};
use serde::{Deserialize, Serialize};

use super::CryptoApiError;

/// JOSE `alg` identifier per RFC 7518.
///
/// Covers key-management, signature, and MAC algorithms supported by `/v1/crypto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum JoseAlgorithm {
    /// Direct key agreement — no key wrapping (RFC 7518 §4.5)
    #[serde(rename = "dir")]
    Dir,
    // ── RSA PKCS#1 v1.5 signatures (RFC 7518 §3.3) ──
    RS256,
    RS384,
    RS512,
    // ── RSA PSS signatures (RFC 7518 §3.5) ──
    PS256,
    PS384,
    PS512,
    // ── ECDSA signatures (RFC 7518 §3.4) ──
    ES256,
    ES384,
    ES512,
    // ── HMAC (RFC 7518 §3.2) ──
    HS256,
    HS384,
    HS512,
    // ── Non-FIPS algorithms ──
    #[cfg(feature = "non-fips")]
    EdDSA,
    #[cfg(feature = "non-fips")]
    MLDSA44,
}

impl fmt::Display for JoseAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Dir => "dir",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            #[cfg(feature = "non-fips")]
            Self::EdDSA => "EdDSA",
            #[cfg(feature = "non-fips")]
            Self::MLDSA44 => "MLDSA44",
        };
        f.write_str(s)
    }
}

impl FromStr for JoseAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dir" => Ok(Self::Dir),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            #[cfg(feature = "non-fips")]
            "EdDSA" => Ok(Self::EdDSA),
            #[cfg(feature = "non-fips")]
            "MLDSA44" => Ok(Self::MLDSA44),
            other => Err(format!(
                "Unknown JOSE alg identifier '{other}'. Supported: dir, RS256, RS384, RS512, \
                 PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512, \
                 EdDSA (non-FIPS), MLDSA44 (non-FIPS)."
            )),
        }
    }
}

/// JOSE `enc` content-encryption algorithm identifier (RFC 7518 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum JoseEncAlgorithm {
    A128GCM,
    A192GCM,
    A256GCM,
}

impl fmt::Display for JoseEncAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::A128GCM => "A128GCM",
            Self::A192GCM => "A192GCM",
            Self::A256GCM => "A256GCM",
        };
        f.write_str(s)
    }
}

impl FromStr for JoseEncAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A128GCM" => Ok(Self::A128GCM),
            "A192GCM" => Ok(Self::A192GCM),
            "A256GCM" => Ok(Self::A256GCM),
            other => Err(format!(
                "Unsupported content-encryption algorithm '{other}'. \
                 Supported: A128GCM, A192GCM, A256GCM."
            )),
        }
    }
}

/// Derive KMIP `CryptographicParameters` from JOSE algorithm identifiers.
///
/// For encrypt/decrypt, pass both `alg` and `enc`.
/// For sign/verify, pass only `alg` (set `enc = None`).
/// For MAC, pass only `alg` (set `enc = None`).
pub(crate) fn jose_to_kmip_params(
    alg: JoseAlgorithm,
    enc: Option<JoseEncAlgorithm>,
) -> Result<CryptographicParameters, CryptoApiError> {
    enc.map_or_else(
        || build_alg_params(alg),
        |enc_val| build_enc_params(alg, enc_val),
    )
}

/// Build KMIP parameters for content-encryption operations (encrypt/decrypt).
fn build_enc_params(
    alg: JoseAlgorithm,
    enc: JoseEncAlgorithm,
) -> Result<CryptographicParameters, CryptoApiError> {
    if alg != JoseAlgorithm::Dir {
        return Err(CryptoApiError::UnsupportedAlgorithm(format!(
            "Unsupported key management algorithm '{alg}'. /v1/crypto supports only 'dir'."
        )));
    }

    // padding_method is co-located with block_cipher_mode intentionally:
    // GCM is a stream-cipher mode and requires PaddingMethod::None; CBC-like modes
    // require PKCS5 padding.  Adding a new enc here without also setting the right
    // padding_method would be a silent crypto error.
    let (block_cipher_mode, padding_method) = match enc {
        JoseEncAlgorithm::A128GCM | JoseEncAlgorithm::A192GCM | JoseEncAlgorithm::A256GCM => {
            (BlockCipherMode::GCM, PaddingMethod::None)
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
fn build_alg_params(alg: JoseAlgorithm) -> Result<CryptographicParameters, CryptoApiError> {
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
        JoseAlgorithm::RS256 => (DigitalSignatureAlgorithm::SHA256WithRSAEncryption, None),
        JoseAlgorithm::RS384 => (DigitalSignatureAlgorithm::SHA384WithRSAEncryption, None),
        JoseAlgorithm::RS512 => (DigitalSignatureAlgorithm::SHA512WithRSAEncryption, None),
        JoseAlgorithm::PS256 => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA256),
        ),
        JoseAlgorithm::PS384 => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA384),
        ),
        JoseAlgorithm::PS512 => (
            DigitalSignatureAlgorithm::RSASSAPSS,
            Some(HashingAlgorithm::SHA512),
        ),
        JoseAlgorithm::ES256 => (DigitalSignatureAlgorithm::ECDSAWithSHA256, None),
        JoseAlgorithm::ES384 => (DigitalSignatureAlgorithm::ECDSAWithSHA384, None),
        JoseAlgorithm::ES512 => (DigitalSignatureAlgorithm::ECDSAWithSHA512, None),
        #[cfg(feature = "non-fips")]
        JoseAlgorithm::EdDSA | JoseAlgorithm::MLDSA44 => {
            // These use CryptographicAlgorithm directly, not DigitalSignatureAlgorithm
            return build_pqc_params(alg);
        }
        // Dir and HS* (already handled by try_mac_params) are not signature algorithms.
        _ => {
            return Err(CryptoApiError::UnsupportedAlgorithm(format!(
                "Algorithm '{alg}' is not a signature algorithm."
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
fn try_mac_params(alg: JoseAlgorithm) -> Option<CryptographicParameters> {
    let (crypto_alg, hashing_alg) = match alg {
        JoseAlgorithm::HS256 => (CryptographicAlgorithm::HMACSHA256, HashingAlgorithm::SHA256),
        JoseAlgorithm::HS384 => (CryptographicAlgorithm::HMACSHA384, HashingAlgorithm::SHA384),
        JoseAlgorithm::HS512 => (CryptographicAlgorithm::HMACSHA512, HashingAlgorithm::SHA512),
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
fn build_pqc_params(alg: JoseAlgorithm) -> Result<CryptographicParameters, CryptoApiError> {
    let crypto_alg = match alg {
        JoseAlgorithm::EdDSA => CryptographicAlgorithm::Ed25519,
        JoseAlgorithm::MLDSA44 => CryptographicAlgorithm::MLDSA_44,
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
