//! # Crypto Oracle
//! The crypto oracle interface should be implemented by plugins that provide cryptographic
//! capabilities (encryption, decryption, signing) for a given key prefix.
//! Once implemented, a crypto oracle must be registered on the KMS instance for that prefix.
//! HSMs that implement the `HSM` interface have a blanket implementation of this interface called
//! `HsmCryptoOracle`.
use async_trait::async_trait;
use cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::kmip_types::{
        CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
    },
};
use zeroize::Zeroizing;

use crate::{InterfaceError, KeyType, error::InterfaceResult};

#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub key_type: KeyType,
    pub key_length_in_bits: usize,
    pub sensitive: bool,
    pub id: String,
    /// Curve metadata for EC-family keys, including Edwards/Montgomery curves when enabled.
    pub curve: Option<crate::EcCurve>,
    /// PKCS#11 `CKA_START_DATE` — when the key became active.
    pub start_date: Option<time::Date>,
    /// PKCS#11 `CKA_END_DATE` — when the key is due for rotation.
    pub end_date: Option<time::Date>,
    /// Keyset name parsed from `CKA_LABEL` (`rotate_name::generation::key_id[@latest]`).
    /// `None` means the key has no keyset membership.
    pub rotate_name: Option<String>,
    /// Keyset generation counter parsed from `CKA_LABEL`.
    pub rotate_generation: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    AesCbc,
    AesGcm,
    RsaPkcsV15,
    RsaOaepSha256,
    RsaOaepSha1,
}

impl CryptoAlgorithm {
    pub fn from_kmip(value: &CryptographicParameters) -> Result<Option<Self>, InterfaceError> {
        value
            .cryptographic_algorithm
            .map_or(Ok(None), |algorithm| match algorithm {
                cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::AES => value
                    .block_cipher_mode
                    .map_or(
                        Ok(Some(Self::AesGcm)),
                        |block_cipher_mode| match block_cipher_mode {
                            BlockCipherMode::CBC => Ok(Some(Self::AesCbc)),
                            BlockCipherMode::GCM => Ok(Some(Self::AesGcm)),
                            bcm => Err(InterfaceError::Default(format!(
                                "Block cipher mode: {bcm:?} not supported for AES",
                            ))),
                        },
                    ),
                cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm::RSA => value
                    .padding_method
                    .map_or(Ok(Some(Self::RsaOaepSha256)), |padding_method| {
                        match padding_method {
                            PaddingMethod::OAEP => match value.hashing_algorithm {
                                Some(HashingAlgorithm::SHA1) => Ok(Some(Self::RsaOaepSha1)),
                                _ => Ok(Some(Self::RsaOaepSha256)), // this is debatable
                            },
                            PaddingMethod::PKCS1v15 => Ok(Some(Self::RsaPkcsV15)),
                            pm => Err(InterfaceError::Default(format!(
                                "Padding method: {pm:?} not supported for RSA",
                            ))),
                        }
                    }),
                x => Err(InterfaceError::Default(format!(
                    "Cryptographic algorithm: {x:?} not supported",
                ))),
            })
    }

    /// Selects a default AES algorithm from the provided list of supported algorithms.
    ///
    /// Preference order:
    /// 1. `AesGcm`
    /// 2. `AesCbc`
    pub fn get_aes_algorithm(supported_algorithms: &[Self]) -> InterfaceResult<Self> {
        if supported_algorithms.contains(&Self::AesGcm) {
            return Ok(Self::AesGcm);
        } else if supported_algorithms.contains(&Self::AesCbc) {
            return Ok(Self::AesCbc);
        }
        Err(InterfaceError::InvalidRequest(
            "AES not supported".to_owned(),
        ))
    }

    /// Selects a default RSA algorithm from the provided list of supported algorithms.
    ///
    /// Preference order:
    /// 1. `RsaOaepSha256`
    /// 2. `RsaOaepSha1`
    /// 3. `RsaPkcsV15`
    pub fn get_rsa_algorithm(supported_algorithms: &[Self]) -> InterfaceResult<Self> {
        if supported_algorithms.contains(&Self::RsaOaepSha256) {
            return Ok(Self::RsaOaepSha256);
        } else if supported_algorithms.contains(&Self::RsaOaepSha1) {
            return Ok(Self::RsaOaepSha1);
        } else if supported_algorithms.contains(&Self::RsaPkcsV15) {
            return Ok(Self::RsaPkcsV15);
        }
        Err(InterfaceError::InvalidRequest(
            "RSA not supported".to_owned(),
        ))
    }
}

/// Signing algorithms supported by the crypto oracle / HSM.
///
/// Each variant maps directly to a PKCS#11 signing mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// `CKM_RSA_PKCS` (raw PKCS#1 v1.5 — caller hashes)
    RsaPkcsV15,
    /// `CKM_RSA_PKCS` over a caller-supplied digest, wrapped as a PKCS#1 v1.5 `DigestInfo`.
    RsaPkcsV15Digest { hashing_algorithm: HashingAlgorithm },
    /// `CKM_SHA1_RSA_PKCS`
    Sha1WithRsa,
    /// `CKM_SHA256_RSA_PKCS`
    Sha256WithRsa,
    /// `CKM_SHA384_RSA_PKCS`
    Sha384WithRsa,
    /// `CKM_SHA512_RSA_PKCS`
    Sha512WithRsa,
    /// RSA-PSS signing. When `prehashed` is true the caller already supplied the digest, so HSM
    /// backends must use a raw pre-hash mechanism (e.g. `CKM_RSA_PKCS_PSS`) instead of a
    /// hashing mechanism such as `CKM_SHA256_RSA_PKCS_PSS`.
    RsaPss {
        hashing_algorithm: HashingAlgorithm,
        mask_generator_hashing_algorithm: HashingAlgorithm,
        salt_length: Option<u32>,
        prehashed: bool,
    },
    /// ECDSA signing. When `prehashed` is true the caller already supplied the digest, so HSM
    /// backends must use raw `CKM_ECDSA` instead of `CKM_ECDSA_SHA*`.
    Ecdsa {
        hashing_algorithm: HashingAlgorithm,
        prehashed: bool,
    },
    /// `CKM_EDDSA` over an Ed25519 private key (pure `EdDSA`, no pre-hashing). Non-FIPS: mirrors
    /// the gating of `Ed25519` signing in `crate::crypto::elliptic_curves::sign` (issue #1157).
    #[cfg(feature = "non-fips")]
    Ed25519,
    /// `CKM_EDDSA` over an Ed448 private key. Non-FIPS: see `Ed25519` above.
    #[cfg(feature = "non-fips")]
    Ed448,
}

impl SigningAlgorithm {
    /// Derive a `SigningAlgorithm` from KMIP `CryptographicParameters`.
    ///
    /// Resolution order:
    /// 1. `digital_signature_algorithm` (most explicit)
    /// 2. `cryptographic_algorithm` + `padding_method` + `hashing_algorithm`
    /// 3. fallback to the key's stored algorithm when request parameters are absent
    pub fn from_kmip(
        params: Option<&CryptographicParameters>,
        key_type: KeyType,
        curve: Option<crate::EcCurve>,
        input_is_digest: bool,
        input_len: usize,
    ) -> Result<Self, InterfaceError> {
        let Some(params) = params else {
            return Self::default_for_key(key_type, curve, input_is_digest, input_len);
        };

        // 1. explicit digital_signature_algorithm
        if let Some(dsa) = &params.digital_signature_algorithm {
            // Reject up-front any explicit algorithm family that does not match the actual key
            // type: without this check an RSA key requested with an ECDSA algorithm (or vice
            // versa) would fall through to the HSM, which rejects the mismatched mechanism with
            // an opaque low-level PKCS#11 return code instead of a clear KMIP error.
            let is_rsa_dsa = matches!(
                dsa,
                DigitalSignatureAlgorithm::SHA1WithRSAEncryption
                    | DigitalSignatureAlgorithm::SHA224WithRSAEncryption
                    | DigitalSignatureAlgorithm::SHA256WithRSAEncryption
                    | DigitalSignatureAlgorithm::SHA384WithRSAEncryption
                    | DigitalSignatureAlgorithm::SHA512WithRSAEncryption
                    | DigitalSignatureAlgorithm::RSASSAPSS
            );
            let is_ecdsa = matches!(
                dsa,
                DigitalSignatureAlgorithm::ECDSAWithSHA256
                    | DigitalSignatureAlgorithm::ECDSAWithSHA384
                    | DigitalSignatureAlgorithm::ECDSAWithSHA512
            );
            if (is_rsa_dsa && key_type != KeyType::RsaPrivateKey)
                || (is_ecdsa && key_type != KeyType::EcPrivateKey)
            {
                return Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported digital signature algorithm for HSM signing: {dsa:?}"
                )));
            }

            return match dsa {
                DigitalSignatureAlgorithm::SHA1WithRSAEncryption => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA1, input_is_digest)
                }
                DigitalSignatureAlgorithm::SHA224WithRSAEncryption
                | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA256, input_is_digest)
                }
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA384, input_is_digest)
                }
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA512, input_is_digest)
                }
                DigitalSignatureAlgorithm::RSASSAPSS => Self::rsa_pss_from_params(
                    params.hashing_algorithm,
                    params.mask_generator_hashing_algorithm,
                    params.salt_length,
                    input_is_digest,
                ),
                DigitalSignatureAlgorithm::ECDSAWithSHA256 => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: input_is_digest,
                }),
                DigitalSignatureAlgorithm::ECDSAWithSHA384 => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA384,
                    prehashed: input_is_digest,
                }),
                DigitalSignatureAlgorithm::ECDSAWithSHA512 => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA512,
                    prehashed: input_is_digest,
                }),
                other => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported digital signature algorithm for HSM signing: {other:?}"
                ))),
            };
        }

        // 2. cryptographic_algorithm alone (EdDSA — KMIP has no DigitalSignatureAlgorithm
        // variant for Ed25519/Ed448; the algorithm is carried directly by
        // CryptographicAlgorithm, and `EdDSA` never takes a separate hashing_algorithm or
        // padding_method). Non-FIPS: mirrors the software `EdDSA` signing gating (issue #1157).
        #[cfg(feature = "non-fips")]
        {
            if params.cryptographic_algorithm == Some(CryptographicAlgorithm::Ed25519) {
                if input_is_digest {
                    return Err(InterfaceError::InvalidRequest(
                        "Ed25519 does not support KMIP digested_data signing via CKM_EDDSA"
                            .to_owned(),
                    ));
                }
                return Ok(Self::Ed25519);
            }
            if params.cryptographic_algorithm == Some(CryptographicAlgorithm::Ed448) {
                if input_is_digest {
                    return Err(InterfaceError::InvalidRequest(
                        "Ed448 does not support KMIP digested_data signing via CKM_EDDSA"
                            .to_owned(),
                    ));
                }
                return Ok(Self::Ed448);
            }
        }

        // 3. cryptographic_algorithm + hashing_algorithm (EC/ECDSA)
        if matches!(
            params.cryptographic_algorithm,
            Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA)
        ) {
            return match params.hashing_algorithm {
                Some(HashingAlgorithm::SHA256) | None => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: input_is_digest,
                }),
                Some(HashingAlgorithm::SHA384) => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA384,
                    prehashed: input_is_digest,
                }),
                Some(HashingAlgorithm::SHA512) => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA512,
                    prehashed: input_is_digest,
                }),
                Some(other) => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for ECDSA signing: {other:?}"
                ))),
            };
        }

        // 2. cryptographic_algorithm + padding_method + hashing_algorithm
        if params.cryptographic_algorithm == Some(CryptographicAlgorithm::RSA) {
            if params.padding_method == Some(PaddingMethod::PSS) {
                return Self::rsa_pss_from_params(
                    params.hashing_algorithm,
                    params.mask_generator_hashing_algorithm,
                    params.salt_length,
                    input_is_digest,
                );
            }
            return match params.hashing_algorithm {
                Some(HashingAlgorithm::SHA1) => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA1, input_is_digest)
                }
                Some(HashingAlgorithm::SHA256) | None => {
                    let hash = params
                        .hashing_algorithm
                        .or_else(|| Self::infer_hash_from_digest_len(input_len))
                        .unwrap_or(HashingAlgorithm::SHA256);
                    Self::rsa_pkcs1_from_hash(hash, input_is_digest)
                }
                Some(HashingAlgorithm::SHA384) => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA384, input_is_digest)
                }
                Some(HashingAlgorithm::SHA512) => {
                    Self::rsa_pkcs1_from_hash(HashingAlgorithm::SHA512, input_is_digest)
                }
                Some(other) => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for RSA signing: {other:?}"
                ))),
            };
        }

        Self::default_for_key(key_type, curve, input_is_digest, input_len)
    }

    fn default_for_key(
        key_type: KeyType,
        curve: Option<crate::EcCurve>,
        input_is_digest: bool,
        input_len: usize,
    ) -> Result<Self, InterfaceError> {
        match key_type {
            KeyType::RsaPrivateKey => {
                let hash =
                    Self::infer_hash_from_digest_len(input_len).unwrap_or(HashingAlgorithm::SHA256);
                Self::rsa_pkcs1_from_hash(hash, input_is_digest)
            }
            KeyType::EcPrivateKey => match curve {
                Some(crate::EcCurve::P384) => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA384,
                    prehashed: input_is_digest,
                }),
                Some(crate::EcCurve::P521) => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA512,
                    prehashed: input_is_digest,
                }),
                #[cfg(feature = "non-fips")]
                Some(crate::EcCurve::Ed25519) => {
                    if input_is_digest {
                        Err(InterfaceError::InvalidRequest(
                            "Ed25519 does not support KMIP digested_data signing via CKM_EDDSA"
                                .to_owned(),
                        ))
                    } else {
                        Ok(Self::Ed25519)
                    }
                }
                #[cfg(feature = "non-fips")]
                Some(crate::EcCurve::Ed448) => {
                    if input_is_digest {
                        Err(InterfaceError::InvalidRequest(
                            "Ed448 does not support KMIP digested_data signing via CKM_EDDSA"
                                .to_owned(),
                        ))
                    } else {
                        Ok(Self::Ed448)
                    }
                }
                #[cfg(feature = "non-fips")]
                Some(crate::EcCurve::X25519) => Err(InterfaceError::InvalidRequest(
                    "X25519 keys support key agreement, not signing".to_owned(),
                )),
                Some(crate::EcCurve::P224 | crate::EcCurve::P256) | None => Ok(Self::Ecdsa {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    prehashed: input_is_digest,
                }),
            },
            other => Err(InterfaceError::InvalidRequest(format!(
                "Unsupported private key type for HSM signing: {other:?}"
            ))),
        }
    }

    fn rsa_pkcs1_from_hash(
        hashing_algorithm: HashingAlgorithm,
        input_is_digest: bool,
    ) -> Result<Self, InterfaceError> {
        if input_is_digest {
            return match hashing_algorithm {
                HashingAlgorithm::SHA1
                | HashingAlgorithm::SHA256
                | HashingAlgorithm::SHA384
                | HashingAlgorithm::SHA512 => Ok(Self::RsaPkcsV15Digest { hashing_algorithm }),
                other => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for RSA PKCS#1 v1.5 signing: {other:?}"
                ))),
            };
        }
        match hashing_algorithm {
            HashingAlgorithm::SHA1 => Ok(Self::Sha1WithRsa),
            HashingAlgorithm::SHA256 => Ok(Self::Sha256WithRsa),
            HashingAlgorithm::SHA384 => Ok(Self::Sha384WithRsa),
            HashingAlgorithm::SHA512 => Ok(Self::Sha512WithRsa),
            other => Err(InterfaceError::InvalidRequest(format!(
                "Unsupported hashing algorithm for RSA PKCS#1 v1.5 signing: {other:?}"
            ))),
        }
    }

    const fn infer_hash_from_digest_len(input_len: usize) -> Option<HashingAlgorithm> {
        match input_len {
            20 => Some(HashingAlgorithm::SHA1),
            32 => Some(HashingAlgorithm::SHA256),
            48 => Some(HashingAlgorithm::SHA384),
            64 => Some(HashingAlgorithm::SHA512),
            _ => None,
        }
    }

    /// Resolve an RSASSA-PSS `SigningAlgorithm` variant from an optional KMIP hashing algorithm
    /// (defaulting to SHA-256, matching the software RSASSA-PSS default), an optional explicit
    /// MGF1 hash (defaulting to the signature hash when omitted), and an optional signed salt
    /// length (rejecting negative values, which are meaningless for PKCS#11's unsigned
    /// `CK_ULONG` salt-length parameter).
    fn rsa_pss_from_params(
        hashing_algorithm: Option<HashingAlgorithm>,
        mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
        salt_length: Option<i32>,
        prehashed: bool,
    ) -> Result<Self, InterfaceError> {
        let salt_length = salt_length.map(u32::try_from).transpose().map_err(|_e| {
            InterfaceError::InvalidRequest(
                "RSASSA-PSS: salt_length must not be negative".to_owned(),
            )
        })?;
        let hashing_algorithm = hashing_algorithm.unwrap_or(HashingAlgorithm::SHA256);
        match hashing_algorithm {
            HashingAlgorithm::SHA384 => Ok(Self::RsaPss {
                hashing_algorithm,
                mask_generator_hashing_algorithm: mask_generator_hashing_algorithm
                    .unwrap_or(HashingAlgorithm::SHA384),
                salt_length,
                prehashed,
            }),
            HashingAlgorithm::SHA512 => Ok(Self::RsaPss {
                hashing_algorithm,
                mask_generator_hashing_algorithm: mask_generator_hashing_algorithm
                    .unwrap_or(HashingAlgorithm::SHA512),
                salt_length,
                prehashed,
            }),
            HashingAlgorithm::SHA256 => Ok(Self::RsaPss {
                hashing_algorithm,
                mask_generator_hashing_algorithm: mask_generator_hashing_algorithm
                    .unwrap_or(HashingAlgorithm::SHA256),
                salt_length,
                prehashed,
            }),
            other => Err(InterfaceError::InvalidRequest(format!(
                "Unsupported hashing algorithm for RSASSA-PSS signing: {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Default)]
pub struct EncryptedContent {
    pub ciphertext: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    pub tag: Option<Vec<u8>>,
}

#[async_trait]
pub trait CryptoOracle: Send + Sync {
    /// Encrypt data
    /// # Arguments
    /// * `uid` - the ID of the key to use for encryption.
    /// * `data` - the data to encrypt.
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for encryption.
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated encryption.
    /// # Returns
    /// * `Vec<u8>` - the encrypted data
    async fn encrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<EncryptedContent>;

    /// Decrypt data
    /// # Arguments
    /// * `uid` - the ID of the key to use for decryption.
    /// * `data` - the data to decrypt.
    /// * `cryptographic_algorithm` - the cryptographic algorithm to use for decryption.
    /// * `authenticated_encryption_additional_data` - the additional data to use for authenticated decryption.
    /// # Returns
    /// * `Vec<u8>` - the decrypted data
    async fn decrypt(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_algorithm: Option<CryptoAlgorithm>,
        authenticated_encryption_additional_data: Option<&[u8]>,
    ) -> InterfaceResult<Zeroizing<Vec<u8>>>;

    /// Get the key type
    /// On HSMs, this should be a single call to the HSM.
    /// # Arguments
    /// * `uid` - the ID of the key
    /// # Returns
    /// * `KeyType` - the type of the key
    async fn get_key_type(&self, uid: &str) -> InterfaceResult<Option<KeyType>>;

    /// Get the metadata of a key
    /// On HSMs, this should be a double call to the HSM.
    /// # Arguments
    /// * `uid` - the ID of the key
    /// # Returns
    /// * `KeyMetadata` - the metadata of the key
    async fn get_key_metadata(&self, uid: &str) -> InterfaceResult<Option<KeyMetadata>>;

    /// Sign data using the key identified by `uid`.
    ///
    /// # Arguments
    /// * `uid` - the ID of the private key to use for signing
    /// * `data` - the data (or pre-digested data) to sign
    /// * `cryptographic_parameters` - optional cryptographic parameters (algorithm, padding, …)
    /// # Returns
    /// * `InterfaceResult<Vec<u8>>` - the raw signature bytes
    async fn sign(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_parameters: Option<&CryptographicParameters>,
        input_is_digest: bool,
    ) -> InterfaceResult<Vec<u8>>;

    /// Verify a signature using the key identified by `uid`.
    ///
    /// # Arguments
    /// * `uid` - the ID of the public key to use for verification
    /// * `data` - the data that was signed
    /// * `signature` - the signature to verify
    /// * `cryptographic_parameters` - optional cryptographic parameters (algorithm, padding, …)
    /// # Returns
    /// * `InterfaceResult<bool>` - `true` if the signature is valid
    async fn signature_verify(
        &self,
        uid: &str,
        data: &[u8],
        signature: &[u8],
        cryptographic_parameters: Option<&CryptographicParameters>,
    ) -> InterfaceResult<bool>;

    /// Compute a MAC (Message Authentication Code) using the key identified by `uid`.
    ///
    /// # Arguments
    /// * `uid` - the ID of the key to use for MAC computation
    /// * `data` - the data to authenticate
    /// * `cryptographic_parameters` - optional cryptographic parameters (algorithm, …)
    /// # Returns
    /// * `InterfaceResult<Vec<u8>>` - the MAC bytes
    async fn mac(
        &self,
        uid: &str,
        data: &[u8],
        cryptographic_parameters: Option<&CryptographicParameters>,
    ) -> InterfaceResult<Vec<u8>>;

    /// Verify a MAC using the key identified by `uid`.
    ///
    /// # Arguments
    /// * `uid` - the ID of the key to use for MAC verification
    /// * `data` - the data that was authenticated
    /// * `mac_data` - the MAC to verify
    /// * `cryptographic_parameters` - optional cryptographic parameters (algorithm, …)
    /// # Returns
    /// * `InterfaceResult<bool>` - `true` if the MAC is valid
    async fn mac_verify(
        &self,
        uid: &str,
        data: &[u8],
        mac_data: &[u8],
        cryptographic_parameters: Option<&CryptographicParameters>,
    ) -> InterfaceResult<bool>;
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {

    use super::*;

    fn params_with(
        digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
        cryptographic_algorithm: Option<CryptographicAlgorithm>,
        hashing_algorithm: Option<HashingAlgorithm>,
        padding_method: Option<PaddingMethod>,
        salt_length: Option<i32>,
    ) -> CryptographicParameters {
        CryptographicParameters {
            digital_signature_algorithm,
            cryptographic_algorithm,
            hashing_algorithm,
            padding_method,
            salt_length,
            ..Default::default()
        }
    }

    #[test]
    fn from_kmip_none_defaults_to_sha256_with_rsa() {
        assert_eq!(
            SigningAlgorithm::from_kmip(None, KeyType::RsaPrivateKey, None, false, 0)
                .expect("should resolve"),
            SigningAlgorithm::Sha256WithRsa
        );
    }

    #[test]
    fn from_kmip_none_defaults_to_curve_appropriate_ecdsa() {
        assert_eq!(
            SigningAlgorithm::from_kmip(
                None,
                KeyType::EcPrivateKey,
                Some(crate::EcCurve::P384),
                true,
                48,
            )
            .expect("should resolve"),
            SigningAlgorithm::Ecdsa {
                hashing_algorithm: HashingAlgorithm::SHA384,
                prehashed: true,
            }
        );
    }

    #[test]
    fn from_kmip_explicit_rsassa_pss_resolves_hash_and_defaults_salt_to_none() {
        for (hash, expected) in [
            (
                HashingAlgorithm::SHA256,
                SigningAlgorithm::RsaPss {
                    hashing_algorithm: HashingAlgorithm::SHA256,
                    mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                    salt_length: None,
                    prehashed: false,
                },
            ),
            (
                HashingAlgorithm::SHA384,
                SigningAlgorithm::RsaPss {
                    hashing_algorithm: HashingAlgorithm::SHA384,
                    mask_generator_hashing_algorithm: HashingAlgorithm::SHA384,
                    salt_length: None,
                    prehashed: false,
                },
            ),
            (
                HashingAlgorithm::SHA512,
                SigningAlgorithm::RsaPss {
                    hashing_algorithm: HashingAlgorithm::SHA512,
                    mask_generator_hashing_algorithm: HashingAlgorithm::SHA512,
                    salt_length: None,
                    prehashed: false,
                },
            ),
        ] {
            let params = params_with(
                Some(DigitalSignatureAlgorithm::RSASSAPSS),
                None,
                Some(hash),
                None,
                None,
            );
            assert_eq!(
                SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0,)
                    .expect("should resolve"),
                expected,
                "hash: {hash:?}"
            );
        }
    }

    #[test]
    fn from_kmip_rsassa_pss_no_hash_defaults_to_sha256() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::RSASSAPSS),
            None,
            None,
            None,
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0)
                .expect("should resolve"),
            SigningAlgorithm::RsaPss {
                hashing_algorithm: HashingAlgorithm::SHA256,
                mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                salt_length: None,
                prehashed: false,
            }
        );
    }

    #[test]
    fn from_kmip_rsassa_pss_honors_explicit_salt_length() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::RSASSAPSS),
            None,
            Some(HashingAlgorithm::SHA256),
            None,
            Some(0),
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, true, 32)
                .expect("should resolve"),
            SigningAlgorithm::RsaPss {
                hashing_algorithm: HashingAlgorithm::SHA256,
                mask_generator_hashing_algorithm: HashingAlgorithm::SHA256,
                salt_length: Some(0),
                prehashed: true,
            }
        );
    }

    #[test]
    fn from_kmip_rsassa_pss_honors_explicit_mgf_hash() {
        let mut params = params_with(
            Some(DigitalSignatureAlgorithm::RSASSAPSS),
            None,
            Some(HashingAlgorithm::SHA256),
            None,
            None,
        );
        params.mask_generator_hashing_algorithm = Some(HashingAlgorithm::SHA384);
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, true, 32)
                .expect("should resolve"),
            SigningAlgorithm::RsaPss {
                hashing_algorithm: HashingAlgorithm::SHA256,
                mask_generator_hashing_algorithm: HashingAlgorithm::SHA384,
                salt_length: None,
                prehashed: true,
            }
        );
    }

    #[test]
    fn from_kmip_rsassa_pss_rejects_negative_salt_length() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::RSASSAPSS),
            None,
            Some(HashingAlgorithm::SHA256),
            None,
            Some(-1),
        );
        let err =
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0)
                .expect_err("must reject");
        assert!(matches!(err, InterfaceError::InvalidRequest(_)));
    }

    #[test]
    fn from_kmip_rsassa_pss_rejects_unsupported_hash() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::RSASSAPSS),
            None,
            Some(HashingAlgorithm::SHA1),
            None,
            None,
        );
        let err =
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0)
                .expect_err("must reject");
        assert!(matches!(err, InterfaceError::InvalidRequest(_)));
    }

    #[test]
    fn from_kmip_rsa_padding_method_pss_resolves_pss_variant() {
        let params = params_with(
            None,
            Some(CryptographicAlgorithm::RSA),
            Some(HashingAlgorithm::SHA384),
            Some(PaddingMethod::PSS),
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0)
                .expect("should resolve"),
            SigningAlgorithm::RsaPss {
                hashing_algorithm: HashingAlgorithm::SHA384,
                mask_generator_hashing_algorithm: HashingAlgorithm::SHA384,
                salt_length: None,
                prehashed: false,
            }
        );
    }

    #[test]
    fn from_kmip_rsa_pkcs1v15_still_resolves_as_before() {
        let params = params_with(
            None,
            Some(CryptographicAlgorithm::RSA),
            Some(HashingAlgorithm::SHA384),
            None,
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 0)
                .expect("should resolve"),
            SigningAlgorithm::Sha384WithRsa
        );
    }

    #[test]
    fn from_kmip_prehashed_rsa_pkcs1_uses_digest_variant() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::SHA384WithRSAEncryption),
            Some(CryptographicAlgorithm::RSA),
            Some(HashingAlgorithm::SHA384),
            None,
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, true, 48)
                .expect("should resolve"),
            SigningAlgorithm::RsaPkcsV15Digest {
                hashing_algorithm: HashingAlgorithm::SHA384,
            }
        );
    }

    #[test]
    fn from_kmip_prehashed_ecdsa_uses_raw_ecdsa_variant() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA512),
            Some(CryptographicAlgorithm::EC),
            Some(HashingAlgorithm::SHA512),
            None,
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params), KeyType::EcPrivateKey, None, true, 64)
                .expect("should resolve"),
            SigningAlgorithm::Ecdsa {
                hashing_algorithm: HashingAlgorithm::SHA512,
                prehashed: true,
            }
        );
    }

    #[test]
    /// Regression test: requesting `ECDSAWithSHA256` against an RSA key must be rejected early
    /// with a friendly `InvalidRequest` error instead of silently resolving to
    /// `SigningAlgorithm::Ecdsa`, which would otherwise reach the HSM and fail with an opaque,
    /// low-level PKCS#11 return code (see PR #1169 CI failure
    /// `test_vec_hsm_resident_rsa2048_sign_ecdsa_rejected`).
    fn from_kmip_rejects_ecdsa_algorithm_for_rsa_key() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            Some(CryptographicAlgorithm::RSA),
            Some(HashingAlgorithm::SHA256),
            None,
            None,
        );
        let err =
            SigningAlgorithm::from_kmip(Some(&params), KeyType::RsaPrivateKey, None, false, 32)
                .expect_err("should be rejected");
        assert!(
            err.to_string()
                .contains("Unsupported digital signature algorithm for HSM signing")
        );
    }

    #[test]
    /// Symmetric regression test: requesting an RSA-family algorithm against an EC key must
    /// also be rejected early.
    fn from_kmip_rejects_rsa_algorithm_for_ec_key() {
        let params = params_with(
            Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            Some(CryptographicAlgorithm::EC),
            Some(HashingAlgorithm::SHA256),
            None,
            None,
        );
        let err =
            SigningAlgorithm::from_kmip(Some(&params), KeyType::EcPrivateKey, None, false, 32)
                .expect_err("should be rejected");
        assert!(
            err.to_string()
                .contains("Unsupported digital signature algorithm for HSM signing")
        );
    }

    /// HSM-delegated `EdDSA` signing (issue #1157). `EdDSA` has no `DigitalSignatureAlgorithm`
    /// variant in KMIP 2.1: it is resolved from `CryptographicAlgorithm::Ed25519`/`Ed448` alone,
    /// with no accompanying `hashing_algorithm`/`padding_method` (unlike RSA/ECDSA above).
    #[cfg(feature = "non-fips")]
    #[test]
    fn from_kmip_ed25519_resolves_via_cryptographic_algorithm_alone() {
        let params = params_with(
            None,
            Some(CryptographicAlgorithm::Ed25519),
            None,
            None,
            None,
        );
        assert_eq!(
            SigningAlgorithm::from_kmip(
                Some(&params),
                KeyType::EcPrivateKey,
                Some(crate::EcCurve::Ed25519),
                false,
                0,
            )
            .expect("should resolve"),
            SigningAlgorithm::Ed25519
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn from_kmip_ed448_resolves_via_cryptographic_algorithm_alone() {
        let params = params_with(None, Some(CryptographicAlgorithm::Ed448), None, None, None);
        assert_eq!(
            SigningAlgorithm::from_kmip(
                Some(&params),
                KeyType::EcPrivateKey,
                Some(crate::EcCurve::Ed448),
                false,
                0,
            )
            .expect("should resolve"),
            SigningAlgorithm::Ed448
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn from_kmip_rejects_prehashed_eddsa() {
        let params = params_with(
            None,
            Some(CryptographicAlgorithm::Ed25519),
            None,
            None,
            None,
        );
        let err = SigningAlgorithm::from_kmip(
            Some(&params),
            KeyType::EcPrivateKey,
            Some(crate::EcCurve::Ed25519),
            true,
            32,
        )
        .expect_err("must reject");
        assert!(matches!(err, InterfaceError::InvalidRequest(_)));
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn from_kmip_none_defaults_to_eddsa_for_ed25519_keys() {
        assert_eq!(
            SigningAlgorithm::from_kmip(
                None,
                KeyType::EcPrivateKey,
                Some(crate::EcCurve::Ed25519),
                false,
                0,
            )
            .expect("should resolve"),
            SigningAlgorithm::Ed25519
        );
    }
}
