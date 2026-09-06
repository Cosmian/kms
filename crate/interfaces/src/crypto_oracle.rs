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
    /// `CKM_SHA1_RSA_PKCS`
    Sha1WithRsa,
    /// `CKM_SHA256_RSA_PKCS`
    Sha256WithRsa,
    /// `CKM_SHA384_RSA_PKCS`
    Sha384WithRsa,
    /// `CKM_SHA512_RSA_PKCS`
    Sha512WithRsa,
    /// `CKM_SHA256_RSA_PKCS_PSS` (MGF1-SHA256). `salt_length` in bytes; `None` defaults to the
    /// digest length (32 bytes), matching the software RSASSA-PSS default.
    RsaPssSha256 { salt_length: Option<u32> },
    /// `CKM_SHA384_RSA_PKCS_PSS` (MGF1-SHA384). `salt_length` in bytes; `None` defaults to the
    /// digest length (48 bytes).
    RsaPssSha384 { salt_length: Option<u32> },
    /// `CKM_SHA512_RSA_PKCS_PSS` (MGF1-SHA512). `salt_length` in bytes; `None` defaults to the
    /// digest length (64 bytes).
    RsaPssSha512 { salt_length: Option<u32> },
    /// `CKM_ECDSA_SHA256`
    EcdsaSha256,
    /// `CKM_ECDSA_SHA384`
    EcdsaSha384,
    /// `CKM_ECDSA_SHA512`
    EcdsaSha512,
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
    /// 3. fallback to `Sha256WithRsa` when only RSA is specified
    pub fn from_kmip(params: Option<&CryptographicParameters>) -> Result<Self, InterfaceError> {
        let Some(params) = params else {
            return Ok(Self::Sha256WithRsa);
        };

        // 1. explicit digital_signature_algorithm
        if let Some(dsa) = &params.digital_signature_algorithm {
            return match dsa {
                DigitalSignatureAlgorithm::SHA1WithRSAEncryption => Ok(Self::Sha1WithRsa),
                DigitalSignatureAlgorithm::SHA224WithRSAEncryption
                | DigitalSignatureAlgorithm::SHA256WithRSAEncryption => Ok(Self::Sha256WithRsa),
                DigitalSignatureAlgorithm::SHA384WithRSAEncryption => Ok(Self::Sha384WithRsa),
                DigitalSignatureAlgorithm::SHA512WithRSAEncryption => Ok(Self::Sha512WithRsa),
                DigitalSignatureAlgorithm::RSASSAPSS => {
                    Self::rsa_pss_from_hash_and_salt(params.hashing_algorithm, params.salt_length)
                }
                DigitalSignatureAlgorithm::ECDSAWithSHA256 => Ok(Self::EcdsaSha256),
                DigitalSignatureAlgorithm::ECDSAWithSHA384 => Ok(Self::EcdsaSha384),
                DigitalSignatureAlgorithm::ECDSAWithSHA512 => Ok(Self::EcdsaSha512),
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
                return Ok(Self::Ed25519);
            }
            if params.cryptographic_algorithm == Some(CryptographicAlgorithm::Ed448) {
                return Ok(Self::Ed448);
            }
        }

        // 3. cryptographic_algorithm + hashing_algorithm (EC/ECDSA)
        if matches!(
            params.cryptographic_algorithm,
            Some(CryptographicAlgorithm::EC | CryptographicAlgorithm::ECDSA)
        ) {
            return match params.hashing_algorithm {
                Some(HashingAlgorithm::SHA256) | None => Ok(Self::EcdsaSha256),
                Some(HashingAlgorithm::SHA384) => Ok(Self::EcdsaSha384),
                Some(HashingAlgorithm::SHA512) => Ok(Self::EcdsaSha512),
                Some(other) => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for ECDSA signing: {other:?}"
                ))),
            };
        }

        // 2. cryptographic_algorithm + padding_method + hashing_algorithm
        if params.cryptographic_algorithm == Some(CryptographicAlgorithm::RSA) {
            if params.padding_method == Some(PaddingMethod::PSS) {
                return Self::rsa_pss_from_hash_and_salt(
                    params.hashing_algorithm,
                    params.salt_length,
                );
            }
            return match params.hashing_algorithm {
                Some(HashingAlgorithm::SHA1) => Ok(Self::Sha1WithRsa),
                Some(HashingAlgorithm::SHA256) | None => Ok(Self::Sha256WithRsa),
                Some(HashingAlgorithm::SHA384) => Ok(Self::Sha384WithRsa),
                Some(HashingAlgorithm::SHA512) => Ok(Self::Sha512WithRsa),
                Some(other) => Err(InterfaceError::InvalidRequest(format!(
                    "Unsupported hashing algorithm for RSA signing: {other:?}"
                ))),
            };
        }

        // Default
        Ok(Self::Sha256WithRsa)
    }

    /// Resolve an RSASSA-PSS `SigningAlgorithm` variant from an optional KMIP hashing algorithm
    /// (defaulting to SHA-256, matching the software RSASSA-PSS default) and an optional,
    /// KMIP-signed salt length (rejecting negative values, which are meaningless for PKCS#11's
    /// unsigned `CK_ULONG` salt-length parameter).
    fn rsa_pss_from_hash_and_salt(
        hashing_algorithm: Option<HashingAlgorithm>,
        salt_length: Option<i32>,
    ) -> Result<Self, InterfaceError> {
        let salt_length = salt_length.map(u32::try_from).transpose().map_err(|_e| {
            InterfaceError::InvalidRequest(
                "RSASSA-PSS: salt_length must not be negative".to_owned(),
            )
        })?;
        match hashing_algorithm {
            Some(HashingAlgorithm::SHA384) => Ok(Self::RsaPssSha384 { salt_length }),
            Some(HashingAlgorithm::SHA512) => Ok(Self::RsaPssSha512 { salt_length }),
            Some(HashingAlgorithm::SHA256) | None => Ok(Self::RsaPssSha256 { salt_length }),
            Some(other) => Err(InterfaceError::InvalidRequest(format!(
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
            SigningAlgorithm::from_kmip(None).expect("should resolve"),
            SigningAlgorithm::Sha256WithRsa
        );
    }

    #[test]
    fn from_kmip_explicit_rsassa_pss_resolves_hash_and_defaults_salt_to_none() {
        for (hash, expected) in [
            (
                HashingAlgorithm::SHA256,
                SigningAlgorithm::RsaPssSha256 { salt_length: None },
            ),
            (
                HashingAlgorithm::SHA384,
                SigningAlgorithm::RsaPssSha384 { salt_length: None },
            ),
            (
                HashingAlgorithm::SHA512,
                SigningAlgorithm::RsaPssSha512 { salt_length: None },
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
                SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
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
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::RsaPssSha256 { salt_length: None }
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
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::RsaPssSha256 {
                salt_length: Some(0)
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
        let err = SigningAlgorithm::from_kmip(Some(&params)).expect_err("must reject");
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
        let err = SigningAlgorithm::from_kmip(Some(&params)).expect_err("must reject");
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
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::RsaPssSha384 { salt_length: None }
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
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::Sha384WithRsa
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
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::Ed25519
        );
    }

    #[cfg(feature = "non-fips")]
    #[test]
    fn from_kmip_ed448_resolves_via_cryptographic_algorithm_alone() {
        let params = params_with(None, Some(CryptographicAlgorithm::Ed448), None, None, None);
        assert_eq!(
            SigningAlgorithm::from_kmip(Some(&params)).expect("should resolve"),
            SigningAlgorithm::Ed448
        );
    }
}
