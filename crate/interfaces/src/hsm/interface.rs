//! HSM interface.
//! This module defines the interface that an HSM must implement to be used as an object store and
//! a crypto oracle.

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_types::CryptographicAlgorithm,
};
use zeroize::Zeroizing;

use crate::{
    CryptoAlgorithm, InterfaceError, InterfaceResult, KeyMetadata, KeyType, SigningAlgorithm,
    crypto_oracle::EncryptedContent,
};

/// Supported key algorithms
pub enum HsmKeyAlgorithm {
    AES,
}

/// Supported key pair algorithms
#[derive(Debug, Clone, Copy)]
pub enum HsmKeypairAlgorithm {
    RSA,
    /// Elliptic Curve. The specific FIPS-approved NIST curve (P-224/P-256/P-384/P-521) is
    /// selected via the `key_length_in_bits` parameter of `HSM::create_keypair`, mirroring how
    /// RSA selects its modulus size, so no new parameter is added to the trait.
    EC,
    /// Ed25519 (`CKM_EC_EDWARDS_KEY_PAIR_GEN`), for `EdDSA` signing. Non-FIPS: mirrors the
    /// gating of `Ed25519` in `crate::crypto::elliptic_curves::sign` (issue #1157).
    #[cfg(feature = "non-fips")]
    Ed25519,
    /// Ed448 (`CKM_EC_EDWARDS_KEY_PAIR_GEN`), for `EdDSA` signing. Non-FIPS: see `Ed25519` above.
    #[cfg(feature = "non-fips")]
    Ed448,
    /// X25519 (`CKM_EC_MONTGOMERY_KEY_PAIR_GEN`), for ECDH key agreement. Non-FIPS: see
    /// `Ed25519` above.
    #[cfg(feature = "non-fips")]
    X25519,
}

/// FIPS-approved NIST elliptic curves supported for HSM-delegated EC key generation and ECDSA
/// signing, plus (behind the `non-fips` feature) the Edwards/Montgomery curves used for
/// `EdDSA` signing and X25519 ECDH key agreement (issue #1157). Only prime curves over `GF(p)`
/// are supported for ECDSA, matching the software EC key generation gating in
/// `crate::crypto::elliptic_curves::operation` (`P192`/`SECP256K1`/`SECP224K1` remain
/// non-fips-only and are intentionally not exposed for HSM delegation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    P224,
    P256,
    P384,
    P521,
    /// Edwards curve used for `EdDSA` signing (`CKM_EDDSA` / `CKM_EC_EDWARDS_KEY_PAIR_GEN`).
    /// Non-FIPS: mirrors the gating of `Ed25519`/`Ed448` in
    /// `crate::crypto::elliptic_curves::sign` (issue #1157).
    #[cfg(feature = "non-fips")]
    Ed25519,
    /// Edwards curve used for `EdDSA` signing. Non-FIPS: see `Ed25519` above.
    #[cfg(feature = "non-fips")]
    Ed448,
    /// Montgomery curve used for X25519 ECDH key agreement
    /// (`CKM_EC_MONTGOMERY_KEY_PAIR_GEN` / `CKM_ECDH1_DERIVE`). Non-FIPS: see `Ed25519` above.
    #[cfg(feature = "non-fips")]
    X25519,
}

impl EcCurve {
    /// Select a curve from a requested key length in bits, mirroring the RSA key-size
    /// selection convention used by `HSM::create_keypair`.
    ///
    /// Only selects among the FIPS-approved NIST prime curves; Edwards/Montgomery curves are
    /// selected explicitly (e.g. `EcCurve::Ed25519`), not by key length, since key length alone
    /// does not disambiguate them (Ed25519 and X25519 share a 256-bit field size).
    pub fn from_key_length_in_bits(key_length_in_bits: usize) -> InterfaceResult<Self> {
        match key_length_in_bits {
            224 => Ok(Self::P224),
            256 => Ok(Self::P256),
            384 => Ok(Self::P384),
            521 => Ok(Self::P521),
            x => Err(InterfaceError::Default(format!(
                "Invalid key length: {x} bits, for an HSM EC key (valid values are 224, 256, \
                 384, 521)"
            ))),
        }
    }

    /// The curve's field size, in bits (matches the `key_length_in_bits` used to select it).
    #[must_use]
    pub const fn key_length_in_bits(self) -> usize {
        match self {
            Self::P224 => 224,
            Self::P256 => 256,
            Self::P384 => 384,
            Self::P521 => 521,
            #[cfg(feature = "non-fips")]
            Self::Ed25519 | Self::X25519 => 256,
            #[cfg(feature = "non-fips")]
            Self::Ed448 => 456,
        }
    }
}

/// Supported object filters on find
#[derive(Clone, PartialEq, Eq)]
pub enum HsmObjectFilter {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
    EcKey,
    EcPrivateKey,
    EcPublicKey,
}

impl TryFrom<&Attributes> for HsmObjectFilter {
    type Error = InterfaceError;

    fn try_from(researched_attributes: &Attributes) -> InterfaceResult<Self> {
        let mut object_filter = if let Some(cryptographic_algorithm) =
            researched_attributes.cryptographic_algorithm
        {
            match cryptographic_algorithm {
                CryptographicAlgorithm::AES => Self::AesKey,
                CryptographicAlgorithm::RSA => Self::RsaKey,
                CryptographicAlgorithm::EC
                | CryptographicAlgorithm::ECDSA
                | CryptographicAlgorithm::ECDH => Self::EcKey,
                #[cfg(feature = "non-fips")]
                CryptographicAlgorithm::Ed25519 | CryptographicAlgorithm::Ed448 => Self::EcKey,
                _ => {
                    return Err(InterfaceError::Default(format!(
                        "Unsupported cryptographic algorithm for HSMs: {cryptographic_algorithm}"
                    )));
                }
            }
        } else {
            Self::Any
        };

        if let Some(object_type) = researched_attributes.object_type {
            object_filter = match object_type {
                ObjectType::SymmetricKey => {
                    if object_filter == Self::RsaKey || object_filter == Self::EcKey {
                        return Err(InterfaceError::Default(
                            "Incompatible object type: SymmetricKey with RSA/EC".to_owned(),
                        ));
                    }
                    Self::AesKey
                }
                ObjectType::PublicKey => {
                    if object_filter == Self::AesKey {
                        return Err(InterfaceError::Default(
                            "Incompatible object type: PublicKey with AES".to_owned(),
                        ));
                    }
                    if object_filter == Self::EcKey {
                        Self::EcPublicKey
                    } else {
                        Self::RsaPublicKey
                    }
                }
                ObjectType::PrivateKey => {
                    if object_filter == Self::AesKey {
                        return Err(InterfaceError::Default(
                            "Incompatible object type: PrivateKey with AES".to_owned(),
                        ));
                    }
                    if object_filter == Self::EcKey {
                        Self::EcPrivateKey
                    } else {
                        Self::RsaPrivateKey
                    }
                }
                _ => {
                    return Err(InterfaceError::Default(format!(
                        "Unsupported object type for HSMs: {object_type}"
                    )));
                }
            };
        }

        Ok(object_filter)
    }
}

/// RSA private key value representation
/// All values are in big-endian format
#[derive(Debug)]
pub struct RsaPrivateKeyMaterial {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Zeroizing<Vec<u8>>,
    pub prime_1: Zeroizing<Vec<u8>>,
    pub prime_2: Zeroizing<Vec<u8>>,
    pub exponent_1: Zeroizing<Vec<u8>>,
    pub exponent_2: Zeroizing<Vec<u8>>,
    pub coefficient: Zeroizing<Vec<u8>>,
}

/// RSA public key value representation
/// All values are in big-endian format
#[derive(Debug)]
pub struct RsaPublicKeyMaterial {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
}

/// EC private key value representation.
/// `d` is the private scalar in big-endian format; `curve` identifies the NIST curve.
#[derive(Debug)]
pub struct EcPrivateKeyMaterial {
    pub curve: EcCurve,
    pub d: Zeroizing<Vec<u8>>,
}

/// EC public key value representation.
/// `q` is the public point in uncompressed X9.62 format (`0x04 || X || Y`).
#[derive(Debug)]
pub struct EcPublicKeyMaterial {
    pub curve: EcCurve,
    pub q: Vec<u8>,
}

/// Key material representation
#[derive(Debug)]
pub enum KeyMaterial {
    AesKey(Zeroizing<Vec<u8>>),
    RsaPrivateKey(RsaPrivateKeyMaterial),
    RsaPublicKey(RsaPublicKeyMaterial),
    EcPrivateKey(EcPrivateKeyMaterial),
    EcPublicKey(EcPublicKeyMaterial),
}

/// HSM object representation
#[derive(Debug)]
pub struct HsmObject {
    key_material: KeyMaterial,
    id: String,
}

impl HsmObject {
    #[must_use]
    pub const fn new(key_material: KeyMaterial, label: String) -> Self {
        Self {
            key_material,
            id: label,
        }
    }

    #[must_use]
    pub const fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// HSM trait
/// This trait defines the operations that can be performed on an HSM.
/// The HSM is assumed to be a PKCS#11 compliant device.
#[async_trait]
pub trait HSM: Send + Sync {
    /// Get the list of available slot identifiers for the HSM.
    ///
    /// This function retrieves the identifiers of all slots that the HSM
    /// has been initialized with.
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>>;

    /// Get the supported cryptographic algorithms for a given HSM slot.
    ///
    /// This function queries the HSM to retrieve the list of algorithms
    /// that can be used for cryptographic operations in the specified slot.
    /// The returned algorithms reflect the capabilities of the underlying
    /// HSM and may vary depending on the slot and device configuration.
    ///
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    ///
    /// # Returns
    /// * `InterfaceResult<Vec<CryptoAlgorithm>>` - the supported algorithms
    async fn get_supported_algorithms(
        &self,
        slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>>;

    /// Create the given key in the HSM.
    /// The key ID will be generated by the HSM and returned.
    ///
    /// The key will not be exportable from the HSM if the sensitive flag is set to true.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `id` - the ID of the key
    /// * `algorithm` - the key algorithm to use
    /// * `key_length_in_bits` - the length of the key in bits
    /// * `sensitive` - whether the key should be exportable
    /// # Returns
    /// * `PluginResult<usize>` - the ID of the key
    async fn create_key(
        &self,
        slot_id: usize,
        id: &[u8],
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()>;

    /// Create the given key pair in the HSM.
    /// The private key ID and Public key ID will be generated by the HSM
    /// and returned in that order.
    ///
    /// The key pair will not be exportable from the HSM if the sensitive flag is set to true.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `sk_id` - the ID of the private key
    /// * `pk_id` - the ID of the public key
    /// * `algorithm` - the key pair algorithm to use
    /// * `key_length_in_bits` - the length of the key in bits
    /// * `sensitive` - whether the key pair should be exportable
    /// # Returns
    /// * `PluginResult<(usize, usize)>` - the IDs of the private and public keys
    async fn create_keypair(
        &self,
        slot_id: usize,
        sk_id: &[u8],
        pk_id: &[u8],
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()>;

    /// Export objects from the HSN.
    ///
    /// To be exportable, the object must have been created with the sensitive flag set to false.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_id` - the ID of the object to export
    /// # Returns
    /// * `PluginResult<Option<HsmObject>>` - the exported object
    async fn export(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<Option<HsmObject>>;

    /// Delete an object from the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_id` - the ID of the object to delete
    /// # Returns
    /// * `PluginResult<()>` - the result of the operation
    async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()>;

    /// Find objects in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `object_filter` - the filter to apply to the objects
    /// # Returns
    /// * `PluginResult<Vec<HsmId>>` - the IDs of the objects found
    async fn find(
        &self,
        slot_id: usize,
        object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>>;

    /// Encrypt data using the given key in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key to use for encryption
    /// * `algorithm` - the encryption algorithm to use
    /// * `data` - the data to encrypt
    /// # Returns
    /// * `PluginResult<Vec<u8>>` - the encrypted data
    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<EncryptedContent>;

    /// Decrypt data using the given key in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key to use for decryption
    /// * `algorithm` - the encryption algorithm to use
    /// * `data` - the data to decrypt
    /// # Returns
    /// * `PluginResult<Vec<u8>>` - the decrypted data
    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>>;

    /// Get the type of the key.
    /// This should be a single call to the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key
    /// # Returns
    /// * `PluginResult<Option<KeyType>>` - the type of the key
    async fn get_key_type(&self, slot_id: usize, key_id: &[u8])
    -> InterfaceResult<Option<KeyType>>;

    /// Get the metadata of the key.
    /// This will be two to three calls to the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key
    /// # Returns
    /// * `PluginResult<Option<KeyMetadata>>` - the metadata of the key
    async fn get_key_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>>;

    /// Sign data using the given private key in the HSM.
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the private key to use for signing
    /// * `algorithm` - the signing algorithm to use
    /// * `data` - the data to sign
    /// # Returns
    /// * `InterfaceResult<Vec<u8>>` - the signature bytes
    async fn sign(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: SigningAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>>;

    /// Generate cryptographically secure random bytes using the HSM RNG.
    ///
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM to use for RNG
    /// * `len` - number of random bytes to generate
    ///
    /// # Returns
    /// * `InterfaceResult<Vec<u8>>` - random bytes
    async fn generate_random(&self, slot_id: usize, len: usize) -> InterfaceResult<Vec<u8>>;

    /// Seed the HSM RNG with the provided data. Some devices may not support seeding and
    /// can return an error; callers may choose to ignore such errors.
    async fn seed_random(&self, slot_id: usize, seed: &[u8]) -> InterfaceResult<()>;

    /// Set `CKA_START_DATE` and `CKA_END_DATE` on a key object.
    ///
    /// These PKCS#11 attributes are used to track rotation scheduling:
    /// - `start_date` — when the current rotation interval began.
    /// - `end_date` — when the key is due for rotation.
    ///
    /// Passing `None` for either date clears that attribute (sets to empty `CK_DATE`).
    ///
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the ID of the key
    /// * `start_date` - optional start date
    /// * `end_date` - optional end date
    async fn set_key_dates(
        &self,
        slot_id: usize,
        key_id: &[u8],
        start_date: Option<time::Date>,
        end_date: Option<time::Date>,
    ) -> InterfaceResult<()>;

    /// Set `CKA_LABEL` on a key object.
    ///
    /// The label encodes keyset metadata in the format
    /// `rotate_name::generation::key_id[@latest]`.
    ///
    /// # Arguments
    /// * `slot_id` - the slot ID of the HSM
    /// * `key_id` - the `CKA_ID` bytes of the key to update
    /// * `label` - the new label string to set
    async fn set_key_label(
        &self,
        slot_id: usize,
        key_id: &[u8],
        label: &str,
    ) -> InterfaceResult<()>;

    /// Get a reference to the underlying PKCS#11 library for direct function calls.
    ///
    /// This method provides access to the raw PKCS#11 library (`HsmLib`) to enable
    /// direct calls to PKCS#11 functions. This is primarily used for KMIP PKCS#11
    /// operations that need to map directly to specific PKCS#11 functions.
    ///
    /// # Returns
    /// * `Option<&dyn std::any::Any>` - A trait object that can be downcast to `Arc<HsmLib>`
    fn hsm_lib(&self) -> Option<&dyn std::any::Any>;
}
