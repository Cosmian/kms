//! HSM interface.
//! This module defines the interface that an HSM must implement to be used as an object store and
//! an encryption oracle.

use async_trait::async_trait;
use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_types::CryptographicAlgorithm,
};
use zeroize::Zeroizing;

use crate::{
    CryptoAlgorithm, InterfaceError, InterfaceResult, KeyMetadata, KeyType,
    encryption_oracle::EncryptedContent,
};

/// Supported key algorithms
pub enum HsmKeyAlgorithm {
    AES,
}

/// Supported key pair algorithms
pub enum HsmKeypairAlgorithm {
    RSA,
}

/// Supported object filters on find
#[derive(Clone, PartialEq, Eq)]
pub enum HsmObjectFilter {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
}

impl TryFrom<&Attributes> for HsmObjectFilter {
    type Error = InterfaceError;

    fn try_from(researched_attributes: &Attributes) -> InterfaceResult<Self> {
        let mut object_filter = Self::Any;

        if let Some(cryptographic_algorithm) = researched_attributes.cryptographic_algorithm {
            object_filter = match cryptographic_algorithm {
                CryptographicAlgorithm::AES => Self::AesKey,
                CryptographicAlgorithm::RSA => Self::RsaKey,
                _ => {
                    return Err(InterfaceError::Default(format!(
                        "Unsupported cryptographic algorithm for HSMs: {cryptographic_algorithm}"
                    )))
                }
            };
        }

        if let Some(object_type) = researched_attributes.object_type {
            object_filter = match object_type {
                ObjectType::SymmetricKey => {
                    if object_filter == Self::RsaKey {
                        return Err(InterfaceError::Default(
                            "Incompatible object type: SymmetricKey with RSA".to_owned(),
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
                    Self::RsaPublicKey
                }
                ObjectType::PrivateKey => {
                    if object_filter == Self::AesKey {
                        return Err(InterfaceError::Default(
                            "Incompatible object type: PrivateKey with AES".to_owned(),
                        ));
                    }
                    Self::RsaPrivateKey
                }
                _ => {
                    return Err(InterfaceError::Default(format!(
                        "Unsupported object type for HSMs: {object_type}"
                    )))
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

/// Key material representation
#[derive(Debug)]
pub enum KeyMaterial {
    AesKey(Zeroizing<Vec<u8>>),
    RsaPrivateKey(RsaPrivateKeyMaterial),
    RsaPublicKey(RsaPublicKeyMaterial),
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
        pk_is: &[u8],
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
}
