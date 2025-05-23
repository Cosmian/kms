//! HSM interface.
//! This module defines the interface that an HSM must implement to be used as an object store and
//! an encryption oracle.

use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::{
    CryptoAlgorithm, InterfaceResult, KeyMetadata, KeyType, encryption_oracle::EncryptedContent,
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
pub enum HsmObjectFilter {
    Any,
    AesKey,
    RsaKey,
    RsaPrivateKey,
    RsaPublicKey,
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
    pub fn new(key_material: KeyMaterial, label: String) -> Self {
        HsmObject {
            key_material,
            id: label,
        }
    }

    pub fn key_material(&self) -> &KeyMaterial {
        &self.key_material
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

/// HSM trait
/// This trait defines the operations that can be performed on an HSM.
/// The HSM is assumed to be a PKCS#11 compliant device.
#[async_trait]
pub trait HSM: Send + Sync {
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
