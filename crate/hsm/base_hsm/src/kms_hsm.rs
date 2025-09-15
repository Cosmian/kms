//! Implementation of the Hardware Security Module (HSM) trait for `BaseHsm`
//!
//! This implementation provides cryptographic operations using a Hardware Security Module,
//! supporting various key management and cryptographic operations.
//!
//! # Implemented Operations
//!
//! - Key Generation: Create symmetric (AES) and asymmetric (RSA) keys
//! - Key Pair Generation: Create public/private key pairs
//! - Key Export: Export HSM objects
//! - Key Deletion: Remove keys from the HSM
//! - Key Search: Find keys based on object type filters
//! - Encryption/Decryption: Perform cryptographic operations
//! - Key Information: Retrieve key types and metadata
//!
//! # Supported Algorithms
//!
//! - AES: 128-bit and 256-bit keys
//! - RSA: 1024-bit, 2048-bit, 3072-bit, and 4096-bit keys
//!
//! # Error Handling
//!
//! All operations return `InterfaceResult<T>` which may contain:
//! - Errors for duplicate key IDs
//! - Invalid key sizes
//! - Object not found errors
//! - General HSM operation failures
//!
//! # Security Features
//!
//! - Support for sensitive key material handling
//! - Secure session management
//! - Zero-copy cleanup for sensitive data using `Zeroizing`
use async_trait::async_trait;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject,
    HsmObjectFilter, InterfaceError, InterfaceResult, KeyMetadata, KeyType,
};
use zeroize::Zeroizing;

use crate::{AesKeySize, BaseHsm, RsaKeySize, hsm_capabilities::HsmProvider};

#[async_trait]
impl<P: HsmProvider> HSM for BaseHsm<P> {
    async fn get_supported_algorithms(
        &self,
        slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
        Ok(self.get_algorithms(slot_id)?)
    }

    async fn create_key(
        &self,
        slot_id: usize,
        id: &[u8],
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        if session.get_object_handle(id).is_ok() {
            return Err(InterfaceError::Default(
                "A secret key with this id already exists".to_owned(),
            ));
        }

        match algorithm {
            HsmKeyAlgorithm::AES => {
                let key_size = match key_length_in_bits {
                    128 => AesKeySize::Aes128,
                    256 => AesKeySize::Aes256,
                    x => {
                        return Err(InterfaceError::Default(format!(
                            "Invalid key length: {x} bits, for and HSM AES key"
                        )))
                    }
                };
                let _ = session.generate_aes_key(id, key_size, sensitive)?;
                Ok(())
            }
        }
    }

    async fn create_keypair(
        &self,
        slot_id: usize,
        sk_id: &[u8],
        pk_id: &[u8],
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
    ) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;

        if session.get_object_handle(sk_id).is_ok() {
            return Err(InterfaceError::Default(
                "A private key with this ID already exists".to_owned(),
            ));
        }
        if session.get_object_handle(pk_id).is_ok() {
            return Err(InterfaceError::Default(
                "A public key with this ID and the '_pk' suffix already exists".to_owned(),
            ));
        }

        let key_length_in_bits = match key_length_in_bits {
            1024 => RsaKeySize::Rsa1024,
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            x => {
                return Err(InterfaceError::Default(format!(
                    "Invalid key length: {x} bits, for and HSM RSA key (valid values are 1024, \
                     2048, 3072, 4096)"
                )))
            }
        };

        match algorithm {
            HsmKeypairAlgorithm::RSA => {
                session.generate_rsa_key_pair(sk_id, pk_id, key_length_in_bits, sensitive)?;
                Ok(())
            }
        }
    }

    async fn export(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<Option<HsmObject>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(object_id)?;
        let object = session.export_key(handle)?;
        Ok(object)
    }

    async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(object_id)?;
        session.destroy_object(handle)?;
        session.delete_object_handle(object_id)?;
        Ok(())
    }

    async fn find(
        &self,
        slot_id: usize,
        object_type: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handles = session.list_objects(object_type)?;
        let mut object_ids = Vec::with_capacity(handles.len());
        for handle in handles {
            if let Some(object_id) = session.get_object_id(handle)? {
                object_ids.push(object_id);
            }
        }
        Ok(object_ids)
    }

    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<EncryptedContent> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let encrypted_content = session.encrypt(handle, algorithm.clone().into(), data)?;
        Ok(encrypted_content)
    }

    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let plaintext = session.decrypt(handle, algorithm.into(), data)?;
        Ok(plaintext)
    }

    async fn get_key_type(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let key_type = session.get_key_type(handle)?;
        Ok(key_type)
    }

    async fn get_key_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        let slot = self.get_slot(slot_id)?;
        let session = slot.open_session(true)?;
        let handle = session.get_object_handle(key_id)?;
        let metadata = session.get_key_metadata(handle)?;
        Ok(metadata)
    }
}
