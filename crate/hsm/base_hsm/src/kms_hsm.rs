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
    HsmObjectFilter, InterfaceError, InterfaceResult, KeyMetadata, KeyType, SigningAlgorithm,
};
use cosmian_logger::debug;
use zeroize::Zeroizing;

use crate::{AesKeySize, BaseHsm, RsaKeySize, hsm_capabilities::HsmProvider};

#[async_trait]
impl<P: HsmProvider> HSM for BaseHsm<P> {
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
        Ok(self.get_available_slot_list()?)
    }

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
        // Validate key parameters before spawning (pure computation, no FFI)
        let key_size = match algorithm {
            HsmKeyAlgorithm::AES => match key_length_in_bits {
                128 => AesKeySize::Aes128,
                256 => AesKeySize::Aes256,
                x => {
                    return Err(InterfaceError::Default(format!(
                        "Invalid key length: {x} bits, for and HSM AES key"
                    )));
                }
            },
        };
        let id_owned = id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            if session.get_object_handle(&id_owned).is_ok() {
                return Err(InterfaceError::Default(
                    "A secret key with this id already exists".to_owned(),
                ));
            }
            Ok(session
                .generate_aes_key(&id_owned, key_size, sensitive)
                .map(|_| ())?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM create_key task panicked: {e}")))?
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
        // Validate key parameters before spawning (pure computation, no FFI)
        let rsa_key_size = match algorithm {
            HsmKeypairAlgorithm::RSA => match key_length_in_bits {
                1024 => RsaKeySize::Rsa1024,
                2048 => RsaKeySize::Rsa2048,
                3072 => RsaKeySize::Rsa3072,
                4096 => RsaKeySize::Rsa4096,
                x => {
                    return Err(InterfaceError::Default(format!(
                        "Invalid key length: {x} bits, for and HSM RSA key (valid values are 1024, 2048, 3072, 4096)"
                    )));
                }
            },
        };
        let sk_id_owned = sk_id.to_vec();
        let pk_id_owned = pk_id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            if session.get_object_handle(&sk_id_owned).is_ok() {
                return Err(InterfaceError::Default(
                    "A private key with this ID already exists".to_owned(),
                ));
            }
            if session.get_object_handle(&pk_id_owned).is_ok() {
                return Err(InterfaceError::Default(
                    "A public key with this ID and the '_pk' suffix already exists".to_owned(),
                ));
            }
            session.generate_rsa_key_pair(&sk_id_owned, &pk_id_owned, rsa_key_size, sensitive)?;
            Ok(())
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM create_keypair task panicked: {e}")))?
    }

    async fn export(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<Option<HsmObject>> {
        let slot = self.get_slot(slot_id)?;
        let object_id_owned = object_id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&object_id_owned)?;
            Ok(session.export_key(handle)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM export task panicked: {e}")))?
    }

    async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let object_id_owned = object_id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&object_id_owned)?;
            session.destroy_object(handle)?;
            Ok(session.delete_object_handle(&object_id_owned)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM delete task panicked: {e}")))?
    }

    async fn find(
        &self,
        slot_id: usize,
        object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handles = session.list_objects(object_filter)?;
            let mut object_ids = Vec::with_capacity(handles.len());
            for handle in handles {
                if let Ok(Some(object_id)) = session.get_object_id(handle) {
                    object_ids.push(object_id);
                } else {
                    debug!("Invalid object, skipping");
                }
            }
            InterfaceResult::Ok(object_ids)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM find task panicked: {e}")))?
    }

    async fn encrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<EncryptedContent> {
        // PKCS#11 FFI calls (C_OpenSession, C_FindObjects, C_Encrypt) are synchronous
        // and potentially slow (HSM latency). Running them directly on the tokio
        // executor thread would block the runtime and prevent it from accepting new
        // connections or processing other tasks. Offload to the blocking thread pool.
        let slot = self.get_slot(slot_id)?;
        let key_id_owned = key_id.to_vec();
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id_owned)?;
            Ok(session.encrypt(handle, algorithm.into(), &data_owned)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM encrypt task panicked: {e}")))?
    }

    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        let slot = self.get_slot(slot_id)?;
        let key_id_owned = key_id.to_vec();
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id_owned)?;
            Ok(session.decrypt(handle, algorithm.into(), &data_owned)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM decrypt task panicked: {e}")))?
    }

    async fn sign(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: SigningAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        let key_id_owned = key_id.to_vec();
        let data_owned = data.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id_owned)?;
            Ok(session.sign(handle, algorithm.into(), &data_owned)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM sign task panicked: {e}")))?
    }

    async fn get_key_type(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        let slot = self.get_slot(slot_id)?;
        let key_id_owned = key_id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id_owned)?;
            Ok(session.get_key_type(handle)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM get_key_type task panicked: {e}")))?
    }

    async fn get_key_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        let slot = self.get_slot(slot_id)?;
        let key_id_owned = key_id.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            let handle = session.get_object_handle(&key_id_owned)?;
            Ok(session.get_key_metadata(handle)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM get_key_metadata task panicked: {e}")))?
    }

    async fn generate_random(&self, slot_id: usize, len: usize) -> InterfaceResult<Vec<u8>> {
        let slot = self.get_slot(slot_id)?;
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            Ok(session.generate_random(len)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM generate_random task panicked: {e}")))?
    }

    async fn seed_random(&self, slot_id: usize, seed: &[u8]) -> InterfaceResult<()> {
        let slot = self.get_slot(slot_id)?;
        let seed_owned = seed.to_vec();
        tokio::task::spawn_blocking(move || -> InterfaceResult<_> {
            let session = slot.open_session(true)?;
            Ok(session.seed_random(&seed_owned)?)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("HSM seed_random task panicked: {e}")))?
    }

    fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
        Some(self.hsm_lib())
    }
}
