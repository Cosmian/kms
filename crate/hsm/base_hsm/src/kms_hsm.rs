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
//! - RSA: 2048-bit, 3072-bit, and 4096-bit keys
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
use std::collections::HashSet;

use async_trait::async_trait;
use cosmian_kms_interfaces::{
    CryptoAlgorithm, EcCurve, EncryptedContent, HSM, HsmKeyAlgorithm, HsmKeyPairIds,
    HsmKeypairAlgorithm, HsmObject, HsmObjectFilter, InterfaceError, InterfaceResult, KeyMetadata,
    KeyType, SigningAlgorithm, SigningKeyMetadata,
};
use cosmian_logger::debug;
use pkcs11_sys::CK_OBJECT_HANDLE;
use zeroize::Zeroizing;

use crate::{
    AesKeySize, BaseHsm, RsaKeySize, Session, SessionGuard, SlotManager,
    base_hsm::aes_key_wrap_mechanism, hsm_capabilities::HsmProvider,
};

#[cfg(not(feature = "non-fips"))]
fn generate_hsm_keypair(
    session: &Session,
    sk_id: &[u8],
    pk_id: &[u8],
    algorithm: HsmKeypairAlgorithm,
    key_length_in_bits: usize,
    sensitive: bool,
    tags: &HashSet<String>,
) -> InterfaceResult<()> {
    match algorithm {
        HsmKeypairAlgorithm::RSA => {
            let key_size = match key_length_in_bits {
                2048 => RsaKeySize::Rsa2048,
                3072 => RsaKeySize::Rsa3072,
                4096 => RsaKeySize::Rsa4096,
                x => {
                    return Err(InterfaceError::Default(format!(
                        "Invalid key length: {x} bits for an HSM RSA key \
                         (valid values are 2048, 3072, 4096)"
                    )));
                }
            };
            session.generate_rsa_key_pair(sk_id, pk_id, key_size, sensitive, Some(tags))?;
        }
        HsmKeypairAlgorithm::EC => {
            let curve = EcCurve::from_key_length_in_bits(key_length_in_bits)
                .map_err(|e| InterfaceError::Default(e.to_string()))?;
            session.generate_ec_key_pair(sk_id, pk_id, curve, sensitive, Some(tags))?;
        }
    }
    Ok(())
}

#[cfg(feature = "non-fips")]
fn generate_hsm_keypair(
    session: &Session,
    sk_id: &[u8],
    pk_id: &[u8],
    algorithm: HsmKeypairAlgorithm,
    key_length_in_bits: usize,
    sensitive: bool,
    tags: &HashSet<String>,
) -> InterfaceResult<()> {
    match algorithm {
        HsmKeypairAlgorithm::RSA => {
            let key_size = match key_length_in_bits {
                2048 => RsaKeySize::Rsa2048,
                3072 => RsaKeySize::Rsa3072,
                4096 => RsaKeySize::Rsa4096,
                x => {
                    return Err(InterfaceError::Default(format!(
                        "Invalid key length: {x} bits for an HSM RSA key \
                         (valid values are 2048, 3072, 4096)"
                    )));
                }
            };
            session.generate_rsa_key_pair(sk_id, pk_id, key_size, sensitive, Some(tags))?;
        }
        HsmKeypairAlgorithm::EC => {
            let curve = EcCurve::from_key_length_in_bits(key_length_in_bits)
                .map_err(|e| InterfaceError::Default(e.to_string()))?;
            session.generate_ec_key_pair(sk_id, pk_id, curve, sensitive, Some(tags))?;
        }
        HsmKeypairAlgorithm::Secp256k1 => {
            session.generate_ec_key_pair(
                sk_id,
                pk_id,
                EcCurve::Secp256k1,
                sensitive,
                Some(tags),
            )?;
        }
        HsmKeypairAlgorithm::Secp192k1 => {
            session.generate_ec_key_pair(
                sk_id,
                pk_id,
                EcCurve::Secp192k1,
                sensitive,
                Some(tags),
            )?;
        }
        HsmKeypairAlgorithm::Ed25519 => {
            session.generate_ec_key_pair(sk_id, pk_id, EcCurve::Ed25519, sensitive, Some(tags))?;
        }
        HsmKeypairAlgorithm::Ed448 => {
            session.generate_ec_key_pair(sk_id, pk_id, EcCurve::Ed448, sensitive, Some(tags))?;
        }
        HsmKeypairAlgorithm::X25519 => {
            return Err(InterfaceError::NotSupported(
                "X25519 HSM key creation is disabled until DeriveKey support is implemented"
                    .to_owned(),
            ));
        }
    }
    Ok(())
}

impl<P: HsmProvider> BaseHsm<P> {
    /// Run `f` on a pooled session of `slot_id` inside `spawn_blocking`.
    ///
    /// The session is checked back in only when `f` succeeds; on error the guard
    /// is dropped, which closes the session instead of returning it to the pool.
    async fn with_session<T, F>(
        &self,
        slot_id: usize,
        for_signature: bool,
        f: F,
    ) -> InterfaceResult<T>
    where
        T: Send + 'static,
        F: FnOnce(&SlotManager, &Session) -> InterfaceResult<T> + Send + 'static,
    {
        let slot = self.get_slot(slot_id)?;
        let permit = slot
            .acquire_session_permit()
            .await
            .map_err(|e| InterfaceError::Default(e.to_string()))?;
        tokio::task::spawn_blocking(move || {
            let checked_out = if for_signature {
                slot.checkout_session_for_signature()?
            } else {
                slot.checkout_session()?
            };
            let session = SessionGuard::new(&slot, checked_out, permit);
            let result = f(&slot, session.session()?)?;
            session.checkin();
            Ok(result)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("spawn_blocking error: {e}")))?
    }
}

/// Fetch signing-key metadata from the handle cache, populating it on miss.
fn cached_signing_metadata(
    session: &Session,
    handle: CK_OBJECT_HANDLE,
    not_found: &str,
) -> InterfaceResult<SigningKeyMetadata> {
    if let Some(meta) = session.object_handles_cache().get_metadata(handle)? {
        return Ok(meta);
    }
    let meta = session
        .get_signing_key_metadata(handle)?
        .ok_or_else(|| InterfaceError::InvalidRequest(not_found.to_owned()))?;
    session
        .object_handles_cache()
        .insert_metadata(handle, meta.clone())?;
    Ok(meta)
}

#[async_trait]
impl<P: HsmProvider> HSM for BaseHsm<P> {
    async fn get_available_slot_list(&self) -> InterfaceResult<Vec<usize>> {
        Ok(self.get_available_slot_list()?)
    }

    async fn get_supported_algorithms(
        &self,
        slot_id: usize,
    ) -> InterfaceResult<Vec<CryptoAlgorithm>> {
        let slot = self.get_slot(slot_id)?;
        tokio::task::spawn_blocking(move || {
            crate::base_hsm::algorithms_for_slot(&slot).map_err(InterfaceError::from)
        })
        .await
        .map_err(|e| InterfaceError::Default(format!("spawn_blocking error: {e}")))?
    }

    async fn create_key<'a>(
        &'a self,
        slot_id: usize,
        id: &'a [u8],
        algorithm: HsmKeyAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        let id = id.to_vec();
        let tags = tags.clone();
        self.with_session(slot_id, false, move |_, session| {
            if session.get_object_handle(&id).is_ok() {
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
                            )));
                        }
                    };
                    let _ = session.generate_aes_key(&id, key_size, sensitive, Some(&tags))?;
                }
            }
            Ok(())
        })
        .await
    }

    async fn create_keypair<'a>(
        &'a self,
        slot_id: usize,
        ids: HsmKeyPairIds<'a>,
        algorithm: HsmKeypairAlgorithm,
        key_length_in_bits: usize,
        sensitive: bool,
        tags: &'a HashSet<String>,
    ) -> InterfaceResult<()> {
        let HsmKeyPairIds {
            private: sk_id,
            public: pk_id,
        } = ids;
        let sk_id = sk_id.to_vec();
        let pk_id = pk_id.to_vec();
        let tags = tags.clone();
        self.with_session(slot_id, false, move |_, session| {
            if session.get_object_handle(&sk_id).is_ok() {
                return Err(InterfaceError::Default(
                    "A private key with this ID already exists".to_owned(),
                ));
            }
            if session.get_object_handle(&pk_id).is_ok() {
                return Err(InterfaceError::Default(
                    "A public key with this ID and the '_pk' suffix already exists".to_owned(),
                ));
            }
            generate_hsm_keypair(
                session,
                &sk_id,
                &pk_id,
                algorithm,
                key_length_in_bits,
                sensitive,
                &tags,
            )
        })
        .await
    }

    async fn export(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<Option<HsmObject>> {
        let object_id = object_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&object_id)?;
            Ok(session.export_key(handle)?)
        })
        .await
    }

    async fn delete(&self, slot_id: usize, object_id: &[u8]) -> InterfaceResult<()> {
        let object_id = object_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&object_id)?;
            session.destroy_object(handle)?;
            session.delete_object_handle(&object_id)?;
            Ok(())
        })
        .await
    }

    async fn find(
        &self,
        slot_id: usize,
        object_filter: HsmObjectFilter,
    ) -> InterfaceResult<Vec<Vec<u8>>> {
        self.with_session(slot_id, false, move |_, session| {
            let handles = session.list_objects(object_filter)?;
            let mut object_ids = Vec::with_capacity(handles.len());
            for handle in handles {
                if let Ok(Some(object_id)) = session.get_object_id(handle) {
                    // Pre-populate the object handle cache so that subsequent
                    // export()/get_object_handle() calls get a cache hit instead of
                    // re-searching via find_by_id_or_label() which may fail due to
                    // CKA_ID/CKA_LABEL asymmetry.
                    drop(session.cache_object_handle(&object_id, handle));
                    object_ids.push(object_id);
                } else {
                    debug!("Invalid object, skipping");
                }
            }
            Ok(object_ids)
        })
        .await
    }

    async fn encrypt<'a>(
        &'a self,
        slot_id: usize,
        key_id: &'a [u8],
        algorithm: CryptoAlgorithm,
        data: &'a [u8],
        iv_counter_nonce: &'a [u8],
    ) -> InterfaceResult<EncryptedContent> {
        let key_id = key_id.to_vec();
        let data = Zeroizing::new(data.to_vec());
        let iv_counter_nonce = iv_counter_nonce.to_vec();
        self.with_session(slot_id, false, move |slot, session| {
            let handle = session.get_object_handle(&key_id)?;
            if matches!(
                algorithm,
                CryptoAlgorithm::AesKeyWrap | CryptoAlgorithm::AesKeyWrapPad
            ) {
                let m = aes_key_wrap_mechanism(slot, slot_id, &algorithm, false)?;
                Ok(EncryptedContent {
                    ciphertext: session.aes_key_wrap(handle, m, &data)?,
                    iv: None,
                    tag: None,
                    cryptographic_algorithm: None,
                })
            } else {
                Ok(session.encrypt(
                    handle,
                    algorithm.into(),
                    &data,
                    (!iv_counter_nonce.is_empty()).then_some(&iv_counter_nonce),
                )?)
            }
        })
        .await
    }

    async fn decrypt(
        &self,
        slot_id: usize,
        key_id: &[u8],
        algorithm: CryptoAlgorithm,
        data: &[u8],
    ) -> InterfaceResult<Zeroizing<Vec<u8>>> {
        let key_id = key_id.to_vec();
        let data = data.to_vec();
        self.with_session(slot_id, false, move |slot, session| {
            let handle = session.get_object_handle(&key_id)?;
            if matches!(
                algorithm,
                CryptoAlgorithm::AesKeyWrap | CryptoAlgorithm::AesKeyWrapPad
            ) {
                let m = aes_key_wrap_mechanism(slot, slot_id, &algorithm, true)?;
                Ok(session.aes_key_unwrap(handle, m, &data)?)
            } else {
                Ok(session.decrypt(handle, algorithm.into(), &data)?)
            }
        })
        .await
    }

    async fn set_key_wrap(
        &self,
        slot_id: usize,
        key_id: &[u8],
        enabled: bool,
    ) -> InterfaceResult<()> {
        let key_id = key_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            Ok(session.set_wrap_attributes(handle, enabled)?)
        })
        .await
    }

    async fn sign_with_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
        resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
    ) -> InterfaceResult<Vec<u8>> {
        let key_id = key_id.to_vec();
        let data = data.to_vec();
        self.with_session(slot_id, true, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            let metadata =
                cached_signing_metadata(session, handle, "Sign: key not found on the HSM")?;
            let algorithm = resolve_algorithm(&metadata)?;
            Ok(session.sign(handle, algorithm.into(), &data)?)
        })
        .await
    }

    async fn verify_with_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
        resolve_algorithm: Box<
            dyn for<'a> Fn(&'a SigningKeyMetadata) -> InterfaceResult<SigningAlgorithm>
                + Send
                + Sync
                + 'static,
        >,
        data: &[u8],
        signature: &[u8],
    ) -> InterfaceResult<bool> {
        let key_id = key_id.to_vec();
        let data = data.to_vec();
        let signature = signature.to_vec();
        self.with_session(slot_id, true, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            let metadata = cached_signing_metadata(
                session,
                handle,
                "SignatureVerify: key not found on the HSM",
            )?;
            let algorithm = resolve_algorithm(&metadata)?;
            Ok(session.verify(handle, algorithm.into(), &data, &signature)?)
        })
        .await
    }

    async fn get_key_type(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyType>> {
        let key_id = key_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            Ok(session.get_key_type(handle)?)
        })
        .await
    }

    async fn get_key_metadata(
        &self,
        slot_id: usize,
        key_id: &[u8],
    ) -> InterfaceResult<Option<KeyMetadata>> {
        let key_id = key_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            Ok(session.get_key_metadata(handle)?)
        })
        .await
    }

    async fn generate_random(&self, slot_id: usize, len: usize) -> InterfaceResult<Vec<u8>> {
        self.with_session(slot_id, false, move |_, session| {
            Ok(session.generate_random(len)?)
        })
        .await
    }

    async fn seed_random(&self, slot_id: usize, seed: &[u8]) -> InterfaceResult<()> {
        let seed = seed.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            Ok(session.seed_random(&seed)?)
        })
        .await
    }

    /// Sets `CKA_START_DATE` and `CKA_END_DATE` on the key identified by `key_id`. Pass `None` to clear a date.
    async fn set_key_dates(
        &self,
        slot_id: usize,
        key_id: &[u8],
        start_date: Option<time::Date>,
        end_date: Option<time::Date>,
    ) -> InterfaceResult<()> {
        let key_id = key_id.to_vec();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            Ok(session.set_key_dates(handle, start_date, end_date)?)
        })
        .await
    }

    /// Sets `CKA_LABEL` on the key identified by `key_id`.
    async fn set_key_label(
        &self,
        slot_id: usize,
        key_id: &[u8],
        label: &str,
    ) -> InterfaceResult<()> {
        let key_id = key_id.to_vec();
        let label = label.to_owned();
        self.with_session(slot_id, false, move |_, session| {
            let handle = session.get_object_handle(&key_id)?;
            Ok(session.set_label(handle, &label)?)
        })
        .await
    }

    fn hsm_lib(&self) -> Option<&dyn std::any::Any> {
        Some(self.hsm_lib())
    }
}
