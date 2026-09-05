//! PKCS#11 session implementation for HSM interaction.

use std::{
    cmp::min,
    ops::Add,
    ptr,
    sync::{Arc, Mutex},
};

use cosmian_kms_interfaces::{
    CryptoAlgorithm, EcPrivateKeyMaterial, EcPublicKeyMaterial, EncryptedContent, HsmObject,
    HsmObjectFilter, KeyMaterial, KeyMetadata, KeyType,
    KeyType::{AesKey, RsaPrivateKey, RsaPublicKey},
    RsaPrivateKeyMaterial, RsaPublicKeyMaterial, SigningAlgorithm,
};
use cosmian_logger::{debug, trace};
#[cfg(feature = "non-fips")]
use pkcs11_sys::CKM_EDDSA;
use pkcs11_sys::{
    CK_AES_GCM_PARAMS, CK_ATTRIBUTE, CK_BBOOL, CK_DATE, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RSA_PKCS_MGF_TYPE,
    CK_RSA_PKCS_OAEP_PARAMS, CK_RSA_PKCS_PSS_PARAMS, CK_SESSION_HANDLE, CK_TRUE, CK_ULONG,
    CKA_CLASS, CKA_COEFFICIENT, CKA_EC_PARAMS, CKA_EC_POINT, CKA_END_DATE, CKA_EXPONENT_1,
    CKA_EXPONENT_2, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_PRIME_1, CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_START_DATE, CKA_VALUE,
    CKA_VALUE_LEN, CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKK_AES,
    CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_RSA, CKK_VENDOR_DEFINED, CKM_AES_CBC,
    CKM_AES_GCM, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_RSA_PKCS,
    CKM_RSA_PKCS_OAEP, CKM_SHA_1, CKM_SHA1_RSA_PKCS, CKM_SHA256, CKM_SHA256_RSA_PKCS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512,
    CKM_SHA512_RSA_PKCS, CKM_SHA512_RSA_PKCS_PSS, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CKO_VENDOR_DEFINED, CKR_ATTRIBUTE_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK,
    CKZ_DATA_SPECIFIED,
};
use rand::{TryRng, rngs::SysRng};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::session::{aes::AesKeySize, rsa::RsaKeySize};
use crate::{
    HError, HResult, ObjectHandlesCache, hsm_call,
    hsm_capabilities::HsmCapabilities,
    session::{curve_byte_size, curve_from_der_oid},
};

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;
const AES_CBC_IV_LENGTH: usize = 16;
const AES_GCM_IV_LENGTH: usize = 12;
const AES_GCM_AUTH_TAG_LENGTH: usize = 16;

/// Generate a random nonce of size T
/// This function is used to generate a random nonce for the AES GCM or a random IV for AES CBC encryption
fn generate_random_nonce<const T: usize>() -> HResult<[u8; T]> {
    let mut bytes = [0_u8; T];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| HError::Default(format!("Error generating random nonce: {e}")))?;
    Ok(bytes)
}

/// Encryption algorithm supported by the HSM
#[derive(Debug, Clone, Copy)]
pub enum HsmEncryptionAlgorithm {
    AesCbc,
    AesGcm,
    RsaPkcsV15,
    RsaOaepSha256,
    RsaOaepSha1,
}

impl From<CryptoAlgorithm> for HsmEncryptionAlgorithm {
    fn from(algorithm: CryptoAlgorithm) -> Self {
        match algorithm {
            CryptoAlgorithm::AesCbc => Self::AesCbc,
            CryptoAlgorithm::AesGcm => Self::AesGcm,
            CryptoAlgorithm::RsaPkcsV15 => Self::RsaPkcsV15,
            CryptoAlgorithm::RsaOaepSha256 => Self::RsaOaepSha256,
            CryptoAlgorithm::RsaOaepSha1 => Self::RsaOaepSha1,
        }
    }
}

/// Signing algorithm supported by the HSM
#[derive(Debug, Clone, Copy)]
pub enum HsmSigningAlgorithm {
    RsaPkcsV15,
    Sha1WithRsa,
    Sha256WithRsa,
    Sha384WithRsa,
    Sha512WithRsa,
    /// `CKM_SHA256_RSA_PKCS_PSS`. `salt_length` in bytes; `None` defaults to the SHA-256 digest
    /// length (32 bytes).
    RsaPssSha256 {
        salt_length: Option<u32>,
    },
    /// `CKM_SHA384_RSA_PKCS_PSS`. `salt_length` in bytes; `None` defaults to the SHA-384 digest
    /// length (48 bytes).
    RsaPssSha384 {
        salt_length: Option<u32>,
    },
    /// `CKM_SHA512_RSA_PKCS_PSS`. `salt_length` in bytes; `None` defaults to the SHA-512 digest
    /// length (64 bytes).
    RsaPssSha512 {
        salt_length: Option<u32>,
    },
    /// `CKM_ECDSA_SHA256`. Produces a raw `r || s` signature that is re-encoded to DER to match
    /// the software ECDSA signing convention (`ecdsa_sign` in `crate::crypto`).
    EcdsaSha256,
    /// `CKM_ECDSA_SHA384`.
    EcdsaSha384,
    /// `CKM_ECDSA_SHA512`.
    EcdsaSha512,
    /// `CKM_EDDSA` over an Ed25519 private key (pure `EdDSA`, un-hashed input). Non-FIPS: see
    /// `crate::crypto::elliptic_curves::sign` for the equivalent software gating (issue #1157).
    #[cfg(feature = "non-fips")]
    Ed25519,
    /// `CKM_EDDSA` over an Ed448 private key.
    #[cfg(feature = "non-fips")]
    Ed448,
}

impl From<SigningAlgorithm> for HsmSigningAlgorithm {
    fn from(algorithm: SigningAlgorithm) -> Self {
        match algorithm {
            SigningAlgorithm::RsaPkcsV15 => Self::RsaPkcsV15,
            SigningAlgorithm::Sha1WithRsa => Self::Sha1WithRsa,
            SigningAlgorithm::Sha256WithRsa => Self::Sha256WithRsa,
            SigningAlgorithm::Sha384WithRsa => Self::Sha384WithRsa,
            SigningAlgorithm::Sha512WithRsa => Self::Sha512WithRsa,
            SigningAlgorithm::RsaPssSha256 { salt_length } => Self::RsaPssSha256 { salt_length },
            SigningAlgorithm::RsaPssSha384 { salt_length } => Self::RsaPssSha384 { salt_length },
            SigningAlgorithm::RsaPssSha512 { salt_length } => Self::RsaPssSha512 { salt_length },
            SigningAlgorithm::EcdsaSha256 => Self::EcdsaSha256,
            SigningAlgorithm::EcdsaSha384 => Self::EcdsaSha384,
            SigningAlgorithm::EcdsaSha512 => Self::EcdsaSha512,
            #[cfg(feature = "non-fips")]
            SigningAlgorithm::Ed25519 => Self::Ed25519,
            #[cfg(feature = "non-fips")]
            SigningAlgorithm::Ed448 => Self::Ed448,
        }
    }
}

/// An active PKCS#11 session with an HSM.
pub struct Session {
    hsm: Arc<crate::hsm_lib::HsmLib>,
    handle: CK_SESSION_HANDLE,
    object_handles_cache: Arc<ObjectHandlesCache>,
    supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
    logging_in: bool,
    hsm_capabilities: HsmCapabilities,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::hsm_lib::HsmLib>,
        session_handle: CK_SESSION_HANDLE,
        object_handles_cache: Arc<ObjectHandlesCache>,
        supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
        logging_in: bool,
        hsm_capabilities: HsmCapabilities,
    ) -> Self {
        debug!("Creating new session: {session_handle}. Logging in? {logging_in}");
        Self {
            hsm,
            handle: session_handle,
            object_handles_cache,
            supported_oaep_hash_cache,
            logging_in,
            hsm_capabilities,
        }
    }

    /// Get the HSM library interface
    pub(crate) fn hsm(&self) -> Arc<crate::hsm_lib::HsmLib> {
        self.hsm.clone()
    }

    /// Get the PKCS#11 session handle
    pub(crate) const fn session_handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    /// Get the object handles cache
    pub(crate) fn object_handles_cache(&self) -> Arc<ObjectHandlesCache> {
        self.object_handles_cache.clone()
    }

    /// Pre-populate the object handle cache with a known object_id-to-handle mapping.
    ///
    /// Called during `find()` to ensure that subsequent `get_object_handle()` calls
    /// get a cache hit instead of re-searching via `find_by_id_or_label()`.
    pub fn cache_object_handle(&self, object_id: &[u8], handle: CK_OBJECT_HANDLE) -> HResult<()> {
        self.object_handles_cache.insert(object_id.to_vec(), handle)
    }

    /// Close the session and log out if necessary
    pub fn close(&self) -> HResult<()> {
        if self.logging_in {
            hsm_call!(self.hsm, "Failed logging out", C_Logout, self.handle);
        }
        hsm_call!(
            self.hsm,
            "Failed closing a session",
            C_CloseSession,
            self.handle
        );
        Ok(())
    }

    /// Retrieve the hash algorithms supported for RSA OAEP encryption by the HSM.
    ///
    /// This function determines which hashing algorithms can be used in combination with
    /// the RSA OAEP mechanism since support for OAEP hash algorithms varies between HSM
    /// implementations.
    ///
    /// The check works by generating a temporary RSA key pair, then attempting to initialize
    /// the OAEP mechanism with different candidate hash algorithms. If `C_EncryptInit` succeeds,
    /// the hash algorithm is considered supported.
    ///
    /// Results are cached for subsequent calls to avoid redundant key generation and mechanism checks.
    ///
    /// # Returns
    /// * `HResult<Vec<CK_MECHANISM_TYPE>>` - A result containing a vector of supported hash
    ///   mechanisms (e.g., `CKM_SHA256`) usable with RSA OAEP in this slot.
    ///
    /// # Errors
    /// * Returns an error if RSA key pair generation fails.
    /// * Returns an error if the HSM library does not provide the `C_EncryptInit` function.
    /// * Returns an error if destroying the temporary test keys fails.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library. All temporary keys are
    /// cleaned up after testing.
    pub fn get_supported_oaep_hash(&self) -> HResult<Vec<CK_MECHANISM_TYPE>> {
        let mut cache = self
            .supported_oaep_hash_cache
            .lock()
            .map_err(|e| HError::Default(format!("Failed to acquire OAEP hash cache lock: {e}")))?;
        if let Some(ref list) = *cache {
            return Ok(list.clone());
        }

        // Create a temporary key for testing
        let sk_id = Uuid::new_v4().to_string();
        let pk_id = sk_id.clone() + "_pk";
        let (sk_handle, pk_handle) = self.generate_rsa_key_pair(
            sk_id.as_bytes(),
            pk_id.as_bytes(),
            RsaKeySize::Rsa1024, //As the specific key size doesn't matter, use the smallest (fastest) algorithm supported.
            false,
        )?;

        let candidates: &[(CK_MECHANISM_TYPE, CK_RSA_PKCS_MGF_TYPE)] = &[
            (CKM_SHA_1, CKG_MGF1_SHA1),
            (CKM_SHA256, CKG_MGF1_SHA256),
            (CKM_SHA384, CKG_MGF1_SHA384),
            (CKM_SHA512, CKG_MGF1_SHA512),
        ];

        let mut supported = Vec::new();

        // Probe each hash by performing a real (dummy) single-part encryption.
        // Using encrypt_with_mechanism (C_EncryptInit + C_Encrypt) guarantees the
        // session returns to a clean state after each probe: per PKCS#11, C_Encrypt
        // terminates the active encryption operation on completion.  Stopping at
        // C_EncryptInit would leave `self.handle` in ENCRYPT state, causing
        // CKR_OPERATION_ACTIVE (130) for the next hash and for any later operations
        // (including C_DestroyObject on the temp key and keys created by other tests).
        for (hash, mgf) in candidates {
            let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                hashAlg: *hash,
                mgf: *mgf,
                source: CKZ_DATA_SPECIFIED,
                pSourceData: ptr::null_mut(),
                ulSourceDataLen: 0,
            };

            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_RSA_PKCS_OAEP,
                pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                ulParameterLen: CK_ULONG::try_from(size_of::<CK_RSA_PKCS_OAEP_PARAMS>())?,
            };

            // A 1-byte plaintext is minimal but valid for RSA-1024 OAEP.
            let dummy_plaintext = [0_u8; 1];
            match self.encrypt_with_mechanism(pk_handle, &mut mechanism, &dummy_plaintext) {
                Ok(_) => supported.push(*hash),
                Err(e) => debug!("OAEP hash {hash} not supported: {e}"),
            }
        }
        self.destroy_object(sk_handle)?;
        self.destroy_object(pk_handle)?;

        *cache = Some(supported.clone());
        Ok(supported)
    }

    /// Search for and retrieve object handles that match the provided attribute template.
    ///
    /// This function queries the HSM to find all objects in the current slot / session
    /// that match the provided attribute template (for example, objects with a specific
    /// label, class, or key type).
    ///
    /// # Arguments
    /// * `template` - A vector of `CK_ATTRIBUTE` structures defining the search criteria.
    ///   Each attribute specifies a property (such as `CKA_LABEL` or `CKA_CLASS`) and the
    ///   expected value. Providing an empty vector will result in all available objects
    ///   being returned
    ///
    /// # Returns
    /// * `HResult<Vec<CK_OBJECT_HANDLE>>` - A result containing a vector of object handles
    ///   that match the specified template. The vector will be empty if no objects match.
    ///
    /// # Errors
    /// * Returns an error if the HSM fails to initialize, execute, or finalize the object search.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions from the HSM library.
    fn find_object_handles(
        &self,
        mut template: Vec<CK_ATTRIBUTE>,
    ) -> HResult<Vec<CK_OBJECT_HANDLE>> {
        let mut object_handles: Vec<CK_OBJECT_HANDLE> = Vec::new();
        hsm_call!(
            self.hsm,
            "Failed to initialize object search: C_FindObjectsInit failed",
            C_FindObjectsInit,
            self.handle,
            template.as_mut_ptr(),
            CK_ULONG::try_from(template.len())?
        );

        let max_object_count = usize::try_from(self.hsm_capabilities.find_max_object_count)?;
        let mut handles_buf = vec![CK_OBJECT_HANDLE::default(); max_object_count];
        let mut object_count: CK_ULONG = 0;
        loop {
            hsm_call!(
                self.hsm,
                "Failed to find objects",
                C_FindObjects,
                self.handle,
                handles_buf.as_mut_ptr(),
                self.hsm_capabilities.find_max_object_count, // ulMaxObjectCount
                &raw mut object_count
            );
            if object_count == 0 {
                break;
            }
            trace!("Found {object_count} objects");
            if object_count > CK_ULONG::try_from(max_object_count)? {
                return Err(HError::Default(
                    "More objects returned than requested".to_owned(),
                ));
            }
            object_handles.extend_from_slice(
                handles_buf
                    .get(..usize::try_from(object_count)?)
                    .ok_or_else(|| {
                        HError::Default("Invalid object count returned from HSM".to_owned())
                    })?,
            );
        }
        hsm_call!(
            self.hsm,
            "Failed to finalize object search",
            C_FindObjectsFinal,
            self.handle
        );
        Ok(object_handles)
    }

    /// Retrieve the object handle for a given object ID from the HSM.
    ///
    /// This function attempts to locate the handle of an object (such as a key) in the HSM
    /// by first searching by `CKA_ID` (set by Cosmian KMS on every key it creates), then
    /// falling back to `CKA_LABEL` for externally provisioned keys that may not have `CKA_ID`.
    /// To optimize performance, previously found handles are cached and reused if available.
    ///
    /// Special handling is included for key pairs who might be saved with the same label for both:
    /// * If the provided ID ends with `_pk`, the function first tries to find an exact match.
    ///   If none is found, it retries with the suffix removed (and an optional trailing space removed).
    /// * If multiple objects are returned for the same label (e.g., both public and private keys
    ///   sharing a label), the function inspects the key type of each candidate and selects
    ///   the one that matches the requested identifier (`_pk` → public key, otherwise private/secret key).
    ///
    /// # Arguments
    /// * `object_id` - A byte slice representing the identifier of the object to find.
    ///
    /// # Returns
    /// * `HResult<CK_OBJECT_HANDLE>` - A result containing the handle of the object if found.
    ///
    /// # Errors
    /// * Returns an error if no object with the given identifier can be found in the HSM.
    /// * Returns an error if multiple objects match but none correspond to the expected key type.
    /// * Returns an error if underlying PKCS#11 calls fail while retrieving handles or key types.
    ///
    /// # Safety
    /// This function calls unsafe PKCS#11 FFI functions indirectly (via `find_object_handles`
    /// and `get_key_type`).
    pub fn get_object_handle(&self, object_id: &[u8]) -> HResult<CK_OBJECT_HANDLE> {
        if let Some(handle) = self.object_handles_cache.get(object_id)? {
            return Ok(handle);
        }

        // Search by CKA_ID first (set by KMS on every key it creates), then fall back to
        // CKA_LABEL for externally provisioned keys that may not have CKA_ID set.
        let mut object_handles = self.find_by_id_or_label(object_id)?;
        if object_handles.is_empty() {
            if object_id.ends_with(b"_pk") {
                // Check if the HSM stores the public key without the _pk suffix
                let mut object_id_trimmed = object_id.strip_suffix(b"_pk").unwrap_or(object_id);
                object_id_trimmed = object_id_trimmed
                    .strip_suffix(b" ")
                    .unwrap_or(object_id_trimmed);
                object_handles = self.find_by_id_or_label(object_id_trimmed)?;
                if object_handles.is_empty() {
                    return Err(HError::Default("Object not found".to_owned()));
                }
            } else {
                return Err(HError::Default("Object not found".to_owned()));
            }
        }

        let mut object_handle = *object_handles
            .first()
            .ok_or_else(|| HError::Default("Object handles empty".to_owned()))?;
        if object_handles.len() > 1 {
            // Multiple matches; this happens when the HSM uses the same label for SK and PK.
            // Disambiguate by key type.
            debug!("Found {} possible handles", object_handles.len());
            let mut matched_type_count = 0;
            for handle in object_handles {
                let Some(object_type) = self.get_key_type(handle)? else {
                    continue;
                };
                if object_id.ends_with(b"_pk") {
                    // We are looking for a public key. Check if the results contain one.
                    if object_type == RsaPublicKey {
                        if matched_type_count > 0 {
                            let label = std::str::from_utf8(object_id).unwrap_or("<non-utf8>");
                            return Err(HError::Default(format!(
                                "Multiple RSA public keys with label '{label}' found in the HSM slot. \
                                 Labels must be unique per key type."
                            )));
                        }
                        object_handle = handle;
                        matched_type_count += 1;
                    }
                } else if object_type == AesKey || object_type == RsaPrivateKey {
                    if matched_type_count > 0 {
                        let label = std::str::from_utf8(object_id).unwrap_or("<non-utf8>");
                        return Err(HError::Default(format!(
                            "Multiple keys with label '{label}' and the same key type found in the \
                             HSM slot. Labels must be unique per key type."
                        )));
                    }
                    object_handle = handle;
                    matched_type_count += 1;
                }
            }
        }

        // update cache
        self.object_handles_cache
            .insert(object_id.to_vec(), object_handle)?;

        Ok(object_handle)
    }

    /// Find PKCS#11 object handles by searching `CKA_ID` first, then `CKA_LABEL`.
    ///
    /// Cosmian KMS sets both `CKA_ID` and `CKA_LABEL` on every key it creates, so
    /// `CKA_ID`-based lookup is the primary path.  `CKA_LABEL` is the fallback for
    /// externally provisioned keys (e.g., pre-loaded via `pkcs11-tool`) that may not
    /// have `CKA_ID` set.
    fn find_by_id_or_label(&self, id: &[u8]) -> HResult<Vec<CK_OBJECT_HANDLE>> {
        let id_template = [CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(id.len())?,
        }];
        let handles = self.find_object_handles(id_template.to_vec())?;
        if !handles.is_empty() {
            return Ok(handles);
        }
        // Fall back to CKA_LABEL for keys not created by Cosmian KMS
        let label_template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(id.len())?,
        }];
        self.find_object_handles(label_template.to_vec())
    }

    /// Clear all cached object handles for this HSM slot.
    ///
    /// This function removes all entries from the object handle cache associated with
    /// this session's `SlotManager`. Clearing the cache may be useful especially for testing.
    pub fn clear_object_handles(&self) -> HResult<()> {
        self.object_handles_cache.clear()?;
        Ok(())
    }

    pub fn delete_object_handle(&self, id: &[u8]) -> HResult<()> {
        self.object_handles_cache.remove(id)?;
        Ok(())
    }

    pub fn generate_random(&self, len: usize) -> HResult<Vec<u8>> {
        let mut values = vec![0_u8; len];
        #[cfg(target_os = "windows")]
        let len = u32::try_from(len)?;
        #[cfg(not(target_os = "windows"))]
        let len = u64::try_from(len)?;
        hsm_call!(
            self.hsm,
            "Failed generating random data",
            C_GenerateRandom,
            self.handle,
            values.as_mut_ptr(),
            len
        );
        Ok(values)
    }

    /// Seed the HSM RNG with the provided data
    pub fn seed_random(&self, seed: &[u8]) -> HResult<()> {
        if seed.is_empty() {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        let len = u32::try_from(seed.len())?;
        #[cfg(not(target_os = "windows"))]
        let len = u64::try_from(seed.len())?;
        // PKCS#11 expects a mutable u8 pointer, cast away constness safely here.
        let mut_ptr = seed.as_ptr().cast_mut();
        hsm_call!(
            self.hsm,
            "Failed seeding HSM RNG",
            C_SeedRandom,
            self.handle,
            mut_ptr,
            len
        );
        Ok(())
    }

    /// List objects in the HSM that match the specified filter
    /// The filter can be used to narrow down the search to specific types of objects
    /// such as AES keys, RSA keys, etc.
    /// If no filter is provided, all objects are listed.
    #[allow(clippy::needless_pass_by_value)]
    pub fn list_objects(&self, object_filter: HsmObjectFilter) -> HResult<Vec<CK_OBJECT_HANDLE>> {
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        match object_filter {
            HsmObjectFilter::Any => {}
            HsmObjectFilter::AesKey => {
                template.extend([
                    CK_ATTRIBUTE {
                        type_: CKA_CLASS,
                        pValue: std::ptr::from_ref(&CKO_SECRET_KEY)
                            .cast::<std::ffi::c_void>()
                            .cast_mut(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_KEY_TYPE,
                        pValue: std::ptr::from_ref(&CKK_AES)
                            .cast::<std::ffi::c_void>()
                            .cast_mut(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                    },
                ]);
            }
            HsmObjectFilter::RsaKey => template.extend([CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_RSA)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            }]),
            HsmObjectFilter::RsaPrivateKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PRIVATE_KEY)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                },
            ]),
            HsmObjectFilter::RsaPublicKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PUBLIC_KEY)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                },
            ]),
            HsmObjectFilter::EcKey => template.extend([CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_EC)
                    .cast::<std::ffi::c_void>()
                    .cast_mut(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
            }]),
            HsmObjectFilter::EcPrivateKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PRIVATE_KEY)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_EC)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                },
            ]),
            HsmObjectFilter::EcPublicKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PUBLIC_KEY)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_EC)
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(size_of::<CK_KEY_TYPE>())?,
                },
            ]),
        }
        let object_handles = self.find_object_handles(template)?;
        Ok(object_handles)
    }

    /// Destroy an object in the HSM
    pub fn destroy_object(&self, object_handle: CK_OBJECT_HANDLE) -> HResult<()> {
        hsm_call!(
            self.hsm,
            "Failed to destroy object",
            C_DestroyObject,
            self.handle,
            object_handle
        );
        Ok(())
    }

    /// Apply PKCS#7 padding to the input data.
    ///
    /// PKCS#7 padding ensures that the input length is a multiple of the block size,
    /// which is required for many block cipher encryption algorithms (such as AES in CBC mode).
    /// The padding consists of N bytes, each with value N, where N is the number of padding
    /// bytes required to reach the next block boundary.
    ///
    /// # Arguments
    /// * `data` - The input data to be padded (modified in place).
    /// * `block_size` - The block size in bytes (commonly 16 for AES).
    ///
    /// # Errors
    /// * Returns an error if the block size is 0 or greater than 255.
    /// * Returns an error if the resulting data would exceed reasonable size limits.
    ///
    /// # Examples
    /// For a block size of 16:
    /// - Input of 15 bytes gets 1 padding byte with value 0x01
    /// - Input of 16 bytes gets 16 padding bytes each with value 0x10
    /// - Input of 17 bytes gets 15 padding bytes each with value 0x0F
    fn pkcs7_pad(data: &mut Vec<u8>, block_size: usize) -> HResult<()> {
        if block_size == 0 || block_size > 255 {
            return Err(HError::Default(format!(
                "Invalid block size: {block_size}. Must be between 1 and 255"
            )));
        }

        let current_len = data.len();
        let pad_len = block_size - (current_len % block_size);

        // Ensure we don't overflow when adding padding
        if current_len.saturating_add(pad_len) < current_len {
            return Err(HError::Default(
                "Data too large: adding padding would cause overflow".to_owned(),
            ));
        }

        let pad_byte = u8::try_from(pad_len).map_err(|e| {
            HError::Default(format!("Padding length {pad_len} cannot fit in u8: {e}"))
        })?;

        // Reserve capacity to avoid multiple allocations
        data.reserve(pad_len);
        data.resize(current_len + pad_len, pad_byte);

        Ok(())
    }

    /// Remove PKCS#7 padding from the input data.
    ///
    /// This function verifies and removes PKCS#7 padding from data that was previously
    /// padded for block cipher encryption.
    ///
    /// # Arguments
    /// * `data` - The input buffer wrapped in PKCS#7 padding.
    /// * `block_size` - The block size in bytes (commonly 16 for AES).
    ///
    /// # Returns
    /// * `HResult<Zeroizing<Vec<u8>>>` - A result containing the unpadded data on success,
    ///   or an error if the padding is invalid.
    ///
    /// # Errors
    /// * Returns an error if the input buffer is empty.
    /// * Returns an error if the buffer length is not a multiple of the block size.
    /// * Returns an error if the padding length is invalid or exceeds the block size.
    /// * Returns an error if the padding bytes do not all match the expected value.
    fn pkcs7_unpad(data: Zeroizing<Vec<u8>>, block_size: usize) -> HResult<Zeroizing<Vec<u8>>> {
        if data.is_empty() {
            return Err(HError::Default(
                "Invalid PKCS#7 padding: empty buffer".to_owned(),
            ));
        }
        if !data.len().is_multiple_of(block_size) {
            return Err(HError::Default("Data doesn't align to blocks".to_owned()));
        }
        let pad_len = data.last().map(|&b| usize::from(b)).ok_or_else(|| {
            HError::Default("Invalid PKCS#7 padding: invalid last byte".to_owned())
        })?;
        if pad_len == 0 || pad_len > data.len() || pad_len > block_size {
            return Err(HError::Default("Invalid PKCS#7 padding".to_owned()));
        }
        // verify all pad bytes
        if !data
            .get(data.len() - pad_len..)
            .ok_or_else(|| HError::Default("Failed to get padding bytes".to_owned()))?
            .iter()
            .all(|&b| usize::from(b) == pad_len)
        {
            return Err(HError::Default("Invalid PKCS#7 padding bytes".to_owned()));
        }
        let length = data.len();
        let mut unpadded = data;
        unpadded.truncate(length - pad_len);
        Ok(unpadded)
    }

    /// Encrypt data using the specified key and algorithm
    pub fn encrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: HsmEncryptionAlgorithm,
        plaintext: &[u8],
    ) -> HResult<EncryptedContent> {
        Ok(match &algorithm {
            HsmEncryptionAlgorithm::AesGcm => {
                let mut nonce = generate_random_nonce::<12>()?;
                let mut params = CK_AES_GCM_PARAMS {
                    pIv: nonce.as_mut_ptr(),
                    ulIvLen: CK_ULONG::try_from(AES_GCM_IV_LENGTH)?,
                    ulIvBits: CK_ULONG::try_from(AES_GCM_IV_LENGTH * 8)?,
                    pAAD: ptr::null_mut(),
                    ulAADLen: 0,
                    ulTagBits: CK_ULONG::try_from(AES_GCM_AUTH_TAG_LENGTH * 8)?,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(size_of::<CK_AES_GCM_PARAMS>())?,
                };
                let ciphertext =
                    self.encrypt_with_mechanism(key_handle, &mut mechanism, plaintext)?;
                EncryptedContent {
                    iv: Some(nonce.to_vec()),
                    ciphertext: ciphertext
                        .get(..ciphertext.len() - AES_GCM_AUTH_TAG_LENGTH)
                        .ok_or_else(|| HError::Default("Failed to extract ciphertext".to_owned()))?
                        .to_vec(),
                    tag: Some(
                        ciphertext
                            .get(ciphertext.len() - AES_GCM_AUTH_TAG_LENGTH..)
                            .ok_or_else(|| HError::Default("Failed to extract tag".to_owned()))?
                            .to_vec(),
                    ),
                }
            }
            HsmEncryptionAlgorithm::AesCbc => {
                let mut iv = generate_random_nonce::<AES_CBC_IV_LENGTH>()?;
                if let Some(max_cbc_data_size) = self.hsm_capabilities.max_cbc_data_size {
                    if plaintext.len() > max_cbc_data_size {
                        debug!("Performing multi round AES CBC encryption");
                        return self.encrypt_aes_cbc_multi_round(
                            key_handle,
                            iv,
                            plaintext,
                            max_cbc_data_size,
                        );
                    }
                }
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: iv.as_mut_ptr().cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(iv.len())?,
                };

                let mut padded_plaintext = plaintext.to_vec();
                Self::pkcs7_pad(&mut padded_plaintext, AES_BLOCK_SIZE)?;
                let ciphertext =
                    self.encrypt_with_mechanism(key_handle, &mut mechanism, &padded_plaintext)?;

                EncryptedContent {
                    iv: Some(iv.to_vec()),
                    ciphertext, // no separate tag for CBC
                    tag: None,
                }
            }
            HsmEncryptionAlgorithm::RsaPkcsV15 => {
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };
                EncryptedContent {
                    ciphertext: self.encrypt_with_mechanism(
                        key_handle,
                        &mut mechanism,
                        plaintext,
                    )?,
                    ..Default::default()
                }
            }
            HsmEncryptionAlgorithm::RsaOaepSha256 => {
                let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA256,
                    mgf: CKG_MGF1_SHA256,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: std::ptr::null_mut(),
                    ulSourceDataLen: 0,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS_OAEP,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(
                        std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
                    )?,
                };
                EncryptedContent {
                    ciphertext: self.encrypt_with_mechanism(
                        key_handle,
                        &mut mechanism,
                        plaintext,
                    )?,
                    ..Default::default()
                }
            }
            HsmEncryptionAlgorithm::RsaOaepSha1 => {
                let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA_1,
                    mgf: CKG_MGF1_SHA1,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: ptr::null_mut(),
                    ulSourceDataLen: 0,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS_OAEP,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(size_of::<CK_RSA_PKCS_OAEP_PARAMS>())?,
                };
                EncryptedContent {
                    ciphertext: self.encrypt_with_mechanism(
                        key_handle,
                        &mut mechanism,
                        plaintext,
                    )?,
                    ..Default::default()
                }
            }
        })
    }

    /// Decrypt data using the specified key and algorithm
    pub fn decrypt(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: HsmEncryptionAlgorithm,
        ciphertext: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        match &algorithm {
            HsmEncryptionAlgorithm::AesGcm => {
                if ciphertext.len() < AES_GCM_IV_LENGTH {
                    return Err(HError::Default("Invalid AES GCM ciphertext".to_owned()));
                }
                let mut nonce: [u8; AES_GCM_IV_LENGTH] = ciphertext
                    .get(..AES_GCM_IV_LENGTH)
                    .ok_or_else(|| HError::Default("Failed to extract nonce".to_owned()))?
                    .try_into()
                    .map_err(|e| HError::Default(format!("Invalid AES GCM nonce: {e}")))?;
                let mut params = CK_AES_GCM_PARAMS {
                    pIv: nonce.as_mut_ptr(),
                    ulIvLen: CK_ULONG::try_from(AES_GCM_IV_LENGTH)?,
                    ulIvBits: CK_ULONG::try_from(AES_GCM_IV_LENGTH * 8)?,
                    pAAD: ptr::null_mut(),
                    ulAADLen: 0,
                    ulTagBits: CK_ULONG::try_from(AES_GCM_AUTH_TAG_LENGTH * 8)?,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(size_of::<CK_AES_GCM_PARAMS>())?,
                };
                let plaintext = self.decrypt_with_mechanism(
                    key_handle,
                    &mut mechanism,
                    ciphertext.get(AES_GCM_IV_LENGTH..).ok_or_else(|| {
                        HError::Default("Failed to extract ciphertext".to_owned())
                    })?,
                )?;
                Ok(plaintext)
            }
            HsmEncryptionAlgorithm::AesCbc => {
                if ciphertext.len() < AES_CBC_IV_LENGTH {
                    return Err(HError::Default("Invalid AES CBC ciphertext".to_owned()));
                }
                let mut iv: [u8; AES_CBC_IV_LENGTH] = ciphertext
                    .get(..AES_CBC_IV_LENGTH)
                    .ok_or_else(|| HError::Default("Failed to extract iv".to_owned()))?
                    .try_into()
                    .map_err(|e| HError::Default(format!("Invalid AES CBC IV: {e}")))?;
                if let Some(max_cbc_data_size) = self.hsm_capabilities.max_cbc_data_size {
                    if ciphertext.len() > (max_cbc_data_size + AES_CBC_IV_LENGTH) {
                        debug!("Performing multi round AES CBC decryption");
                        return self.decrypt_aes_cbc_multi_round(
                            key_handle,
                            &iv,
                            ciphertext.get(AES_CBC_IV_LENGTH..).ok_or_else(|| {
                                HError::Default("Failed to extract ciphertext".to_owned())
                            })?,
                            max_cbc_data_size,
                        );
                    }
                }
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: iv.as_mut_ptr().cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(iv.len())?,
                };

                let padded_plaintext = self.decrypt_with_mechanism(
                    key_handle,
                    &mut mechanism,
                    ciphertext.get(AES_CBC_IV_LENGTH..).ok_or_else(|| {
                        HError::Default("Failed to extract ciphertext".to_owned())
                    })?,
                )?;

                let plaintext = Self::pkcs7_unpad(padded_plaintext, AES_BLOCK_SIZE)?;
                Ok(plaintext)
            }
            HsmEncryptionAlgorithm::RsaPkcsV15 => {
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS,
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                };
                self.decrypt_with_mechanism(key_handle, &mut mechanism, ciphertext)
            }
            HsmEncryptionAlgorithm::RsaOaepSha256 => {
                let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA256,
                    mgf: CKG_MGF1_SHA256,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: std::ptr::null_mut(),
                    ulSourceDataLen: 0,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS_OAEP,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(
                        std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
                    )?,
                };
                self.decrypt_with_mechanism(key_handle, &mut mechanism, ciphertext)
            }
            HsmEncryptionAlgorithm::RsaOaepSha1 => {
                let mut params = CK_RSA_PKCS_OAEP_PARAMS {
                    hashAlg: CKM_SHA_1,
                    mgf: CKG_MGF1_SHA1,
                    source: CKZ_DATA_SPECIFIED,
                    pSourceData: std::ptr::null_mut(),
                    ulSourceDataLen: 0,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_RSA_PKCS_OAEP,
                    pParameter: (&raw mut params).cast::<std::ffi::c_void>(),
                    ulParameterLen: CK_ULONG::try_from(
                        std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
                    )?,
                };
                self.decrypt_with_mechanism(key_handle, &mut mechanism, ciphertext)
            }
        }
    }

    /// Encrypt data using AES-CBC in multiple rounds with PKCS#7 padding.
    ///
    /// This function performs AES-CBC encryption of the given plaintext, splitting
    /// the operation into multiple rounds if the input exceeds `max_round_length`.
    /// This is useful for large data sets where encrypting in one call would exceed
    /// the module's limits.
    ///
    /// Multiple rounds can be performed without compromising security because
    /// each block of ciphertext becomes the initialization vector (IV) for the
    /// next block. This function preserves that property by carrying forward the
    /// final ciphertext block of one round as the IV for the next round. As a result,
    /// the ciphertext produced by multi-round encryption is bit-for-bit identical
    /// to what would be produced by a single-shot AES-CBC encryption with the same
    /// key, IV, and plaintext without compromising secrets in any way.
    ///
    /// # Arguments
    /// * `key_handle` - The handle of the AES key object to encrypt with.
    /// * `iv` - A 16-byte initialization vector.
    /// * `plaintext` - The data to be encrypted.
    /// * `max_round_length` - The maximum number of bytes to process per round (must be a multiple of 16).
    ///
    /// # Returns
    /// * `HResult<EncryptedContent>` - A result containing the encrypted data and IV.
    ///
    /// # Errors
    /// * Returns an error if `max_round_length` is less than 16 or not a multiple of 16.
    /// * Returns an error if the HSM encryption operation fails during any round.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions to perform encryption via the HSM library.
    pub fn encrypt_aes_cbc_multi_round(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        iv: [u8; AES_CBC_IV_LENGTH],
        plaintext: &[u8],
        max_round_length: usize,
    ) -> HResult<EncryptedContent> {
        if max_round_length < AES_BLOCK_SIZE {
            return Err(HError::Default("Too small maximum round length".to_owned()));
        }
        if !max_round_length.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(HError::Default(
                "Round length must be multiple of block size (16)".to_owned(),
            ));
        }
        let mut padded_plaintext = plaintext.to_vec();
        Self::pkcs7_pad(&mut padded_plaintext, AES_BLOCK_SIZE)?;
        let mut round_iv = iv;
        let total_length = padded_plaintext.len();
        let mut processed_length = 0;
        let mut ciphertext: Vec<u8> = Vec::with_capacity(total_length);

        loop {
            let round_length = min(total_length - processed_length, max_round_length);
            if round_length == 0 {
                break;
            }
            trace!(
                "Doing round with {round_length} bytes. {processed_length} of {total_length} done"
            );
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: round_iv.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulParameterLen: CK_ULONG::try_from(iv.len())?,
            };
            let round_ciphertext = self.encrypt_with_mechanism(
                key_handle,
                &mut mechanism,
                padded_plaintext
                    .as_slice()
                    .get(processed_length..processed_length + round_length)
                    .ok_or_else(|| HError::Default("Failed to round data".to_owned()))?,
            )?;
            for (i, iv_byte) in round_iv.iter_mut().enumerate().take(iv.len()) {
                *iv_byte = *round_ciphertext
                    .get(round_ciphertext.len() - iv.len() + i)
                    .ok_or_else(|| HError::Default("Failed to get iv byte".to_owned()))?;
            }
            ciphertext.extend(round_ciphertext);
            processed_length += round_length;
        }
        Ok(EncryptedContent {
            iv: Some(iv.to_vec()),
            ciphertext, // no separate tag for CBC
            tag: None,
        })
    }

    /// Decrypt data using AES-CBC in multiple rounds before removing PKCS#7 padding.
    ///
    /// This function performs AES-CBC decryption of the given ciphertext, splitting
    /// the operation into multiple rounds if the input exceeds `max_round_length`.
    /// This is useful for large ciphertexts where decrypting in one call would exceed
    /// the module's limits.
    ///
    /// For more details see [`Session::encrypt_aes_cbc_multi_round`].
    ///
    /// # Arguments
    /// * `key_handle` - The handle to the AES key object stored in the HSM.
    /// * `iv` - A 16-byte initialization vector.
    /// * `ciphertext` - The data to decrypt (must be a multiple of the AES block size, 16 bytes).
    /// * `max_round_length` - The maximum number of bytes to process per round (must be a multiple of 16).
    ///
    /// # Returns
    /// * `HResult<Zeroizing<Vec<u8>>>` - A result containing the decrypted plaintext.
    ///
    /// # Errors
    /// * Returns an error if `max_round_length` is less than 16 or not a multiple of 16.
    /// * Returns an error if the ciphertext length is not a multiple of 16.
    /// * Returns an error if the IV length is not exactly 16 bytes.
    /// * Returns an error if PKCS#7 unpadding fails.
    /// * Returns an error if the HSM decryption operation fails during any round.
    ///
    /// # Safety
    /// This function calls unsafe FFI functions to perform decryption via the HSM library.
    pub fn decrypt_aes_cbc_multi_round(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        iv: &[u8],
        ciphertext: &[u8],
        max_round_length: usize,
    ) -> HResult<Zeroizing<Vec<u8>>> {
        if max_round_length < AES_BLOCK_SIZE {
            return Err(HError::Default("Too small maximum round length".to_owned()));
        }
        if !max_round_length.is_multiple_of(AES_BLOCK_SIZE) {
            return Err(HError::Default(format!(
                "Round length must be multiple of block size ({AES_BLOCK_SIZE}))"
            )));
        }
        if !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(HError::Default(format!(
                "AES CBC ciphertext must be multiple of block size ({AES_BLOCK_SIZE})"
            )));
        }
        if iv.len() != AES_CBC_IV_LENGTH {
            return Err(HError::Default(format!(
                "Wrong IV length. Must be {AES_CBC_IV_LENGTH} bytes long"
            )));
        }

        let mut round_iv: [u8; AES_CBC_IV_LENGTH] = iv
            .get(..AES_CBC_IV_LENGTH)
            .ok_or_else(|| HError::Default("Failed to get iv".to_owned()))?
            .try_into()
            .map_err(|e| HError::Default(format!("Invalid IV: {e}")))?;
        let total_length = ciphertext.len();
        let mut processed_length = 0;
        let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(total_length));

        loop {
            let round_length = min(total_length - processed_length, max_round_length);
            if round_length == 0 {
                break;
            }
            trace!(
                "Doing round with {round_length} bytes. {processed_length} of {total_length} done"
            );
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: round_iv.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulParameterLen: CK_ULONG::try_from(iv.len())?,
            };
            let round_plaintext = self.decrypt_with_mechanism(
                key_handle,
                &mut mechanism,
                ciphertext
                    .get(processed_length..processed_length + round_length)
                    .ok_or_else(|| {
                        HError::Default("Failed to extract round ciphertext".to_owned())
                    })?,
            )?;

            plaintext.extend_from_slice(&round_plaintext);
            processed_length += round_length;
            for (i, iv_byte) in round_iv.iter_mut().enumerate().take(iv.len()) {
                *iv_byte = *ciphertext
                    .get(processed_length - iv.len() + i)
                    .ok_or_else(|| HError::Default("Failed to get iv byte".to_owned()))?;
            }
        }
        Self::pkcs7_unpad(plaintext, AES_BLOCK_SIZE)
    }

    fn encrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut data = data.to_vec();
        hsm_call!(
            self.hsm,
            "Failed to initialize encryption",
            C_EncryptInit,
            self.handle,
            mechanism,
            key_handle
        );

        let mut encrypted_data_len: CK_ULONG = 0;
        hsm_call!(
            self.hsm,
            format!(
                "Failed to allocate encrypted data length. Data to encrypt is likely too big: {} \
                 bytes. Error code",
                data.len()
            ),
            C_Encrypt,
            self.handle,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            ptr::null_mut(),
            &raw mut encrypted_data_len
        );

        let mut encrypted_data = vec![0_u8; usize::try_from(encrypted_data_len)?];
        hsm_call!(
            self.hsm,
            "Failed to encrypt data",
            C_Encrypt,
            self.handle,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            encrypted_data.as_mut_ptr(),
            &raw mut encrypted_data_len
        );

        encrypted_data.truncate(usize::try_from(encrypted_data_len)?);
        Ok(encrypted_data)
    }

    fn decrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        encrypted_data: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        let mut encrypted_data = encrypted_data.to_vec();
        hsm_call!(
            self.hsm,
            "Failed to initialize decryption",
            C_DecryptInit,
            self.handle,
            mechanism,
            key_handle
        );

        let mut decrypted_data_len: CK_ULONG = 0;
        hsm_call!(
            self.hsm,
            "Failed to get decrypted data length",
            C_Decrypt,
            self.handle,
            encrypted_data.as_mut_ptr(),
            CK_ULONG::try_from(encrypted_data.len())?,
            ptr::null_mut(),
            &raw mut decrypted_data_len
        );

        let mut decrypted_data = vec![0_u8; usize::try_from(decrypted_data_len)?];
        hsm_call!(
            self.hsm,
            "Failed to decrypt data",
            C_Decrypt,
            self.handle,
            encrypted_data.as_mut_ptr(),
            CK_ULONG::try_from(encrypted_data.len())?,
            decrypted_data.as_mut_ptr(),
            &raw mut decrypted_data_len
        );

        decrypted_data.truncate(usize::try_from(decrypted_data_len)?);
        Ok(Zeroizing::new(decrypted_data))
    }

    /// Sign data using the specified key and algorithm
    pub fn sign(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        algorithm: HsmSigningAlgorithm,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        match algorithm {
            HsmSigningAlgorithm::RsaPkcsV15 => {
                self.sign_with_simple_mechanism(key_handle, CKM_RSA_PKCS, data)
            }
            HsmSigningAlgorithm::Sha1WithRsa => {
                self.sign_with_simple_mechanism(key_handle, CKM_SHA1_RSA_PKCS, data)
            }
            HsmSigningAlgorithm::Sha256WithRsa => {
                self.sign_with_simple_mechanism(key_handle, CKM_SHA256_RSA_PKCS, data)
            }
            HsmSigningAlgorithm::Sha384WithRsa => {
                self.sign_with_simple_mechanism(key_handle, CKM_SHA384_RSA_PKCS, data)
            }
            HsmSigningAlgorithm::Sha512WithRsa => {
                self.sign_with_simple_mechanism(key_handle, CKM_SHA512_RSA_PKCS, data)
            }
            HsmSigningAlgorithm::RsaPssSha256 { salt_length } => {
                let mut params =
                    Self::rsa_pkcs_pss_params(CKM_SHA256, CKG_MGF1_SHA256, 32, salt_length);
                self.sign_with_pss_mechanism(key_handle, CKM_SHA256_RSA_PKCS_PSS, &mut params, data)
            }
            HsmSigningAlgorithm::RsaPssSha384 { salt_length } => {
                let mut params =
                    Self::rsa_pkcs_pss_params(CKM_SHA384, CKG_MGF1_SHA384, 48, salt_length);
                self.sign_with_pss_mechanism(key_handle, CKM_SHA384_RSA_PKCS_PSS, &mut params, data)
            }
            HsmSigningAlgorithm::RsaPssSha512 { salt_length } => {
                let mut params =
                    Self::rsa_pkcs_pss_params(CKM_SHA512, CKG_MGF1_SHA512, 64, salt_length);
                self.sign_with_pss_mechanism(key_handle, CKM_SHA512_RSA_PKCS_PSS, &mut params, data)
            }
            HsmSigningAlgorithm::EcdsaSha256 => {
                let raw = self.sign_with_simple_mechanism(key_handle, CKM_ECDSA_SHA256, data)?;
                Self::ecdsa_raw_to_der(&raw)
            }
            HsmSigningAlgorithm::EcdsaSha384 => {
                let raw = self.sign_with_simple_mechanism(key_handle, CKM_ECDSA_SHA384, data)?;
                Self::ecdsa_raw_to_der(&raw)
            }
            HsmSigningAlgorithm::EcdsaSha512 => {
                let raw = self.sign_with_simple_mechanism(key_handle, CKM_ECDSA_SHA512, data)?;
                Self::ecdsa_raw_to_der(&raw)
            }
            // EdDSA (Ed25519/Ed448) is a pure, un-hashed signature scheme (RFC 8032): the raw
            // message is passed directly to CKM_EDDSA, with no digest and no DER re-encoding
            // (unlike ECDSA above), matching the software `eddsa_sign` convention.
            #[cfg(feature = "non-fips")]
            HsmSigningAlgorithm::Ed25519 | HsmSigningAlgorithm::Ed448 => {
                self.sign_with_simple_mechanism(key_handle, CKM_EDDSA, data)
            }
        }
    }

    /// Convert a PKCS#11 raw `r || s` ECDSA signature (each half zero-padded to the curve's
    /// field size) into a DER-encoded `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`),
    /// matching the signature encoding produced by the software ECDSA path
    /// (`crate::crypto::elliptic_curves::sign::ecdsa_sign`, which returns `EcdsaSig::to_der()`).
    fn ecdsa_raw_to_der(raw: &[u8]) -> HResult<Vec<u8>> {
        if raw.is_empty() || !raw.len().is_multiple_of(2) {
            return Err(HError::Default(format!(
                "ECDSA: unexpected raw signature length: {}",
                raw.len()
            )));
        }
        let half = raw.len() / 2;
        let (r, s) = raw.split_at(half);
        let r = Self::der_encode_unsigned_integer(r)?;
        let s = Self::der_encode_unsigned_integer(s)?;
        let mut content = Vec::with_capacity(r.len() + s.len());
        content.extend_from_slice(&r);
        content.extend_from_slice(&s);
        let mut der = vec![0x30_u8];
        Self::der_push_length(&mut der, content.len())?;
        der.extend_from_slice(&content);
        Ok(der)
    }

    /// DER-encode a big-endian unsigned integer as an ASN.1 `INTEGER` (strips leading zero
    /// bytes, then re-adds a single `0x00` prefix byte if the high bit would otherwise make the
    /// value look negative).
    fn der_encode_unsigned_integer(value: &[u8]) -> HResult<Vec<u8>> {
        let leading_zeros = value
            .iter()
            .take(value.len().saturating_sub(1))
            .take_while(|&&b| b == 0)
            .count();
        let trimmed = value.get(leading_zeros..).unwrap_or(value);
        let needs_zero_pad = trimmed.first().is_some_and(|b| *b & 0x80 != 0);
        let content_len = trimmed.len() + usize::from(needs_zero_pad);
        let mut out = vec![0x02_u8];
        Self::der_push_length(&mut out, content_len)?;
        if needs_zero_pad {
            out.push(0);
        }
        out.extend_from_slice(trimmed);
        Ok(out)
    }

    /// Push a DER length (short or long form) onto `out`.
    fn der_push_length(out: &mut Vec<u8>, len: usize) -> HResult<()> {
        if len < 0x80 {
            out.push(u8::try_from(len).map_err(|e| {
                HError::Default(format!("ECDSA: DER length conversion failed: {e}"))
            })?);
        } else {
            let bytes = len.to_be_bytes();
            let first_nonzero = bytes
                .iter()
                .position(|b| *b != 0)
                .unwrap_or(bytes.len() - 1);
            let len_bytes = bytes.get(first_nonzero..).unwrap_or(&bytes);
            out.push(
                0x80 | u8::try_from(len_bytes.len()).map_err(|e| {
                    HError::Default(format!("ECDSA: DER length conversion failed: {e}"))
                })?,
            );
            out.extend_from_slice(len_bytes);
        }
        Ok(())
    }

    /// Sign using a parameterless mechanism (raw PKCS#1 v1.5 or one of its hash-prefixed
    /// variants).
    fn sign_with_simple_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism_type: CK_MECHANISM_TYPE,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        self.sign_with_mechanism(key_handle, &mut mechanism, data)
    }

    /// Sign using an RSASSA-PSS mechanism, passing the pre-built `CK_RSA_PKCS_PSS_PARAMS` as the
    /// mechanism parameter.
    fn sign_with_pss_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism_type: CK_MECHANISM_TYPE,
        params: &mut CK_RSA_PKCS_PSS_PARAMS,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut mechanism = CK_MECHANISM {
            mechanism: mechanism_type,
            pParameter: (&raw mut *params).cast::<std::ffi::c_void>(),
            ulParameterLen: CK_ULONG::try_from(size_of::<CK_RSA_PKCS_PSS_PARAMS>())?,
        };
        self.sign_with_mechanism(key_handle, &mut mechanism, data)
    }

    /// Build a `CK_RSA_PKCS_PSS_PARAMS` value for RSASSA-PSS signing.
    ///
    /// `salt_length` defaults to `digest_len_bytes` (the widely-used "salt length = digest
    /// length" convention, matching the software RSASSA-PSS default in
    /// `crate::crypto::rsa::sign`) when not explicitly provided by the caller.
    fn rsa_pkcs_pss_params(
        hash_alg: CK_MECHANISM_TYPE,
        mgf: CK_RSA_PKCS_MGF_TYPE,
        digest_len_bytes: u32,
        salt_length: Option<u32>,
    ) -> CK_RSA_PKCS_PSS_PARAMS {
        let salt_len = salt_length.unwrap_or(digest_len_bytes);
        CK_RSA_PKCS_PSS_PARAMS {
            hashAlg: hash_alg,
            mgf,
            sLen: CK_ULONG::from(salt_len),
        }
    }

    fn sign_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut data = data.to_vec();
        hsm_call!(
            self.hsm,
            "Failed to initialize signing",
            C_SignInit,
            self.handle,
            mechanism,
            key_handle
        );

        let mut signature_len: CK_ULONG = 0;
        hsm_call!(
            self.hsm,
            "Failed to get signature length",
            C_Sign,
            self.handle,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            ptr::null_mut(),
            &raw mut signature_len
        );

        let expected_len = signature_len;
        let mut signature = vec![0_u8; usize::try_from(signature_len)?];
        hsm_call!(
            self.hsm,
            "Failed to sign data",
            C_Sign,
            self.handle,
            data.as_mut_ptr(),
            CK_ULONG::try_from(data.len())?,
            signature.as_mut_ptr(),
            &raw mut signature_len
        );

        if signature_len != expected_len {
            return Err(HError::Default(format!(
                "C_Sign: signature length mismatch: expected {expected_len}, got {signature_len}"
            )));
        }
        Ok(signature)
    }

    /// Export a key from the HSM
    pub fn export_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut class: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&raw mut class).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&raw mut key_type).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ];

        self.call_get_attributes(key_handle, &mut template)?;
        let object_type = match key_type {
            CKK_AES => KeyType::AesKey,
            CKK_RSA => {
                if class == CKO_PRIVATE_KEY {
                    KeyType::RsaPrivateKey
                } else {
                    KeyType::RsaPublicKey
                }
            }
            CKK_EC | CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => {
                if class == CKO_PRIVATE_KEY {
                    KeyType::EcPrivateKey
                } else {
                    KeyType::EcPublicKey
                }
            }
            x => {
                return Err(HError::Default(format!(
                    "Export: unsupported key type: {x}"
                )));
            }
        };

        match object_type {
            KeyType::AesKey => self.export_aes_key(key_handle),
            KeyType::RsaPrivateKey => self.export_rsa_private_key(key_handle),
            KeyType::RsaPublicKey => self.export_rsa_public_key(key_handle),
            KeyType::EcPrivateKey => self.export_ec_private_key(key_handle),
            KeyType::EcPublicKey => self.export_ec_public_key(key_handle),
        }
    }

    fn export_rsa_private_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        // Get the key size
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE_EXPONENT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_1,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_2,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_1,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_2,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_COEFFICIENT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let public_exponent_len = template[0].ulValueLen;
        let private_exponent_len = template[1].ulValueLen;
        let prime_1_len = template[2].ulValueLen;
        let prime_2_len = template[3].ulValueLen;
        let exponent_1_len = template[4].ulValueLen;
        let exponent_2_len = template[5].ulValueLen;
        let coefficient_len = template[6].ulValueLen;
        let modulus_len = template[7].ulValueLen;
        let label_len = template[8].ulValueLen;
        let mut public_exponent: Vec<u8> = vec![0_u8; usize::try_from(public_exponent_len)?];
        let mut private_exponent: Vec<u8> = vec![0_u8; usize::try_from(private_exponent_len)?];
        let mut prime_1: Vec<u8> = vec![0_u8; usize::try_from(prime_1_len)?];
        let mut prime_2: Vec<u8> = vec![0_u8; usize::try_from(prime_2_len)?];
        let mut exponent_1: Vec<u8> = vec![0_u8; usize::try_from(exponent_1_len)?];
        let mut exponent_2: Vec<u8> = vec![0_u8; usize::try_from(exponent_2_len)?];
        let mut coefficient: Vec<u8> = vec![0_u8; usize::try_from(coefficient_len)?];
        let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
        let mut modulus: Vec<u8> = vec![0_u8; usize::try_from(modulus_len)?];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: public_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE_EXPONENT,
                pValue: private_exponent.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: private_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_1,
                pValue: prime_1.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: prime_1_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_2,
                pValue: prime_2.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: prime_2_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_1,
                pValue: exponent_1.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: exponent_1_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_2,
                pValue: exponent_2.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: exponent_2_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_COEFFICIENT,
                pValue: coefficient.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: coefficient_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: modulus.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: modulus_len,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let label = String::from_utf8(label_bytes)
            .map_err(|e| HError::Default(format!("Failed to convert label to string: {e}")))?;
        Ok(Some(HsmObject::new(
            KeyMaterial::RsaPrivateKey(RsaPrivateKeyMaterial {
                modulus,
                public_exponent,
                private_exponent: Zeroizing::new(private_exponent),
                prime_1: Zeroizing::new(prime_1),
                prime_2: Zeroizing::new(prime_2),
                exponent_1: Zeroizing::new(exponent_1),
                exponent_2: Zeroizing::new(exponent_2),
                coefficient: Zeroizing::new(coefficient),
            }),
            label,
        )))
    }

    fn export_rsa_public_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        // Get the key size
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let public_exponent_len = template[0].ulValueLen;
        let modulus_len = template[1].ulValueLen;
        let label_len = template[2].ulValueLen;
        let mut public_exponent: Vec<u8> = vec![0_u8; usize::try_from(public_exponent_len)?];
        let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
        let mut modulus: Vec<u8> = vec![0_u8; usize::try_from(modulus_len)?];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: public_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: modulus.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: modulus_len,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let mut label = String::from_utf8(label_bytes)
            .map_err(|e| HError::Default(format!("Failed to convert label to string: {e}")))?;
        if !label.trim().ends_with("_pk") {
            label = label.trim().to_owned().add("_pk");
        }
        Ok(Some(HsmObject::new(
            KeyMaterial::RsaPublicKey(RsaPublicKeyMaterial {
                modulus,
                public_exponent,
            }),
            label,
        )))
    }

    fn export_ec_private_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let ec_params_len = template[0].ulValueLen;
        let value_len = template[1].ulValueLen;
        let label_len = template[2].ulValueLen;
        let mut ec_params: Vec<u8> = vec![0_u8; usize::try_from(ec_params_len)?];
        let mut value: Vec<u8> = vec![0_u8; usize::try_from(value_len)?];
        let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ec_params.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: ec_params_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: value.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: value_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: label_len,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let curve = curve_from_der_oid(&ec_params)?;
        let label = String::from_utf8(label_bytes)
            .map_err(|e| HError::Default(format!("Failed to convert label to string: {e}")))?;
        // Left-pad the private scalar to the curve's field size, in case the token stripped
        // leading zero bytes.
        let byte_size = curve_byte_size(curve);
        let mut d = vec![0_u8; byte_size.saturating_sub(value.len())];
        d.extend_from_slice(&value);
        Ok(Some(HsmObject::new(
            KeyMaterial::EcPrivateKey(EcPrivateKeyMaterial {
                curve,
                d: Zeroizing::new(d),
            }),
            label,
        )))
    }

    fn export_ec_public_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_POINT,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let ec_params_len = template[0].ulValueLen;
        let ec_point_len = template[1].ulValueLen;
        let label_len = template[2].ulValueLen;
        let mut ec_params: Vec<u8> = vec![0_u8; usize::try_from(ec_params_len)?];
        let mut ec_point: Vec<u8> = vec![0_u8; usize::try_from(ec_point_len)?];
        let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_EC_PARAMS,
                pValue: ec_params.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: ec_params_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_EC_POINT,
                pValue: ec_point.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: ec_point_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: label_len,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let curve = curve_from_der_oid(&ec_params)?;
        let mut label = String::from_utf8(label_bytes)
            .map_err(|e| HError::Default(format!("Failed to convert label to string: {e}")))?;
        if !label.trim().ends_with("_pk") {
            label = label.trim().to_owned().add("_pk");
        }
        let q = Self::der_octet_string_content(&ec_point)?;
        Ok(Some(HsmObject::new(
            KeyMaterial::EcPublicKey(EcPublicKeyMaterial { curve, q }),
            label,
        )))
    }

    /// PKCS#11's `CKA_EC_POINT` is a DER-encoded `OCTET STRING` wrapping the raw EC point
    /// (typically uncompressed `0x04 || X || Y`). Strip the outer `OCTET STRING` tag/length to
    /// recover the raw point bytes expected by KMIP's `TransparentECPublicKey.q_string`.
    fn der_octet_string_content(der: &[u8]) -> HResult<Vec<u8>> {
        let [tag, rest @ ..] = der else {
            return Err(HError::Default("CKA_EC_POINT: empty DER value".to_owned()));
        };
        // 0x04 is the ASN.1 OCTET STRING tag.
        if *tag != 0x04 {
            // Some tokens return the raw point without DER wrapping; accept it as-is.
            return Ok(der.to_vec());
        }
        let Some((&len_byte, rest)) = rest.split_first() else {
            return Err(HError::Default(
                "CKA_EC_POINT: truncated DER length".to_owned(),
            ));
        };
        if len_byte & 0x80 == 0 {
            let len = usize::from(len_byte);
            return rest.get(..len).map(<[u8]>::to_vec).ok_or_else(|| {
                HError::Default("CKA_EC_POINT: DER length exceeds buffer".to_owned())
            });
        }
        let num_len_bytes = usize::from(len_byte & 0x7F);
        let (len_bytes, rest) = rest.split_at_checked(num_len_bytes).ok_or_else(|| {
            HError::Default("CKA_EC_POINT: truncated long-form DER length".to_owned())
        })?;
        let mut len: usize = 0;
        for b in len_bytes {
            len = len
                .checked_shl(8)
                .and_then(|v| v.checked_add(usize::from(*b)))
                .ok_or_else(|| HError::Default("CKA_EC_POINT: DER length overflow".to_owned()))?;
        }
        rest.get(..len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| HError::Default("CKA_EC_POINT: DER length exceeds buffer".to_owned()))
    }

    fn export_aes_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        // Get the key size
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        // Export the value
        let value_len = template[0].ulValueLen;
        let label_len = template[1].ulValueLen;
        let mut key_value: Vec<u8> = vec![0_u8; usize::try_from(value_len)?];
        let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
        let mut key_size: CK_ULONG = 0;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: key_value.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: value_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: (&raw mut key_size).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ];
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let label = String::from_utf8(label_bytes)
            .map_err(|e| HError::Default(format!("Failed to convert label to string: {e}")))?;
        Ok(Some(HsmObject::new(
            KeyMaterial::AesKey(Zeroizing::new(key_value)),
            label,
        )))
    }

    fn call_get_attributes(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        template: &mut [CK_ATTRIBUTE],
    ) -> HResult<Option<()>> {
        debug!("Retrieving HSM key attributes for key handle: {key_handle}");
        // Get the length of the key value
        #[expect(unsafe_code)]
        let rv = match self.hsm.C_GetAttributeValue {
            Some(func) => unsafe {
                func(
                    self.handle,
                    key_handle,
                    template.as_ptr().cast_mut(),
                    CK_ULONG::try_from(template.len())?,
                )
            },
            None => {
                return Err(HError::Default(
                    "C_GetAttributeValue not available on library".to_owned(),
                ));
            }
        };
        if rv == CKR_ATTRIBUTE_SENSITIVE {
            return Err(HError::Default(
                "This key is sensitive and cannot be exported from the HSM.".to_owned(),
            ));
        }
        if rv == CKR_OBJECT_HANDLE_INVALID {
            // The key was not found
            return Ok(None);
        }
        if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed to get the HSM attributes for key handle: {key_handle}. Return code: {rv}"
            )));
        }
        Ok(Some(()))
    }

    /// Parse a `CK_DATE` (8-byte ASCII "YYYYMMDD") into a `time::Date`.
    /// Returns `None` if the date is empty/zeroed.
    fn parse_ck_date(date: CK_DATE) -> Option<time::Date> {
        let year_str = std::str::from_utf8(&date.year).ok()?;
        let month_str = std::str::from_utf8(&date.month).ok()?;
        let day_str = std::str::from_utf8(&date.day).ok()?;
        let year: i32 = year_str.trim().parse().ok()?;
        let month: u8 = month_str.trim().parse().ok()?;
        let day: u8 = day_str.trim().parse().ok()?;
        if year == 0 && month == 0 && day == 0 {
            return None;
        }
        let month = time::Month::try_from(month).ok()?;
        time::Date::from_calendar_date(year, month, day).ok()
    }

    /// Read `CKA_START_DATE` and `CKA_END_DATE` from a key handle.
    /// Returns `(start_date, end_date)`. Attributes that are absent or empty
    /// (zeroed) are returned as `None`.
    fn get_key_dates(
        &self,
        key_handle: CK_OBJECT_HANDLE,
    ) -> HResult<(Option<time::Date>, Option<time::Date>)> {
        let mut start_date = CK_DATE {
            year: [0; 4],
            month: [0; 2],
            day: [0; 2],
        };
        let mut end_date = CK_DATE {
            year: [0; 4],
            month: [0; 2],
            day: [0; 2],
        };
        let mut template = vec![
            CK_ATTRIBUTE {
                type_: CKA_START_DATE,
                pValue: (&raw mut start_date).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_DATE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_END_DATE,
                pValue: (&raw mut end_date).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_DATE>())?,
            },
        ];
        // If the HSM doesn't support these attributes, just return None for both
        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok((None, None));
        }
        // Check if the returned length is 0 (attribute present but empty)
        let start = if template.first().is_none_or(|t| t.ulValueLen == 0) {
            None
        } else {
            Self::parse_ck_date(start_date)
        };
        let end = if template.get(1).is_none_or(|t| t.ulValueLen == 0) {
            None
        } else {
            Self::parse_ck_date(end_date)
        };
        Ok((start, end))
    }

    /// Format a `time::Date` into a `CK_DATE` (8-byte ASCII "YYYYMMDD").
    fn format_ck_date(date: time::Date) -> CK_DATE {
        let year = date.year();
        let month: u8 = date.month().into();
        let day = date.day();
        // These format! calls always produce exactly the right number of bytes
        let mut year_bytes = [b'0'; 4];
        let mut month_bytes = [b'0'; 2];
        let mut day_bytes = [b'0'; 2];
        let year_str = format!("{year:04}");
        let month_str = format!("{month:02}");
        let day_str = format!("{day:02}");
        year_bytes.copy_from_slice(year_str.as_bytes().get(..4).unwrap_or(&[b'0'; 4]));
        month_bytes.copy_from_slice(month_str.as_bytes().get(..2).unwrap_or(&[b'0'; 2]));
        day_bytes.copy_from_slice(day_str.as_bytes().get(..2).unwrap_or(&[b'0'; 2]));
        CK_DATE {
            year: year_bytes,
            month: month_bytes,
            day: day_bytes,
        }
    }

    /// Set `CKA_START_DATE` and/or `CKA_END_DATE` on a key object.
    /// Passing `None` clears the attribute (sets to empty `CK_DATE`).
    pub fn set_key_dates(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        start_date: Option<time::Date>,
        end_date: Option<time::Date>,
    ) -> HResult<()> {
        let start_ck = start_date.map_or(
            CK_DATE {
                year: [0; 4],
                month: [0; 2],
                day: [0; 2],
            },
            Self::format_ck_date,
        );
        let end_ck = end_date.map_or(
            CK_DATE {
                year: [0; 4],
                month: [0; 2],
                day: [0; 2],
            },
            Self::format_ck_date,
        );

        let mut template = vec![
            CK_ATTRIBUTE {
                type_: CKA_START_DATE,
                pValue: ptr::addr_of!(start_ck).cast_mut().cast(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_DATE>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_END_DATE,
                pValue: ptr::addr_of!(end_ck).cast_mut().cast(),
                ulValueLen: CK_ULONG::try_from(std::mem::size_of::<CK_DATE>())?,
            },
        ];

        #[expect(unsafe_code)]
        let rv = match self.hsm.C_SetAttributeValue {
            Some(func) => unsafe {
                func(
                    self.handle,
                    key_handle,
                    template.as_mut_ptr(),
                    CK_ULONG::try_from(template.len())?,
                )
            },
            None => {
                return Err(HError::Default(
                    "C_SetAttributeValue not available on library".to_owned(),
                ));
            }
        };
        if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed to set key dates for key handle: {key_handle}. Return code: {rv}"
            )));
        }
        Ok(())
    }

    /// Parse keyset metadata from a `CKA_LABEL` value.
    ///
    /// Format: `rotate_name::generation::key_id[@latest]`
    /// The optional `@latest` suffix is accepted for backward compatibility with
    /// existing HSM keys (older format used `::latest`) but is not used for
    /// determining the latest generation; callers compare `rotate_generation` values.
    ///
    /// Returns `(rotate_name, rotate_generation)`.
    /// Returns `(None, None)` if the label does not match the format
    /// (e.g. plain keys whose label is just an identifier).
    pub(crate) fn parse_label_metadata(label: &str) -> (Option<String>, Option<i32>) {
        // Format: "rotate_name::generation::key_id[@latest]"
        //
        // `rotate_name` may itself contain "::" — for HSM-resident keys the convention is
        // rotate_name = "hsm::<model>::<slot>::<key_id>" (the full base UID, including the
        // model segment), which is unique across slots.  Split from the RIGHT so the
        // variable-length rotate_name is always the residual left segment, regardless of
        // how many "::" it contains.
        //
        // rsplitn(3, "::") yields (from right to left):
        //   index 0 → key_id[@latest]
        //   index 1 → generation (must parse as i32)
        //   index 2 → rotate_name  (may contain "::")
        let mut rparts = label.rsplitn(3, "::");
        let Some(_key_id) = rparts.next() else {
            return (None, None);
        };
        let Some(gen_str) = rparts.next() else {
            return (None, None);
        };
        let Some(rotate_name) = rparts.next() else {
            return (None, None);
        };
        let Ok(generation) = gen_str.parse::<i32>() else {
            return (None, None);
        };
        (Some(rotate_name.to_owned()), Some(generation))
    }

    /// Build the `CKA_LABEL` value for a keyset key.
    ///
    /// Format: `rotate_name::generation::key_id` (retired) or
    ///         `rotate_name::generation::key_id@latest` (current latest).
    // Used by the HSM ReKey flow (Phase 3).
    #[allow(dead_code)]
    pub(crate) fn build_keyset_label(
        rotate_name: &str,
        generation: i32,
        key_id: &str,
        latest: bool,
    ) -> String {
        if latest {
            format!("{rotate_name}::{generation}::{key_id}@latest")
        } else {
            format!("{rotate_name}::{generation}::{key_id}")
        }
    }

    /// Set `CKA_LABEL` on a key object via `C_SetAttributeValue`.
    pub fn set_label(&self, key_handle: CK_OBJECT_HANDLE, label: &str) -> HResult<()> {
        let label_bytes = label.as_bytes();
        let mut template = vec![CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: label_bytes.as_ptr().cast_mut().cast(),
            ulValueLen: CK_ULONG::try_from(label_bytes.len())?,
        }];
        #[expect(unsafe_code)]
        let rv = match self.hsm.C_SetAttributeValue {
            Some(func) => unsafe {
                func(
                    self.handle,
                    key_handle,
                    template.as_mut_ptr(),
                    CK_ULONG::try_from(template.len())?,
                )
            },
            None => {
                return Err(HError::Default(
                    "C_SetAttributeValue not available on library".to_owned(),
                ));
            }
        };
        if rv != CKR_OK {
            return Err(HError::Default(format!(
                "Failed to set label for key handle: {key_handle}. Return code: {rv}"
            )));
        }
        Ok(())
    }

    /// Get the metadata for a key
    pub fn get_key_metadata(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<KeyMetadata>> {
        let Some(key_type) = self.get_key_type(key_handle)? else {
            return Ok(None);
        };
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }]
        .to_vec();
        match key_type {
            KeyType::AesKey => {
                let mut key_size: CK_ULONG = 0;
                let mut sensitive: CK_BBOOL = CK_FALSE;
                template.extend([
                    CK_ATTRIBUTE {
                        type_: CKA_VALUE_LEN,
                        pValue: (&raw mut key_size).cast::<std::ffi::c_void>(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: (&raw mut sensitive).cast::<std::ffi::c_void>(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                    },
                ]);
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template
                    .first()
                    .ok_or_else(|| HError::Default("Failed to get label length".to_owned()))?
                    .ulValueLen;
                let label = if label_len == 0 {
                    String::new()
                } else {
                    let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
                    let mut template = [CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                        ulValueLen: label_len,
                    }];
                    if self
                        .call_get_attributes(key_handle, &mut template)?
                        .is_none()
                    {
                        return Ok(None);
                    }
                    String::from_utf8(label_bytes).map_err(|e| {
                        HError::Default(format!("Failed to convert label to string: {e}"))
                    })?
                };
                let (start_date, end_date) = self.get_key_dates(key_handle).unwrap_or((None, None));
                let (rotate_name, rotate_generation) = Self::parse_label_metadata(&label);
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits: usize::try_from(key_size).map_err(|e| {
                        HError::Default(format!("Failed to convert key size to usize: {e}"))
                    })? * 8,
                    sensitive: sensitive == CK_TRUE,
                    id: label,
                    start_date,
                    end_date,
                    rotate_name,
                    rotate_generation,
                }))
            }
            KeyType::RsaPrivateKey | KeyType::RsaPublicKey => {
                template.push(CK_ATTRIBUTE {
                    type_: CKA_MODULUS,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0,
                });
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template
                    .first()
                    .ok_or_else(|| HError::Default("Failed to get template length".to_owned()))?
                    .ulValueLen;
                let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
                let modulus_len = template
                    .get(1)
                    .ok_or_else(|| HError::Default("Failed to get modulus length".to_owned()))?
                    .ulValueLen;
                let mut modulus: Vec<u8> = vec![0_u8; usize::try_from(modulus_len)?];
                let mut sensitive: CK_BBOOL = CK_FALSE;
                let mut template = vec![CK_ATTRIBUTE {
                    type_: CKA_MODULUS,
                    pValue: modulus.as_mut_ptr().cast::<std::ffi::c_void>(),
                    ulValueLen: modulus_len,
                }];
                if label_len > 0 {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                        ulValueLen: label_len,
                    });
                }
                if key_type == KeyType::RsaPrivateKey {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: (&raw mut sensitive).cast::<std::ffi::c_void>(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                    });
                }
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let key_length_in_bits = modulus.len() * 8;

                let mut label = if label_len == 0 {
                    String::new()
                } else {
                    String::from_utf8(label_bytes).map_err(|e| {
                        HError::Default(format!("Failed to convert label to string: {e}"))
                    })?
                };
                if key_type == KeyType::RsaPublicKey && !label.trim().ends_with("_pk") {
                    label = label.trim().to_owned().add("_pk");
                }
                let sensitive = sensitive == CK_TRUE;
                let (start_date, end_date) = self.get_key_dates(key_handle).unwrap_or((None, None));
                let (rotate_name, rotate_generation) = Self::parse_label_metadata(&label);
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits,
                    sensitive,
                    id: label,
                    start_date,
                    end_date,
                    rotate_name,
                    rotate_generation,
                }))
            }
            KeyType::EcPrivateKey | KeyType::EcPublicKey => {
                template.push(CK_ATTRIBUTE {
                    type_: CKA_EC_PARAMS,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0,
                });
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template
                    .first()
                    .ok_or_else(|| HError::Default("Failed to get template length".to_owned()))?
                    .ulValueLen;
                let mut label_bytes: Vec<u8> = vec![0_u8; usize::try_from(label_len)?];
                let ec_params_len = template
                    .get(1)
                    .ok_or_else(|| HError::Default("Failed to get EC params length".to_owned()))?
                    .ulValueLen;
                let mut ec_params: Vec<u8> = vec![0_u8; usize::try_from(ec_params_len)?];
                let mut sensitive: CK_BBOOL = CK_FALSE;
                let mut template = vec![CK_ATTRIBUTE {
                    type_: CKA_EC_PARAMS,
                    pValue: ec_params.as_mut_ptr().cast::<std::ffi::c_void>(),
                    ulValueLen: ec_params_len,
                }];
                if label_len > 0 {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
                        ulValueLen: label_len,
                    });
                }
                if key_type == KeyType::EcPrivateKey {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: (&raw mut sensitive).cast::<std::ffi::c_void>(),
                        ulValueLen: CK_ULONG::try_from(size_of::<CK_BBOOL>())?,
                    });
                }
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let curve = curve_from_der_oid(&ec_params)?;
                let key_length_in_bits = curve.key_length_in_bits();

                let mut label = if label_len == 0 {
                    String::new()
                } else {
                    String::from_utf8(label_bytes).map_err(|e| {
                        HError::Default(format!("Failed to convert label to string: {e}"))
                    })?
                };
                if key_type == KeyType::EcPublicKey && !label.trim().ends_with("_pk") {
                    label = label.trim().to_owned().add("_pk");
                }
                let sensitive = sensitive == CK_TRUE;
                let (start_date, end_date) = self.get_key_dates(key_handle).unwrap_or((None, None));
                let (rotate_name, rotate_generation) = Self::parse_label_metadata(&label);
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits,
                    sensitive,
                    id: label,
                    start_date,
                    end_date,
                    rotate_name,
                    rotate_generation,
                }))
            }
        }
    }

    ///  Get the key type, sensitivity and label length
    /// # Arguments
    /// * `key_handle` - The key handle
    /// # Returns
    /// * `Result<Option<KeyType>>` - The key type if the key exists
    pub fn get_key_type(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<KeyType>> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut class: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&raw mut class).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_OBJECT_CLASS>())?,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: (&raw mut key_type).cast::<std::ffi::c_void>(),
                ulValueLen: CK_ULONG::try_from(size_of::<CK_ULONG>())?,
            },
        ];

        if self
            .call_get_attributes(key_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let key_type = match key_type {
            CKK_AES => KeyType::AesKey,
            CKK_RSA => {
                if class == CKO_PRIVATE_KEY {
                    KeyType::RsaPrivateKey
                } else {
                    KeyType::RsaPublicKey
                }
            }
            // Validate that the curve is one Cosmian KMS recognizes (CKA_EC_PARAMS decodes to
            // a supported `EcCurve`, including Ed25519/Ed448/X25519, issue #1157). This
            // rejects HSM objects using curves outside the supported set (e.g. brainpool
            // curves), keeping them excluded from generic searches/exports exactly like any
            // other unsupported key type.
            CKK_EC | CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => {
                let mut len_template = [CK_ATTRIBUTE {
                    type_: CKA_EC_PARAMS,
                    pValue: ptr::null_mut(),
                    ulValueLen: 0,
                }];
                if self
                    .call_get_attributes(key_handle, &mut len_template)?
                    .is_none()
                {
                    return Err(HError::Default(
                        "Export: unable to read CKA_EC_PARAMS for EC key".to_owned(),
                    ));
                }
                let ec_params_len = len_template[0].ulValueLen;
                let mut ec_params = vec![0_u8; usize::try_from(ec_params_len)?];
                let mut template = [CK_ATTRIBUTE {
                    type_: CKA_EC_PARAMS,
                    pValue: ec_params.as_mut_ptr().cast::<std::ffi::c_void>(),
                    ulValueLen: ec_params_len,
                }];
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Err(HError::Default(
                        "Export: unable to read CKA_EC_PARAMS for EC key".to_owned(),
                    ));
                }
                // Reject unsupported/unrecognized curves.
                curve_from_der_oid(&ec_params)?;
                if class == CKO_PRIVATE_KEY {
                    KeyType::EcPrivateKey
                } else {
                    KeyType::EcPublicKey
                }
            }
            x => {
                return Err(HError::Default(format!(
                    "Export: unsupported key type: {x}"
                )));
            }
        };
        debug!("Retrieved HSM key type for key handle {key_handle}: {key_type:?}");
        Ok(Some(key_type))
    }

    /// Get the Object id
    /// # Arguments
    /// * `object_handle` - The object handle
    /// # Returns
    /// * `Result<Option<Vec<u8>>>` - The key object id if the object exists
    ///
    /// Reads `CKA_ID` first (set by Cosmian KMS on every key it creates); if absent or
    /// empty, falls back to `CKA_LABEL` (for externally provisioned keys).
    /// For RSA public keys read via `CKA_LABEL`, the `_pk` suffix is appended if missing.
    pub fn get_object_id(&self, object_handle: CK_OBJECT_HANDLE) -> HResult<Option<Vec<u8>>> {
        // Try CKA_ID first, then CKA_LABEL
        for attr_type in [CKA_ID, CKA_LABEL] {
            let mut template = [CK_ATTRIBUTE {
                type_: attr_type,
                pValue: ptr::null_mut(),
                ulValueLen: 0,
            }];
            if self
                .call_get_attributes(object_handle, &mut template)?
                .is_none()
            {
                continue;
            }
            let id_len = template[0].ulValueLen;
            if id_len == 0 {
                continue;
            }
            let mut id: Vec<u8> = vec![0_u8; usize::try_from(id_len)?];
            let mut template = [CK_ATTRIBUTE {
                type_: attr_type,
                pValue: id.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: id_len,
            }];
            if self
                .call_get_attributes(object_handle, &mut template)?
                .is_none()
            {
                continue;
            }
            if id.is_empty() {
                continue;
            }
            // When read via CKA_LABEL, append _pk for RSA public keys lacking the suffix.
            // (When read via CKA_ID, KMS already stored the _pk suffix in the id.)
            if attr_type == CKA_LABEL
                && self.get_key_type(object_handle)? == Some(KeyType::RsaPublicKey)
                && !id.ends_with(b"_pk")
            {
                id.extend_from_slice(b"_pk");
            }
            return Ok(Some(id));
        }
        Ok(None)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.close());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_pkcs_pss_params_defaults_salt_length_to_digest_length() {
        let params = Session::rsa_pkcs_pss_params(CKM_SHA256, CKG_MGF1_SHA256, 32, None);
        assert_eq!(params.hashAlg, CKM_SHA256);
        assert_eq!(params.mgf, CKG_MGF1_SHA256);
        assert_eq!(params.sLen, 32);
    }

    #[test]
    fn rsa_pkcs_pss_params_honors_explicit_salt_length() {
        let params = Session::rsa_pkcs_pss_params(CKM_SHA384, CKG_MGF1_SHA384, 48, Some(0));
        assert_eq!(params.hashAlg, CKM_SHA384);
        assert_eq!(params.mgf, CKG_MGF1_SHA384);
        assert_eq!(params.sLen, 0);
    }

    #[test]
    fn rsa_pkcs_pss_params_sha512_digest_length_default() {
        let params = Session::rsa_pkcs_pss_params(CKM_SHA512, CKG_MGF1_SHA512, 64, None);
        assert_eq!(params.sLen, 64);
    }

    #[test]
    fn hsm_signing_algorithm_from_signing_algorithm_preserves_pss_salt_length() {
        let algo: HsmSigningAlgorithm = SigningAlgorithm::RsaPssSha256 {
            salt_length: Some(16),
        }
        .into();
        assert!(matches!(
            algo,
            HsmSigningAlgorithm::RsaPssSha256 {
                salt_length: Some(16)
            }
        ));
    }
}
