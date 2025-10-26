//! Hardware Security Module (HSM) Session Implementation
//!
//! This module provides the implementation of a session with a Hardware Security Module (HSM)
//! following the PKCS#11 standard. It includes functionality for:
//!
//! - Managing HSM session lifecycle (creation, authentication, closure)
//! - Object handling (creation, deletion, listing)
//! - Cryptographic operations (encryption, decryption)
//! - Key management (export, metadata retrieval)
//!
//! The implementation supports various cryptographic algorithms, including:
//! - AES-GCM for symmetric encryption
//! - RSA PKCS#1 v1.5 and OAEP for asymmetric encryption
//!
//! # Key Features
//!
//! - Session management with HSM devices
//! - Object handle caching for improved performance
//! - Support for both symmetric and asymmetric cryptographic operations
//! - Key export capabilities with security controls
//! - Comprehensive error handling
//!
//! # Security Considerations
//!
//! - Sensitive key material is protected using the `Zeroizing` type
//! - Login state is tracked to ensure proper session closure
//! - Object handle caching is thread-safe using `Arc`
//!
//! # Examples
//!
//! ```no_run
//! use hsm::Session;
//!
//! let session = Session::new(hsm, session_handle, cache, true);
//! let random_bytes = session.generate_random(32)?;
//! ```

use std::{
    cmp::min,
    ops::Add,
    ptr,
    sync::{Arc, Mutex},
};

use cosmian_kms_interfaces::{
    CryptoAlgorithm, EncryptedContent, HsmObject, HsmObjectFilter, KeyMaterial, KeyMetadata,
    KeyType,
    KeyType::{AesKey, RsaPrivateKey, RsaPublicKey},
    RsaPrivateKeyMaterial, RsaPublicKeyMaterial,
};
use cosmian_logger::{debug, trace};
use pkcs11_sys::{
    CK_AES_GCM_PARAMS, CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RSA_PKCS_MGF_TYPE,
    CK_RSA_PKCS_OAEP_PARAMS, CK_SESSION_HANDLE, CK_TRUE, CK_ULONG, CKA_CLASS, CKA_COEFFICIENT,
    CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_PRIME_1, CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_VALUE, CKA_VALUE_LEN,
    CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKK_AES, CKK_RSA,
    CKK_VENDOR_DEFINED, CKM_AES_CBC, CKM_AES_GCM, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA_1,
    CKM_SHA256, CKM_SHA384, CKM_SHA512, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CKO_VENDOR_DEFINED, CKR_ATTRIBUTE_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK,
    CKZ_DATA_SPECIFIED,
};
use rand::{TryRngCore, rngs::OsRng};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::session::{aes::AesKeySize, rsa::RsaKeySize};
use crate::{HError, HResult, ObjectHandlesCache, hsm_call, hsm_capabilities::HsmCapabilities};

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;
const AES_CBC_IV_LENGTH: usize = 16;
const AES_GCM_IV_LENGTH: usize = 12;
const AES_GCM_AUTH_TAG_LENGTH: usize = 16;

/// Generate a random nonce of size T
/// This function is used to generate a random nonce for the AES GCM or a random IV for AES CBC encryption
fn generate_random_nonce<const T: usize>() -> HResult<[u8; T]> {
    let mut bytes = [0_u8; T];
    OsRng
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

/// A session with an HSM (Hardware Security Module) that implements PKCS#11 interface.
///
/// This structure represents an active connection to the HSM and provides methods to
/// perform cryptographic operations and key management.
///
/// # Structure Fields
/// * `hsm` - Arc reference to the HSM library interface
/// * `session_handle` - PKCS#11 session handle
/// * `object_handles_cache` - Cache for object handles
/// * `supported_oaep_hash_cache` - Cache for supported OAEP hashing algorithms
/// * `is_logged_in` - Login state of the session
///
/// # Methods
/// The session provides several categories of operations:
///
/// ## Session Management
/// * `new()` - Creates a new session
/// * `close()` - Closes the session and logs out if necessary
///
/// ## Object Management
/// * `get_object_handle()` - Retrieves handle for an object by its ID
/// * `clear_object_handles()` - Removes all object handles from the cache
/// * `delete_object_handle()` - Removes an object handle from cache
/// * `list_objects()` - Lists objects matching specified filter
/// * `destroy_object()` - Deletes an object from the HSM
///
/// ## Cryptographic Operations
/// * `encrypt()` - Encrypts data using specified algorithm
/// * `decrypt()` - Decrypts data using specified algorithm
/// * `encrypt_aes_cbc_multi_round` - Encrypt data using AES-CBC in multiple rounds
/// * `decrypt_aes_cbc_multi_round` - Decrypt data using AES-CBC in multiple rounds
/// * `generate_random()` - Generates random data
/// * `get_supported_oaep_hash` - List the supported OAEP hashing algorithms
///
/// ## Key Management
/// * `export_key()` - Exports a key from the HSM (if allowed)
/// * `get_key_metadata()` - Retrieves metadata about a key
/// * `get_key_type()` - Gets the type of a key
/// * `get_object_id()` - Gets the ID of an object
///
/// ## Internal Helpers
/// * `encrypt_with_mechanism()` - Internal encryption implementation
/// * `decrypt_with_mechanism()` - Internal decryption implementation
/// * `export_rsa_private_key()` - Exports RSA private key
/// * `export_rsa_public_key()` - Exports RSA public key
/// * `export_aes_key()` - Exports AES key
/// * `call_get_attributes()` - Helper for retrieving object attributes
/// * `pkcs7_pad()` - Apply PKCS#7 padding to the input data
/// * `pkcs7_unpad()` - Remove PKCS#7 padding from the input data.
/// * `find_object_handles` - retrieve object handles that match the provided attribute template
///
/// # Safety
/// Many methods in this implementation contain unsafe blocks as they interact with
/// the PKCS#11 C interface. Care should be taken when using these methods, and all
/// preconditions must be met to ensure safe operation.
///
/// # Error Handling
/// Methods return `PResult<T>` which is a custom result type for handling HSM-related
/// errors. Operations can fail due to various reasons including:
/// * Invalid object handles
/// * Permission issues
/// * Communication errors with HSM
/// * Invalid parameters
/// * Unsupported operations
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

            // We don't actually encrypt, just see if init succeeds
            #[expect(unsafe_code)]
            let rv = unsafe {
                self.hsm.C_EncryptInit.ok_or_else(|| {
                    drop(self.destroy_object(sk_handle));
                    drop(self.destroy_object(pk_handle));
                    HError::Default("C_EncryptInit not available on library".to_owned())
                })?(self.handle, &raw mut mechanism, pk_handle)
            };

            if rv == CKR_OK {
                supported.push(*hash);
            } else {
                debug!("Failed to encrypt data with hash {hash}: {rv}");
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
    /// by searching for objects whose `CKA_LABEL` attribute matches the provided object ID.
    /// attribute when searching. To optimize performance, previously found handles are cached
    /// and reused if available.
    ///
    /// Special handling is included for key pairs who might be saved with the same label for both:
    /// * If the provided ID ends with `_pk`, the function first tries to find an exact match.
    ///   If none is found, it retries with the suffix removed (and an optional trailing space removed).
    /// * If multiple objects are returned for the same label (e.g., both public and private keys
    ///   sharing a label), the function inspects the key type of each candidate and selects
    ///   the one that matches the requested identifier (`_pk` → public key, otherwise private/secret key).
    ///
    /// # Arguments
    /// * `object_id` - A byte slice representing the identifier (label) of the object to find.
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

        // Proteccio does not allow the ID for secret keys so we use the label
        // and we do the same on base HSM
        let template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: object_id.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            ulValueLen: CK_ULONG::try_from(object_id.len())?,
        }];

        // Get all handles for objects that have the appropriate label
        let mut object_handles = self.find_object_handles(template.to_vec())?;
        if object_handles.is_empty() {
            if object_id.ends_with(b"_pk") {
                // Check if the HSM stores the object without the suffix
                let mut object_id_trimmed = object_id.strip_suffix(b"_pk").unwrap_or(object_id);
                object_id_trimmed = object_id_trimmed
                    .strip_suffix(b" ")
                    .unwrap_or(object_id_trimmed);
                let template_trimmed = [CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: object_id_trimmed
                        .as_ptr()
                        .cast::<std::ffi::c_void>()
                        .cast_mut(),
                    ulValueLen: CK_ULONG::try_from(object_id_trimmed.len())?,
                }];
                object_handles = self.find_object_handles(template_trimmed.to_vec())?;
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
            // Multiple matches in case the HSM uses the same ID for SK and PK
            debug!("Found {} possible handles", object_handles.len());
            for handle in object_handles {
                let Some(object_type) = self.get_key_type(handle)? else {
                    continue;
                };
                if object_id.ends_with(b"_pk") {
                    // We are looking for a public key. Check if the results contain one.
                    if object_type == RsaPublicKey {
                        object_handle = handle;
                        break;
                    }
                } else if object_type == AesKey || object_type == RsaPrivateKey {
                    object_handle = handle;
                    break;
                }
            }
        }

        // update cache
        self.object_handles_cache
            .insert(object_id.to_vec(), object_handle)?;

        Ok(object_handle)
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
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits: usize::try_from(key_size).map_err(|e| {
                        HError::Default(format!("Failed to convert key size to usize: {e}"))
                    })? * 8,
                    sensitive: sensitive == CK_TRUE,
                    id: label,
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
                Ok(Some(KeyMetadata {
                    key_type,
                    key_length_in_bits,
                    sensitive,
                    id: label,
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
    pub fn get_object_id(&self, object_handle: CK_OBJECT_HANDLE) -> HResult<Option<Vec<u8>>> {
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL, // Must be CKA_LABEL to match get_object_handle
            pValue: ptr::null_mut(),
            ulValueLen: 0,
        }];
        if self
            .call_get_attributes(object_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let id_len = template[0].ulValueLen;
        let mut id: Vec<u8> = vec![0_u8; usize::try_from(id_len)?];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: id.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulValueLen: id_len,
        }];
        if self
            .call_get_attributes(object_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        if self.get_key_type(object_handle)? == Some(KeyType::RsaPublicKey) && !id.ends_with(b"_pk")
        {
            id.extend_from_slice(b"_pk");
        }
        Ok(Some(id))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.close());
    }
}
