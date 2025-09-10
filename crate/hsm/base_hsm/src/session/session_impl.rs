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
use cosmian_logger::debug;
use pkcs11_sys::{
    CK_AES_GCM_PARAMS, CK_ATTRIBUTE, CK_BBOOL, CK_FALSE, CK_KEY_TYPE, CK_MECHANISM,
    CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RSA_PKCS_MGF_TYPE,
    CK_RSA_PKCS_OAEP_PARAMS, CK_SESSION_HANDLE, CK_TRUE, CK_ULONG, CK_VOID_PTR, CKA_CLASS,
    CKA_COEFFICIENT, CKA_EXPONENT_1, CKA_EXPONENT_2, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS,
    CKA_PRIME_1, CKA_PRIME_2, CKA_PRIVATE_EXPONENT, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_VALUE,
    CKA_VALUE_LEN, CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512, CKK_AES,
    CKK_RSA, CKK_VENDOR_DEFINED, CKM_AES_CBC, CKM_AES_GCM, CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP,
    CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CKO_VENDOR_DEFINED, CKR_ATTRIBUTE_SENSITIVE, CKR_OBJECT_HANDLE_INVALID, CKR_OK,
    CKZ_DATA_SPECIFIED,
};
use rand::{TryRngCore, rngs::OsRng};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::session::{aes::AesKeySize, rsa::RsaKeySize};
use crate::{HError, HResult, ObjectHandlesCache, hsm_capabilities::HsmCapabilities};

/// AES block size in bytes
const AES_BLOCK_SIZE: usize = 16;
const AES_CBC_IV_LENGTH: usize = 16;
const AES_GCM_IV_LENGTH: usize = 12;
const AES_GCM_AUTH_TAG_LENGTH: usize = 16;

/// Generate a random nonce of size T
/// This function is used to generate a random nonce for the AES GCM or a random IV for AES CBC encryption
fn generate_random_nonce<const T: usize>() -> HResult<[u8; T]> {
    let mut bytes = [0u8; T];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| HError::Default(format!("Error generating random nonce: {e}")))?;
    Ok(bytes)
}

/// Encryption algorithm supported by the HSM
#[derive(Debug)]
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
            CryptoAlgorithm::AesCbc => HsmEncryptionAlgorithm::AesCbc,
            CryptoAlgorithm::AesGcm => HsmEncryptionAlgorithm::AesGcm,
            CryptoAlgorithm::RsaPkcsV15 => HsmEncryptionAlgorithm::RsaPkcsV15,
            CryptoAlgorithm::RsaOaepSha256 => HsmEncryptionAlgorithm::RsaOaepSha256,
            CryptoAlgorithm::RsaOaepSha1 => HsmEncryptionAlgorithm::RsaOaepSha1,
        }
    }
}

/// A session with an HSM (Hardware Security Module) that implements PKCS#11 interface.
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
    session_handle: CK_SESSION_HANDLE,
    object_handles_cache: Arc<ObjectHandlesCache>,
    supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
    is_logged_in: bool,
    hsm_capabilities: HsmCapabilities,
}

impl Session {
    pub fn new(
        hsm: Arc<crate::hsm_lib::HsmLib>,
        session_handle: CK_SESSION_HANDLE,
        object_handles_cache: Arc<ObjectHandlesCache>,
        supported_oaep_hash_cache: Arc<Mutex<Option<Vec<CK_MECHANISM_TYPE>>>>,
        is_logged_in: bool,
        hsm_capabilities: HsmCapabilities,
    ) -> Self {
        debug!("Creating new session: {session_handle}");
        Session {
            hsm,
            session_handle,
            object_handles_cache,
            supported_oaep_hash_cache,
            is_logged_in,
            hsm_capabilities,
        }
    }

    /// Get the HSM library interface
    pub(crate) fn hsm(&self) -> Arc<crate::hsm_lib::HsmLib> {
        self.hsm.clone()
    }

    /// Get the PKCS#11 session handle
    pub(crate) fn session_handle(&self) -> CK_SESSION_HANDLE {
        self.session_handle
    }

    /// Get the object handles cache
    pub(crate) fn object_handles_cache(&self) -> Arc<ObjectHandlesCache> {
        self.object_handles_cache.clone()
    }

    /// Close the session and log out if necessary
    pub fn close(&self) -> HResult<()> {
        unsafe {
            if self.is_logged_in {
                let rv = self.hsm.C_Logout.ok_or_else(|| {
                    HError::Default("C_Logout not available on library".to_string())
                })?(self.session_handle);
                if rv != CKR_OK {
                    return Err(HError::Default("Failed logging out".to_string()));
                }
            }
            let rv = self.hsm.C_CloseSession.ok_or_else(|| {
                HError::Default("C_CloseSession not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
                return Err(HError::Default("Failed closing a session".to_string()));
            }
            Ok(())
        }
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
        let mut cache = self.supported_oaep_hash_cache.lock().unwrap();
        if let Some(ref list) = *cache {
            return Ok(list.clone());
        }

        // Create a temporary key for testing
        let sk_id = Uuid::new_v4().to_string();
        let pk_id = sk_id.clone() + "_pk";
        let (sk_handle, pk_handle) = self.generate_rsa_key_pair(
            sk_id.as_bytes(),
            pk_id.as_bytes(),
            RsaKeySize::Rsa1024,
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
                pParameter: &raw mut params as CK_VOID_PTR,
                ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
            };

            // We don't actually encrypt, just see if init succeeds
            let rv = unsafe {
                self.hsm.C_EncryptInit.ok_or_else(|| {
                    let _ = self.destroy_object(sk_handle);
                    let _ = self.destroy_object(pk_handle);
                    HError::Default("C_EncryptInit not available on library".to_string())
                })?(self.session_handle, &mut mechanism, pk_handle)
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
        unsafe {
            let rv = self.hsm.C_FindObjectsInit.ok_or_else(|| {
                HError::Default("C_FindObjectsInit not available on library".to_string())
            })?(
                self.session_handle,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            );
            if rv != CKR_OK {
                return Err(HError::Default(
                    "Failed to initialize object search".to_string(),
                ));
            }

            let mut object_handle: CK_OBJECT_HANDLE = 0;
            let mut object_count: CK_ULONG = 0;
            loop {
                let rv = self.hsm.C_FindObjects.ok_or_else(|| {
                    HError::Default("C_FindObjects not available on library".to_string())
                })?(
                    self.session_handle,
                    &raw mut object_handle,
                    1,
                    &raw mut object_count,
                );
                if rv != CKR_OK {
                    return Err(HError::Default("Failed to find objects".to_string()));
                }
                if object_count == 0 {
                    break;
                }
                object_handles.push(object_handle);
            }

            let rv = self.hsm.C_FindObjectsFinal.ok_or_else(|| {
                HError::Default("C_FindObjectsFinal not available on library".to_string())
            })?(self.session_handle);
            if rv != CKR_OK {
                return Err(HError::Default(
                    "Failed to finalize object search".to_string(),
                ));
            }
        }
        Ok(object_handles)
    }

    pub fn get_object_handle(&self, object_id: &[u8]) -> HResult<CK_OBJECT_HANDLE> {
        let object_id_string = String::from_utf8(Vec::from(object_id))
            .map_err(|e| HError::Default(format!("Failed to convert object_id to string: {e}")))?;
        debug!("Retrieving Object handle for id: {object_id_string}");
        if let Some(handle) = self.object_handles_cache.get(object_id) {
            return Ok(handle);
        }

        // Proteccio does not allow the ID for secret keys so we use the label
        // and we do the same on base HSM
        let template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: object_id.as_ptr() as CK_VOID_PTR,
            ulValueLen: object_id.len() as CK_ULONG,
        }];

        let mut object_handles = self.find_object_handles(template.to_vec())?;
        if object_handles.is_empty() {
            if object_id_string.trim().ends_with("_pk") {
                //Check if the HSM stores the object without the suffix
                let trimmed = object_id_string.trim().strip_suffix("_pk");
                let object_id_trimmed = match trimmed {
                    Some(trimmed) => trimmed,
                    None => object_id_string.trim(),
                }
                .as_bytes();
                let template_trimmed = [CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    pValue: object_id_trimmed.as_ptr() as CK_VOID_PTR,
                    ulValueLen: object_id_trimmed.len() as CK_ULONG,
                }];
                object_handles = self.find_object_handles(template_trimmed.to_vec())?;
                if object_handles.is_empty() {
                    return Err(HError::Default("Object not found".to_string()));
                }
            } else {
                return Err(HError::Default("Object not found".to_string()));
            }
        }

        let mut object_handle = object_handles[0];
        if object_handles.len() > 1 {
            //Multiple matches in case the HSM uses the same ID for SK and PK
            debug!("Found {} possible handles", object_handles.len());
            for handle in object_handles {
                let object_type = match self.get_key_type(handle)? {
                    None => continue,
                    Some(object_type) => object_type,
                };
                if object_id_string.trim().ends_with("_pk") {
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

        //update cache
        self.object_handles_cache
            .insert(object_id.to_vec(), object_handle);

        Ok(object_handle)
    }

    pub fn delete_object_handle(&self, id: &[u8]) {
        self.object_handles_cache.remove(id);
    }

    pub fn generate_random(&self, len: usize) -> HResult<Vec<u8>> {
        unsafe {
            let mut values = vec![0u8; len];
            let values_ptr: *mut u8 = values.as_mut_ptr();
            #[cfg(target_os = "windows")]
            let len = u32::try_from(len)?;
            #[cfg(not(target_os = "windows"))]
            let len = u64::try_from(len)?;
            let rv = self.hsm.C_GenerateRandom.ok_or_else(|| {
                HError::Default("C_GenerateRandom not available on library".to_string())
            })?(self.session_handle, values_ptr, len);
            if rv != CKR_OK {
                return Err(HError::Default("Failed generating random data".to_string()));
            }
            Ok(values)
        }
    }

    /// List objects in the HSM that match the specified filter
    /// The filter can be used to narrow down the search to specific types of objects
    /// such as AES keys, RSA keys, etc.
    /// If no filter is provided, all objects are listed.
    pub fn list_objects(&self, object_filter: HsmObjectFilter) -> HResult<Vec<CK_OBJECT_HANDLE>> {
        let mut template: Vec<CK_ATTRIBUTE> = Vec::new();
        match object_filter {
            HsmObjectFilter::Any => {}
            HsmObjectFilter::AesKey => {
                template.extend([
                    CK_ATTRIBUTE {
                        type_: CKA_CLASS,
                        pValue: std::ptr::from_ref(&CKO_SECRET_KEY) as *mut _,
                        ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_KEY_TYPE,
                        pValue: std::ptr::from_ref(&CKK_AES) as *mut _,
                        ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                    },
                ]);
            }
            HsmObjectFilter::RsaKey => template.extend([CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: std::ptr::from_ref(&CKK_RSA) as *mut _,
                ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
            }]),
            HsmObjectFilter::RsaPrivateKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PRIVATE_KEY) as *mut _,
                    ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA) as *mut _,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
            ]),
            HsmObjectFilter::RsaPublicKey => template.extend([
                CK_ATTRIBUTE {
                    type_: CKA_CLASS,
                    pValue: std::ptr::from_ref(&CKO_PUBLIC_KEY) as *mut _,
                    ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    pValue: std::ptr::from_ref(&CKK_RSA) as *mut _,
                    ulValueLen: size_of::<CK_KEY_TYPE>() as CK_ULONG,
                },
            ]),
        }
        let object_handles = self.find_object_handles(template)?;
        Ok(object_handles)
    }

    /// Destroy an object in the HSM
    pub fn destroy_object(&self, object_handle: CK_OBJECT_HANDLE) -> HResult<()> {
        unsafe {
            let rv = self.hsm.C_DestroyObject.ok_or_else(|| {
                HError::Default("C_DestroyObject not available on library".to_string())
            })?(self.session_handle, object_handle);
            if rv != CKR_OK {
                return Err(HError::Default("Failed to destroy object".to_string()));
            }
        }
        Ok(())
    }

    /// Apply PKCS#7 padding to the input data.
    ///
    /// PKCS#7 padding ensures that the input length is a multiple of the block size,
    /// which is required for many block cipher encryption algorithms (such as AES in CBC mode).
    ///
    /// # Arguments
    /// * `data` - The input data to be padded.
    /// * `block_size` - The block size in bytes (commonly 16 for AES).
    ///
    /// # Returns
    /// * `Vec<u8>` - A new buffer containing the original data with PKCS#7 padding appended.
    fn pkcs7_pad(&self, data: Vec<u8>, block_size: usize) -> Vec<u8> {
        let pad_len = block_size - (data.len() % block_size);
        let mut padded = data;
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        padded
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
    fn pkcs7_unpad(
        &self,
        data: Zeroizing<Vec<u8>>,
        block_size: usize,
    ) -> HResult<Zeroizing<Vec<u8>>> {
        if data.is_empty() {
            return Err(HError::Default(
                "Invalid PKCS#7 padding: empty buffer".to_string(),
            ));
        }
        if (data.len() % block_size) != 0 {
            return Err(HError::Default("Data doesn't align to blocks".to_string()));
        }
        let pad_len = *data.last().unwrap() as usize;
        if pad_len == 0 || pad_len > data.len() || pad_len > block_size {
            return Err(HError::Default("Invalid PKCS#7 padding".to_string()));
        }
        // verify all pad bytes
        if !data[data.len() - pad_len..]
            .iter()
            .all(|&b| b as usize == pad_len)
        {
            return Err(HError::Default("Invalid PKCS#7 padding bytes".to_string()));
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
        Ok(match algorithm {
            HsmEncryptionAlgorithm::AesGcm => {
                let mut nonce = generate_random_nonce::<12>()?;
                let mut params = CK_AES_GCM_PARAMS {
                    pIv: &mut nonce as *mut u8,
                    ulIvLen: AES_GCM_IV_LENGTH as CK_ULONG,
                    ulIvBits: (AES_GCM_IV_LENGTH * 8) as CK_ULONG,
                    pAAD: ptr::null_mut(),
                    ulAADLen: 0,
                    ulTagBits: (AES_GCM_AUTH_TAG_LENGTH * 8) as CK_ULONG,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: size_of::<CK_AES_GCM_PARAMS>() as CK_ULONG,
                };
                let ciphertext =
                    self.encrypt_with_mechanism(key_handle, &mut mechanism, plaintext)?;
                EncryptedContent {
                    iv: Some(nonce.to_vec()),
                    ciphertext: ciphertext[..ciphertext.len() - AES_GCM_AUTH_TAG_LENGTH].to_vec(),
                    tag: Some(ciphertext[ciphertext.len() - AES_GCM_AUTH_TAG_LENGTH..].to_vec()),
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
                    pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
                    ulParameterLen: iv.len() as CK_ULONG,
                };

                let padded_plaintext = self.pkcs7_pad(plaintext.to_vec(), AES_BLOCK_SIZE);
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
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
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
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
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
        match algorithm {
            HsmEncryptionAlgorithm::AesGcm => {
                if ciphertext.len() < AES_GCM_IV_LENGTH {
                    return Err(HError::Default("Invalid AES GCM ciphertext".to_string()));
                }
                let mut nonce: [u8; AES_GCM_IV_LENGTH] = ciphertext[..AES_GCM_IV_LENGTH]
                    .try_into()
                    .map_err(|_| HError::Default("Invalid AES GCM nonce".to_string()))?;
                let mut params = CK_AES_GCM_PARAMS {
                    pIv: &mut nonce as *mut u8,
                    ulIvLen: AES_GCM_IV_LENGTH as CK_ULONG,
                    ulIvBits: (AES_GCM_IV_LENGTH * 8) as CK_ULONG,
                    pAAD: ptr::null_mut(),
                    ulAADLen: 0,
                    ulTagBits: (AES_GCM_AUTH_TAG_LENGTH * 8) as CK_ULONG,
                };
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_GCM,
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: size_of::<CK_AES_GCM_PARAMS>() as CK_ULONG,
                };
                let plaintext = self.decrypt_with_mechanism(
                    key_handle,
                    &mut mechanism,
                    &ciphertext[AES_GCM_IV_LENGTH..],
                )?;
                Ok(plaintext)
            }
            HsmEncryptionAlgorithm::AesCbc => {
                if ciphertext.len() < AES_CBC_IV_LENGTH {
                    return Err(HError::Default("Invalid AES CBC ciphertext".to_string()));
                }
                let mut iv: [u8; AES_CBC_IV_LENGTH] = ciphertext[..AES_CBC_IV_LENGTH]
                    .try_into()
                    .map_err(|_| HError::Default("Invalid AES CBC IV".to_string()))?;
                if let Some(max_cbc_data_size) = self.hsm_capabilities.max_cbc_data_size {
                    if ciphertext.len() > (max_cbc_data_size + AES_CBC_IV_LENGTH) {
                        debug!("Performing multi round AES CBC decryption");
                        return self.decrypt_aes_cbc_multi_round(
                            key_handle,
                            &iv,
                            &ciphertext[AES_CBC_IV_LENGTH..],
                            max_cbc_data_size,
                        );
                    }
                }
                let mut mechanism = CK_MECHANISM {
                    mechanism: CKM_AES_CBC,
                    pParameter: iv.as_mut_ptr() as CK_VOID_PTR,
                    ulParameterLen: iv.len() as CK_ULONG,
                };

                let paddedPlaintext = self.decrypt_with_mechanism(
                    key_handle,
                    &mut mechanism,
                    &ciphertext[AES_CBC_IV_LENGTH..],
                )?;

                let plaintext = self.pkcs7_unpad(paddedPlaintext, AES_BLOCK_SIZE)?;
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
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
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
                    pParameter: &raw mut params as CK_VOID_PTR,
                    ulParameterLen: std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG,
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
            return Err(HError::Default(
                "Too small maximum round length".to_string(),
            ));
        }
        if max_round_length % AES_BLOCK_SIZE != 0 {
            return Err(HError::Default(
                "Round length must be multiple of block size (16)".to_string(),
            ));
        }
        let padded_plaintext = self.pkcs7_pad(plaintext.to_vec(), AES_BLOCK_SIZE);
        let mut round_iv = iv;
        let total_length = padded_plaintext.len();
        let mut processed_length = 0;
        let mut ciphertext: Vec<u8> = Vec::with_capacity(total_length);

        loop {
            let round_length = min(total_length - processed_length, max_round_length);
            if round_length == 0 {
                break
            };
            trace!(
                "Doing round with {round_length} bytes. {processed_length} of {total_length} done"
            );
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: round_iv.as_mut_ptr() as CK_VOID_PTR,
                ulParameterLen: iv.len() as CK_ULONG,
            };
            let round_ciphertext = self.encrypt_with_mechanism(
                key_handle,
                &mut mechanism,
                &padded_plaintext.as_slice()[processed_length..processed_length + round_length],
            )?;
            for i in 0..iv.len() {
                round_iv[i] = round_ciphertext[round_ciphertext.len() - iv.len() + i];
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
    /// For more details see [Session::encrypt_aes_cbc_multi_round].
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
            return Err(HError::Default(
                "Too small maximum round length".to_string(),
            ));
        }
        if max_round_length % AES_BLOCK_SIZE != 0 {
            return Err(HError::Default(format!(
                "Round length must be multiple of block size ({AES_BLOCK_SIZE}))"
            )));
        }
        if ciphertext.len() % AES_BLOCK_SIZE != 0 {
            return Err(HError::Default(format!(
                "AES CBC ciphertext must be multiple of block size ({AES_BLOCK_SIZE})"
            )));
        }
        if iv.len() != AES_CBC_IV_LENGTH {
            return Err(HError::Default(format!(
                "Wrong IV length. Must be {AES_CBC_IV_LENGTH} bytes long"
            )));
        }

        let mut round_iv: [u8; AES_CBC_IV_LENGTH] = iv[..AES_CBC_IV_LENGTH]
            .try_into()
            .map_err(|_| HError::Default("Invalid IV".to_string()))?;
        let total_length = ciphertext.len();
        let mut processed_length = 0;
        let mut plaintext: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(total_length));

        loop {
            let round_length = min(total_length - processed_length, max_round_length);
            if round_length == 0 {
                break
            };
            trace!(
                "Doing round with {round_length} bytes. {processed_length} of {total_length} done"
            );
            let mut mechanism = CK_MECHANISM {
                mechanism: CKM_AES_CBC,
                pParameter: round_iv.as_mut_ptr() as CK_VOID_PTR,
                ulParameterLen: iv.len() as CK_ULONG,
            };
            let round_plaintext = self.decrypt_with_mechanism(
                key_handle,
                &mut mechanism,
                &ciphertext[processed_length..processed_length + round_length],
            )?;

            plaintext.extend_from_slice(&round_plaintext);
            processed_length += round_length;
            for i in 0..iv.len() {
                round_iv[i] = ciphertext[processed_length - iv.len() + i];
            }
        }
        self.pkcs7_unpad(plaintext, AES_BLOCK_SIZE)
    }

    fn encrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        data: &[u8],
    ) -> HResult<Vec<u8>> {
        let mut data = data.to_vec();
        unsafe {
            let ck_fn = self.hsm.C_EncryptInit.ok_or_else(|| {
                HError::Default("C_EncryptInit not available on library".to_string())
            })?;

            let rv = ck_fn(self.session_handle, mechanism, key_handle);
            if rv != CKR_OK {
                return Err(HError::Default(
                    "Failed to initialize encryption".to_string(),
                ));
            }

            let ck_fn = self
                .hsm
                .C_Encrypt
                .ok_or_else(|| HError::Default("C_Encrypt not available on library".to_string()))?;

            let mut encrypted_data_len: CK_ULONG = 0;
            let rv = ck_fn(
                self.session_handle,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &raw mut encrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to allocate encrypted data length. Data to encrypt is likely too big: \
                     {} bytes. Error code: {rv}",
                    data.len()
                )));
            }

            let mut encrypted_data = vec![0u8; encrypted_data_len as usize];
            let rv = ck_fn(
                self.session_handle,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                encrypted_data.as_mut_ptr(),
                &raw mut encrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!("Failed to encrypt data: {rv}")));
            }

            encrypted_data.truncate(encrypted_data_len as usize);
            Ok(encrypted_data)
        }
    }

    fn decrypt_with_mechanism(
        &self,
        key_handle: CK_OBJECT_HANDLE,
        mechanism: &mut CK_MECHANISM,
        encrypted_data: &[u8],
    ) -> HResult<Zeroizing<Vec<u8>>> {
        let mut encrypted_data = encrypted_data.to_vec();
        unsafe {
            let ck_fn = self.hsm.C_DecryptInit.ok_or_else(|| {
                HError::Default("C_DecryptInit not available on library".to_string())
            })?;

            let rv = ck_fn(self.session_handle, mechanism, key_handle);
            if rv != CKR_OK {
                return Err(HError::Default(
                    "Failed to initialize decryption".to_string(),
                ));
            }

            let ck_fn = self
                .hsm
                .C_Decrypt
                .ok_or_else(|| HError::Default("C_Decrypt not available on library".to_string()))?;

            let mut decrypted_data_len: CK_ULONG = 0;
            let rv = ck_fn(
                self.session_handle,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                ptr::null_mut(),
                &raw mut decrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(
                    "Failed to get decrypted data length".to_string(),
                ));
            }

            let mut decrypted_data = vec![0u8; decrypted_data_len as usize];
            let rv = ck_fn(
                self.session_handle,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                decrypted_data.as_mut_ptr(),
                &raw mut decrypted_data_len,
            );
            if rv != CKR_OK {
                return Err(HError::Default(format!("Failed to decrypt data: {rv}")));
            }

            decrypted_data.truncate(decrypted_data_len as usize);
            Ok(Zeroizing::new(decrypted_data))
        }
    }

    /// Export a key from the HSM
    pub fn export_key(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<HsmObject>> {
        let mut key_type: CK_KEY_TYPE = CKK_VENDOR_DEFINED;
        let mut class: CK_OBJECT_CLASS = CKO_VENDOR_DEFINED;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: &raw mut class as CK_VOID_PTR,
                ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &raw mut key_type as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
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
        let mut public_exponent: Vec<u8> = vec![0_u8; public_exponent_len as usize];
        let mut private_exponent: Vec<u8> = vec![0_u8; private_exponent_len as usize];
        let mut prime_1: Vec<u8> = vec![0_u8; prime_1_len as usize];
        let mut prime_2: Vec<u8> = vec![0_u8; prime_2_len as usize];
        let mut exponent_1: Vec<u8> = vec![0_u8; exponent_1_len as usize];
        let mut exponent_2: Vec<u8> = vec![0_u8; exponent_2_len as usize];
        let mut coefficient: Vec<u8> = vec![0_u8; coefficient_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: public_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE_EXPONENT,
                pValue: private_exponent.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: private_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_1,
                pValue: prime_1.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: prime_1_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIME_2,
                pValue: prime_2.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: prime_2_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_1,
                pValue: exponent_1.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: exponent_1_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_EXPONENT_2,
                pValue: exponent_2.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: exponent_2_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_COEFFICIENT,
                pValue: coefficient.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: coefficient_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
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
        let mut public_exponent: Vec<u8> = vec![0_u8; public_exponent_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_PUBLIC_EXPONENT,
                pValue: public_exponent.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: public_exponent_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_MODULUS,
                pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
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
        let mut key_value: Vec<u8> = vec![0_u8; value_len as usize];
        let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
        let mut key_size: CK_ULONG = 0;
        let mut template = [
            CK_ATTRIBUTE {
                type_: CKA_VALUE,
                pValue: key_value.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: value_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_LABEL,
                pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                ulValueLen: label_len,
            },
            CK_ATTRIBUTE {
                type_: CKA_VALUE_LEN,
                pValue: &raw mut key_size as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
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
        unsafe {
            debug!("Retrieving HSM key attributes for key handle: {key_handle}");
            // Get the length of the key value
            let rv = self.hsm.C_GetAttributeValue.ok_or_else(|| {
                HError::Default("C_GetAttributeValue not available on library".to_string())
            })?(
                self.session_handle,
                key_handle,
                template.as_ptr().cast_mut(),
                template.len() as CK_ULONG,
            );
            if rv == CKR_ATTRIBUTE_SENSITIVE {
                return Err(HError::Default(
                    "This key is sensitive and cannot be exported from the HSM.".to_string(),
                ));
            }
            if rv == CKR_OBJECT_HANDLE_INVALID {
                // The key was not found
                return Ok(None);
            }
            if rv != CKR_OK {
                return Err(HError::Default(format!(
                    "Failed to get the HSM attributes for key handle: {key_handle}"
                )));
            }
            Ok(Some(()))
        }
    }

    /// Get the metadata for a key
    pub fn get_key_metadata(&self, key_handle: CK_OBJECT_HANDLE) -> HResult<Option<KeyMetadata>> {
        let key_type = match self.get_key_type(key_handle)? {
            None => return Ok(None),
            Some(key_type) => key_type,
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
                        pValue: &raw mut key_size as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
                    },
                    CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: &raw mut sensitive as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                    },
                ]);
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let label_len = template[0].ulValueLen;
                let label = if label_len == 0 {
                    String::new()
                } else {
                    let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
                    let mut template = [CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
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
                let label_len = template[0].ulValueLen;
                let mut label_bytes: Vec<u8> = vec![0_u8; label_len as usize];
                let modulus_len = template[1].ulValueLen;
                let mut modulus: Vec<u8> = vec![0_u8; modulus_len as usize];
                let mut sensitive: CK_BBOOL = CK_FALSE;
                let mut template = vec![CK_ATTRIBUTE {
                    type_: CKA_MODULUS,
                    pValue: modulus.as_mut_ptr() as CK_VOID_PTR,
                    ulValueLen: modulus_len,
                }];
                if label_len > 0 {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_LABEL,
                        pValue: label_bytes.as_mut_ptr() as CK_VOID_PTR,
                        ulValueLen: label_len,
                    });
                }
                if key_type == KeyType::RsaPrivateKey {
                    template.push(CK_ATTRIBUTE {
                        type_: CKA_SENSITIVE,
                        pValue: &raw mut sensitive as CK_VOID_PTR,
                        ulValueLen: size_of::<CK_BBOOL>() as CK_ULONG,
                    });
                }
                if self
                    .call_get_attributes(key_handle, &mut template)?
                    .is_none()
                {
                    return Ok(None);
                }
                let key_length_in_bits = modulus.len() * 8;

                let label = if label_len == 0 {
                    String::new()
                } else {
                    String::from_utf8(label_bytes).map_err(|e| {
                        HError::Default(format!("Failed to convert label to string: {e}"))
                    })?
                };
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
                pValue: &raw mut class as CK_VOID_PTR,
                ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
            },
            CK_ATTRIBUTE {
                type_: CKA_KEY_TYPE,
                pValue: &raw mut key_type as CK_VOID_PTR,
                ulValueLen: size_of::<CK_ULONG>() as CK_ULONG,
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
            type_: CKA_LABEL, //Must be CKA_LABEL to match get_object_handle
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
        let mut id: Vec<u8> = vec![0_u8; id_len as usize];
        let mut template = [CK_ATTRIBUTE {
            type_: CKA_LABEL,
            pValue: id.as_mut_ptr() as CK_VOID_PTR,
            ulValueLen: id_len,
        }];
        if self
            .call_get_attributes(object_handle, &mut template)?
            .is_none()
        {
            return Ok(None);
        }
        let key_type = match self.get_key_type(object_handle)? {
            None => return Ok(Some(id)),
            Some(key_type) => key_type,
        };
        let term = "_pk".as_bytes();
        if id.ends_with(term) {
            return Ok(Some(id))
        }
        if key_type == KeyType::RsaPublicKey {
            id.append(&mut term.to_vec())
        }
        Ok(Some(id))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        drop(self.close());
    }
}
