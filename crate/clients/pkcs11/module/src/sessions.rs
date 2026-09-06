// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.
//
// Original code:
// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(clippy::as_conversions)]
#![allow(clippy::significant_drop_in_scrutinee)]
#![allow(clippy::branches_sharing_code)]

use std::{
    collections::HashMap,
    sync::{self, Arc, atomic::Ordering},
};

use cosmian_logger::{debug, trace, warn};
use pkcs11_sys::{
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_PROFILE_ID, CK_SESSION_HANDLE,
    CK_ULONG, CK_ULONG_PTR, CKP_AUTHENTICATION_TOKEN, CKP_BASELINE_PROVIDER, CKP_EXTENDED_PROVIDER,
    CKP_PUBLIC_CERTIFICATES_TOKEN,
};

use crate::{
    MResultHelper, ModuleError, ModuleResult,
    core::{
        attribute::Attributes,
        mechanism::Mechanism,
        object::{Object, ObjectType},
    },
    objects_store::{OBJECTS_STORE, ObjectsStore},
    traits::{
        DecryptContext, EncryptContext, KeyAlgorithm, SearchOptions, SignContext, backend,
        use_pin_as_access_token,
    },
};

/// PKCS#11 v3.1 conformance profiles ([OASIS PKCS#11 Profiles v3.1]) that this module
/// self-declares via `CKO_PROFILE` objects returned by `C_FindObjects`.
///
/// - `CKP_BASELINE_PROVIDER`: mandatory Session and Object Management functions.
/// - `CKP_EXTENDED_PROVIDER`: Baseline plus `C_GetMechanismList`/`C_GetMechanismInfo` and
///   `C_Login`/`C_LoginUser`/`C_Logout` — satisfied now that `C_LoginUser` is implemented.
/// - `CKP_AUTHENTICATION_TOKEN`: Baseline plus asymmetric key pairs usable for
///   challenge/response authentication — satisfied by the existing private-key signing
///   support.
/// - `CKP_PUBLIC_CERTIFICATES_TOKEN`: Baseline plus `CKO_CERTIFICATE` objects discoverable
///   without login — satisfied by the existing certificate support, **except** in
///   OIDC-pin-as-access-token mode: there, `C_Logout` clears the registered backend (see
///   `traits::backend::clear_backend`), so `find_all_certificates()` starts returning
///   `UserNotLoggedIn` for the remainder of the session and the "discoverable without
///   login" guarantee would no longer hold. This profile is therefore omitted while that
///   mode is active.
///
/// `CKP_COMPLETE_PROVIDER` is intentionally NOT declared: it additionally requires
/// `C_WrapKey`/`C_UnwrapKey`/`C_DeriveKey` and digest mechanisms that are not implemented.
fn supported_profiles() -> Vec<CK_PROFILE_ID> {
    let mut profiles = vec![
        CKP_BASELINE_PROVIDER,
        CKP_EXTENDED_PROVIDER,
        CKP_AUTHENTICATION_TOKEN,
    ];
    if !use_pin_as_access_token() {
        profiles.push(CKP_PUBLIC_CERTIFICATES_TOKEN);
    }
    profiles
}

/// Prefix used to identify Oracle Key Management (KM) encryption keys.
/// This prefix is typically used in PKCS#11 object labels or attributes to mark
/// Oracle-specific encryption key material. The full label should start with this
/// string, followed by the specific key identifier.
///
/// From a KMS point of view, it is a `SecretData` object.
const PREFIX_ORACLE_SECURITY_KM: &str = "ORACLE.SECURITY.KM.ENCRYPTION.";
/// Prefix used to identify Oracle Transparent Data Encryption (TDE) HSM master keys.
/// This prefix is used in PKCS#11 object labels or attributes to mark Oracle TDE
/// HSM master keys. The full label should start with this string, followed by the
/// master key identifier.
///
/// From a KMS point of view, it is a `TransparentSymmetricKey` object.
const PREFIX_ORACLE_TDE_HSM_MK: &str = "ORACLE.TDE.HSM.MK.";

/// Suffix appended by the KMS to a key-pair base UID to derive the *public* key
/// unique identifier: a key pair is stored as `<base>` (private key) and
/// `<base>_pk` (public key).
///
/// This mirrors `SYSTEM_TAG_PUBLIC_KEY` in
/// `crate/kmip/src/kmip_2_1/extra/tagging.rs`. The PKCS#11 module cannot depend
/// on `cosmian_kmip`, so the value is duplicated here.
///
/// Standard PKCS#11 clients (e.g. OpenSSH) read a public key's `CKA_ID` and
/// reuse it to locate the paired *private* key before signing. Because the two
/// keys carry distinct UIDs, a `CKO_PRIVATE_KEY` search by the public key's
/// `CKA_ID` must strip this suffix to resolve the private key.
const PUBLIC_KEY_ID_SUFFIX: &str = "_pk";

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU64 = sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

static SESSIONS: std::sync::LazyLock<sync::Mutex<SessionMap>> =
    std::sync::LazyLock::new(Default::default);

#[derive(Default)]
pub(crate) struct Session {
    flags: CK_FLAGS,
    /// The objects found by `C_FindObjectsInit`
    /// and that have not yet been read by `C_FindObjects`
    pub find_objects_ctx: Vec<CK_OBJECT_HANDLE>,
    pub sign_ctx: Option<SignContext>,
    pub decrypt_ctx: Option<DecryptContext>,
    pub encrypt_ctx: Option<EncryptContext>,
}

impl Session {
    pub(crate) fn update_find_objects_context(
        &mut self,
        object: Arc<Object>,
    ) -> ModuleResult<CK_OBJECT_HANDLE> {
        let mut objects_store = OBJECTS_STORE.write()?;
        let handle = objects_store.upsert(object);
        self.find_objects_ctx.push(handle);
        Ok(handle)
    }

    /// Conversion example:
    /// Map
    /// `ORACLE.SECURITY.KM.ENCRYPTION.30363946333744303931413733443446313342463243453932314542324346303830`
    /// to
    /// `ORACLE.TDE.HSM.MK.069F37D091A73D4F13BF2CE921EB2CF080`
    pub(crate) fn map_oracle_tde_security_to_mk(label: &str) -> ModuleResult<String> {
        debug!("map_oracle_tde_security_to_mk: processing label: {label}");
        // check prefix
        if !label.starts_with(PREFIX_ORACLE_SECURITY_KM) {
            // just ignore and return
            return Ok(label.to_owned());
        }
        // Extract the ID portion after the prefix
        let key_id_hex = label
            .strip_prefix(PREFIX_ORACLE_SECURITY_KM)
            .ok_or_else(|| ModuleError::BadArguments(format!("Invalid label format: {label}")))?;
        let key_id_bytes = hex::decode(key_id_hex).map_err(|e| {
            ModuleError::BadArguments(format!("Invalid hex encoding: {key_id_hex}. Error: {e}"))
        })?;
        let key_id = String::from_utf8_lossy(&key_id_bytes).to_string();
        Ok(format!("{PREFIX_ORACLE_TDE_HSM_MK}{key_id}"))
    }

    pub(crate) fn load_find_context(&mut self, attributes: &Attributes) -> ModuleResult<()> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "load_find_context: empty attributes".to_owned(),
            ));
        }
        if attributes
            .get(crate::core::attribute::AttributeType::ProfileId)
            .is_some()
        {
            // A template combining `CKA_PROFILE_ID` with an explicit, *different*
            // `CKA_CLASS` (e.g. `CKO_PRIVATE_KEY`) asks for an object that is
            // simultaneously a profile object and something else: no object in this
            // module's model ever satisfies both (profile objects carry no other
            // class-identifying attributes, and non-profile objects never carry
            // `CKA_PROFILE_ID`), so it correctly yields no matches instead of being
            // incorrectly routed to the profile-only fast path below, which would
            // otherwise ignore the requested class and any other template attributes
            // entirely.
            match attributes.get_class() {
                Ok(class) if class != pkcs11_sys::CKO_PROFILE => {
                    self.clear_find_objects_ctx();
                    return Ok(());
                }
                _ => return self.load_find_context_by_class(attributes, pkcs11_sys::CKO_PROFILE),
            }
        }
        // Find all objects
        for object in backend()?.find_all_objects()? {
            self.update_find_objects_context(object)?;
        }

        let search_class = attributes.get_class();
        if let Ok(search_class) = search_class {
            self.load_find_context_by_class(attributes, search_class)
        } else {
            let label = attributes.get_label()?;
            let label = Self::map_oracle_tde_security_to_mk(&label)?;
            let find_ctx = OBJECTS_STORE.read()?;
            debug!(
                "load_find_context: loading for label: {label:?} and attributes: {attributes:?}"
            );
            debug!("load_find_context: display current store: {find_ctx}");
            if let Some((object, handle)) = find_ctx.get_using_id(&label) {
                debug!(
                    "load_find_context: search by id: {label} -> handle: {} -> object: {}: {}",
                    handle,
                    object.name(),
                    object.remote_id()
                );
                self.clear_find_objects_ctx();
                self.add_to_find_objects_ctx(handle);
            } else {
                warn!("load_find_context: id {label} not found in store");
                self.clear_find_objects_ctx();
                return Ok(());
            }
            Ok(())
        }?;

        trace!("load_find_context succeeded");
        Ok(())
    }

    #[expect(clippy::too_many_lines)]
    pub(crate) fn load_find_context_by_class(
        &mut self,
        attributes: &Attributes,
        search_class: CK_OBJECT_CLASS,
    ) -> ModuleResult<()> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "load_find_context_by_class: empty attributes".to_owned(),
            ));
        }
        let search_options = SearchOptions::try_from(attributes)?;
        debug!(
            "load_find_context_by_class: loading for class: {search_class:?} and options: \
             {search_options:?}, attributes: {attributes:?}",
        );
        match search_options {
            SearchOptions::All => {
                self.clear_find_objects_ctx();
                let res = match search_class {
                    pkcs11_sys::CKO_CERTIFICATE => {
                        attributes.ensure_X509_or_none()?;
                        backend()?
                            .find_all_certificates()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::Certificate(c)))
                            })
                            .collect::<ModuleResult<Vec<_>>>()?
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => backend()?
                        .find_all_public_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PublicKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_PRIVATE_KEY => backend()?
                        .find_all_private_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PrivateKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_SECRET_KEY => backend()?
                        .find_all_symmetric_keys()?
                        .into_iter()
                        .map(|c| {
                            self.update_find_objects_context(Arc::new(Object::SymmetricKey(c)))
                        })
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_DATA => {
                        // Use OBJECTS_STORE directly for CKO_DATA searches.
                        //
                        // `load_find_context` calls `find_all_objects()` before this function,
                        // which already populates OBJECTS_STORE with all KMS DataObject entries
                        // (via locate + get_attributes). Newly-created companions from a recent
                        // C_CreateObject are also already in OBJECTS_STORE (inserted by upsert).
                        //
                        // Querying the KMS via `find_all_data_objects()` instead would make a
                        // `batch_get` request that fails the ENTIRE batch when ANY single object
                        // cannot be fetched (e.g. old SecretData objects in unexpected state).
                        // Using the local store avoids that fragility entirely.
                        let label_filter = attributes.get_label().ok();
                        let find_ctx = OBJECTS_STORE.read()?;
                        let data_objects = find_ctx.get_using_type(&ObjectType::DataObject);
                        debug!(
                            "CKO_DATA search: label_filter={:?}, store has {} DataObjects",
                            label_filter,
                            data_objects.len()
                        );
                        let mut result = vec![];
                        for (object, handle) in data_objects {
                            if let Object::DataObject(data) = &*object {
                                if label_filter.as_ref().is_none_or(|l| data.remote_id() == *l) {
                                    debug!(
                                        "CKO_DATA match: remote_id={}, handle={}",
                                        data.remote_id(),
                                        handle
                                    );
                                    self.find_objects_ctx.push(handle);
                                    result.push(handle);
                                }
                            }
                        }
                        result
                    }
                    pkcs11_sys::CKO_PROFILE => {
                        // Profile objects are static/local: no KMIP round-trip needed, the
                        // module self-declares which OASIS conformance profiles it satisfies.
                        supported_profiles()
                            .into_iter()
                            .map(|id| {
                                self.update_find_objects_context(Arc::new(Object::Profile(id)))
                            })
                            .collect::<ModuleResult<Vec<_>>>()?
                    }
                    o => return Err(ModuleError::Todo(format!("Object not supported: {o}"))),
                };
                debug!(
                    "load_find_context_by_class: added {} objects with handles: {:?}",
                    res.len(),
                    res
                );
            }

            SearchOptions::Id(id) => {
                if search_class == pkcs11_sys::CKO_CERTIFICATE {
                    // Find certificates which have this CKA_ID as private key ID
                    let find_ctx = OBJECTS_STORE.read()?;
                    let certificates = find_ctx.get_using_type(&ObjectType::Certificate);
                    for (object, handle) in certificates {
                        match &*object {
                            Object::Certificate(c) => {
                                if c.private_key_id() == id {
                                    debug!(
                                        "load_find_context_by_class: search by id: {} -> handle: \
                                         {} -> certificate: {}:{}",
                                        id,
                                        handle,
                                        object.name(),
                                        object.remote_id()
                                    );
                                    self.clear_find_objects_ctx();
                                    self.add_to_find_objects_ctx(handle);
                                }
                            }
                            // TODO may be we should treat Public Keys the same as Certificates
                            o => {
                                return Err(ModuleError::Todo(format!(
                                    "This should not happen, returning: {:?}",
                                    o.object_type()
                                )));
                            }
                        }
                    }
                } else {
                    let find_ctx = OBJECTS_STORE.read()?;
                    // Resolve the object requested by CKA_ID, enforcing that the
                    // returned object's class matches `search_class`.
                    //
                    // For `CKO_PRIVATE_KEY`, standard PKCS#11 clients (e.g. OpenSSH)
                    // pass the *public* key's `CKA_ID` (`<base>_pk`) to locate the
                    // paired private key. The KMS stores the private key under the
                    // base UID (`<base>`), so the suffix is stripped before lookup.
                    let resolved = Self::resolve_object_by_class(&find_ctx, &id, search_class);
                    if let Some((object, handle)) = resolved {
                        debug!(
                            "load_find_context_by_class: search by id: {} -> handle: {} -> \
                             object: {}:{}",
                            id,
                            handle,
                            object.name(),
                            object.remote_id()
                        );
                        self.clear_find_objects_ctx();
                        self.add_to_find_objects_ctx(handle);
                    } else if search_class == pkcs11_sys::CKO_PRIVATE_KEY {
                        // The initial store lookup failed. `find_all_objects` (called
                        // from `load_find_context`) may have silently missed private
                        // keys because it uses single system tags. Fall back to the
                        // backend's `find_all_private_keys` which uses user-scoped
                        // combined tags (e.g. `["ssh-auth", "_sk"]`), retrying the
                        // store lookup afterwards.
                        drop(find_ctx);
                        if let Ok(private_keys) = backend()?.find_all_private_keys() {
                            for pk in private_keys {
                                self.update_find_objects_context(Arc::new(Object::PrivateKey(pk)))?;
                            }
                        }
                        let find_ctx = OBJECTS_STORE.read()?;
                        if let Some((object, handle)) =
                            Self::resolve_object_by_class(&find_ctx, &id, search_class)
                        {
                            debug!(
                                "load_find_context_by_class: backend fallback — search by id: {} \
                                 -> handle: {} -> object: {}:{}",
                                id,
                                handle,
                                object.name(),
                                object.remote_id()
                            );
                            self.clear_find_objects_ctx();
                            self.add_to_find_objects_ctx(handle);
                        } else {
                            warn!(
                                "load_find_context_by_class: no {search_class:?} object found for \
                                 id {id}"
                            );
                            self.clear_find_objects_ctx();
                        }
                    } else {
                        // A search that matches no object is valid PKCS#11 behavior:
                        // `C_FindObjects` simply returns zero objects.
                        warn!(
                            "load_find_context_by_class: no {search_class:?} object found for id \
                             {id}"
                        );
                        self.clear_find_objects_ctx();
                    }
                }
            }
            SearchOptions::ProfileId(id) => {
                self.clear_find_objects_ctx();
                if search_class == pkcs11_sys::CKO_PROFILE && supported_profiles().contains(&id) {
                    self.update_find_objects_context(Arc::new(Object::Profile(id)))?;
                }
            }
        }
        Ok(())
    }

    /// Clear the unread index
    fn clear_find_objects_ctx(&mut self) {
        self.find_objects_ctx.clear();
    }

    /// Add to the unread index
    fn add_to_find_objects_ctx(&mut self, handle: CK_OBJECT_HANDLE) {
        self.find_objects_ctx.push(handle);
    }

    /// Map a PKCS#11 object class (`CKO_*`) to the corresponding [`ObjectType`].
    /// Returns `None` for classes the store does not track by type.
    const fn class_to_object_type(search_class: CK_OBJECT_CLASS) -> Option<ObjectType> {
        match search_class {
            pkcs11_sys::CKO_PRIVATE_KEY => Some(ObjectType::PrivateKey),
            pkcs11_sys::CKO_PUBLIC_KEY => Some(ObjectType::PublicKey),
            pkcs11_sys::CKO_SECRET_KEY => Some(ObjectType::SymmetricKey),
            pkcs11_sys::CKO_CERTIFICATE => Some(ObjectType::Certificate),
            pkcs11_sys::CKO_DATA => Some(ObjectType::DataObject),
            _ => None,
        }
    }

    /// Resolve an object requested by `CKA_ID`, enforcing that the returned
    /// object's class matches `search_class`.
    ///
    /// Resolution order:
    /// 1. Exact `id` match whose class equals `search_class`.
    /// 2. For `CKO_PRIVATE_KEY` only: the caller may have passed the paired
    ///    *public* key's `CKA_ID` (`<base>_pk`) — as OpenSSH does — so the
    ///    [`PUBLIC_KEY_ID_SUFFIX`] is stripped and the private key is looked up
    ///    under the base UID (`<base>`).
    ///
    /// Returns `None` when no object of the requested class matches. The class
    /// check prevents a class-scoped search from ever returning a wrong-class
    /// object (e.g. a public key for a `CKO_PRIVATE_KEY` search).
    fn resolve_object_by_class(
        store: &ObjectsStore,
        id: &str,
        search_class: CK_OBJECT_CLASS,
    ) -> Option<(Arc<Object>, CK_OBJECT_HANDLE)> {
        let expected_type = Self::class_to_object_type(search_class)?;
        // 1. Exact id match with the correct class.
        if let Some((object, handle)) = store.get_using_id(id) {
            if object.object_type() == expected_type {
                return Some((object, handle));
            }
        }
        // 2. Private-key search using the paired public key's CKA_ID.
        if expected_type == ObjectType::PrivateKey {
            if let Some(base) = id.strip_suffix(PUBLIC_KEY_ID_SUFFIX) {
                if let Some((object, handle)) = store.get_using_id(base) {
                    if object.object_type() == ObjectType::PrivateKey {
                        return Some((object, handle));
                    }
                }
            }
        }
        None
    }

    /// Sign the provided data, or stored payload if data is not provided.
    pub(crate) unsafe fn sign(
        &mut self,
        data: Option<&[u8]>,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) -> ModuleResult<()> {
        let Some(sign_ctx) = self.sign_ctx.as_mut() else {
            return Err(ModuleError::OperationNotInitialized(0));
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(ModuleError::OperationNotInitialized(0))?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                return Err(ModuleError::BadArguments(format!(
                    "signature failed: {e:?}"
                )));
            }
        };
        if !pSignature.is_null() {
            // TODO(bweeks): This will cause a second sign call when this function is
            // called again with an appropriately-sized buffer. Do we really need to
            // sign twice for ECDSA? Consider storing the signature in the ctx for the next
            // call.
            if (unsafe { usize::try_from(*pulSignatureLen)? }) < signature.len() {
                return Err(ModuleError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pSignature, signature.len()) }
                .copy_from_slice(&signature);
            self.sign_ctx = None;
        }
        unsafe {
            *pulSignatureLen = signature.len().try_into()?;
        }
        Ok(())
    }

    pub(crate) fn decrypt(
        &mut self,
        ciphertext: Vec<u8>,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    ) -> ModuleResult<()> {
        let decrypt_ctx = self
            .decrypt_ctx
            .as_ref()
            .ok_or_else(|| ModuleError::OperationNotInitialized(0))?;
        let cleartext = backend()?.decrypt(decrypt_ctx, ciphertext)?;
        unsafe {
            if pData.is_null() {
                *pulDataLen = cleartext.len() as CK_ULONG;
            } else {
                if (usize::try_from(*pulDataLen)?) < cleartext.len() {
                    return Err(ModuleError::BufferTooSmall);
                }
                std::slice::from_raw_parts_mut(pData, cleartext.len()).copy_from_slice(&cleartext);
                *pulDataLen = cleartext.len() as CK_ULONG;
                self.decrypt_ctx = None;
            }
        }
        Ok(())
    }

    pub(crate) fn encrypt(
        &mut self,
        cleartext: Vec<u8>,
        pEncryptedData: CK_BYTE_PTR,
        pulEncryptedDataLen: CK_ULONG_PTR,
    ) -> ModuleResult<()> {
        let encrypt_ctx = self
            .encrypt_ctx
            .as_ref()
            .ok_or_else(|| ModuleError::OperationNotInitialized(0))?;
        let ciphertext = backend()?.encrypt(encrypt_ctx, cleartext)?;
        unsafe {
            *pulEncryptedDataLen = ciphertext.len() as CK_ULONG;
            if !pEncryptedData.is_null() {
                if (usize::try_from(*pulEncryptedDataLen)?) < ciphertext.len() {
                    return Err(ModuleError::BufferTooSmall);
                }
                std::slice::from_raw_parts_mut(pEncryptedData, ciphertext.len())
                    .copy_from_slice(&ciphertext);
                self.encrypt_ctx = None;
            }
        }
        Ok(())
    }

    pub(crate) fn generate_key(
        mechanism: Mechanism,
        attributes: &Attributes,
    ) -> ModuleResult<CK_OBJECT_HANDLE> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "generate_key: empty attributes".to_owned(),
            ));
        }

        debug!(
            "generate_key: generating key with mechanism: {:?} and attributes: {:?}",
            mechanism, attributes
        );

        let mut objects_store = OBJECTS_STORE.write()?;

        let key_length = attributes.get_value_len()?;
        let sensitive = attributes.get_sensitive()?;
        let label = attributes.get_label()?;

        let object = backend()?.generate_key(
            KeyAlgorithm::try_from(mechanism)?,
            key_length.try_into()?,
            sensitive,
            Some(&label),
        )?;
        let handle = objects_store.upsert(Arc::new(Object::SymmetricKey(object)));

        debug!("generate_key: generated key with handle: {handle}");
        Ok(handle)
    }

    pub(crate) fn create_object(attributes: &Attributes) -> ModuleResult<CK_OBJECT_HANDLE> {
        if attributes.is_empty() {
            return Err(ModuleError::BadArguments(
                "create_object: empty attributes".to_owned(),
            ));
        }

        debug!("create_object: attributes: {attributes:?}");

        let mut objects_store = OBJECTS_STORE.write()?;
        let class = attributes.get_class()?;
        trace!("create_object: class: {class:?}");
        let label = attributes.get_label()?;
        let value = attributes.get_value()?;
        let object = match class {
            pkcs11_sys::CKO_DATA => backend()?.create_object(&label, &value)?,
            o => {
                trace!("create_object: Object not supported: {o}");
                return Err(ModuleError::Todo(format!("Object not supported: {o}")));
            }
        };

        let handle = objects_store.upsert(Arc::new(Object::DataObject(object)));

        debug!("create_object: created object with handle: {handle}");
        Ok(handle)
    }

    pub(crate) fn destroy_object(handle: CK_OBJECT_HANDLE) -> ModuleResult<()> {
        debug!("destroy_object: handle: {handle}");

        let mut objects_store = OBJECTS_STORE.write()?;
        match objects_store.get_using_handle(handle) {
            Some(object) => {
                backend()?.revoke_object(&object.remote_id())?;
                backend()?.destroy_object(&object.remote_id())?;
            }
            None => return Err(ModuleError::ObjectHandleInvalid(handle)),
        }

        objects_store.remove_by_handle(handle)?;
        debug!("destroy_object: handle: {handle}");

        Ok(())
    }
}

fn ignore_sessions() -> bool {
    std::env::var("COSMIAN_PKCS11_IGNORE_SESSIONS")
        .unwrap_or_else(|_| "false".to_owned())
        .to_lowercase()
        == "true"
}

#[expect(clippy::expect_used)]
pub(crate) fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
    if ignore_sessions() {
        {
            let mut session_map = SESSIONS.lock().expect("failed locking the sessions map");
            if session_map.is_empty() {
                session_map.insert(
                    0,
                    Session {
                        flags,
                        ..Default::default()
                    },
                );
            }
        }
        0
    } else {
        let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::SeqCst);
        SESSIONS
            .lock()
            .expect("failed locking the sessions map")
            .insert(
                handle,
                Session {
                    flags,
                    ..Default::default()
                },
            );
        handle
    }
}

pub(crate) fn exists(handle: CK_SESSION_HANDLE) -> ModuleResult<bool> {
    Ok(SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .contains_key(&handle))
}

pub(crate) fn flags(handle: CK_SESSION_HANDLE) -> ModuleResult<CK_FLAGS> {
    Ok(SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .get(&handle)
        .ok_or_else(|| ModuleError::SessionHandleInvalid(handle))?
        .flags)
}

pub(crate) fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> ModuleResult<()>
where
    F: FnOnce(&mut Session) -> ModuleResult<()>,
{
    let mut session_map = SESSIONS.lock().context("failed locking the sessions map")?;
    let session = session_map
        .get_mut(&h)
        .ok_or(ModuleError::SessionHandleInvalid(h))?;
    debug!("session: {h} found");
    callback(session)
}

pub(crate) fn close(handle: CK_SESSION_HANDLE) -> ModuleResult<bool> {
    if !ignore_sessions() {
        return Ok(SESSIONS
            .lock()
            .context("failed locking the sessions map")?
            .remove(&handle)
            .is_some());
    }
    Ok(true)
}

pub(crate) fn close_all() -> ModuleResult<()> {
    SESSIONS
        .lock()
        .context("failed locking the sessions map")?
        .clear();
    Ok(())
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_oracle_tde_security_to_mk() {
        // Test valid conversion
        let input = "ORACLE.SECURITY.KM.ENCRYPTION.\
                     30363946333744303931413733443446313342463243453932314542324346303830";
        let expected = "ORACLE.TDE.HSM.MK.069F37D091A73D4F13BF2CE921EB2CF080";
        assert_eq!(
            Session::map_oracle_tde_security_to_mk(input).unwrap(),
            expected
        );

        // Test non-oracle label
        let input = "some.other.label";
        assert_eq!(
            Session::map_oracle_tde_security_to_mk(input).unwrap(),
            input
        );

        // Test empty label
        let input = "";
        assert_eq!(
            Session::map_oracle_tde_security_to_mk(input).unwrap(),
            input
        );

        // Test empty key ID
        let input = "ORACLE.SECURITY.KM.ENCRYPTION.";
        let _ = Session::map_oracle_tde_security_to_mk(input).is_err();

        // Test invalid hex after prefix
        let input = "ORACLE.SECURITY.KM.ENCRYPTION.INVALID_HEX";
        Session::map_oracle_tde_security_to_mk(input).unwrap_err();

        // Test partial prefix
        let input = "ORACLE.SECURITY.KM";
        assert_eq!(
            Session::map_oracle_tde_security_to_mk(input).unwrap(),
            input
        );

        // Test case with odd length hex
        let input = "ORACLE.SECURITY.KM.ENCRYPTION.\
                     30363946333744303931413733443446313342463243453932314542324346303";
        Session::map_oracle_tde_security_to_mk(input).unwrap_err();
    }
}
