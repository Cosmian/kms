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
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG,
    CK_ULONG_PTR,
};

use crate::{
    MResultHelper, ModuleError, ModuleResult,
    core::{
        attribute::Attributes,
        mechanism::Mechanism,
        object::{Object, ObjectType},
    },
    objects_store::OBJECTS_STORE,
    traits::{DecryptContext, EncryptContext, KeyAlgorithm, SearchOptions, SignContext, backend},
};

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
        // Find all objects
        for object in backend().find_all_objects()? {
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
                        backend()
                            .find_all_certificates()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::Certificate(c)))
                            })
                            .collect::<ModuleResult<Vec<_>>>()?
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => backend()
                        .find_all_public_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PublicKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_PRIVATE_KEY => backend()
                        .find_all_private_keys()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::PrivateKey(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_SECRET_KEY => backend()
                        .find_all_symmetric_keys()?
                        .into_iter()
                        .map(|c| {
                            self.update_find_objects_context(Arc::new(Object::SymmetricKey(c)))
                        })
                        .collect::<ModuleResult<Vec<_>>>()?,
                    pkcs11_sys::CKO_DATA => backend()
                        .find_all_data_objects()?
                        .into_iter()
                        .map(|c| self.update_find_objects_context(Arc::new(Object::DataObject(c))))
                        .collect::<ModuleResult<Vec<_>>>()?,
                    o => return Err(ModuleError::Todo(format!("Object not supported: {o}"))),
                };
                debug!(
                    "load_find_context_by_class: added {} objects with handles: {:?}",
                    res.len(),
                    res
                );
            }

            SearchOptions::Id(cka_id) => {
                if search_class == pkcs11_sys::CKO_CERTIFICATE {
                    let id = String::from_utf8(cka_id)?;
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
                    let id = String::from_utf8(cka_id)?;

                    let find_ctx = OBJECTS_STORE.read()?;
                    let (object, handle) = find_ctx.get_using_id(&id).ok_or_else(|| {
                        ModuleError::BadArguments(format!(
                            "load_find_context_by_class: id {id} not found in store"
                        ))
                    })?;
                    debug!(
                        "load_find_context_by_class: search by id: {} -> handle: {} -> object: \
                         {}:{}",
                        id,
                        handle,
                        object.name(),
                        object.remote_id()
                    );
                    self.clear_find_objects_ctx();
                    self.add_to_find_objects_ctx(handle);
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
        let cleartext = backend().decrypt(decrypt_ctx, ciphertext)?;
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
        let ciphertext = backend().encrypt(encrypt_ctx, cleartext)?;
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

        let object = backend().generate_key(
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
            pkcs11_sys::CKO_DATA => backend().create_object(&label, &value)?,
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
                backend().revoke_object(&object.remote_id())?;
                backend().destroy_object(&object.remote_id())?;
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
