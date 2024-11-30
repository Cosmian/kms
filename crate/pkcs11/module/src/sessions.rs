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

use std::{
    collections::HashMap,
    sync::{self, atomic::Ordering, Arc},
};

use log::trace;
use once_cell::sync::Lazy;
use pkcs11_sys::{
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
};
use tracing::{debug, error};

use crate::{
    core::{
        attribute::Attributes,
        object::{Object, ObjectType},
    },
    objects_store::OBJECTS_STORE,
    traits::{backend, EncryptionAlgorithm, SearchOptions},
};
use crate::{
    // object_store::ObjectStore,
    traits::{PrivateKey, SignatureAlgorithm},
    MError,
    MResult,
};

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU64 = sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: sync::atomic::AtomicU32 = sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

static SESSIONS: Lazy<sync::Mutex<SessionMap>> = Lazy::new(Default::default);

#[derive(Debug)]
pub(crate) struct SignContext {
    pub algorithm: SignatureAlgorithm,
    pub private_key: Arc<dyn PrivateKey>,
    /// Payload stored for multipart `C_SignUpdate` operations.
    pub payload: Option<Vec<u8>>,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DecryptContext {
    pub remote_object_id: String,
    pub algorithm: EncryptionAlgorithm,
    /// Ciphertext stored for multipart `C_DecryptUpdate` operations.
    pub ciphertext: Option<Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct Session {
    flags: CK_FLAGS,
    /// The objects found by C_FindObjectsInit
    /// and that have not yet been read by C_FindObjects
    pub find_objects_ctx: Vec<CK_OBJECT_HANDLE>,
    pub sign_ctx: Option<SignContext>,
    pub decrypt_ctx: Option<DecryptContext>,
}

impl Session {
    pub(crate) fn update_find_objects_context(
        &mut self,
        object: Arc<Object>,
    ) -> MResult<CK_OBJECT_HANDLE> {
        let mut objects_store = OBJECTS_STORE.write().map_err(|e| {
            error!("insert_in_find_context: failed to lock objects store: {e}");
            MError::ArgumentsBad
        })?;
        let handle = objects_store.upsert(object)?;
        trace!("inserted object with id");
        self.find_objects_ctx.push(handle);
        Ok(handle)
    }

    pub(crate) fn load_find_context(&mut self, template: Attributes) -> MResult<()> {
        if template.is_empty() {
            error!("load_find_context: empty template");
            return Err(MError::ArgumentsBad);
        }
        let search_class = template.get_class()?;
        let search_options = SearchOptions::try_from(&template)?;
        debug!(
            "load_find_context: loading for class: {:?} and options: {:?}, from template {:?}",
            search_class, search_options, template
        );
        match search_options {
            SearchOptions::All => {
                self.clear_find_objects_ctx();
                match search_class {
                    pkcs11_sys::CKO_CERTIFICATE => {
                        template.ensure_X509_or_none()?;
                        let res = backend()
                            .find_all_certificates()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::Certificate(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context: added {} certificates with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => {
                        let res = backend()
                            .find_all_public_keys()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::PublicKey(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context: added {} public keys with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_PRIVATE_KEY => {
                        let res = backend()
                            .find_all_private_keys()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::PrivateKey(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context: added {} private keys with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    pkcs11_sys::CKO_DATA => {
                        let res = backend()
                            .find_all_data_objects()?
                            .into_iter()
                            .map(|c| {
                                self.update_find_objects_context(Arc::new(Object::DataObject(c)))
                            })
                            .collect::<MResult<Vec<_>>>()?;
                        debug!(
                            "load_find_context: added {} data objects with handles: {:?}",
                            res.len(),
                            res
                        );
                    }
                    o => return Err(MError::Todo(format!("Object not supported: {o}"))),
                }
            }
            SearchOptions::Id(cka_id) => match search_class {
                pkcs11_sys::CKO_CERTIFICATE => {
                    // Find certificates which have this CKA_ID as private key ID
                    let find_ctx = OBJECTS_STORE.read().map_err(|e| {
                        error!("load_find_context: failed to lock find context: {e}");
                        MError::ArgumentsBad
                    })?;
                    let certificates = find_ctx.get_using_type(ObjectType::Certificate);
                    for (object, handle) in certificates {
                        match &*object {
                            Object::Certificate(c) => {
                                if c.private_key_id() == cka_id {
                                    debug!(
                                        "load_find_context: search by id: {} -> handle: {} -> \
                                         certificate: {}:{}",
                                        cka_id,
                                        handle,
                                        object.name(),
                                        object.remote_id()
                                    );
                                    self.clear_find_objects_ctx();
                                    self.add_to_find_objects_ctx(handle);
                                }
                            }
                            //TODO may be we should treat Public Keys the same as Certificates
                            o => {
                                return Err(MError::Todo(format!(
                                    "This should not happen, returning: {:?}",
                                    o.object_type()
                                )))
                            }
                        }
                    }
                }
                _ => {
                    let find_ctx = OBJECTS_STORE.read().map_err(|e| {
                        error!("load_find_context: failed to lock find context: {e}");
                        MError::ArgumentsBad
                    })?;
                    let (object, handle) = find_ctx
                        .get_using_id(&cka_id)
                        .ok_or_else(|| MError::ArgumentsBad)?;
                    debug!(
                        "load_find_context: search by id: {} -> handle: {} -> object: {}:{}",
                        cka_id,
                        handle,
                        object.name(),
                        object.remote_id()
                    );
                    self.clear_find_objects_ctx();
                    self.add_to_find_objects_ctx(handle);
                }
            },
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
    ) -> MResult<()> {
        let sign_ctx = match self.sign_ctx.as_mut() {
            Some(sign_ctx) => sign_ctx,
            None => return Err(MError::OperationNotInitialized(0)),
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(MError::OperationNotInitialized(0))?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                error!("signature failed: {e:?}");
                return Err(MError::ArgumentsBad);
            }
        };
        if !pSignature.is_null() {
            // TODO(bweeks): This will cause a second sign call when this function is
            // called again with an appropriately-sized buffer. Do we really need to
            // sign twice for ECDSA? Consider storing the signature in the ctx for the next
            // call.
            if (unsafe { *pulSignatureLen } as usize) < signature.len() {
                return Err(MError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pSignature, signature.len()) }
                .copy_from_slice(&signature);
            self.sign_ctx = None;
        }
        unsafe { *pulSignatureLen = signature.len().try_into().unwrap() };
        Ok(())
    }

    pub(crate) unsafe fn decrypt(
        &mut self,
        ciphertext: Vec<u8>,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    ) -> MResult<()> {
        let decrypt_ctx = match self.decrypt_ctx.as_mut() {
            Some(decrypt_ctx) => decrypt_ctx,
            None => return Err(MError::OperationNotInitialized(0)),
        };
        let cleartext = backend().decrypt(
            decrypt_ctx.remote_object_id.clone(),
            decrypt_ctx.algorithm,
            ciphertext,
        )?;
        if !pData.is_null() {
            if (unsafe { *pulDataLen } as usize) < cleartext.len() {
                return Err(MError::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pData, cleartext.len()) }
                .copy_from_slice(&cleartext);
            unsafe { *pulDataLen = cleartext.len() as CK_ULONG };
            self.decrypt_ctx = None;
        }
        Ok(())
    }
}

fn ignore_sessions() -> bool {
    std::env::var("COSMIAN_PKCS11_IGNORE_SESSIONS")
        .unwrap_or("false".to_string())
        .to_lowercase()
        == "true"
}

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

pub(crate) fn exists(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .contains_key(&handle)
}

pub(crate) fn flags(handle: CK_SESSION_HANDLE) -> CK_FLAGS {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .get(&handle)
        .unwrap()
        .flags
}

pub(crate) fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> MResult<()>
where
    F: FnOnce(&mut Session) -> MResult<()>,
{
    let mut session_map = SESSIONS.lock().expect("failed locking the sessions map");
    let session = &mut session_map
        .get_mut(&h)
        .ok_or(MError::SessionHandleInvalid(h))?;
    debug!("session: {h} found");
    callback(session)
}

pub(crate) fn close(handle: CK_SESSION_HANDLE) -> bool {
    if !ignore_sessions() {
        return SESSIONS
            .lock()
            .expect("failed locking the sessions map")
            .remove(&handle)
            .is_some();
    }
    true
}

pub(crate) fn close_all() {
    SESSIONS
        .lock()
        .expect("failed locking the sessions map")
        .clear();
}
