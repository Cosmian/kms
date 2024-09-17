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

use once_cell::sync::Lazy;
use pkcs11_sys::{
    CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG, CK_ULONG_PTR,
};
use tracing::{debug, error, info};

use crate::{
    core::{attribute::Attributes, object::Object},
    traits::{backend, EncryptionAlgorithm, RemoteObjectId, SearchOptions},
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
// pub static OBJECT_STORE: Lazy<sync::Mutex<ObjectStore>> = Lazy::new(Default::default);

#[derive(Debug)]
pub(crate) struct FindContext {
    /// The PKCS#11 objects manipulated by this context.
    pub objects: Vec<Object>,
    /// The indexes that have not yet been read by `C_FindObjects`
    pub unread_indexes: Vec<CK_OBJECT_HANDLE>,
}

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
    pub remote_object: Arc<dyn RemoteObjectId>,
    pub algorithm: EncryptionAlgorithm,
    /// Ciphertext stored for multipart `C_DecryptUpdate` operations.
    pub ciphertext: Option<Vec<u8>>,
}

impl Session {
    /// Sign the provided data, or stored payload if data is not provided.
    pub(crate) unsafe fn sign(
        &mut self,
        data: Option<&[u8]>,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) -> MResult<()> {
        let Some(sign_ctx) = self.sign_ctx.as_mut() else {
            return Err(MError::OperationNotInitialized)
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(MError::OperationNotInitialized)?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("signature failed: {e:?}");
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
        let Some(decrypt_ctx) = self.decrypt_ctx.as_mut() else {
            return Err(MError::OperationNotInitialized)
        };
        let cleartext = backend().decrypt(
            decrypt_ctx.remote_object.clone(),
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

#[derive(Default, Debug)]
pub(crate) struct Session {
    flags: CK_FLAGS,
    pub find_ctx: Option<FindContext>,
    pub sign_ctx: Option<SignContext>,
    pub decrypt_ctx: Option<DecryptContext>,
}

impl Session {
    pub(crate) fn load_find_context(&mut self, template: Attributes) -> MResult<()> {
        if template.is_empty() {
            error!("load_find_context: empty template");
            return Err(MError::ArgumentsBad);
        }
        let search_class = template.get_class()?;
        let search_options = SearchOptions::try_from(&template)?;
        debug!(
            "load_find_context: loading for class: {:?} and options: {:?} from template {:?}",
            search_class, search_options, template
        );
        match search_options {
            SearchOptions::All => {
                let objects: Vec<Object> = match search_class {
                    pkcs11_sys::CKO_CERTIFICATE => {
                        template.ensure_X509_or_none()?;
                        backend()
                            .find_all_certificates()?
                            .into_iter()
                            .map(Object::Certificate)
                            .collect()
                    }
                    pkcs11_sys::CKO_PUBLIC_KEY => backend()
                        .find_all_public_keys()?
                        .into_iter()
                        .map(Object::PublicKey)
                        .collect(),
                    pkcs11_sys::CKO_PRIVATE_KEY => backend()
                        .find_all_private_keys()?
                        .into_iter()
                        .map(Object::RemoteObjectId)
                        .collect(),
                    pkcs11_sys::CKO_DATA => backend()
                        .find_all_data_objects()?
                        .into_iter()
                        .map(Object::DataObject)
                        .collect(),
                    o => return Err(MError::Todo(format!("Object not supported: {o}"))),
                };
                info!(
                    "load_find_context: found {} objects for search class {}",
                    objects.len(),
                    search_class
                );
                let indexes = objects
                    .iter()
                    .enumerate()
                    .map(|(i, _)| i as CK_OBJECT_HANDLE)
                    .collect();
                self.find_ctx = Some(FindContext {
                    objects,
                    unread_indexes: indexes,
                });
            }
            SearchOptions::Label(_) => {
                todo!("load_find_context: search by label")
            }
            SearchOptions::Id(_) => {
                todo!("load_find_context: search by id")
            }
        }

        Ok(())
    }
}

pub(crate) fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
    let handle = NEXT_SESSION_HANDLE.fetch_add(1, Ordering::SeqCst);
    SESSIONS.lock().unwrap().insert(
        handle,
        Session {
            flags,
            ..Default::default()
        },
    );
    handle
}

pub(crate) fn exists(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().contains_key(&handle)
}

pub(crate) fn flags(handle: CK_SESSION_HANDLE) -> CK_FLAGS {
    SESSIONS.lock().unwrap().get(&handle).unwrap().flags
}

pub(crate) fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> MResult<()>
where
    F: FnOnce(&mut Session) -> MResult<()>,
{
    let mut session_map = SESSIONS.lock().unwrap();
    let session = &mut session_map.get_mut(&h).unwrap();
    callback(session)
}

pub(crate) fn close(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().remove(&handle).is_some()
}

pub(crate) fn close_all() {
    SESSIONS.lock().unwrap().clear();
}
