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
use pkcs11_sys::{CK_BYTE_PTR, CK_FLAGS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG_PTR};

use crate::{
    object_store::ObjectStore,
    traits::{PrivateKey, SignatureAlgorithm},
    Error, Result,
};

// "Valid session handles in Cryptoki always have nonzero values."
#[cfg(not(target_os = "windows"))]
static NEXT_SESSION_HANDLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
#[cfg(target_os = "windows")]
static NEXT_SESSION_HANDLE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

type SessionMap = HashMap<CK_SESSION_HANDLE, Session>;

static SESSIONS: Lazy<sync::Mutex<SessionMap>> = Lazy::new(Default::default);
pub static OBJECT_STORE: Lazy<sync::Mutex<ObjectStore>> = Lazy::new(Default::default);

#[derive(Debug)]
pub struct FindContext {
    pub objects: Vec<CK_OBJECT_HANDLE>,
}

#[derive(Debug)]
pub struct SignContext {
    pub algorithm: SignatureAlgorithm,
    pub private_key: Arc<dyn PrivateKey>,
    /// Payload stored for multipart C_SignUpdate operations.
    pub payload: Option<Vec<u8>>,
}

impl Session {
    /// Sign the provided data, or stored payload if data is not provided.
    pub unsafe fn sign(
        &mut self,
        data: Option<&[u8]>,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) -> Result {
        let sign_ctx = match self.sign_ctx.as_mut() {
            Some(sign_ctx) => sign_ctx,
            None => return Err(Error::OperationNotInitialized),
        };
        let data = data
            .or(sign_ctx.payload.as_deref())
            .ok_or(Error::OperationNotInitialized)?;
        let signature = match sign_ctx.private_key.sign(&sign_ctx.algorithm, data) {
            Ok(sig) => sig,
            Err(e) => {
                tracing::error!("signature failed: {e:?}");
                return Err(Error::ArgumentsBad);
            }
        };
        if !pSignature.is_null() {
            // TODO(bweeks): This will cause a second sign call when this function is
            // called again with an appropriately-sized buffer. Do we really need to
            // sign twice for ECDSA? Consider storing the signature in the ctx for the next
            // call.
            if (unsafe { *pulSignatureLen } as usize) < signature.len() {
                return Err(Error::BufferTooSmall);
            }
            unsafe { std::slice::from_raw_parts_mut(pSignature, signature.len()) }
                .copy_from_slice(&signature);
            self.sign_ctx = None;
        }
        unsafe { *pulSignatureLen = signature.len().try_into().unwrap() };
        Ok(())
    }
}

#[derive(Default)]
pub struct Session {
    flags: CK_FLAGS,
    pub find_ctx: Option<FindContext>,
    pub sign_ctx: Option<SignContext>,
}

pub fn create(flags: CK_FLAGS) -> CK_SESSION_HANDLE {
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

pub fn exists(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().contains_key(&handle)
}

pub fn flags(handle: CK_SESSION_HANDLE) -> CK_FLAGS {
    SESSIONS.lock().unwrap().get(&handle).unwrap().flags
}

pub fn session<F>(h: CK_SESSION_HANDLE, callback: F) -> crate::Result
where
    F: FnOnce(&mut Session) -> crate::Result,
{
    let mut session_map = SESSIONS.lock().unwrap();
    let session = &mut session_map.get_mut(&h).unwrap();
    callback(session)
}

pub fn close(handle: CK_SESSION_HANDLE) -> bool {
    SESSIONS.lock().unwrap().remove(&handle).is_some()
}

pub fn close_all() {
    SESSIONS.lock().unwrap().clear()
}
