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

#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![deny(unsafe_op_in_unsafe_fn)]
//avoid renaming all unused parameters with _ in all unused functions
#![allow(unused_variables)]

use core::{
    attribute::{Attribute, Attributes},
    mechanism::{parse_mechanism, SUPPORTED_SIGNATURE_MECHANISMS},
    object::Object,
};
use std::{
    cmp, slice, sync,
    sync::atomic::{AtomicBool, Ordering},
};

use log::debug;
use once_cell::sync::Lazy;
use pkcs11_sys::{
    CKF_HW_SLOT, CKF_PROTECTED_AUTHENTICATION_PATH, CKF_RNG, CKF_RW_SESSION, CKF_SERIAL_SESSION,
    CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT, CKF_USER_PIN_INITIALIZED,
    CKF_WRITE_PROTECTED, CKS_RO_USER_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CK_ATTRIBUTE_PTR, CK_BBOOL,
    CK_BYTE_PTR, CK_C_INITIALIZE_ARGS_PTR, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_INFO_PTR,
    CK_MECHANISM_INFO, CK_MECHANISM_INFO_PTR, CK_MECHANISM_PTR, CK_MECHANISM_TYPE,
    CK_MECHANISM_TYPE_PTR, CK_NOTIFY, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR, CK_SESSION_HANDLE,
    CK_SESSION_HANDLE_PTR, CK_SESSION_INFO, CK_SESSION_INFO_PTR, CK_SLOT_ID, CK_SLOT_ID_PTR,
    CK_SLOT_INFO, CK_SLOT_INFO_PTR, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR, CK_ULONG, CK_ULONG_PTR,
    CK_UNAVAILABLE_INFORMATION, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION, CK_VOID_PTR,
    CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR,
};
pub use pkcs11_sys::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV};
use rand::RngCore;
use tracing::{info, trace};

use crate::{sessions::SignContext, traits::backend};

pub mod core;
mod error;

pub use error::{MError, MResult};

use crate::{
    core::attribute::AttributeType,
    sessions::{DecryptContext, FindContext},
};

static FIND_CONTEXT: Lazy<sync::RwLock<FindContext>> = Lazy::new(Default::default);

mod sessions;
#[cfg(test)]
mod tests;
pub mod traits;

const SLOT_DESCRIPTION: &[u8; 64] =
    b"Platform Cryptography Support                                   ";
const SLOT_ID: CK_SLOT_ID = 1;

static INITIALIZED: AtomicBool = AtomicBool::new(false);

fn result_to_rv<F>(name: &str, f: F) -> CK_RV
where
    F: FnOnce() -> MResult<()>,
{
    match f() {
        Ok(()) => CKR_OK,
        Err(e) => {
            tracing::error!("{}: {}", name, e);
            e.into()
        }
    }
}

#[macro_export]
macro_rules! cryptoki_fn {
    (fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument(level = tracing::Level::TRACE, ret)]
        #[no_mangle]
        pub extern "C" fn $name($($arg: $type),*) -> CK_RV {
            result_to_rv(stringify!($name), || $body)
        }
    };
    (unsafe fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument(level = tracing::Level::TRACE, ret)]
        #[no_mangle]
        pub unsafe extern "C" fn $name($($arg: $type),*) -> CK_RV {
            result_to_rv(stringify!($name), || $body)
        }
    };
}

macro_rules! cryptoki_fn_not_supported {
    ($name:ident, $($arg:ident: $type:ty),*) => {
        cryptoki_fn!(fn $name($($arg: $type),*) {Err(MError::FunctionNotSupported)});
    };
}

#[macro_export]
macro_rules! not_null {
    ($ptr:expr) => {
        if $ptr.is_null() {
            return Err(MError::ArgumentsBad);
        }
    };
}

macro_rules! initialized {
    () => {
        if INITIALIZED.load(Ordering::SeqCst) == false {
            return Err(MError::CryptokiNotInitialized);
        }
    };
}

macro_rules! valid_session {
    ($handle:expr) => {
        if !sessions::exists($handle) {
            return Err(MError::SessionHandleInvalid($handle));
        }
    };
}

macro_rules! valid_slot {
    ($id:expr) => {
        if $id != SLOT_ID {
            return Err(MError::SlotIdInvalid($id));
        }
    };
}

pub static mut FUNC_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    // In this structure 'version' is the cryptoki specification version number. The major and minor
    // versions must be set to 0x02 and 0x28 indicating a version 2.40 compatible structure.
    version: CK_VERSION { major: 2, minor: 4 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: None,
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

cryptoki_fn!(
    fn C_Initialize(pInitArgs: CK_VOID_PTR) {
        if !pInitArgs.is_null() {
            let args = unsafe { *(pInitArgs as CK_C_INITIALIZE_ARGS_PTR) };
            if !args.pReserved.is_null() {
                return Err(MError::ArgumentsBad);
            }
        }
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(MError::CryptokiAlreadyInitialized);
        }
        Ok(())
    }
);

cryptoki_fn!(
    fn C_Finalize(pReserved: CK_VOID_PTR) {
        initialized!();
        if !pReserved.is_null() {
            return Err(MError::ArgumentsBad);
        }
        INITIALIZED.store(false, Ordering::SeqCst);
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetInfo(pInfo: CK_INFO_PTR) {
        initialized!();
        not_null!(pInfo);
        let backend = backend();
        let info = CK_INFO {
            cryptokiVersion: CK_VERSION {
                major: CRYPTOKI_VERSION_MAJOR,
                minor: CRYPTOKI_VERSION_MINOR,
            },
            manufacturerID: backend.token_manufacturer_id(),
            flags: 0,
            libraryDescription: backend.library_description(),
            libraryVersion: CK_VERSION {
                major: backend.library_version().major,
                minor: backend.library_version().minor,
            },
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotList(
        _tokenPresent: CK_BBOOL,
        pSlotList: CK_SLOT_ID_PTR,
        pulCount: CK_ULONG_PTR,
    ) {
        initialized!();
        not_null!(pulCount);
        if !pSlotList.is_null() {
            if unsafe { *pulCount } < 1 {
                return Err(MError::BufferTooSmall);
            }
            // TODO: this should be an array.
            unsafe { *pSlotList = SLOT_ID };
        }
        unsafe { *pulCount = 1 };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);
        let backend = backend();
        let info = CK_SLOT_INFO {
            slotDescription: *SLOT_DESCRIPTION,
            manufacturerID: backend.token_manufacturer_id(),
            flags: CKF_TOKEN_PRESENT,
            hardwareVersion: CK_VERSION {
                major: backend.library_version().major,
                minor: backend.library_version().minor,
            },
            firmwareVersion: CK_VERSION {
                major: backend.library_version().major,
                minor: backend.library_version().minor,
            },
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);

        let backend = backend();

        let info = CK_TOKEN_INFO {
            label: backend.token_label(),
            manufacturerID: backend.token_manufacturer_id(),
            model: backend.token_model(),
            serialNumber: backend.token_serial_number(),
            flags: CKF_TOKEN_INITIALIZED
                | CKF_PROTECTED_AUTHENTICATION_PATH
                | CKF_WRITE_PROTECTED
                | CKF_USER_PIN_INITIALIZED
                | CKF_RNG
                | CKF_HW_SLOT, /* systemd-cryptenroll() requires this to be a hardware slot to
                                * be detected by auto */
            ulMaxSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulMaxRwSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulRwSessionCount: CK_UNAVAILABLE_INFORMATION,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            // TODO: populate all fields.
            ..Default::default()
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetMechanismList(
        slotID: CK_SLOT_ID,
        pMechanismList: CK_MECHANISM_TYPE_PTR,
        pulCount: CK_ULONG_PTR,
    ) {
        initialized!();
        not_null!(pulCount);
        valid_slot!(slotID);
        if !pMechanismList.is_null() {
            if (unsafe { *pulCount } as usize) < SUPPORTED_SIGNATURE_MECHANISMS.len() {
                unsafe { *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG };
                return Err(MError::BufferTooSmall);
            }
            unsafe {
                slice::from_raw_parts_mut(pMechanismList, SUPPORTED_SIGNATURE_MECHANISMS.len())
            }
            .copy_from_slice(SUPPORTED_SIGNATURE_MECHANISMS);
        }
        unsafe { *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG };
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetMechanismInfo(
        slotID: CK_SLOT_ID,
        mechType: CK_MECHANISM_TYPE,
        pInfo: CK_MECHANISM_INFO_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo);
        if !SUPPORTED_SIGNATURE_MECHANISMS.contains(&mechType) {
            return Err(MError::MechanismInvalid(mechType));
        }
        let info = CK_MECHANISM_INFO {
            flags: CKF_SIGN,
            ..Default::default()
        };
        unsafe { *pInfo = info };
        Ok(())
    }
);

cryptoki_fn!(
    fn C_InitToken(
        slotID: CK_SLOT_ID,
        _pPin: CK_UTF8CHAR_PTR,
        _ulPinLen: CK_ULONG,
        _pLabel: CK_UTF8CHAR_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        Err(MError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_InitPIN(hSession: CK_SESSION_HANDLE, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        Err(MError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_SetPIN(
        hSession: CK_SESSION_HANDLE,
        _pOldPin: CK_UTF8CHAR_PTR,
        _ulOldLen: CK_ULONG,
        _pNewPin: CK_UTF8CHAR_PTR,
        _ulNewLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        Err(MError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    unsafe fn C_OpenSession(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        _pApplication: CK_VOID_PTR,
        _Notify: CK_NOTIFY,
        phSession: CK_SESSION_HANDLE_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        not_null!(phSession);
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(MError::SessionParallelNotSupported);
        }
        unsafe { *phSession = sessions::create(flags) };
        info!(
            "C_OpenSession: slot: {:?}, flags: {:?}, session: {}",
            slotID,
            flags,
            unsafe { *phSession }
        );
        Ok(())
    }
);

cryptoki_fn!(
    fn C_CloseSession(hSession: CK_SESSION_HANDLE) {
        initialized!();
        info!("C_CloseSession: session: {:?}", hSession);
        if sessions::close(hSession) {
            return Ok(());
        }
        Err(MError::SessionHandleInvalid(hSession))
    }
);

cryptoki_fn!(
    fn C_CloseAllSessions(slotID: CK_SLOT_ID) {
        initialized!();
        valid_slot!(slotID);
        info!("C_CloseAllSessions: slot: {:?}", slotID);
        sessions::close_all();
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) {
        initialized!();
        valid_session!(hSession);
        not_null!(pInfo);
        let flags = sessions::flags(hSession);
        let state = if flags & CKF_RW_SESSION == 0 {
            CKS_RO_USER_FUNCTIONS
        } else {
            CKS_RW_USER_FUNCTIONS
        };
        let info = CK_SESSION_INFO {
            slotID: SLOT_ID,
            state,
            flags,
            ulDeviceError: 0,
        };
        unsafe { *pInfo = info };
        trace!(
            "C_GetSessionInfo: session: {:?}, slot: {:?}, state: {:?}, flags: {:?}",
            hSession,
            SLOT_ID,
            state,
            flags
        );
        Ok(())
    }
);

cryptoki_fn_not_supported!(
    C_GetOperationState,
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    pulOperationStateLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_SetOperationState,
    hSession: CK_SESSION_HANDLE,
    pOperationState: CK_BYTE_PTR,
    ulOperationStateLen: CK_ULONG,
    hEncryptionKey: CK_OBJECT_HANDLE,
    hAuthenticationKey: CK_OBJECT_HANDLE
);

cryptoki_fn!(
    fn C_Login(
        hSession: CK_SESSION_HANDLE,
        _userType: CK_USER_TYPE,
        _pPin: CK_UTF8CHAR_PTR,
        _ulPinLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        Ok(())
    }
);

cryptoki_fn!(
    fn C_Logout(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Ok(())
    }
);

cryptoki_fn_not_supported!(
    C_CreateObject,
    hSession: CK_SESSION_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phObject: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_CopyObject,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_DestroyObject,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_GetObjectSize,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pulSize: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_GetAttributeValue(
        hSession: CK_SESSION_HANDLE,
        hObject: CK_OBJECT_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
    ) {
        trace!(
            "C_GetAttributeValue: session: {:?}, object: {:?}",
            hSession,
            hObject
        );
        initialized!();
        valid_session!(hSession);
        not_null!(pTemplate);

        sessions::session(hSession, |session| -> MResult<()> {
            let find_ctx = FIND_CONTEXT
                .read()
                .map_err(|_| MError::OperationNotInitialized(hSession))?;
            let object = match find_ctx.get_using_handle(hObject) {
                Some(object) => object,
                None => {
                    return Err(MError::ObjectHandleInvalid(hObject));
                }
            };
            let template = if ulCount > 0 {
                if pTemplate.is_null() {
                    return Err(MError::ArgumentsBad);
                }
                unsafe { slice::from_raw_parts_mut(pTemplate, ulCount as usize) }
            } else {
                &mut []
            };
            for attribute in template.iter_mut() {
                let type_: AttributeType = attribute
                    .type_
                    .try_into()
                    .map_err(|_| MError::AttributeTypeInvalid(attribute.type_))?;
                info!(
                    "C_GetAttributeValue: session: {:?}, object: {:?}, type: {:?}",
                    hSession,
                    object.remote_id(),
                    type_.to_string(),
                );
                if let Some(value) = object.attribute(type_)? {
                    let value = value.as_raw_value();
                    attribute.ulValueLen = value.len() as CK_ULONG;
                    if attribute.pValue.is_null() {
                        continue;
                    }
                    if (attribute.ulValueLen as usize) < value.len() {
                        continue;
                    }
                    unsafe {
                        slice::from_raw_parts_mut(attribute.pValue.cast::<u8>(), value.len())
                    }
                    .copy_from_slice(&value);
                } else {
                    attribute.ulValueLen = CK_UNAVAILABLE_INFORMATION;
                }
            }
            Ok(())
        })
    }
);

cryptoki_fn_not_supported!(
    C_SetAttributeValue,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG
);

cryptoki_fn!(
    unsafe fn C_FindObjectsInit(
        hSession: CK_SESSION_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);

        let template: Attributes = unsafe { slice::from_raw_parts(pTemplate, ulCount as usize) }
            .iter()
            .map(|attr| (*attr).try_into())
            .collect::<MResult<Vec<Attribute>>>()?
            .into();

        sessions::session(hSession, |session| -> MResult<()> {
            info!("C_FindObjectsInit: session: {:?}, load context", hSession);
            session.load_find_context(template)
        })
    }
);

cryptoki_fn!(
    unsafe fn C_FindObjects(
        hSession: CK_SESSION_HANDLE,
        phObject: CK_OBJECT_HANDLE_PTR,
        ulMaxObjectCount: CK_ULONG,
        pulObjectCount: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(phObject);
        not_null!(pulObjectCount);
        sessions::session(hSession, |session| -> MResult<()> {
            // let find_ctx = match &mut session.find_ctx {
            //     Some(find_ctx) => find_ctx,
            //     None => {
            //         unsafe { *pulObjectCount = 0 };
            //         return Err(MError::OperationNotInitialized(hSession));
            //     }
            // };
            trace!(
                "C_FindObjects: session: {:?}, objects available: {:?}",
                hSession,
                session.unread_indexes
            );
            if session.unread_indexes.is_empty() {
                info!(
                    "C_FindObjects: session: {:?}, no more objects to return",
                    hSession
                );
                unsafe { *pulObjectCount = 0 };
                return Ok(());
            }
            let max_objects = cmp::min(session.unread_indexes.len(), ulMaxObjectCount as usize);
            let handles = session
                .unread_indexes
                .drain(0..max_objects)
                .collect::<Vec<_>>();
            info!(
                "C_FindObjects: session: {:?}, returning {} object with handles {:?}",
                hSession,
                handles.len(),
                handles
            );
            let output = unsafe { slice::from_raw_parts_mut(phObject, max_objects) };
            output.copy_from_slice(handles.as_slice());
            unsafe { *pulObjectCount = max_objects as CK_ULONG };
            Ok(())
        })
    }
);

cryptoki_fn!(
    fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        // sessions::session(hSession, |session| -> MResult<()> {
        //     // re-initialize the find context unread indexes
        //     let find_ctx = session
        //         .find_ctx
        //         .as_mut()
        //         .ok_or(MError::OperationNotInitialized(hSession))?;
        //     find_ctx.unread_indexes = find_ctx
        //         .objects
        //         .iter()
        //         .enumerate()
        //         .map(|(i, _)| i as CK_OBJECT_HANDLE)
        //         .collect();
        //     Ok(())
        // })
        Ok(())
    }
);

cryptoki_fn_not_supported!(
    C_EncryptInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_Encrypt,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pEncryptedData: CK_BYTE_PTR,
    pulEncryptedDataLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_EncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_EncryptFinal,
    hSession: CK_SESSION_HANDLE,
    pLastEncryptedPart: CK_BYTE_PTR,
    pulLastEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_DecryptInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism);
        sessions::session(hSession, |session| -> MResult<()> {
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;
            let find_ctx = FIND_CONTEXT
                .read()
                .map_err(|_| MError::OperationNotInitialized(hSession))?;
            match find_ctx.get_using_handle(hKey).as_deref() {
                Some(Object::PrivateKey(sk)) => {
                    debug!(
                        "C_DecryptInit: session: {:?}, remote_object: {:?}, mechanism: {:?}",
                        hSession,
                        &sk.remote_id(),
                        &mechanism
                    );
                    session.decrypt_ctx = Some(DecryptContext {
                        remote_object_id: sk.remote_id().to_string(),
                        algorithm: mechanism.into(),
                        ciphertext: None,
                    });
                    Ok(())
                }
                Some(_) | None => Err(MError::KeyHandleInvalid(hKey)),
            }
        })
    }
);

cryptoki_fn!(
    unsafe fn C_Decrypt(
        hSession: CK_SESSION_HANDLE,
        pEncryptedData: CK_BYTE_PTR,
        ulEncryptedDataLen: CK_ULONG,
        pData: CK_BYTE_PTR,
        pulDataLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        if ulEncryptedDataLen == 0 {
            return Err(MError::ArgumentsBad);
        }
        not_null!(pEncryptedData);
        not_null!(pData);
        not_null!(pulDataLen);
        sessions::session(hSession, |session| -> MResult<()> {
            let encrypted_data =
                unsafe { slice::from_raw_parts(pEncryptedData, ulEncryptedDataLen as usize) };
            unsafe {
                debug!(
                    "C_Decrypt: session: {:?}, encrypted_data_len: {:?}, cleartext_len: {:?}, \
                     ciphertext: {:?}",
                    hSession,
                    encrypted_data.len(),
                    *pulDataLen as usize,
                    hex::encode(encrypted_data)
                );
            }
            unsafe { session.decrypt(encrypted_data.to_vec(), pData, pulDataLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_DecryptUpdate(
        hSession: CK_SESSION_HANDLE,
        pEncryptedPart: CK_BYTE_PTR,
        ulEncryptedPartLen: CK_ULONG,
        pPart: CK_BYTE_PTR,
        pulPartLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        if ulEncryptedPartLen == 0 {
            return Err(MError::ArgumentsBad);
        }
        not_null!(pEncryptedPart);
        not_null!(pPart);
        not_null!(pulPartLen);
        Err(MError::FunctionNotSupported)
    }
);

cryptoki_fn!(
    unsafe fn C_DecryptFinal(
        hSession: CK_SESSION_HANDLE,
        pLastPart: CK_BYTE_PTR,
        pulLastPartLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pLastPart);
        not_null!(pulLastPartLen);
        Err(MError::FunctionNotSupported)
    }
);

cryptoki_fn_not_supported!(
    C_DigestInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR
);

cryptoki_fn_not_supported!(
    C_Digest,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DigestUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_DigestKey,
    hSession: CK_SESSION_HANDLE,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_DigestFinal,
    hSession: CK_SESSION_HANDLE,
    pDigest: CK_BYTE_PTR,
    pulDigestLen: CK_ULONG_PTR
);

cryptoki_fn!(
    unsafe fn C_SignInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism);
        sessions::session(hSession, |session| -> MResult<()> {
            let find_ctx = FIND_CONTEXT
                .read()
                .map_err(|_| MError::OperationNotInitialized(hSession))?;
            let object = find_ctx.get_using_handle(hKey);
            let private_key = match object.as_deref() {
                Some(Object::PrivateKey(private_key)) => private_key,
                Some(_) | None => return Err(MError::KeyHandleInvalid(hKey)),
            };
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;
            session.sign_ctx = Some(SignContext {
                algorithm: mechanism.into(),
                private_key: private_key.clone(),
                payload: None,
            });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_Sign(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pData);
        not_null!(pulSignatureLen);
        sessions::session(hSession, |session| -> MResult<()> {
            let data = unsafe { slice::from_raw_parts(pData, ulDataLen as usize) };
            unsafe { session.sign(Some(data), pSignature, pulSignatureLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pPart);
        sessions::session(hSession, |session| -> MResult<()> {
            let sign_ctx = match session.sign_ctx.as_mut() {
                None => return Err(MError::OperationNotInitialized(hSession)),
                Some(sign_ctx) => sign_ctx,
            };
            sign_ctx
                .payload
                .get_or_insert(vec![])
                .extend_from_slice(unsafe { slice::from_raw_parts(pPart, ulPartLen as usize) });
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_SignFinal(
        hSession: CK_SESSION_HANDLE,
        pSignature: CK_BYTE_PTR,
        pulSignatureLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pSignature);
        not_null!(pulSignatureLen);
        sessions::session(hSession, |session| -> MResult<()> {
            unsafe { session.sign(None, pSignature, pulSignatureLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn_not_supported!(
    C_SignRecoverInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_SignRecover,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_VerifyInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_Verify,
    hSession: CK_SESSION_HANDLE,
    pData: CK_BYTE_PTR,
    ulDataLen: CK_ULONG,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_VerifyUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_VerifyFinal,
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG
);

cryptoki_fn_not_supported!(
    C_VerifyRecoverInit,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE
);

cryptoki_fn_not_supported!(
    C_VerifyRecover,
    hSession: CK_SESSION_HANDLE,
    pSignature: CK_BYTE_PTR,
    ulSignatureLen: CK_ULONG,
    pData: CK_BYTE_PTR,
    pulDataLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DigestEncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptDigestUpdate,
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_SignEncryptUpdate,
    hSession: CK_SESSION_HANDLE,
    pPart: CK_BYTE_PTR,
    ulPartLen: CK_ULONG,
    pEncryptedPart: CK_BYTE_PTR,
    pulEncryptedPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_DecryptVerifyUpdate,
    hSession: CK_SESSION_HANDLE,
    pEncryptedPart: CK_BYTE_PTR,
    ulEncryptedPartLen: CK_ULONG,
    pPart: CK_BYTE_PTR,
    pulPartLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_GenerateKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_GenerateKeyPair,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPublicKeyAttributeCount: CK_ULONG,
    pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    ulPrivateKeyAttributeCount: CK_ULONG,
    phPublicKey: CK_OBJECT_HANDLE_PTR,
    phPrivateKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_WrapKey,
    hSession: CK_SESSION_HANDLE,
    _pMechanism: CK_MECHANISM_PTR,
    _hWrappingKey: CK_OBJECT_HANDLE,
    _hKey: CK_OBJECT_HANDLE,
    _pWrappedKey: CK_BYTE_PTR,
    _pulWrappedKeyLen: CK_ULONG_PTR
);

cryptoki_fn_not_supported!(
    C_UnwrapKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hUnwrappingKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    ulWrappedKeyLen: CK_ULONG,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn_not_supported!(
    C_DeriveKey,
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulAttributeCount: CK_ULONG,
    phKey: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn!(
    fn C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, _ulSeedLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pSeed);
        Err(MError::RandomNoRng)
    }
);

cryptoki_fn!(
    unsafe fn C_GenerateRandom(
        hSession: CK_SESSION_HANDLE,
        pRandomData: CK_BYTE_PTR,
        ulRandomLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pRandomData);
        let mut bytes = vec![0; ulRandomLen as usize];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut bytes);
        unsafe { slice::from_raw_parts_mut(pRandomData, ulRandomLen as usize) }
            .copy_from_slice(&bytes);
        trace!("Generated random: {}", hex::encode(&bytes));
        Ok(())
    }
);

cryptoki_fn!(
    fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(MError::FunctionNotParallel)
    }
);

cryptoki_fn!(
    fn C_CancelFunction(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(MError::FunctionNotParallel)
    }
);

cryptoki_fn_not_supported!(
    C_WaitForSlotEvent,
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pReserved: CK_VOID_PTR
);
