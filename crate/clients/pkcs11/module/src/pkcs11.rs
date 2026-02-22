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

use std::{
    cmp, slice,
    sync::atomic::{AtomicBool, Ordering},
};

use cosmian_logger::{debug, error, info, trace};
use pkcs11_sys::{
    CK_ATTRIBUTE_PTR, CK_BBOOL, CK_BYTE_PTR, CK_C_INITIALIZE_ARGS_PTR, CK_FLAGS, CK_FUNCTION_LIST,
    CK_INFO, CK_INFO_PTR, CK_MECHANISM_INFO, CK_MECHANISM_INFO_PTR, CK_MECHANISM_PTR,
    CK_MECHANISM_TYPE, CK_MECHANISM_TYPE_PTR, CK_NOTIFY, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR,
    CK_RV, CK_SESSION_HANDLE, CK_SESSION_HANDLE_PTR, CK_SESSION_INFO, CK_SESSION_INFO_PTR,
    CK_SLOT_ID, CK_SLOT_ID_PTR, CK_SLOT_INFO, CK_SLOT_INFO_PTR, CK_TOKEN_INFO, CK_TOKEN_INFO_PTR,
    CK_ULONG, CK_ULONG_PTR, CK_UNAVAILABLE_INFORMATION, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_VERSION,
    CK_VOID_PTR, CKF_HW_SLOT, CKF_PROTECTED_AUTHENTICATION_PATH, CKF_RNG, CKF_RW_SESSION,
    CKF_SERIAL_SESSION, CKF_SIGN, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT,
    CKF_USER_PIN_INITIALIZED, CKF_WRITE_PROTECTED, CKR_OK, CKS_RO_USER_FUNCTIONS,
    CKS_RW_USER_FUNCTIONS, CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR,
};
use rand::RngCore;

use crate::{
    MResultHelper, ModuleError, ModuleResult,
    core::{
        attribute::{AttributeType, Attributes},
        mechanism::{Mechanism, SUPPORTED_SIGNATURE_MECHANISMS, parse_mechanism},
        object::Object,
    },
    objects_store::OBJECTS_STORE,
    sessions::{self, Session},
    traits::{DecryptContext, EncryptContext, EncryptionAlgorithm, SignContext, backend},
};

pub(crate) const SLOT_DESCRIPTION: &[u8; 64] =
    b"Platform Cryptography Support                                   ";
pub const SLOT_ID: CK_SLOT_ID = 1;

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(crate) fn result_to_rv<F>(name: &str, f: F) -> CK_RV
where
    F: FnOnce() -> ModuleResult<()>,
{
    match f() {
        Ok(()) => CKR_OK,
        Err(e) => {
            cosmian_logger::error!("{}: {}", name, e);
            e.into()
        }
    }
}

#[macro_export]
macro_rules! cryptoki_fn {
    (fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument(level = tracing::Level::TRACE, ret)]
        #[unsafe(no_mangle)]
        pub extern "C" fn $name($($arg: $type),*) -> CK_RV {
            result_to_rv(stringify!($name), || $body)
        }
    };
    (unsafe fn $name:ident ( $($arg:ident : $type:ty),* $(,)?) $body:block) => {
        #[tracing::instrument(level = tracing::Level::TRACE, ret)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($($arg: $type),*) -> pkcs11_sys::CK_RV {
            use $crate::pkcs11::result_to_rv;
            result_to_rv(stringify!($name), || $body)
        }
    };
}

macro_rules! cryptoki_fn_not_supported {
    ($name:ident, $($arg:ident: $type:ty),*) => {
        cryptoki_fn!(fn $name($($arg: $type),*) {Err(ModuleError::FunctionNotSupported)});
    };
}

#[macro_export]
macro_rules! not_null {
    ($ptr:expr, $variable_name:expr) => {
        if $ptr.is_null() {
            return Err(ModuleError::BadArguments(format!(
                "{} is a null pointer",
                $variable_name
            )));
        }
    };
}

macro_rules! initialized {
    () => {
        if INITIALIZED.load(Ordering::SeqCst) == false {
            return Err(ModuleError::CryptokiNotInitialized);
        }
    };
}

macro_rules! valid_session {
    ($handle:expr) => {
        if !sessions::exists($handle)? {
            return Err(ModuleError::SessionHandleInvalid($handle));
        }
    };
}

macro_rules! valid_slot {
    ($id:expr) => {
        if $id != SLOT_ID {
            return Err(ModuleError::SlotIdInvalid($id));
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
                return Err(ModuleError::BadArguments(
                    "C_Initialize: pReserved is null".to_owned(),
                ));
            }
        }
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(ModuleError::CryptokiAlreadyInitialized);
        }
        Ok(())
    }
);

cryptoki_fn!(
    fn C_Finalize(pReserved: CK_VOID_PTR) {
        initialized!();
        if !pReserved.is_null() {
            return Err(ModuleError::BadArguments(
                "C_Finalize: pReserved is null".to_owned(),
            ));
        }
        INITIALIZED.store(false, Ordering::SeqCst);
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetInfo(pInfo: CK_INFO_PTR) {
        initialized!();
        not_null!(pInfo, "C_GetInfo: pInfo");
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
        unsafe {
            *pInfo = info;
        }
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotList(
        tokenPresent: CK_BBOOL,
        pSlotList: CK_SLOT_ID_PTR,
        pulCount: CK_ULONG_PTR,
    ) {
        initialized!();
        not_null!(pulCount, "C_GetSlotList: pulCount");
        unsafe {
            if !pSlotList.is_null() {
                if *pulCount < 1 {
                    return Err(ModuleError::BufferTooSmall);
                }
                // TODO: this should be an array.
                *pSlotList = SLOT_ID;
            }
            *pulCount = 1;
        }
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo, "C_GetSlotInfo: pInfo");
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
        unsafe {
            *pInfo = info;
        }
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) {
        initialized!();
        valid_slot!(slotID);
        not_null!(pInfo, "C_GetTokenInfo: pInfo");

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
        unsafe {
            *pInfo = info;
        }
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
        not_null!(pulCount, "C_GetMechanismList: pulCount");
        valid_slot!(slotID);
        unsafe {
            if !pMechanismList.is_null() {
                if (usize::try_from(*pulCount)?) < SUPPORTED_SIGNATURE_MECHANISMS.len() {
                    *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG;
                    return Err(ModuleError::BufferTooSmall);
                }
                slice::from_raw_parts_mut(pMechanismList, SUPPORTED_SIGNATURE_MECHANISMS.len())
                    .copy_from_slice(SUPPORTED_SIGNATURE_MECHANISMS);
            }
            *pulCount = SUPPORTED_SIGNATURE_MECHANISMS.len() as CK_ULONG;
        }
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
        not_null!(pInfo, "C_GetMechanismInfo: pInfo");
        if !SUPPORTED_SIGNATURE_MECHANISMS.contains(&mechType) {
            return Err(ModuleError::MechanismInvalid(mechType));
        }
        let info = CK_MECHANISM_INFO {
            flags: CKF_SIGN,
            ..Default::default()
        };
        unsafe {
            *pInfo = info;
        }
        Ok(())
    }
);

cryptoki_fn!(
    fn C_InitToken(
        slotID: CK_SLOT_ID,
        pPin: CK_UTF8CHAR_PTR,
        ulPinLen: CK_ULONG,
        pLabel: CK_UTF8CHAR_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        Err(ModuleError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_InitPIN(hSession: CK_SESSION_HANDLE, pPin: CK_UTF8CHAR_PTR, ulPinLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        Err(ModuleError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    fn C_SetPIN(
        hSession: CK_SESSION_HANDLE,
        pOldPin: CK_UTF8CHAR_PTR,
        ulOldLen: CK_ULONG,
        pNewPin: CK_UTF8CHAR_PTR,
        ulNewLen: CK_ULONG,
    ) {
        initialized!();
        valid_session!(hSession);
        Err(ModuleError::TokenWriteProtected)
    }
);

cryptoki_fn!(
    unsafe fn C_OpenSession(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        pApplication: CK_VOID_PTR,
        Notify: CK_NOTIFY,
        phSession: CK_SESSION_HANDLE_PTR,
    ) {
        initialized!();
        valid_slot!(slotID);
        not_null!(phSession, "C_OpenSession: phSession");
        if flags & CKF_SERIAL_SESSION == 0 {
            return Err(ModuleError::SessionParallelNotSupported);
        }
        unsafe {
            *phSession = sessions::create(flags);
        }
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
        if sessions::close(hSession)? {
            return Ok(());
        }
        Err(ModuleError::SessionHandleInvalid(hSession))
    }
);

cryptoki_fn!(
    fn C_CloseAllSessions(slotID: CK_SLOT_ID) {
        initialized!();
        valid_slot!(slotID);
        info!("C_CloseAllSessions: slot: {:?}", slotID);
        sessions::close_all()?;
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_GetSessionInfo(hSession: CK_SESSION_HANDLE, pInfo: CK_SESSION_INFO_PTR) {
        initialized!();
        valid_session!(hSession);
        not_null!(pInfo, "C_GetSessionInfo: pInfo");
        let flags = sessions::flags(hSession)?;
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
        unsafe {
            *pInfo = info;
        }
        trace!(
            "C_GetSessionInfo: session: {:?}, slot: {:?}, state: {:?}, flags: {:?}",
            hSession, SLOT_ID, state, flags
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
        userType: CK_USER_TYPE,
        pPin: CK_UTF8CHAR_PTR,
        ulPinLen: CK_ULONG,
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

cryptoki_fn!(
    unsafe fn C_CreateObject(
        hSession: CK_SESSION_HANDLE,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
        phObject: CK_OBJECT_HANDLE_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pTemplate, "C_CreateObject: pTemplate");
        not_null!(phObject, "C_CreateObject: phObject");

        debug!(
            "C_CreateObject: session: {hSession:?}, pTemplate: {pTemplate:?}, ulCount: \
             {ulCount:?}, phObject: {phObject:?}"
        );
        let attributes = Attributes::try_from((pTemplate, ulCount))
            .context("C_CreateObject: attributes conversion failed")?;

        sessions::session(hSession, |_session| -> ModuleResult<()> {
            unsafe {
                *phObject = Session::create_object(&attributes)?;
            };

            Ok(())
        })
    }
);

cryptoki_fn_not_supported!(
    C_CopyObject,
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
    phNewObject: CK_OBJECT_HANDLE_PTR
);

cryptoki_fn!(
    unsafe fn C_DestroyObject(hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE) {
        initialized!();
        valid_session!(hSession);

        debug!("C_DestroyObject: session: {hSession:?}, hObject: {hObject}");

        sessions::session(hSession, |_session| -> ModuleResult<()> {
            Session::destroy_object(hObject)?;
            Ok(())
        })
    }
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
            hSession, hObject
        );
        initialized!();
        valid_session!(hSession);
        not_null!(pTemplate, "C_GetAttributeValue: pTemplate");

        sessions::session(hSession, |_session| -> ModuleResult<()> {
            let find_ctx = OBJECTS_STORE.read()?;
            let Some(object) = find_ctx.get_using_handle(hObject) else {
                return Err(ModuleError::ObjectHandleInvalid(hObject));
            };
            let template = if ulCount > 0 {
                if pTemplate.is_null() {
                    return Err(ModuleError::BadArguments(
                        "C_GetAttributeValue: pTemplate is null".to_owned(),
                    ));
                }
                unsafe { slice::from_raw_parts_mut(pTemplate, usize::try_from(ulCount)?) }
            } else {
                &mut []
            };
            for attribute in template.iter_mut() {
                let type_: AttributeType = attribute.type_.try_into().map_err(|e| {
                    let attribute_type = attribute.type_;
                    error!(
                        "C_GetAttributeValue: error: {e}, session: {:?}, object: {:?}, type: {:?}",
                        hSession,
                        object.remote_id(),
                        attribute_type
                    );
                    ModuleError::AttributeTypeInvalid(attribute.type_)
                })?;
                info!(
                    "C_GetAttributeValue: session: {:?}, object: {:?} [handle: {}], type: {:?}",
                    hSession,
                    object.remote_id(),
                    hObject,
                    type_.to_string(),
                );
                if let Some(value) = object.attribute(type_)? {
                    let value = value.as_raw_value();
                    attribute.ulValueLen = value.len() as CK_ULONG;
                    if attribute.pValue.is_null() {
                        continue;
                    }
                    if (usize::try_from(attribute.ulValueLen)?) < value.len() {
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

        let attributes = Attributes::try_from((pTemplate, ulCount))
            .context("C_FindObjectsInit: attributes conversion failed")?;
        sessions::session(hSession, |session| -> ModuleResult<()> {
            info!(
                "C_FindObjectsInit: session: {hSession:?}, load Objects Store context for \
                 attributes: {attributes:?}"
            );
            session.load_find_context(&attributes)
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
        not_null!(phObject, "C_FindObjects: phObject");
        not_null!(pulObjectCount, "C_FindObjects: pulObjectCount");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            trace!(
                "C_FindObjects: session: {:?}, objects available: {:?}",
                hSession, session.find_objects_ctx
            );
            if session.find_objects_ctx.is_empty() {
                info!(
                    "C_FindObjects: session: {:?}, no more objects to return",
                    hSession
                );
                unsafe {
                    *pulObjectCount = 0;
                }
                return Ok(());
            }
            let max_objects = cmp::min(
                session.find_objects_ctx.len(),
                usize::try_from(ulMaxObjectCount)?,
            );
            let handles = session
                .find_objects_ctx
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
            unsafe {
                *pulObjectCount = max_objects as CK_ULONG;
            }
            Ok(())
        })
    }
);

cryptoki_fn!(
    fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Ok(())
    }
);

cryptoki_fn!(
    unsafe fn C_EncryptInit(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        hKey: CK_OBJECT_HANDLE,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism, "C_EncryptInit: pMechanism");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let parsed_mechanism = unsafe { pMechanism.read() };
            let mechanism = unsafe { parse_mechanism(parsed_mechanism) }?;
            let find_ctx = OBJECTS_STORE.read()?;
            let object = find_ctx.get_using_handle(hKey);
            debug!(
                "C_EncryptInit: session: {hSession:?}, hKey: {hKey:?}, mechanism: {mechanism:?}, \
                 object: {object:?}",
            );
            match object.as_deref() {
                Some(Object::PublicKey(pk)) => {
                    session.encrypt_ctx = Some(EncryptContext {
                        remote_object_id: pk.remote_id(),
                        algorithm: mechanism.try_into()?,
                        iv: None,
                    });
                    Ok(())
                }
                Some(Object::SymmetricKey(sk)) => {
                    let iv = match &mechanism {
                        Mechanism::AesCbcPad { iv } | Mechanism::AesCbc { iv } => Some(iv.to_vec()),
                        mech => {
                            return Err(ModuleError::MechanismInvalid(CK_MECHANISM_TYPE::from(
                                mech,
                            )));
                        }
                    };
                    session.encrypt_ctx = Some(EncryptContext {
                        remote_object_id: sk.remote_id(),
                        algorithm: EncryptionAlgorithm::try_from(mechanism)?,
                        iv,
                    });
                    Ok(())
                }
                Some(Object::DataObject(data)) => {
                    let iv = match &mechanism {
                        Mechanism::AesCbcPad { iv } | Mechanism::AesCbc { iv } => Some(iv.to_vec()),
                        mech => {
                            return Err(ModuleError::MechanismInvalid(CK_MECHANISM_TYPE::from(
                                mech,
                            )));
                        }
                    };
                    session.encrypt_ctx = Some(EncryptContext {
                        remote_object_id: data.remote_id(),
                        algorithm: EncryptionAlgorithm::try_from(mechanism)?,
                        iv,
                    });
                    Ok(())
                }
                Some(_) | None => Err(ModuleError::KeyHandleInvalid(hKey)),
            }
        })
    }
);

cryptoki_fn!(
    unsafe fn C_Encrypt(
        hSession: CK_SESSION_HANDLE,
        pData: CK_BYTE_PTR,
        ulDataLen: CK_ULONG,
        pEncryptedData: CK_BYTE_PTR,
        pulEncryptedDataLen: CK_ULONG_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        debug!(
            "C_Encrypt: pData: {pData:?}, ulDataLen: {ulDataLen:?}, pEncryptedData: \
             {pEncryptedData:?}, pulEncryptedDataLen: {pulEncryptedDataLen:?}"
        );
        if ulDataLen == 0 {
            return Err(ModuleError::BadArguments(
                "C_Encrypt: ulDataLen is 0".to_owned(),
            ));
        }
        not_null!(pData, "C_Encrypt: pData");
        not_null!(pulEncryptedDataLen, "C_Encrypt: pulEncryptedDataLen");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let cleartext_data =
                unsafe { slice::from_raw_parts(pData, usize::try_from(ulDataLen)?) };
            unsafe {
                debug!(
                    "C_Encrypt: session: {:?}, plain_data_len: {:?}, ciphertext_len: {:?}, \
                     cleartext: {:?}",
                    hSession,
                    cleartext_data.len(),
                    usize::try_from(*pulEncryptedDataLen)?,
                    hex::encode(cleartext_data)
                );
                session.encrypt(cleartext_data.to_vec(), pEncryptedData, pulEncryptedDataLen)
            }?;
            Ok(())
        })
    }
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
        not_null!(pMechanism, "C_DecryptInit: pMechanism");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let parsed_mechanism = unsafe { pMechanism.read() };
            let mechanism = unsafe { parse_mechanism(parsed_mechanism) }?;
            let find_ctx = OBJECTS_STORE.read()?;
            let object = find_ctx.get_using_handle(hKey);
            debug!(
                "C_DecryptInit: session: {hSession:?}, hKey: {hKey:?}, mechanism: {mechanism:?}, \
                 object: {object:?}",
            );
            match object.as_deref() {
                Some(Object::PrivateKey(sk)) => {
                    session.decrypt_ctx = Some(DecryptContext {
                        remote_object_id: sk.remote_id(),
                        algorithm: mechanism.try_into()?,
                        iv: None,
                    });
                    Ok(())
                }
                Some(Object::SymmetricKey(sk)) => {
                    let iv = match &mechanism {
                        Mechanism::AesCbcPad { iv } | Mechanism::AesCbc { iv } => Some(iv.to_vec()),
                        mech => {
                            return Err(ModuleError::MechanismInvalid(CK_MECHANISM_TYPE::from(
                                mech,
                            )));
                        }
                    };

                    session.decrypt_ctx = Some(DecryptContext {
                        remote_object_id: sk.remote_id(),
                        algorithm: mechanism.try_into()?,
                        iv,
                    });
                    Ok(())
                }
                Some(Object::DataObject(data)) => {
                    let iv = match &mechanism {
                        Mechanism::AesCbcPad { iv } | Mechanism::AesCbc { iv } => Some(iv.to_vec()),
                        mech => {
                            return Err(ModuleError::MechanismInvalid(CK_MECHANISM_TYPE::from(
                                mech,
                            )));
                        }
                    };
                    session.decrypt_ctx = Some(DecryptContext {
                        remote_object_id: data.remote_id(),
                        algorithm: mechanism.try_into()?,
                        iv,
                    });
                    Ok(())
                }
                Some(_) | None => Err(ModuleError::KeyHandleInvalid(hKey)),
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
        debug!(
            "C_Decrypt: pEncryptedData: {pEncryptedData:?}, ulEncryptedDataLen: \
             {ulEncryptedDataLen:?}, pData: {pData:?}, pulDataLen: {pulDataLen:?}"
        );

        if ulEncryptedDataLen == 0 {
            return Err(ModuleError::BadArguments(
                "C_Decrypt: ulEncryptedDataLen is 0".to_owned(),
            ));
        }
        not_null!(pEncryptedData, "C_Decrypt: pEncryptedData");
        not_null!(pulDataLen, "C_Decrypt: pulDataLen");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let encrypted_data = unsafe {
                slice::from_raw_parts(pEncryptedData, usize::try_from(ulEncryptedDataLen)?)
            };
            unsafe {
                debug!(
                    "C_Decrypt: session: {:?}, encrypted_data_len: {:?}, cleartext_len: {:?}, \
                     ciphertext: {:?}",
                    hSession,
                    encrypted_data.len(),
                    usize::try_from(*pulDataLen)?,
                    hex::encode(encrypted_data)
                );
                session.decrypt(encrypted_data.to_vec(), pData, pulDataLen)
            }?;
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
            return Err(ModuleError::BadArguments(
                "C_DecryptUpdate: ulEncryptedPartLen is 0".to_owned(),
            ));
        }
        not_null!(pEncryptedPart, "C_DecryptUpdate: pEncryptedPart");
        not_null!(pPart, "C_DecryptUpdate: pPart");
        not_null!(pulPartLen, "C_DecryptUpdate: pulPartLen");
        Err(ModuleError::FunctionNotSupported)
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
        not_null!(pLastPart, "C_DecryptFinal: pLastPart");
        not_null!(pulLastPartLen, "C_DecryptFinal: pulLastPartLen");
        Err(ModuleError::FunctionNotSupported)
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
        not_null!(pMechanism, "C_SignInit: pMechanism");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let find_ctx = OBJECTS_STORE.read()?;
            // .map_err(|_| ModuleError::OperationNotInitialized(hSession))?;
            let object = find_ctx.get_using_handle(hKey);
            let Some(Object::PrivateKey(private_key)) = object.as_deref() else {
                return Err(ModuleError::KeyHandleInvalid(hKey));
            };
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;
            session.sign_ctx = Some(SignContext {
                algorithm: mechanism.try_into()?,
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
        not_null!(pData, "C_Sign: pData");
        not_null!(pulSignatureLen, "C_Sign: pulSignatureLen");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let data = unsafe { slice::from_raw_parts(pData, usize::try_from(ulDataLen)?) };
            unsafe { session.sign(Some(data), pSignature, pulSignatureLen) }?;
            Ok(())
        })
    }
);

cryptoki_fn!(
    unsafe fn C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pPart, "C_SignUpdate: pPart");
        sessions::session(hSession, |session| -> ModuleResult<()> {
            let Some(sign_ctx) = session.sign_ctx.as_mut() else {
                return Err(ModuleError::OperationNotInitialized(hSession));
            };
            sign_ctx
                .payload
                .get_or_insert(vec![])
                .extend_from_slice(unsafe {
                    slice::from_raw_parts(pPart, usize::try_from(ulPartLen)?)
                });
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
        not_null!(pSignature, "C_SignFinal: pSignature");
        not_null!(pulSignatureLen, "C_SignFinal: pulSignatureLen");
        sessions::session(hSession, |session| -> ModuleResult<()> {
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

cryptoki_fn!(
    unsafe fn C_GenerateKey(
        hSession: CK_SESSION_HANDLE,
        pMechanism: CK_MECHANISM_PTR,
        pTemplate: CK_ATTRIBUTE_PTR,
        ulCount: CK_ULONG,
        phKey: CK_OBJECT_HANDLE_PTR,
    ) {
        initialized!();
        valid_session!(hSession);
        not_null!(pMechanism, "C_GenerateKey: pMechanism");
        not_null!(pTemplate, "C_GenerateKey: pTemplate");

        debug!(
            "C_GenerateKey: session: {hSession:?}, pMechanism: {pMechanism:?}, pTemplate: \
             {pTemplate:?}, ulCount: {ulCount:?}, phKey: {phKey:?}"
        );
        let attributes = Attributes::try_from((pTemplate, ulCount))
            .context("C_GenerateKey: attributes conversion failed")?;

        sessions::session(hSession, |_session| -> ModuleResult<()> {
            let mechanism = unsafe { parse_mechanism(pMechanism.read()) }?;

            unsafe {
                *phKey = Session::generate_key(mechanism, &attributes)?;
            };

            Ok(())
        })
    }
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
    pMechanism: CK_MECHANISM_PTR,
    hWrappingKey: CK_OBJECT_HANDLE,
    hKey: CK_OBJECT_HANDLE,
    pWrappedKey: CK_BYTE_PTR,
    pulWrappedKeyLen: CK_ULONG_PTR
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
    fn C_SeedRandom(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG) {
        initialized!();
        valid_session!(hSession);
        not_null!(pSeed, "C_SeedRandom: pSeed");
        Err(ModuleError::RandomNoRng)
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
        not_null!(pRandomData, "C_GenerateRandom: pRandomData");
        let mut bytes = vec![0; usize::try_from(ulRandomLen)?];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut bytes);
        unsafe { slice::from_raw_parts_mut(pRandomData, usize::try_from(ulRandomLen)?) }
            .copy_from_slice(&bytes);
        trace!("Generated random: {}", hex::encode(&bytes));
        Ok(())
    }
);

cryptoki_fn!(
    fn C_GetFunctionStatus(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(ModuleError::FunctionNotParallel)
    }
);

cryptoki_fn!(
    fn C_CancelFunction(hSession: CK_SESSION_HANDLE) {
        initialized!();
        valid_session!(hSession);
        Err(ModuleError::FunctionNotParallel)
    }
);

cryptoki_fn_not_supported!(
    C_WaitForSlotEvent,
    flags: CK_FLAGS,
    pSlot: CK_SLOT_ID_PTR,
    pReserved: CK_VOID_PTR
);
