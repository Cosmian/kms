#![allow(unreachable_pub)]
#![allow(clippy::as_conversions)]

use std::{
    ptr::{self, addr_of_mut},
    sync::{Arc, atomic::Ordering},
};

use cosmian_logger::log_init;
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_C_INITIALIZE_ARGS, CK_C_INITIALIZE_ARGS_PTR, CK_FALSE, CK_FUNCTION_LIST,
    CK_FUNCTION_LIST_PTR_PTR, CK_INFO, CK_INVALID_HANDLE, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SESSION_INFO,
    CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_VOID_PTR, CKA_CLASS, CKA_ID, CKF_SERIAL_SESSION,
    CKM_DSA, CKM_ECDSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_NOT_PARALLEL,
    CKR_MECHANISM_INVALID, CKR_OBJECT_HANDLE_INVALID, CKR_OK, CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID,
};
use serial_test::serial;
use zeroize::{Zeroize, Zeroizing};

use super::*;
use crate::{
    core::{
        mechanism::{AES_IV_SIZE, SUPPORTED_SIGNATURE_MECHANISMS},
        object::Object,
    },
    objects_store::OBJECTS_STORE,
    pkcs11::{
        C_CloseSession, C_Finalize, C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit,
        C_GetAttributeValue, C_GetFunctionStatus, C_GetInfo, C_GetMechanismInfo,
        C_GetMechanismList, C_GetSessionInfo, C_GetSlotInfo, C_GetSlotList, C_GetTokenInfo,
        C_Initialize, C_OpenSession, C_SignInit, FUNC_LIST, INITIALIZED, SLOT_ID,
    },
    traits::{
        Backend, Certificate, DataObject, DecryptContext, EncryptContext, KeyAlgorithm, PrivateKey,
        PublicKey, SearchOptions, SignatureAlgorithm, SymmetricKey, Version, register_backend,
    },
};

struct DummyDataObject {
    remote_id: String,
    value: Zeroizing<Vec<u8>>,
}

impl DummyDataObject {
    fn new(label: &str, data: &[u8]) -> Self {
        Self {
            remote_id: format!("test-data-{label}"),
            value: Zeroizing::new(data.to_vec()),
        }
    }
}

impl Zeroize for DummyDataObject {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl DataObject for DummyDataObject {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn value(&self) -> Zeroizing<Vec<u8>> {
        self.value.clone()
    }

    fn application(&self) -> Vec<u8> {
        b"Test PKCS#11 Application".to_vec()
    }

    fn data_hash(&self) -> Vec<u8> {
        // Simple test hash - just the first 32 bytes repeated or padded
        let mut hash = vec![0_u8; 32];
        let data = self.value.as_slice();
        for (i, &byte) in data.iter().take(32).enumerate() {
            hash[i] = byte;
        }
        hash
    }
}

struct DummySymKey;

impl SymmetricKey for DummySymKey {
    fn remote_id(&self) -> &'static str {
        "dummy_key"
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::Aes256
    }

    fn key_size(&self) -> usize {
        32
    }

    fn raw_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0; self.key_size()]))
    }
}

struct TestBackend;

impl Backend for TestBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Foo software token              "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Foo manufacturer id             "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"Foo model       "
    }

    fn token_serial_number(&self) -> [u8; 16] {
        *b"1234567890abcdef"
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Foo PKCS#11 library             "
    }

    fn library_version(&self) -> Version {
        Version { major: 1, minor: 0 }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_public_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        Ok(vec![])
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![])
    }

    fn find_data_object(&self, _query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        Ok(None)
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        Ok(vec![])
    }

    fn find_symmetric_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        Ok(vec![])
    }

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _key_length: usize,
        _sensitive: bool,
        _label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Ok(Arc::new(DummySymKey {}))
    }

    fn create_object(&self, label: &str, data: &[u8]) -> ModuleResult<Arc<dyn DataObject>> {
        Ok(Arc::new(DummyDataObject::new(label, data)))
    }

    fn revoke_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn destroy_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn encrypt(&self, _encrypt_ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>> {
        Ok(vec![0; cleartext.len() + AES_IV_SIZE])
    }

    fn decrypt(
        &self,
        _decrypt_ctx: &DecryptContext,
        _data: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0; 32]))
    }

    fn remote_sign(
        &self,
        _remote_id: &str,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
    ) -> ModuleResult<Vec<u8>> {
        Err(ModuleError::FunctionNotSupported)
    }
}

cryptoki_fn!(
    unsafe fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) {
        not_null!(ppFunctionList, "C_GetFunctionList: ppFunctionList");
        unsafe {
            *ppFunctionList = addr_of_mut!(FUNC_LIST);
        }
        register_backend(Box::new(TestBackend {}));
        Ok(())
    }
);

pub(crate) fn test_init() {
    log_init(None);
    if !INITIALIZED.load(Ordering::SeqCst) {
        let func_list = &mut CK_FUNCTION_LIST::default();
        // Update the function list with this PKCS#11 entry function
        func_list.C_GetFunctionList = Some(C_GetFunctionList);
        unsafe {
            C_GetFunctionList(&mut std::ptr::from_mut(func_list));
        }
    }
}

#[test]
#[serial]
fn get_initialize() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        { C_Initialize(ptr::null_mut()) },
        CKR_CRYPTOKI_ALREADY_INITIALIZED
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    let mut args = CK_C_INITIALIZE_ARGS::default();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_OK
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    args.pReserved = std::ptr::dangling_mut::<u32>().cast::<std::ffi::c_void>();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_ARGUMENTS_BAD
    );
}

#[test]
#[serial]
fn finalize() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    assert_eq!(
        C_Finalize(std::ptr::dangling_mut::<u32>().cast::<std::ffi::c_void>()),
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut info = CK_INFO::default();
    unsafe {
        assert_eq!(C_GetInfo(&raw mut info), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetInfo(ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(C_GetInfo(&raw mut info), CKR_CRYPTOKI_NOT_INITIALIZED);
    }
}

#[test]
#[serial]
fn get_function_list() {
    test_init();
    let mut function_list = CK_FUNCTION_LIST::default();
    let mut function_list_pointer: *mut CK_FUNCTION_LIST = &raw mut function_list;
    unsafe {
        assert_eq!(C_GetFunctionList(&raw mut function_list_pointer), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if ppFunctionList is null.
        assert_eq!(C_GetFunctionList(ptr::null_mut()), CKR_ARGUMENTS_BAD);
    }
}

#[test]
#[serial]
fn get_slot_list() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut count = 0;
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), &raw mut count) },
        CKR_OK
    );
    assert_eq!(count, 1);
    // Expect CKR_ARGUMENTS_BAD if pulCount is null.
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
    // slots.
    let mut count = 0;
    let mut slot_list = vec![0; 0];
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, slot_list.as_mut_ptr(), &raw mut count) },
        CKR_BUFFER_TOO_SMALL
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_slot_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut slot_info = CK_SLOT_INFO::default();
    unsafe {
        assert_eq!(C_GetSlotInfo(SLOT_ID, &raw mut slot_info), CKR_OK);
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetSlotInfo(SLOT_ID, ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetSlotInfo(SLOT_ID + 1, ptr::null_mut()),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    }
}

#[test]
#[serial]
fn get_token_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    unsafe {
        assert_eq!(
            C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()),
            CKR_OK
        );
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetTokenInfo(SLOT_ID + 1, ptr::null_mut()),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pInfo is null.
        assert_eq!(C_GetSlotInfo(SLOT_ID, ptr::null_mut()), CKR_ARGUMENTS_BAD);
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }
}

#[test]
#[serial]
fn get_mechanism_list() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut count = 0;
    unsafe {
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), &raw mut count),
            CKR_OK
        );
        assert_ne!(count, 0);
        let mut mechanisms =
            Vec::<CK_MECHANISM_TYPE>::with_capacity(usize::try_from(count).unwrap());
        assert_eq!(
            C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &raw mut count),
            CKR_OK
        );
        mechanisms.set_len(usize::try_from(count).unwrap());
        assert_eq!(mechanisms, *SUPPORTED_SIGNATURE_MECHANISMS);
        // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
        assert_eq!(
            C_GetMechanismList(SLOT_ID + 1, ptr::null_mut(), &raw mut count),
            CKR_SLOT_ID_INVALID
        );
        // Expect CKR_ARGUMENTS_BAD if pulCount is null.
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()),
            CKR_ARGUMENTS_BAD
        );
        // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
        // mechanisms.
        assert_eq!(
            C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut (count - 1)),
            CKR_BUFFER_TOO_SMALL
        );
        // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
        assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
        assert_eq!(
            C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()),
            CKR_CRYPTOKI_NOT_INITIALIZED
        );
    }
}

#[test]
#[serial]
fn get_mechanism_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut info = CK_MECHANISM_INFO::default();
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], &raw mut info,) },
        CKR_OK
    );
    // Expect CKR_MECHANISM_INVALID if type is an unsupported mechanism.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, CKM_DSA, &raw mut info) },
        CKR_MECHANISM_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn open_session() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let flags = CKF_SERIAL_SESSION;
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, &raw mut handle) },
        CKR_OK
    );
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID + 1, flags, ptr::null_mut(), None, &raw mut handle,) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_SESSION_PARALLEL_NOT_SUPPORTED if CKF_SERIAL_SESSION flag
    // is not set.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, 0, ptr::null_mut(), None, &raw mut handle) },
        CKR_SESSION_PARALLEL_NOT_SUPPORTED
    );
    // Expect CKR_ARGUMENTS_BAD if phSession is null.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn close_session() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    // Expect CKR_SESSION_HANDLE_INVALID if the session has already been closed.
    assert_eq!(C_CloseSession(handle), CKR_SESSION_HANDLE_INVALID);
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        { C_CloseSession(CK_INVALID_HANDLE) },
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_session_info() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    let mut session_info = CK_SESSION_INFO::default();
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, &raw mut session_info) },
        CKR_OK
    );
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        unsafe { C_GetSessionInfo(CK_INVALID_HANDLE, &raw mut session_info) },
        CKR_SESSION_HANDLE_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_attribute_value() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut session_h,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE::default()];
    assert_eq!(
        unsafe {
            C_GetAttributeValue(
                session_h,
                CK_INVALID_HANDLE,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            )
        },
        CKR_OBJECT_HANDLE_INVALID
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_GetAttributeValue(session_h, 0, template.as_mut_ptr(), 0) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_init() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    let mut objects = vec![CK_OBJECT_HANDLE::default()];
    let mut count = 0;
    assert_eq!(
        unsafe { C_FindObjects(handle, objects.as_mut_ptr(), 1, &raw mut count) },
        CKR_OK
    );
    assert_eq!(count, 0);
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    assert_eq!(
        unsafe { C_FindObjects(handle, ptr::null_mut(), 0, ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_final() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: std::ptr::from_ref::<CK_ULONG>(&CKO_PRIVATE_KEY) as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn get_function_status() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn cancel_function() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!(C_CloseSession(session_h), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

#[test]
#[serial]
fn module_test_generate_key_encrypt_decrypt() -> ModuleResult<()> {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    let key_handle = test_generate_key(handle);
    // call to encrypt() test function
    let plaintext = vec![0_u8; 32];
    let encrypted_data = test_encrypt(handle, key_handle, plaintext.clone());
    // call to decrypt() test function
    let decrypted_data = test_decrypt(handle, key_handle, encrypted_data);
    assert_eq!(decrypted_data, plaintext);

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
    Ok(())
}

// ── Regression tests for issue #1076 ──────────────────────────────────────
// OpenSSH resolves the paired private key from a public key's `CKA_ID`
// (`<base>_pk`) before `C_SignInit`. The private key is stored under the base
// UID (`<base>`), so a `CKO_PRIVATE_KEY` search by the public key's id must
// resolve to the private key — not the public key — otherwise `C_SignInit`
// fails with `CKR_KEY_HANDLE_INVALID` (0x60 = 96).

/// Minimal in-memory private key used to populate `OBJECTS_STORE` directly,
/// bypassing the (empty) `TestBackend`.
struct DummyPrivateKey {
    remote_id: String,
}

impl PrivateKey for DummyPrivateKey {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> ModuleResult<Vec<u8>> {
        Ok(vec![0_u8; 64])
    }

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EccP256
    }

    fn key_size(&self) -> usize {
        256
    }

    fn pkcs8_der_bytes(&self) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![]))
    }

    fn rsa_public_exponent(&self) -> ModuleResult<Vec<u8>> {
        Err(ModuleError::FunctionNotSupported)
    }
}

/// Minimal in-memory public key used to populate `OBJECTS_STORE` directly.
struct DummyPublicKey {
    remote_id: String,
}

impl PublicKey for DummyPublicKey {
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn fingerprint(&self) -> &[u8] {
        &[]
    }

    fn verify(
        &self,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
        _signature: &[u8],
    ) -> ModuleResult<()> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn delete(self: Arc<Self>) {}

    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EccP256
    }

    fn rsa_public_key(&self) -> ModuleResult<pkcs1::RsaPublicKey<'_>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn ec_p256_public_key(&self) -> ModuleResult<p256::PublicKey> {
        Err(ModuleError::FunctionNotSupported)
    }
}

/// Insert a private key (`<base>`) and its paired public key (`<base>_pk`)
/// directly into the global `OBJECTS_STORE`, returning the two handles.
fn insert_test_key_pair(base: &str) {
    let sk: Arc<dyn PrivateKey> = Arc::new(DummyPrivateKey {
        remote_id: base.to_owned(),
    });
    let pk: Arc<dyn PublicKey> = Arc::new(DummyPublicKey {
        remote_id: format!("{base}_pk"),
    });
    let mut store = OBJECTS_STORE.write().unwrap();
    store.upsert(Arc::new(Object::PrivateKey(sk)));
    store.upsert(Arc::new(Object::PublicKey(pk)));
}

/// Open a serial session on the test slot.
fn open_test_session() -> CK_SESSION_HANDLE {
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );
    handle
}

/// Run a `C_FindObjectsInit`/`C_FindObjects`/`C_FindObjectsFinal` sequence for
/// the given class and `CKA_ID`, returning the matched object handles.
fn find_by_class_and_id(
    session: CK_SESSION_HANDLE,
    class: CK_OBJECT_CLASS,
    id: &[u8],
) -> Vec<CK_OBJECT_HANDLE> {
    let mut id = id.to_vec();
    let mut template = [
        CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: std::ptr::from_ref::<CK_OBJECT_CLASS>(&class) as CK_VOID_PTR,
            ulValueLen: std::mem::size_of_val(&class) as CK_ULONG,
        },
        CK_ATTRIBUTE {
            type_: CKA_ID,
            pValue: id.as_mut_ptr().cast::<std::ffi::c_void>(),
            ulValueLen: id.len() as CK_ULONG,
        },
    ];
    assert_eq!(
        unsafe { C_FindObjectsInit(session, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    let mut objects = [CK_OBJECT_HANDLE::default(); 8];
    let mut count: CK_ULONG = 0;
    assert_eq!(
        unsafe {
            C_FindObjects(
                session,
                objects.as_mut_ptr(),
                objects.len() as CK_ULONG,
                &raw mut count,
            )
        },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    objects[..count as usize].to_vec()
}

/// Assert that `handle` refers to a private key in the store.
fn assert_is_private_key(handle: CK_OBJECT_HANDLE) {
    let store = OBJECTS_STORE.read().unwrap();
    let object = store.get_using_handle(handle).unwrap();
    assert!(
        matches!(object.as_ref(), Object::PrivateKey(_)),
        "expected handle {handle} to be a private key, got {}",
        object.name()
    );
}

/// Issue #1076: a `CKO_PRIVATE_KEY` search by the *public* key's `CKA_ID`
/// (`<base>_pk`) must resolve to the private key, and `C_SignInit` must succeed.
#[test]
#[serial]
fn find_private_key_by_public_key_id_then_sign() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    insert_test_key_pair("issue1076");
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"issue1076_pk");
    assert_eq!(handles.len(), 1, "expected exactly one private key handle");
    assert_is_private_key(handles[0]);

    // C_SignInit must accept the private-key handle (previously CKR_KEY_HANDLE_INVALID).
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        unsafe { C_SignInit(session, &raw mut mechanism, handles[0]) },
        CKR_OK
    );

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// Regression: a `CKO_PRIVATE_KEY` search by the private key's own id resolves
/// to the private key.
#[test]
#[serial]
fn find_private_key_by_own_id() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    insert_test_key_pair("own_id_sk");
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"own_id_sk");
    assert_eq!(handles.len(), 1);
    assert_is_private_key(handles[0]);

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// Regression: a `CKO_PUBLIC_KEY` search by the public key's own id resolves to
/// the public key.
#[test]
#[serial]
fn find_public_key_by_own_id() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    insert_test_key_pair("pub_own_id");
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PUBLIC_KEY, b"pub_own_id_pk");
    assert_eq!(handles.len(), 1);
    let store = OBJECTS_STORE.read().unwrap();
    let object = store.get_using_handle(handles[0]).unwrap();
    assert!(matches!(object.as_ref(), Object::PublicKey(_)));
    drop(store);

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// A class-scoped search never returns a wrong-class object: searching for a
/// `CKO_PUBLIC_KEY` using the private key's id must return no object.
#[test]
#[serial]
fn find_public_key_by_private_key_id_returns_empty() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    insert_test_key_pair("class_mismatch");
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PUBLIC_KEY, b"class_mismatch");
    assert!(
        handles.is_empty(),
        "class-mismatched search must return no object, got {handles:?}"
    );

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// A search for a non-existent id returns no object and no error.
#[test]
#[serial]
fn find_private_key_by_unknown_id_returns_empty() {
    test_init();
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    insert_test_key_pair("present");
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"does_not_exist");
    assert!(handles.is_empty());

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

// ── Regression tests for issue #1111 ──────────────────────────────────────
// When `find_all_objects` (single system tags) misses the private key, a
// `CKO_PRIVATE_KEY` search by `CKA_ID` must fall back to the backend's
// `find_all_private_keys` (user-scoped combined tags like `["ssh-auth", "_sk"]`)
// rather than silently returning zero objects.

/// Test backend that returns a single named private key from
/// `find_all_private_keys`, with everything else empty. Used to simulate the
/// scenario where the KMS locate by system tags (`["_sk"]`) misses a key but
/// the user-tag-based locate (`["ssh-auth", "_sk"]`) succeeds.
struct FallbackBackend {
    private_key_id: String,
}

impl Backend for FallbackBackend {
    fn token_label(&self) -> [u8; 32] {
        *b"Fallback test token             "
    }

    fn token_manufacturer_id(&self) -> [u8; 32] {
        *b"Test manufacturer               "
    }

    fn token_model(&self) -> [u8; 16] {
        *b"test model      "
    }

    fn token_serial_number(&self) -> [u8; 16] {
        *b"1234567890abcdef"
    }

    fn library_description(&self) -> [u8; 32] {
        *b"Fallback test library           "
    }

    fn library_version(&self) -> Version {
        Version { major: 1, minor: 0 }
    }

    fn find_certificate(
        &self,
        _query: SearchOptions,
    ) -> ModuleResult<Option<Arc<dyn Certificate>>> {
        Ok(None)
    }

    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>> {
        Ok(vec![Arc::new(DummyPrivateKey {
            remote_id: self.private_key_id.clone(),
        })])
    }

    fn find_public_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![])
    }

    fn find_data_object(&self, _query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>> {
        Ok(None)
    }

    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>> {
        Ok(vec![])
    }

    fn find_symmetric_key(&self, _query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Err(ModuleError::FunctionNotSupported)
    }

    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>> {
        Ok(vec![])
    }

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _key_length: usize,
        _sensitive: bool,
        _label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>> {
        Ok(Arc::new(DummySymKey {}))
    }

    fn create_object(&self, label: &str, data: &[u8]) -> ModuleResult<Arc<dyn DataObject>> {
        Ok(Arc::new(DummyDataObject::new(label, data)))
    }

    fn revoke_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn destroy_object(&self, _remote_id: &str) -> ModuleResult<()> {
        Ok(())
    }

    fn encrypt(&self, _encrypt_ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>> {
        Ok(vec![0; cleartext.len() + AES_IV_SIZE])
    }

    fn decrypt(
        &self,
        _decrypt_ctx: &DecryptContext,
        _data: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(vec![0; 32]))
    }

    fn remote_sign(
        &self,
        _remote_id: &str,
        _algorithm: &SignatureAlgorithm,
        _data: &[u8],
    ) -> ModuleResult<Vec<u8>> {
        Err(ModuleError::FunctionNotSupported)
    }
}

/// Register a backend whose `find_all_private_keys` returns the given key id
/// and whose other `find_all_*` methods return empty sets.
fn register_fallback_backend(key_id: &str) {
    register_backend(Box::new(FallbackBackend {
        private_key_id: key_id.to_owned(),
    }));
}

/// Issue #1111 — happy path: the store is empty after `find_all_objects`
/// (single system tags missed the key) but the backend fallback
/// (`find_all_private_keys` → user-scoped combined tags) finds the private
/// key.  A `CKO_PRIVATE_KEY` search by the *public* key's `CKA_ID`
/// (`<base>_pk`) — the exact pattern OpenSSH uses — must resolve to the
/// private key handle, and `C_SignInit` must accept it.
#[test]
#[serial]
fn fallback_finds_private_key_by_public_key_id() {
    test_init();
    register_fallback_backend("fb1_sk");
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let session = open_test_session();

    // Search with the public key's CKA_ID — has _pk suffix.
    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"fb1_sk_pk");
    assert_eq!(
        handles.len(),
        1,
        "fallback should find the private key via _pk suffix stripping"
    );
    assert_is_private_key(handles[0]);

    // C_SignInit must accept the handle resolved via the fallback.
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ECDSA,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    assert_eq!(
        unsafe { C_SignInit(session, &raw mut mechanism, handles[0]) },
        CKR_OK
    );

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// Issue #1111 — a `CKO_PRIVATE_KEY` search by the private key's **own**
/// (base) id also succeeds through the fallback when the initial store
/// lookup fails.
#[test]
#[serial]
fn fallback_finds_private_key_by_own_id() {
    test_init();
    register_fallback_backend("fb2_sk");
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let session = open_test_session();

    // Search with the exact base id — no _pk suffix.
    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"fb2_sk");
    assert_eq!(
        handles.len(),
        1,
        "fallback should find the private key by exact base id"
    );
    assert_is_private_key(handles[0]);

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// Issue #1111 — when BOTH the initial store lookup and the backend fallback
/// return nothing, a `CKO_PRIVATE_KEY` search returns zero objects (not an
/// error).  This is the graceful-degradation path.
#[test]
#[serial]
fn fallback_returns_zero_when_backend_also_empty() {
    test_init();
    // Use the default TestBackend which returns empty for everything.
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PRIVATE_KEY, b"no_such_key_pk");
    assert!(
        handles.is_empty(),
        "search for non-existent key must return 0 objects, got {handles:?}",
    );

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}

/// Issue #1111 — the fallback is only triggered for `CKO_PRIVATE_KEY` searches.
/// A `CKO_PUBLIC_KEY` search by id must NOT trigger the fallback (the fallback
/// guard is `search_class == CKO_PRIVATE_KEY`), so a missing public key still
/// returns zero objects.
#[test]
#[serial]
fn no_fallback_for_non_private_key_class() {
    test_init();
    // Register a fallback backend to confirm it is NOT consulted for
    // CKO_PUBLIC_KEY searches.
    register_fallback_backend("fb3_sk");
    assert_eq!(C_Initialize(ptr::null_mut()), CKR_OK);
    let session = open_test_session();

    let handles = find_by_class_and_id(session, CKO_PUBLIC_KEY, b"fb3_sk_pk");
    assert!(
        handles.is_empty(),
        "CKO_PUBLIC_KEY search must not trigger the CKO_PRIVATE_KEY-only fallback"
    );

    assert_eq!(C_CloseSession(session), CKR_OK);
    assert_eq!(C_Finalize(ptr::null_mut()), CKR_OK);
}
