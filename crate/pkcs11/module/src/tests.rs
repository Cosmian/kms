use std::{
    ptr,
    ptr::addr_of_mut,
    sync::{Arc, Once},
};

use pkcs11_sys::{
    CKA_CLASS, CKM_DSA, CKO_PRIVATE_KEY, CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL,
    CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_NOT_PARALLEL,
    CKR_MECHANISM_INVALID, CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID,
    CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SLOT_ID_INVALID, CK_ATTRIBUTE, CK_C_INITIALIZE_ARGS,
    CK_FALSE, CK_INVALID_HANDLE,
};
use serial_test::serial;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use zeroize::Zeroizing;

use super::*;
use crate::traits::{
    register_backend, Backend, Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm,
    PrivateKey, PublicKey, RemoteObjectId, SearchOptions, Version,
};

static TRACING_INIT: Once = Once::new();
pub(crate) fn initialize_logging() {
    TRACING_INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(Level::INFO) // Adjust the level as needed
            .with_writer(std::io::stdout)
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("Setting default subscriber failed");
    });
}

struct TestBackend {}

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

    fn find_certificate(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn Certificate>>> {
        Ok(None)
    }

    fn find_all_certificates(&self) -> MResult<Vec<Arc<dyn Certificate>>> {
        Ok(vec![])
    }

    fn find_private_key(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn RemoteObjectId>>> {
        Ok(None)
    }

    fn find_public_key(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn PublicKey>>> {
        Ok(None)
    }

    fn find_all_private_keys(&self) -> MResult<Vec<Arc<dyn RemoteObjectId>>> {
        Ok(vec![])
    }

    fn find_all_public_keys(&self) -> MResult<Vec<Arc<dyn PublicKey>>> {
        Ok(vec![])
    }

    fn find_data_object(&self, _query: SearchOptions) -> MResult<Option<Arc<dyn DataObject>>> {
        Ok(None)
    }

    fn find_all_data_objects(&self) -> MResult<Vec<Arc<dyn DataObject>>> {
        Ok(vec![])
    }

    fn generate_key(
        &self,
        _algorithm: KeyAlgorithm,
        _label: Option<&str>,
    ) -> MResult<Arc<dyn PrivateKey>> {
        todo!()
    }

    fn decrypt(
        &self,
        _remote_object: Arc<dyn RemoteObjectId>,
        _algorithm: EncryptionAlgorithm,
        _data: Vec<u8>,
    ) -> MResult<Zeroizing<Vec<u8>>> {
        Ok(Zeroizing::new(Vec::new()))
    }
}

cryptoki_fn!(
    unsafe fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) {
        not_null!(ppFunctionList);
        unsafe { *ppFunctionList = addr_of_mut!(FUNC_LIST) };
        register_backend(Box::new(TestBackend {}));
        Ok(())
    }
);

pub(crate) fn test_init() {
    initialize_logging();
    if !INITIALIZED.load(Ordering::SeqCst) {
        let mut func_list: &mut CK_FUNCTION_LIST = &mut Default::default();
        // Update the function list with this PKCS#11 entry function
        func_list.C_GetFunctionList = Some(C_GetFunctionList);
        unsafe { C_GetFunctionList(std::ptr::addr_of_mut!(func_list) as *mut _) };
    }
}

#[test]
#[serial]
fn get_initialize() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        { C_Initialize(ptr::null_mut()) },
        CKR_CRYPTOKI_ALREADY_INITIALIZED
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    let mut args = CK_C_INITIALIZE_ARGS::default();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_OK
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    args.pReserved = (1 as *mut u32).cast::<std::ffi::c_void>();
    assert_eq!(
        { C_Initialize((&mut args as CK_C_INITIALIZE_ARGS_PTR).cast::<std::ffi::c_void>()) },
        CKR_ARGUMENTS_BAD
    );
}

#[test]
#[serial]
fn finalize() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pReserved is not null.
    assert_eq!(
        { C_Finalize((1 as *mut u32).cast::<std::ffi::c_void>()) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        { C_Finalize(ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_info() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut info = CK_INFO::default();
    assert_eq!(unsafe { C_GetInfo(&mut info) }, CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(unsafe { C_GetInfo(ptr::null_mut()) }, CKR_ARGUMENTS_BAD);
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetInfo(&mut info) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_function_list() {
    test_init();
    let mut function_list = CK_FUNCTION_LIST::default();
    let mut function_list_pointer: *mut CK_FUNCTION_LIST = &mut function_list;
    assert_eq!(
        unsafe { C_GetFunctionList(&mut function_list_pointer) },
        CKR_OK
    );
    // Expect CKR_ARGUMENTS_BAD if ppFunctionList is null.
    assert_eq!(
        unsafe { C_GetFunctionList(ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
}

#[test]
#[serial]
fn get_slot_list() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut count = 0;
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count) },
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
        unsafe { C_GetSlotList(CK_FALSE, slot_list.as_mut_ptr(), &mut count) },
        CKR_BUFFER_TOO_SMALL
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetSlotList(CK_FALSE, ptr::null_mut(), &mut count) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_slot_info() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut slot_info = CK_SLOT_INFO::default();
    assert_eq!(unsafe { C_GetSlotInfo(SLOT_ID, &mut slot_info) }, CKR_OK);
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetSlotInfo(SLOT_ID, ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_GetSlotInfo(SLOT_ID + 1, ptr::null_mut()) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetSlotInfo(SLOT_ID, &mut slot_info) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_token_info() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()) },
        CKR_OK
    );
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_GetTokenInfo(SLOT_ID + 1, ptr::null_mut()) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetSlotInfo(SLOT_ID, ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetTokenInfo(SLOT_ID, &mut CK_TOKEN_INFO::default()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_mechanism_list() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut count = 0;
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), &mut count) },
        CKR_OK
    );
    assert_ne!(count, 0);
    let mut mechanisms = Vec::<CK_MECHANISM_TYPE>::with_capacity(count as usize);
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut count) },
        CKR_OK
    );
    unsafe {
        mechanisms.set_len(count as usize);
    }
    assert_eq!(mechanisms, *SUPPORTED_SIGNATURE_MECHANISMS);
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID + 1, ptr::null_mut(), &mut count) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pulCount is null.
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_BUFFER_TOO_SMALL if pulCount is less than the number of
    // mechanisms.
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID, mechanisms.as_mut_ptr(), &mut (count - 1)) },
        CKR_BUFFER_TOO_SMALL
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetMechanismList(SLOT_ID, ptr::null_mut(), ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn get_mechanism_info() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut info = CK_MECHANISM_INFO::default();
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], &mut info,) },
        CKR_OK
    );
    // Expect CKR_MECHANISM_INVALID if type is an unsupported mechanism.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, CKM_DSA, &mut info) },
        CKR_MECHANISM_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    // Expect CKR_CRYPTOKI_NOT_INITIALIZED if token is not initialized.
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetMechanismInfo(SLOT_ID, SUPPORTED_SIGNATURE_MECHANISMS[0], ptr::null_mut(),) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn open_session() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let flags = CKF_SERIAL_SESSION;
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, &mut handle) },
        CKR_OK
    );
    // Expect CKR_SLOT_ID_INVALID if slotID references a nonexistent slot.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID + 1, flags, ptr::null_mut(), None, &mut handle,) },
        CKR_SLOT_ID_INVALID
    );
    // Expect CKR_SESSION_PARALLEL_NOT_SUPPORTED if CKF_SERIAL_SESSION flag
    // is not set.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, 0, ptr::null_mut(), None, &mut handle) },
        CKR_SESSION_PARALLEL_NOT_SUPPORTED
    );
    // Expect CKR_ARGUMENTS_BAD if phSession is null.
    assert_eq!(
        unsafe { C_OpenSession(SLOT_ID, flags, ptr::null_mut(), None, ptr::null_mut(),) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!({ C_CloseSession(handle) }, CKR_OK);
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
}

#[test]
#[serial]
fn close_session() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    assert_eq!({ C_CloseSession(handle) }, CKR_OK);
    // Expect CKR_SESSION_HANDLE_INVALID if the session has already been closed.
    assert_eq!({ C_CloseSession(handle) }, CKR_SESSION_HANDLE_INVALID);
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        { C_CloseSession(CK_INVALID_HANDLE) },
        CKR_SESSION_HANDLE_INVALID
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
}

#[test]
#[serial]
fn get_session_info() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut session_info = CK_SESSION_INFO::default();
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, &mut session_info) },
        CKR_OK
    );
    // Expect CKR_SESSION_HANDLE_INVALID if hSession is not a valid handle.
    assert_eq!(
        unsafe { C_GetSessionInfo(CK_INVALID_HANDLE, &mut session_info) },
        CKR_SESSION_HANDLE_INVALID
    );
    // Expect CKR_ARGUMENTS_BAD if pInfo is null.
    assert_eq!(
        unsafe { C_GetSessionInfo(handle, ptr::null_mut()) },
        CKR_ARGUMENTS_BAD
    );
    assert_eq!({ C_CloseSession(handle) }, CKR_OK);
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
}

#[test]
#[serial]
fn get_attribute_value() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
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
        CKR_OPERATION_NOT_INITIALIZED
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_GetAttributeValue(session_h, 0, template.as_mut_ptr(), 0) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_init() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &CKO_PRIVATE_KEY as *const CK_ULONG as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &CKO_PRIVATE_KEY as *const CK_ULONG as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    let mut objects = vec![CK_OBJECT_HANDLE::default()];
    let mut count = 0;
    assert_eq!(
        unsafe { C_FindObjects(handle, objects.as_mut_ptr(), 1, &mut count) },
        CKR_OK
    );
    assert_eq!(count, 0);
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!(
        unsafe { C_FindObjects(handle, ptr::null_mut(), 0, ptr::null_mut()) },
        CKR_CRYPTOKI_NOT_INITIALIZED
    );
}

#[test]
#[serial]
fn find_objects_final() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut handle,
            )
        },
        CKR_OK
    );
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &CKO_PRIVATE_KEY as *const CK_ULONG as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&CKO_PRIVATE_KEY) as CK_ULONG,
    }];
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template.len() as CK_ULONG) },
        CKR_OK
    );
    assert_eq!({ C_FindObjectsFinal(handle) }, CKR_OK);
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
    assert_eq!({ C_FindObjectsFinal(handle) }, CKR_CRYPTOKI_NOT_INITIALIZED);
}
#[test]
#[serial]
fn get_function_status() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
}

#[test]
#[serial]
fn cancel_function() {
    test_init();
    assert_eq!({ C_Initialize(ptr::null_mut()) }, CKR_OK);
    let mut session_h = CK_INVALID_HANDLE;
    assert_eq!(
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                ptr::null_mut(),
                None,
                &mut session_h,
            )
        },
        CKR_OK
    );
    assert_eq!(
        { C_GetFunctionStatus(session_h) },
        CKR_FUNCTION_NOT_PARALLEL
    );
    assert_eq!({ C_Finalize(ptr::null_mut()) }, CKR_OK);
}
