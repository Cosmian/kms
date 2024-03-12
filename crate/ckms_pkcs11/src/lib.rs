use std::ptr::addr_of_mut;
use native_pkcs11::{inititalize_logging, CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};

mod backend;
mod export_object;
mod kms_client;
// mod log;
// mod tests;

/// # Safety
/// This function is called by the PKCS#11 library to get the function list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    inititalize_logging("ckms-pkcs11.log", None, None);
    native_pkcs11_traits::register_backend(Box::new(backend::CkmsBackend::new()));
    unsafe { *pp_function_list = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}
