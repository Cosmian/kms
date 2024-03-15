use std::ptr::addr_of_mut;

use native_pkcs11::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};

use crate::logging::inititalize_logging;

mod backend;
// mod export_object;
mod error;
#[allow(dead_code)]
mod kms_client;
mod logging;
// mod tests;

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    inititalize_logging("ckms-pkcs11.log", None, None);
    native_pkcs11_traits::register_backend(Box::new(
        backend::CkmsBackend::instantiate().expect("Failed to instantiate backend."),
    ));
    unsafe { *pp_function_list = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}

#[cfg(test)]
mod tests;
