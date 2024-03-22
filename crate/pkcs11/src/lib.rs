use std::ptr::addr_of_mut;

use native_pkcs11::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};

use crate::{logging::initialize_logging, pkcs_11_data_object::get_kms_client};

mod backend;
mod error;
mod logging;
mod pkcs_11_data_object;

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    initialize_logging("ckms-pkcs11.log", None, None);
    // Instantiate a backend with a kms client using the `kms.json` file in the local default directory.
    native_pkcs11_traits::register_backend(Box::new(
        backend::CkmsBackend::instantiate(
            get_kms_client()
                .expect("failed instantiating the KMS client with the current configuration"),
        )
        .expect("Failed to instantiate backend."),
    ));
    // Update the function list with this PKCS#11 entry function
    FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
    // Return the function list to the client application using the output parameters
    unsafe { *pp_function_list = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}

#[cfg(test)]
mod tests;
