use std::{ptr::addr_of_mut, str::FromStr};

use cosmian_pkcs11_module::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};
use tracing::Level;

use crate::{kms_object::get_kms_client, logging::initialize_logging};

mod backend;
mod error;
mod kms_object;
mod logging;
mod pkcs11_certificate;
mod pkcs11_data_object;
mod pkcs11_private_key;

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    let debug_level =
        std::env::var("COSMIAN_PKCS11_LOGGING_LEVEL").unwrap_or_else(|_| "info".to_owned());
    initialize_logging("ckms-pkcs11", Level::from_str(&debug_level).ok(), None);
    // Instantiate a backend with a kms client using the `kms.json` file in the local default directory.
    cosmian_pkcs11_module::traits::register_backend(Box::new(backend::CkmsBackend::instantiate(
        get_kms_client()
            .expect("failed instantiating the KMS client with the current configuration"),
    )));
    // Update the function list with this PKCS#11 entry function
    FUNC_LIST.C_GetFunctionList = Some(C_GetFunctionList);
    // Return the function list to the client application using the output parameters
    unsafe { *pp_function_list = addr_of_mut!(FUNC_LIST) };
    CKR_OK
}

#[cfg(test)]
mod tests;
