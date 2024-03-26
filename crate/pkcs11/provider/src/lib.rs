use std::ptr::addr_of_mut;

use pkcs11_module::{CKR_OK, CK_FUNCTION_LIST_PTR_PTR, CK_RV, FUNC_LIST};

use crate::{kms_object::get_kms_client, logging::initialize_logging};

mod backend;
mod error;
mod logging;
mod pkcs11_data_object;

/// # Safety
/// This function is the first one called by the PKCS#11 library client
/// to get the PKCS#11 functions list.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(pp_function_list: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
    initialize_logging("ckms-pkcs11.log", Some("/home/bgrieder".to_string()), None);
    // Instantiate a backend with a kms client using the `kms.json` file in the local default directory.
    pkcs11_module::traits::register_backend(Box::new(
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

mod kms_object;
#[cfg(test)]
mod tests;

// // Default tracing using syslog or stderr
// #[cfg(any(not(feature = "custom-function-list"), feature = "local_tests"))]
// fn enable_tracing() {
//     let env_filter = EnvFilter::builder()
//         .with_default_directive(LevelFilter::WARN.into())
//         .from_env_lossy();
//     let force_stderr = std::env::var("NATIVE_PKCS11_LOG_STDERR").is_ok();
//     if !force_stderr {
//         if let Ok(journald_layer) = tracing_journald::layer() {
//             _ = Registry::default()
//                 .with(journald_layer.with_syslog_identifier("native-pkcs11".into()))
//                 .with(env_filter)
//                 .with(ErrorLayer::default())
//                 .try_init();
//             return;
//         }
//     }
//     _ = Registry::default()
//         .with(
//             tracing_subscriber::fmt::layer()
//                 .with_writer(std::io::stderr)
//                 .with_span_events(FmtSpan::ENTER),
//         )
//         .with(env_filter)
//         .with(ErrorLayer::default())
//         .try_init();
// }
