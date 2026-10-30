use std::sync::Arc;

use cosmian_kms_base_hsm::HsmLib;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::kmip_operations::{PKCS11, PKCS11Function, PKCS11Response, PKCS11ReturnCode},
};
use cosmian_logger::trace;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Name of the default PKCS#11 V3.0 interface (the only one served).
const DEFAULT_PKCS11_INTERFACE: &str = "PKCS 11";

/// PKCS#11 operation implementation
///
/// This operation enables the server to perform a PKCS#11 operation following
/// the KMIP 2.1 specification (section 6.1.37).
///
/// The implementation uses real PKCS#11 calls via the HSM interface:
/// - `C_Initialize`: Initialize PKCS#11 library (via HSM)
/// - `C_GetInfo`: Get library information (via HSM)
/// - `C_Finalize`: Finalize PKCS#11 library (via HSM)
/// - Other functions: answered with `CKR_FUNCTION_NOT_SUPPORTED`
///
/// According to the KMIP spec:
/// - PKCS#11 Interface: Optional - only the default V3.0 interface is served
/// - PKCS#11 Function: REQUIRED - The function to perform
/// - Correlation Value: Optional - Must be returned if provided in previous response
/// - PKCS#11 Input Parameters: Optional - Parameters to the function
///
/// Response includes:
/// - PKCS#11 Function: REQUIRED - The function that was performed
/// - PKCS#11 Return Code: REQUIRED - The PKCS#11 return code
/// - Correlation Value: Optional - Server-defined value for client to return next
/// - PKCS#11 Output Parameters: Optional - Parameters output from the function
pub(crate) async fn pkcs11(kms: &KMS, request: PKCS11, _user: &UserId) -> KResult<PKCS11Response> {
    trace!("function={:?}", request.pkcs11_function);

    // PKCS#11 Function is REQUIRED (KMIP 2.1 Table 273)
    let func = request.pkcs11_function.ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Invalid_Field,
            "PKCS#11: the PKCS#11 Function is required".to_owned(),
        )
    })?;

    // Only the default V3.0 interface is supported (KMIP 2.1 Table 273)
    if let Some(interface) = request.pkcs11_interface.as_deref() {
        if interface != DEFAULT_PKCS11_INTERFACE {
            return Err(KmsError::Kmip21Error(
                ErrorReason::PKCS_11_Invalid_Interface,
                format!("PKCS#11: unsupported interface '{interface}'"),
            ));
        }
    }

    // Generate or use provided correlation value
    // According to spec: "Must be returned to the server if provided in a previous response"
    let correl = request
        .correlation_value
        .unwrap_or_else(|| b"PKCS11CV".to_vec());

    // Require HSM for all PKCS#11 operations
    let hsm = kms.hsm.as_ref().ok_or_else(|| {
        KmsError::Kmip21Error(
            ErrorReason::Feature_Not_Supported,
            "PKCS#11 operations require HSM to be configured".to_owned(),
        )
    })?;

    // Get the underlying HsmLib for direct PKCS#11 function calls
    let hsm_lib = hsm
        .hsm_lib()
        .and_then(|any| any.downcast_ref::<Arc<HsmLib>>())
        .ok_or_else(|| {
            KmsError::Kmip21Error(
                ErrorReason::Feature_Not_Supported,
                "HSM does not support PKCS#11 operations".to_owned(),
            )
        })?;

    match func {
        PKCS11Function::C_Initialize => {
            // Call C_Initialize directly on HsmLib
            // Note: The library may already be initialized from instantiation
            match HsmLib::initialize(hsm_lib) {
                Ok(()) => Ok(PKCS11Response {
                    pkcs11_interface: None,
                    pkcs11_function: Some(func),
                    pkcs11_output_parameters: None,
                    pkcs11_return_code: Some(PKCS11ReturnCode::OK),
                    correlation_value: Some(correl),
                }),
                Err(e) => {
                    let error_msg = e.to_string();
                    // Check if already initialized (return code 401 = 0x191 = CKR_CRYPTOKI_ALREADY_INITIALIZED)
                    let return_code = if error_msg.contains("Return code: 401")
                        || error_msg.contains("already initialized")
                        || error_msg.contains("CKR_CRYPTOKI_ALREADY_INITIALIZED")
                    {
                        // Library already initialized - return OK per KMIP test expectations
                        trace!(
                            "PKCS#11 `C_Initialize` called on already initialized library - treating as success"
                        );
                        PKCS11ReturnCode::OK
                    } else {
                        trace!("PKCS#11 `C_Initialize` failed: {e}");
                        PKCS11ReturnCode::CKR_GENERAL_ERROR
                    };
                    Ok(PKCS11Response {
                        pkcs11_interface: None,
                        pkcs11_function: Some(func),
                        pkcs11_output_parameters: None,
                        pkcs11_return_code: Some(return_code),
                        correlation_value: Some(correl),
                    })
                }
            }
        }
        PKCS11Function::C_GetInfo => {
            // Get real PKCS#11 info from HsmLib via `C_GetInfo`
            match hsm_lib.get_info() {
                Ok(output) => Ok(PKCS11Response {
                    pkcs11_interface: None,
                    pkcs11_function: Some(func),
                    pkcs11_output_parameters: if output.is_empty() {
                        None
                    } else {
                        Some(output)
                    },
                    pkcs11_return_code: Some(PKCS11ReturnCode::OK),
                    correlation_value: Some(correl),
                }),
                Err(e) => {
                    // Check if error is due to not being initialized
                    let error_msg = e.to_string();
                    let return_code = if error_msg.contains("not initialized")
                        || error_msg.contains("CKR_CRYPTOKI_NOT_INITIALIZED")
                    {
                        PKCS11ReturnCode::CKR_CRYPTOKI_NOT_INITIALIZED
                    } else {
                        PKCS11ReturnCode::CKR_GENERAL_ERROR
                    };
                    trace!("PKCS#11 `C_GetInfo` failed: {e}");
                    Ok(PKCS11Response {
                        pkcs11_interface: None,
                        pkcs11_function: Some(func),
                        pkcs11_output_parameters: None,
                        pkcs11_return_code: Some(return_code),
                        correlation_value: Some(correl),
                    })
                }
            }
        }
        PKCS11Function::C_Finalize => {
            // Call `C_Finalize` directly on HsmLib
            match hsm_lib.finalize() {
                Ok(()) => Ok(PKCS11Response {
                    pkcs11_interface: None,
                    pkcs11_function: Some(func),
                    pkcs11_output_parameters: None,
                    pkcs11_return_code: Some(PKCS11ReturnCode::OK),
                    // Per spec, correlation value is not returned on Finalize
                    correlation_value: None,
                }),
                Err(e) => {
                    trace!("PKCS#11 `C_Finalize` failed: {e}");
                    Ok(PKCS11Response {
                        pkcs11_interface: None,
                        pkcs11_function: Some(func),
                        pkcs11_output_parameters: None,
                        pkcs11_return_code: Some(PKCS11ReturnCode::CKR_GENERAL_ERROR),
                        correlation_value: Some(correl),
                    })
                }
            }
        }
        // Every other function of CK_FUNCTION_LIST_3_0 is not implemented by the server.
        _ => {
            trace!("PKCS#11 `{func:?}` not implemented");
            Ok(PKCS11Response {
                pkcs11_interface: None,
                pkcs11_function: Some(func),
                pkcs11_output_parameters: None,
                pkcs11_return_code: Some(PKCS11ReturnCode::CKR_FUNCTION_NOT_SUPPORTED),
                correlation_value: Some(correl),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::ErrorReason,
        kmip_2_1::kmip_operations::{PKCS11, PKCS11Function},
    };

    use super::pkcs11;
    use crate::{error::KmsError, middlewares::UserId, tests::test_utils::test_kms};

    async fn reason(request: PKCS11) -> Result<Option<ErrorReason>, String> {
        let kms = test_kms().await.map_err(|e| e.to_string())?;
        match pkcs11(&kms, request, &UserId::from("pkcs11-test@example.com")).await {
            Err(KmsError::Kmip21Error(reason, _)) => Ok(Some(reason)),
            Err(error) => Err(error.to_string()),
            Ok(_) => Ok(None),
        }
    }

    #[tokio::test]
    async fn function_is_required() {
        assert_eq!(
            reason(PKCS11 {
                pkcs11_interface: None,
                pkcs11_function: None,
                pkcs11_input_parameters: None,
                correlation_value: None,
            })
            .await,
            Ok(Some(ErrorReason::Invalid_Field))
        );
    }

    #[tokio::test]
    async fn unknown_interface_is_rejected() {
        assert_eq!(
            reason(PKCS11 {
                pkcs11_interface: Some("PKCS 12".to_owned()),
                pkcs11_function: Some(PKCS11Function::C_Initialize),
                pkcs11_input_parameters: None,
                correlation_value: None,
            })
            .await,
            Ok(Some(ErrorReason::PKCS_11_Invalid_Interface))
        );
    }

    #[tokio::test]
    async fn without_hsm_the_feature_is_not_supported() {
        assert_eq!(
            reason(PKCS11 {
                pkcs11_interface: None,
                pkcs11_function: Some(PKCS11Function::C_GetInfo),
                pkcs11_input_parameters: None,
                correlation_value: None,
            })
            .await,
            Ok(Some(ErrorReason::Feature_Not_Supported))
        );
    }
}
