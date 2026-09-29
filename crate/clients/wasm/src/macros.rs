/// Serialize any KMIP request to a TTLV `JsValue` suitable for `sendKmipRequest()`.
///
/// This replaces the repeated two-line suffix found in 70+ WASM binding functions:
/// ```ignore
/// let objects = to_ttlv(&request).map_err(|e| JsValue::from(e.to_string()))?;
/// serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
/// ```
pub(crate) fn to_wasm_ttlv(request: &impl serde::Serialize) -> Result<JsValue, JsValue> {
    use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::to_ttlv;
    let objects = to_ttlv(request).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&objects).map_err(|e| JsValue::from(e.to_string()))
}

/// Parse a TTLV JSON response string into a typed KMIP response, then serialize to `JsValue`.
///
/// This replaces the `parse_ttlv_response::<T>(response)` helper by making it public
/// within the crate for direct use.
pub(crate) fn parse_ttlv_to_jsvalue<T: serde::de::DeserializeOwned + serde::Serialize>(
    response: &str,
) -> Result<JsValue, JsValue> {
    use cosmian_kms_client_utils::reexport::cosmian_kmip::ttlv::{TTLV, from_ttlv};
    let ttlv: TTLV = serde_json::from_str(response).map_err(|e| JsValue::from(e.to_string()))?;
    let parsed: T = from_ttlv(ttlv).map_err(|e| JsValue::from(e.to_string()))?;
    serde_wasm_bindgen::to_value(&parsed).map_err(|e| JsValue::from(e.to_string()))
}

use wasm_bindgen::prelude::JsValue;

/// Generate a `#[wasm_bindgen]` response parser function.
///
/// Usage:
/// ```ignore
/// wasm_response_parser!(parse_encrypt_ttlv_response, EncryptResponse);
/// ```
/// Expands to:
/// ```ignore
/// #[wasm_bindgen]
/// pub fn parse_encrypt_ttlv_response(response: &str) -> Result<JsValue, JsValue> {
///     crate::macros::parse_ttlv_to_jsvalue::<EncryptResponse>(response)
/// }
/// ```
macro_rules! wasm_response_parser {
    ($fn_name:ident, $response_type:ty) => {
        #[wasm_bindgen]
        pub fn $fn_name(response: &str) -> Result<JsValue, JsValue> {
            $crate::macros::parse_ttlv_to_jsvalue::<$response_type>(response)
        }
    };
}

pub(crate) use wasm_response_parser;
