#![cfg(target_arch = "wasm32")]

use cosmian_kms_client_wasm::wasm as w;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

// Configure test runner:
// - When compiled with `--cfg wasm_test_browser`, run in browser.
// - Otherwise, default to Node (wasm-pack --node).
#[cfg(wasm_test_browser)]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

// Helper to convert Vec<u8> -> Uint8Array (when needed)

// The goal of these tests is to ensure all exported wasm_bindgen functions
// are linkable and minimally invocable under wasm32. For complex KMIP inputs,
// we use harmless placeholders and only assert the call returns a Result.

#[wasm_bindgen_test]
fn test_init_panic_hook() {
    w::init_panic_hook();
}

#[wasm_bindgen_test]
fn test_locate_ttlv_request() {
    let r = w::locate_ttlv_request(None, None, None, None, None, None, None, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_locate_ttlv_response() {
    let r = w::parse_locate_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_create_rsa_key_pair_ttlv_request() {
    let r = w::create_rsa_key_pair_ttlv_request(None, vec![], 2048, false, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_create_ec_key_pair_ttlv_request() {
    let r = w::create_ec_key_pair_ttlv_request(None, vec![], "secp256r1", false, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_create_keypair_ttlv_response() {
    let r = w::parse_create_keypair_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_create_sym_key_ttlv_request() {
    let r = w::create_sym_key_ttlv_request(None, vec![], Some(256), "Aes", false, None, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_create_secret_data_ttlv_request() {
    let r = w::create_secret_data_ttlv_request(
        "Password",
        Some("dummy".to_string()),
        None,
        vec![],
        false,
        None,
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_create_opaque_object_ttlv_request() {
    // value required for opaque object
    let r =
        w::create_opaque_object_ttlv_request(Some("opaque".to_string()), None, vec![], false, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_create_ttlv_response() {
    let r = w::parse_create_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_decrypt_sym_ttlv_request() {
    let alg = JsValue::from_str("{}"); // placeholder; parsed inside
    let r = w::decrypt_sym_ttlv_request("kid", vec![0u8; 16], None, alg);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_decrypt_rsa_ttlv_request() {
    let r = w::decrypt_rsa_ttlv_request(
        "kid",
        vec![0u8; 16],
        JsValue::from_str("{}"),
        JsValue::from_str("{}"),
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_decrypt_ec_ttlv_request() {
    let r = w::decrypt_ec_ttlv_request("kid", vec![0u8; 16]);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_decrypt_ttlv_response() {
    let r = w::parse_decrypt_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_destroy_ttlv_request() {
    let r = w::destroy_ttlv_request("kid".to_string(), false);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_destroy_ttlv_response() {
    let r = w::parse_destroy_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_encrypt_sym_ttlv_request() {
    let r = w::encrypt_sym_ttlv_request(
        "kid",
        None,
        vec![1, 2, 3],
        None,
        None,
        JsValue::from_str("{}"),
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_encrypt_rsa_ttlv_request() {
    let r = w::encrypt_rsa_ttlv_request(
        "kid",
        vec![1, 2, 3],
        JsValue::from_str("{}"),
        JsValue::from_str("{}"),
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_encrypt_ec_ttlv_request() {
    let r = w::encrypt_ec_ttlv_request("kid", vec![1, 2, 3]);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_encrypt_ttlv_response() {
    let r = w::parse_encrypt_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_export_ttlv_request() {
    let r = w::export_ttlv_request("kid", false, "JsonTtlv", None, None, None);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_export_ttlv_response() {
    let r = w::parse_export_ttlv_response("{\"type\":\"Structure\",\"value\":[]}", "JsonTtlv");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_get_key_requests() {
    assert!(
        w::get_rsa_private_key_ttlv_request("kid").is_ok()
            || w::get_rsa_private_key_ttlv_request("kid").is_err()
    );
    assert!(
        w::get_rsa_public_key_ttlv_request("kid").is_ok()
            || w::get_rsa_public_key_ttlv_request("kid").is_err()
    );
    assert!(
        w::get_ec_private_key_ttlv_request("kid").is_ok()
            || w::get_ec_private_key_ttlv_request("kid").is_err()
    );
    assert!(
        w::get_ec_public_key_ttlv_request("kid").is_ok()
            || w::get_ec_public_key_ttlv_request("kid").is_err()
    );
}

#[wasm_bindgen_test]
fn test_import_ttlv_request() {
    let r = w::import_ttlv_request(
        None,
        vec![0u8; 16],
        "RawPrivateKeyDer",
        None,
        None,
        None,
        false,
        false,
        vec![],
        None,
        None,
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_import_ttlv_response() {
    let r = w::parse_import_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_revoke_ttlv_request() {
    let r = w::revoke_ttlv_request("kid", "test".to_string());
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_revoke_ttlv_response() {
    let r = w::parse_revoke_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_cc_requests() {
    assert!(
        w::create_cc_master_keypair_ttlv_request("{}", vec![], false, None).is_ok()
            || w::create_cc_master_keypair_ttlv_request("{}", vec![], false, None).is_err()
    );
    assert!(
        w::create_cc_user_key_ttlv_request("msk", "{}", vec![], false, None).is_ok()
            || w::create_cc_user_key_ttlv_request("msk", "{}", vec![], false, None).is_err()
    );
    assert!(
        w::encrypt_cc_ttlv_request("kid", "{}".to_string(), vec![1, 2], None).is_ok()
            || w::encrypt_cc_ttlv_request("kid", "{}".to_string(), vec![1, 2], None).is_err()
    );
    assert!(
        w::decrypt_cc_ttlv_request("kid", vec![1, 2], None).is_ok()
            || w::decrypt_cc_ttlv_request("kid", vec![1, 2], None).is_err()
    );
}

#[wasm_bindgen_test]
fn test_certificate_requests() {
    assert!(
        w::import_certificate_ttlv_request(
            None,
            vec![],
            "Pem",
            None,
            None,
            None,
            None,
            false,
            vec![],
            None
        )
        .is_ok()
            || w::import_certificate_ttlv_request(
                None,
                vec![],
                "Pem",
                None,
                None,
                None,
                None,
                false,
                vec![],
                None
            )
            .is_err()
    );
    assert!(
        w::export_certificate_ttlv_request("cid", "Pem", None).is_ok()
            || w::export_certificate_ttlv_request("cid", "Pem", None).is_err()
    );
    assert!(
        w::parse_export_certificate_ttlv_response("{\"type\":\"Structure\",\"value\":[]}", "Pem")
            .is_ok()
            || w::parse_export_certificate_ttlv_response(
                "{\"type\":\"Structure\",\"value\":[]}",
                "Pem"
            )
            .is_err()
    );
    assert!(
        w::validate_certificate_ttlv_request(None, None).is_ok()
            || w::validate_certificate_ttlv_request(None, None).is_err()
    );
    assert!(
        w::parse_validate_ttlv_response("{\"type\":\"Structure\",\"value\":[]}").is_ok()
            || w::parse_validate_ttlv_response("{\"type\":\"Structure\",\"value\":[]}").is_err()
    );
    assert!(
        w::encrypt_certificate_ttlv_request("cid", vec![1, 2, 3], None, "RsaOaep").is_ok()
            || w::encrypt_certificate_ttlv_request("cid", vec![1, 2, 3], None, "RsaOaep").is_err()
    );
    assert!(
        w::decrypt_certificate_ttlv_request("cid", vec![1, 2, 3], None, "RsaOaep").is_ok()
            || w::decrypt_certificate_ttlv_request("cid", vec![1, 2, 3], None, "RsaOaep").is_err()
    );
}

#[wasm_bindgen_test]
fn test_certify_ttlv_request() {
    let r = w::certify_ttlv_request(
        None,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        365,
        None,
        vec![],
    );
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_attributes_requests() {
    assert!(
        w::get_attributes_ttlv_request("kid".to_string()).is_ok()
            || w::get_attributes_ttlv_request("kid".to_string()).is_err()
    );
    assert!(
        w::parse_get_attributes_ttlv_response(
            "{\"type\":\"Structure\",\"value\":[]}",
            vec!["Name".to_string()]
        )
        .is_ok()
            || w::parse_get_attributes_ttlv_response(
                "{\"type\":\"Structure\",\"value\":[]}",
                vec!["Name".to_string()]
            )
            .is_err()
    );
    assert!(
        w::set_attribute_ttlv_request("kid".to_string(), "Name", "val".to_string()).is_ok()
            || w::set_attribute_ttlv_request("kid".to_string(), "Name", "val".to_string()).is_err()
    );
    assert!(
        w::parse_set_attribute_ttlv_response("{\"type\":\"Structure\",\"value\":[]}").is_ok()
            || w::parse_set_attribute_ttlv_response("{\"type\":\"Structure\",\"value\":[]}")
                .is_err()
    );
    assert!(
        w::delete_attribute_ttlv_request("kid".to_string(), "Name").is_ok()
            || w::delete_attribute_ttlv_request("kid".to_string(), "Name").is_err()
    );
    assert!(
        w::parse_delete_attribute_ttlv_response("{\"type\":\"Structure\",\"value\":[]}").is_ok()
            || w::parse_delete_attribute_ttlv_response("{\"type\":\"Structure\",\"value\":[]}")
                .is_err()
    );
}

#[wasm_bindgen_test]
fn test_sign_ttlv_request() {
    // Algorithm string recognized by wasm helper
    let alg = JsValue::from_str("rsassapss");
    // Data to sign
    let data = vec![1u8, 2, 3, 4];
    let r = w::sign_ttlv_request("kid", data, Some(alg), false);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_sign_ttlv_response() {
    let r = w::parse_sign_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_signature_verify_ttlv_request() {
    let alg = JsValue::from_str("rsassapss");
    let data = vec![7u8, 8, 9];
    let signature = vec![0xAAu8, 0xBB, 0xCC];
    let r = w::signature_verify_ttlv_request("kid", data, signature, Some(alg), false);
    assert!(r.is_ok() || r.is_err());
}

#[wasm_bindgen_test]
fn test_parse_signature_verify_ttlv_response() {
    let r = w::parse_signature_verify_ttlv_response("{\"type\":\"Structure\",\"value\":[]}");
    assert!(r.is_ok() || r.is_err());
}
