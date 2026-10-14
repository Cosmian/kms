//! Characterization of the JOSE error responses at BASE.

use actix_web::{ResponseError, test as actix_test};

use super::{CryptoApiError, crypto_json_error_handler};

#[tokio::test]
async fn characterization_crypto_api_error_status_and_body() {
    for (e, status, display, body) in [
        (
            CryptoApiError::BadRequest("b".to_owned()),
            400_u16,
            "b",
            r#"{"error":"bad_request","description":"b"}"#,
        ),
        (
            CryptoApiError::UnsupportedAlgorithm("u".to_owned()),
            422,
            "u",
            r#"{"error":"unsupported_algorithm","description":"u"}"#,
        ),
        (
            CryptoApiError::Forbidden("f".to_owned()),
            403,
            "f",
            r#"{"error":"forbidden","description":"Access denied"}"#,
        ),
        (
            CryptoApiError::NotFound("n".to_owned()),
            404,
            "n",
            r#"{"error":"not_found","description":"Key not found"}"#,
        ),
        (
            CryptoApiError::CryptoFailure("c".to_owned()),
            422,
            "c",
            r#"{"error":"crypto_failure","description":"c"}"#,
        ),
        (
            CryptoApiError::DecryptionFailed,
            422,
            "Decryption failed",
            r#"{"error":"decryption_failed","description":"Decryption failed"}"#,
        ),
        (
            CryptoApiError::InternalError("i".to_owned()),
            500,
            "i",
            r#"{"error":"internal_error","description":"Internal server error"}"#,
        ),
    ] {
        assert_eq!(e.to_string(), display);
        let resp = e.error_response();
        assert_eq!(resp.status().as_u16(), status);
        let bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        assert_eq!(String::from_utf8(bytes.to_vec()).unwrap(), body);
    }
}

#[test]
fn characterization_crypto_json_error_handler_wraps_in_bad_request() {
    let err = crypto_json_error_handler(
        actix_web::error::JsonPayloadError::Deserialize(
            serde_json::from_str::<u8>("x").unwrap_err(),
        ),
        &actix_test::TestRequest::default().to_http_request(),
    );
    assert_eq!(err.as_response_error().status_code().as_u16(), 400);
    assert_eq!(
        err.to_string(),
        "Invalid request body: Json deserialize error: expected value at line 1 column 1"
    );
}
