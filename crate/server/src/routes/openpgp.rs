use actix_web::web;
#[cfg(feature = "non-fips")]
use actix_web::{HttpResponse, post};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::openpgp::openpgp_key_to_binary;

#[cfg(feature = "non-fips")]
use crate::error::KmsError;
#[cfg(feature = "non-fips")]
use crate::result::KResult;

/// Registers the `OpenPGP` endpoint when `non-fips` support is enabled.
#[cfg(feature = "non-fips")]
pub(crate) fn configure(config: &mut web::ServiceConfig) {
    config.service(openpgp_key_to_binary_endpoint);
}

/// `OpenPGP` is unavailable in FIPS builds; keep the crypto scope configuration shared.
#[cfg(not(feature = "non-fips"))]
pub(crate) const fn configure(_config: &mut web::ServiceConfig) {}

/// Converts an armored or binary transferable key to binary packet bytes.
#[cfg(feature = "non-fips")]
#[post("/openpgp/binary")]
async fn openpgp_key_to_binary_endpoint(body: web::Bytes) -> KResult<HttpResponse> {
    let mut binary = openpgp_key_to_binary(&body)
        .map_err(|error| KmsError::InvalidRequest(error.to_string()))?;
    let body = std::mem::take(&mut *binary);

    Ok(HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(body))
}

#[cfg(all(test, feature = "non-fips"))]
mod tests {
    use actix_web::{App, http::StatusCode, test};
    use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::openpgp::{
        PgpKeyProfile, generate_openpgp_secret_key, openpgp_normalize,
    };

    use super::openpgp_key_to_binary_endpoint;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn check(condition: bool, message: &str) -> TestResult {
        if condition {
            Ok(())
        } else {
            Err(message.into())
        }
    }

    #[actix_web::test]
    async fn converts_openpgp_secret_key_to_binary_packets() -> TestResult {
        let secret = generate_openpgp_secret_key(
            PgpKeyProfile::Ed25519,
            "Binary Export <binary@example.com>",
        )?;
        let app = test::init_service(App::new().service(openpgp_key_to_binary_endpoint)).await;
        let request = test::TestRequest::post()
            .uri("/openpgp/binary")
            .insert_header(("Content-Type", "application/octet-stream"))
            .set_payload(secret.to_vec())
            .to_request();

        let response = test::call_service(&app, request).await;
        check(
            response.status() == StatusCode::OK,
            "binary export route must return 200",
        )?;
        check(
            response
                .headers()
                .get("Content-Type")
                .and_then(|value| value.to_str().ok())
                == Some("application/octet-stream"),
            "binary export route must return the binary content type",
        )?;
        let binary = test::read_body(response).await;
        check(
            !binary.starts_with(b"-----BEGIN PGP "),
            "binary key must not contain armor",
        )?;
        let (_, is_secret) = openpgp_normalize(&binary)?;
        check(is_secret, "binary key must preserve secret material")?;
        Ok(())
    }

    #[actix_web::test]
    async fn rejects_non_openpgp_input() -> TestResult {
        let app = test::init_service(App::new().service(openpgp_key_to_binary_endpoint)).await;
        let request = test::TestRequest::post()
            .uri("/openpgp/binary")
            .insert_header(("Content-Type", "application/octet-stream"))
            .set_payload(b"not an OpenPGP key".as_slice())
            .to_request();

        let response = test::call_service(&app, request).await;
        check(
            response.status() == StatusCode::UNPROCESSABLE_ENTITY,
            "invalid input must be rejected",
        )?;
        Ok(())
    }
}
