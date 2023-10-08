use std::sync::Arc;

use actix_web::{
    get, post,
    web::{Data, Json},
    HttpRequest,
};
use base64::{engine::general_purpose, Engine};
use clap::crate_version;
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyWrappingData, KeyWrappingSpecification},
    kmip_objects::ObjectType,
    kmip_types::{self, CryptographicAlgorithm, EncodingOption},
};
use cosmian_kms_utils::crypto::symmetric::create_symmetric_key;
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

use crate::{
    core::operations::{unwrap_key, wrap_key},
    result::KResult,
    routes::google_cse::jwt::validate_tokens,
    KMSServer,
};

mod jwt;
mod operations;
pub use jwt::{jwt_authorization_config, GoogleCseConfig};

// {
//   "server_type": "KACLS",
//   "vendor_id": "Test",
//   "version": "demo",
//   "name": "K8 reference",
//   "operations_supported": [
//     "wrap", "unwrap", "privilegedunwrap",
//     "privatekeydecrypt", "privatekeysign", "privilegedprivatekeydecrypt"
//   ]
// }

#[derive(Serialize, Debug)]
pub struct StatusResponse {
    pub server_type: String,
    pub vendor_id: String,
    pub version: String,
    pub name: String,
    pub operations_supported: Vec<String>,
}

/// Get the status for Google CSE
#[get("/status")]
pub async fn get_status(
    req: HttpRequest,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<StatusResponse>> {
    info!("GET /google_cse/status {}", kms.get_user(req)?);
    let response = Json(StatusResponse {
        server_type: "KACLS".to_string(),
        vendor_id: "Cosmian".to_string(),
        version: crate_version!().to_string(),
        name: "Cosmian KMS".to_string(),
        operations_supported: vec![
            "wrap".to_string(),
            "unwrap".to_string(),
            // "privilegedunwrap".to_string(),
            // "privatekeydecrypt".to_string(),
            // "privatekeysign".to_string(),
            // "privilegedprivatekeydecrypt".to_string(),
        ],
    });
    println!("response: {:?}", response);
    Ok(response)
}

#[derive(Deserialize, Debug)]
pub struct WrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub key: String,
    pub reason: String,
}

#[derive(Serialize, Debug)]
pub struct WrapResponse {
    pub wrapped_key: String,
}

/// Returns encrypted Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/wrap")]
pub async fn wrap(
    req_http: HttpRequest,
    wrap_request: Json<WrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<WrapResponse>> {
    info!("POST /google_cse/wrap");

    // unwrap all calls parameters

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    let kms = kms.into_inner();
    let wrap_request = wrap_request.into_inner();
    trace!("wrap_request: {:?}", wrap_request);

    validate_tokens(
        &wrap_request.authentication,
        &wrap_request.authorization,
        cse_config,
        &["writer", "upgrader"],
    )?;

    // decode the DEK and create a KMIP object from the key bytes
    let mut dek = create_symmetric_key(
        &general_purpose::STANDARD.decode(&wrap_request.key)?,
        CryptographicAlgorithm::AES,
    );

    wrap_key(
        "Google CSE DEK",
        dek.key_block_mut()?,
        &KeyWrappingSpecification {
            wrapping_method: kmip_types::WrappingMethod::Encrypt,
            encoding_option: Some(EncodingOption::NoEncoding),
            encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
                unique_identifier: "[google_cse]".to_string(),
                cryptographic_parameters: Some(kmip_types::CryptographicParameters {
                    ..Default::default()
                }),
            }),
            ..Default::default()
        },
        &kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    // re-extract the bytes from the key
    let wrapped_dek = dek.key_block()?.key_bytes()?;

    Ok(Json(WrapResponse {
        wrapped_key: general_purpose::STANDARD.encode(wrapped_dek),
    }))
}

#[derive(Deserialize, Debug)]
pub struct UnwrapRequest {
    pub authentication: String,
    pub authorization: String,
    pub reason: String,
    pub wrapped_key: String,
}

#[derive(Serialize, Debug)]
pub struct UnwrapResponse {
    pub key: String,
}

/// Decrypt the Data Encryption Key (DEK) and associated data.
///
/// See [doc](https://developers.google.com/workspace/cse/reference/wrap) and
/// for more details, see [Encrypt & decrypt data](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data)
#[post("/unwrap")]
pub async fn unwrap(
    req_http: HttpRequest,
    unwrap_request: Json<UnwrapRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<UnwrapResponse>> {
    info!("POST /google_cse/unwrap");

    // unwrap all calls parameters

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    let kms = kms.into_inner();
    let unwrap_request = unwrap_request.into_inner();
    trace!("unwrap_request: {:?}", unwrap_request);

    validate_tokens(
        &unwrap_request.authentication,
        &unwrap_request.authorization,
        cse_config,
        &["writer", "upgrader"],
    )?;

    // Base 64 decode the encrypted DEK and create a wrapped KMIP object from the key bytes
    let mut wrapped_dek = create_symmetric_key(
        &general_purpose::STANDARD.decode(&unwrap_request.wrapped_key)?,
        CryptographicAlgorithm::AES,
    );
    // add key wrapping parameters to the wrapped key
    wrapped_dek.key_block_mut()?.key_wrapping_data = Some(KeyWrappingData {
        wrapping_method: kmip_types::WrappingMethod::Encrypt,
        encryption_key_information: Some(kmip_types::EncryptionKeyInformation {
            unique_identifier: "[google_cse]".to_string(),
            cryptographic_parameters: None,
        }),
        encoding_option: Some(EncodingOption::NoEncoding),
        ..Default::default()
    });

    unwrap_key(
        ObjectType::SymmetricKey,
        wrapped_dek.key_block_mut()?,
        &kms,
        &user,
        database_params.as_ref(),
    )
    .await?;

    // re-extract the bytes from the key
    let dek = wrapped_dek.key_block()?.key_bytes()?;

    Ok(Json(UnwrapResponse {
        key: general_purpose::STANDARD.encode(dek),
    }))
}

#[derive(Deserialize, Debug)]
pub struct DigestRequest {
    pub authorization: String,
    pub reason: String,
    pub wrapped_key: String,
}

#[derive(Serialize, Debug)]
pub struct DigestResponse {
    pub checksum: String,
}

/// Returns the checksum ("digest") of an unwrapped Data Encryption Key (DEK).
///
/// ```SHA-256("KACLMigration" + resource_identifier + unwrapped_dek)```
///
/// See [doc](https://developers.google.com/workspace/cse/reference/digest)
#[post("/digest")]
pub async fn digest(
    req_http: HttpRequest,
    digest_request: Json<DigestRequest>,
    cse_config: Data<Option<GoogleCseConfig>>,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<DigestResponse>> {
    info!("POST /google_cse/digest");

    // unwrap all calls parameters

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(req_http)?;
    let kms = kms.into_inner();
    let digest_request = digest_request.into_inner();
    trace!("digest_request: {:?}", digest_request);

    Ok(Json(DigestResponse {
        checksum: "digest".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use cosmian_logger::log_utils::log_init;
    use tracing::info;

    use crate::routes::google_cse::{
        jwt::{decode_jwt_authorization_token, jwt_authorization_config},
        WrapRequest,
    };

    #[actix_rt::test]
    async fn test_wrap_auth() {
        log_init("info");
        let wrap_request = r#"
        { 
            "authentication": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM2MjYzZDA5NzQ1YjUwMzJlNTdmYTZlMWQwNDFiNzdhNTQwNjZkYmQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI5OTY3Mzk1MTAzNzQtYXU5ZmRiZ3A3MmRhY3JzYWcyNjdja2czMmpmM2QzZTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDI5NjU4MTQxNjkwOTQzMDMxMTIiLCJoZCI6ImNvc21pYW4uY29tIiwiZW1haWwiOiJibHVlQGNvc21pYW4uY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5vbmNlIjoieVpqSXJ0TzRuTHktMU5tSGZVU09rZzpodHRwczovL2NsaWVudC1zaWRlLWVuY3J5cHRpb24uZ29vZ2xlLmNvbSIsIm5iZiI6MTY5Njc0MzU0MSwiaWF0IjoxNjk2NzQzODQxLCJleHAiOjE2OTY3NDc0NDEsImp0aSI6Ijc2YzM1NTYyZjE3MjQ4ZWYyYjdlN2JmZTFiMWNiNzc0OWIyZGY2OWUifQ.E1894qHpBShp9xPLozEejZPainkuCGrEtM8FhLtevz-3-ywAqCzW6K0crw8u8Rd0rsyFH4MLRCXd_WaF1KH97HwKivA9rrTYOom4wESiINmQuIRjUr_8m2nOUQ-BvA8hqC2iu1gOowOAWB_npVQIpBaqujzdeQVy9cZgm5Hqr7QEiZEvh0_fPhIXQi38IOelTvUYqOoLdX_c6QOf2lbFd7RWzbJYgB7ZMHQr_Tyomhx2Budmwu5VCI8w7hERgjepCGdemLJanyW6Ia3YdH6Tj2-Xp7B2-5kFH4idsaqMiimeqopxBKtDD5cpkjLwbi_bryk1sX2MhzcrKZSkie40Eg", 
            "authorization": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFhYTk2ODk5ZThjYmM5YThlODBjMzBjMzU1NjVhOTM4YzE1MTgyNmQiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJnc3VpdGVjc2UtdG9rZW5pc3N1ZXItZHJpdmVAc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJhdWQiOiJjc2UtYXV0aG9yaXphdGlvbiIsImVtYWlsIjoiYmx1ZUBjb3NtaWFuLmNvbSIsInJlc291cmNlX25hbWUiOiIvL2dvb2dsZWFwaXMuY29tL2RyaXZlL2ZpbGVzLzEzQXBwUWpVVmpCT2VVczB3VTc0cXFYbUkzQjZyTFJxcCIsInJvbGUiOiJ3cml0ZXIiLCJrYWNsc191cmwiOiJodHRwczovL2NzZS5jb3NtaWFuLmNvbS9nb29nbGVfY3NlIiwicGVyaW1ldGVyX2lkIjoiIiwiaWF0IjoxNjk2NzQ2MzkxLCJleHAiOjE2OTY3NDk5OTF9.NCR_zrE4K6fuxtGttIZyZVrvpF0cwqryUCYU01DbbPtgmNzO6jd3kVWHAKwouNSI_JU4k9SjNaU9-1T1FUBWIfRtWkPMdETPUgiDC51dmqdgxHTlA0ILvZI2drlrzrXInyWq7hik1G-zqL0KO3MdDa0ioPd0he2Wq2Pi5z8I-A2mwyYK8kzYHbZ-zvQK3NORuQYrqAssAqIGfZeNMz6rlfO1GBYwJoAagGKu23A-__e7dRT_XkebiTJZ-FpAajue4xjPYsqe1D73yi95T6nJo9s7iHZf32j0U2yH0cLgbN3Hn-G_ePVFHrBh3i5LU2x0qb2f3a1HiDiFoOa9qbt5Pg", 
            "key": "GiBtiozOv+COIrEPxPUYH9gFKw1tY9kBzHaW/gSi7u9ZLA==", 
            "reason": "" 
        }
        "#;
        let wrap_request: WrapRequest = serde_json::from_str(wrap_request).unwrap();

        // Note: the token cannot be tested because it is expired. if it were not the case, the following code would work:

        // let jwt_authentication_config = JwtAuthConfig {
        //     jwt_issuer_uri: Some("https://accounts.google.com".to_string()),
        //     jwks_uri: Some("https://www.googleapis.com/oauth2/v3/certs".to_string()),
        //     jwt_audience: None,
        // };
        // let jwt_authentication_config = JwtConfig {
        //     jwt_issuer_uri: jwt_authentication_config.jwt_issuer_uri.clone().unwrap(),
        //     jwks: jwt_authentication_config
        //         .fetch_jwks()
        //         .await
        //         .unwrap()
        //         .unwrap(),
        //     jwt_audience: jwt_authentication_config.jwt_audience.clone(),
        // };

        // let authentication_token = decode_jwt_authentication_token(
        //     &jwt_authentication_config,
        //     &wrap_request.authentication,
        // )
        // .unwrap();
        // println!("AUTHENTICATION token: {:?}", authentication_token);

        let jwt_authorization_config = jwt_authorization_config().await.unwrap();

        let (authorization_token, jwt_headers) =
            decode_jwt_authorization_token(&jwt_authorization_config, &wrap_request.authorization)
                .unwrap();
        info!("AUTHORIZATION token: {:?}", authorization_token);
        info!("AUTHORIZATION token headers: {:?}", jwt_headers);

        assert_eq!(
            authorization_token.email,
            Some("blue@cosmian.com".to_string())
        );
        assert_eq!(
            authorization_token.aud,
            Some("cse-authorization".to_string())
        );
    }
}
