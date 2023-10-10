use std::collections::HashMap;

use alcoholic_jwt::{token_kid, JWKS};
use tracing::{debug, trace};

use crate::{
    error::KmsError,
    kms_ensure,
    middlewares::{decode_jwt_authentication_token, JwtConfig, JwtTokenHeaders, UserClaim},
    result::KResult,
};

async fn fetch_jwks(jwks_uri: &str) -> KResult<JWKS> {
    let jwks = reqwest::get(jwks_uri)
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to fetch Google CSE JWKS at: {jwks_uri}, {e:?} "
            ))
        })?
        .json::<JWKS>()
        .await
        .map_err(|e| {
            KmsError::ServerError(format!(
                "Failed to parse Google CSE JWKS at: {jwks_uri}, {e:?} "
            ))
        })?;

    Ok(jwks)
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' or 'meet'
async fn jwt_authorization_config_application(application: &str) -> KResult<JwtConfig> {
    let jwks_uri= std::env::var(format!("KMS_GOOGLE_CSE_{}_JWKS_URI",application.to_uppercase()))
        .unwrap_or(format!("https://www.googleapis.com/service_accounts/v1/jwk/gsuitecse-tokenissuer-{}@system.gserviceaccount.com",application));

    // Fetch the JWKS for the two Google CSE service accounts
    let jwks = fetch_jwks(&jwks_uri).await?;

    Ok(JwtConfig {
        jwt_issuer_uri: std::env::var(format!(
            "KMS_GOOGLE_CSE_{}_JWT_ISSUER",
            application.to_uppercase()
        ))
        .unwrap_or(format!(
            "gsuitecse-tokenissuer-{}@system.gserviceaccount.com",
            application
        )),
        jwks,
        jwt_audience: Some(
            std::env::var("KMS_GOOGLE_CSE_AUDIENCE").unwrap_or("cse-authorization".to_string()),
        ),
    })
}

/// Fetch the JWT authorization configuration for Google CSE 'drive' and'meet'
pub async fn jwt_authorization_config() -> KResult<HashMap<String, JwtConfig>> {
    let mut jwt_authorization_config = HashMap::new();
    jwt_authorization_config.insert(
        "drive".to_string(),
        jwt_authorization_config_application("drive").await?,
    );
    jwt_authorization_config.insert(
        "meet".to_string(),
        jwt_authorization_config_application("meet").await?,
    );
    Ok(jwt_authorization_config)
}

/// Decode a json web token (JWT) used for Google CSE
pub fn decode_jwt_authorization_token(
    jwt_config: &JwtConfig,
    token: &str,
) -> KResult<(UserClaim, JwtTokenHeaders)> {
    kms_ensure!(
        !token.is_empty(),
        KmsError::Unauthorized("authorization token is empty".to_owned())
    );
    tracing::trace!(
        "validating CSE authorization token, expected issuer : {}",
        &jwt_config.jwt_issuer_uri
    );

    let validations = vec![
        alcoholic_jwt::Validation::Issuer(jwt_config.jwt_issuer_uri.to_string()),
        alcoholic_jwt::Validation::Audience(
            jwt_config
                .jwt_audience
                .as_ref()
                .ok_or_else(|| {
                    KmsError::ServerError(
                        "JWT audience should be configured with Google Workspace client-side \
                         encryption"
                            .to_string(),
                    )
                })?
                .to_string(),
        ),
    ];

    // If a JWKS contains multiple keys, the correct KID first
    // needs to be fetched from the token headers.
    let kid = token_kid(token)
        .map_err(|_| KmsError::Unauthorized("Failed to decode token headers".to_string()))?
        .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_string()))?;

    let jwk = jwt_config
        .jwks
        .find(&kid)
        .ok_or_else(|| KmsError::Unauthorized("Specified key not found in set".to_string()))?;

    let valid_jwt = alcoholic_jwt::validate(token, jwk, validations)
        .map_err(|err| KmsError::Unauthorized(format!("Cannot validate token: {err:?}")))?;

    trace!("valid_jwt user claims: {:?}", valid_jwt.claims);
    trace!("valid_jwt headers: {:?}", valid_jwt.headers);

    let user_claims = serde_json::from_value(valid_jwt.claims)
        .map_err(|err| KmsError::Unauthorized(format!("JWT claims are malformed: {err:?}")))?;

    let jwt_headers = serde_json::from_value(valid_jwt.headers)
        .map_err(|err| KmsError::Unauthorized(format!("JWT headers is malformed: {err:?}")))?;

    Ok((user_claims, jwt_headers))
}

/// The configuration for for Google CSE:
///  - JWT authentication and authorization configurations
///  - external KACLS URL of this server configured in Google Workspace client-side encryption
/// (something like <https://cse.mydomain.com/google_cse>)
#[derive(Clone)]
pub struct GoogleCseConfig {
    pub authentication: JwtConfig,
    pub authorization: HashMap<String, JwtConfig>,
    pub kacls_url: String,
}

/// Validate the authentication and the authorization tokens and return the calling user
/// See [doc](https://developers.google.com/workspace/cse/guides/encrypt-and-decrypt-data?hl=en)
pub fn validate_tokens(
    authentication_token: &str,
    authorization_token: &str,
    cse_config: &Option<GoogleCseConfig>,
    application: &str,
    roles: &[&str],
) -> KResult<String> {
    let cse_config = cse_config.as_ref().ok_or_else(|| {
        KmsError::ServerError(
            "JWT authentication and authorization configurations for Google CSE are not set"
                .to_string(),
        )
    })?;

    // validate authentication token
    let authentication_token =
        decode_jwt_authentication_token(&cse_config.authentication, authentication_token)?;
    trace!("authentication token: {:?}", authentication_token);

    let (authorization_token, jwt_headers) = decode_jwt_authorization_token(
        cse_config.authorization.get(application).ok_or_else(|| {
            KmsError::NotSupported(format!(
                "no JWT config available for application: {application} "
            ))
        })?,
        authorization_token,
    )?;
    trace!("authorization token: {:?}", authorization_token);
    trace!("authorization token headers: {:?}", jwt_headers);

    // The emails should match (case insensitive)
    let authentication_email = authentication_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authentication token should contain an email".to_string())
    })?;
    let authorization_email = authorization_token.email.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain an email".to_string())
    })?;
    kms_ensure!(
        authorization_email == authentication_email,
        KmsError::Unauthorized(
            "Authentication and authorization emails in tokens do not match".to_string()
        )
    );

    let role = authorization_token.role.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain a role".to_string())
    })?;
    kms_ensure!(
        roles.contains(&role.as_str()),
        KmsError::Unauthorized(
            "Authorization token should contain a role of writer or owner".to_string()
        )
    );

    let kacls_url = authorization_token.kacls_url.ok_or_else(|| {
        KmsError::Unauthorized("Authorization token should contain a kacls_url".to_string())
    })?;
    kms_ensure!(
        kacls_url == cse_config.kacls_url,
        KmsError::Unauthorized(format!(
            "KACLS Urls should match: expected: {}, got: {} ",
            cse_config.kacls_url, kacls_url
        ))
    );

    debug!("wrap request authorized for user {}", authentication_email);

    Ok(authentication_email)
}

#[cfg(test)]
mod tests {
    use cosmian_logger::log_utils::log_init;
    use tracing::info;

    use crate::routes::google_cse::{
        jwt::{decode_jwt_authorization_token, jwt_authorization_config},
        operations::WrapRequest,
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

        let (authorization_token, jwt_headers) = decode_jwt_authorization_token(
            jwt_authorization_config.get("drive").unwrap(),
            &wrap_request.authorization,
        )
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
