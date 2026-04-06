use cosmian_kms_client::GmailApiConf;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use super::GoogleApiError;

#[derive(Serialize, Deserialize, Debug)]
pub(super) struct GoogleAuthResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
}

#[derive(Serialize, Deserialize)]
pub(super) struct GoogleAuthRequest {
    grant_type: String,
    assertion: String,
}

const GRANT_TYPE_SERVICE_ACCOUNT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
impl GoogleAuthRequest {
    pub(crate) fn new(assertion: String) -> Self {
        Self {
            grant_type: GRANT_TYPE_SERVICE_ACCOUNT.to_owned(),
            assertion,
        }
    }
}

pub(super) const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.settings.basic";
pub(super) const GOOGLE_AUD_VALUE: &str = "https://oauth2.googleapis.com/token";
// Token expiration time in hours
const TOKEN_EXPIRATION_TIME_HOURS: i64 = 1;

#[derive(Serialize, Deserialize)]
struct JwtAuthClaims {
    aud: String,
    iss: String,
    scope: String,
    sub: String,
    iat: i64,
    exp: i64,
}

pub(super) fn create_jwt(
    service_account: &GmailApiConf,
    user_email: &str,
) -> Result<String, GoogleApiError> {
    let now = OffsetDateTime::now_utc();
    let claims = JwtAuthClaims {
        aud: GOOGLE_AUD_VALUE.to_owned(),
        iss: service_account.client_email.clone(),
        scope: GMAIL_SCOPE.to_owned(),
        sub: user_email.to_owned(),
        iat: now.unix_timestamp(),
        exp: (now + Duration::hours(TOKEN_EXPIRATION_TIME_HOURS)).unix_timestamp(),
    };

    let key = EncodingKey::from_rsa_pem(service_account.private_key.as_bytes())?;
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_owned());
    Ok(encode(&header, &claims, &key)?)
}

pub(super) async fn retrieve_token(
    service_account: &GmailApiConf,
    user_email: &str,
) -> Result<String, GoogleApiError> {
    let jwt = create_jwt(service_account, user_email)?;

    let client = reqwest::Client::new();

    let response: GoogleAuthResponse = client
        .post(&service_account.token_uri)
        .form(&GoogleAuthRequest::new(jwt))
        .send()
        .await?
        .json()
        .await?;
    Ok(response.access_token)
}
