use jwt_simple::{
    algorithms::RSAKeyPairLike,
    prelude::{Claims, Duration, RS256KeyPair},
};
use serde::{Deserialize, Serialize};

use super::{service_account::ServiceAccount, GoogleApiError};

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GoogleAuthResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct GoogleAuthRequest {
    grant_type: String,
    assertion: String,
}

const GRANT_TYPE_SERVICE_ACCOUNT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
impl GoogleAuthRequest {
    pub(crate) fn new(assertion: String) -> Self {
        Self {
            grant_type: GRANT_TYPE_SERVICE_ACCOUNT.to_string(),
            assertion,
        }
    }
}

pub(crate) const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.settings.basic";
pub(crate) const GOOGLE_AUD_VALUE: &str = "https://oauth2.googleapis.com/token";
// Token expiration time in hours
const TOKEN_EXPIRATION_TIME: u64 = 1;

#[derive(Serialize, Deserialize)]
struct JwtAuth {
    aud: String,
    iss: String,
    scope: String,
    sub: String,
}

pub(crate) fn create_jwt(
    service_account: &ServiceAccount,
    user_email: &str,
) -> Result<String, GoogleApiError> {
    let key_pair = RS256KeyPair::from_pem(&service_account.private_key)?;
    let jwt_data = JwtAuth {
        aud: GOOGLE_AUD_VALUE.to_string(),
        iss: service_account.client_email.clone(),
        scope: GMAIL_SCOPE.to_string(),
        sub: user_email.to_string(),
    };

    let claims = Claims::with_custom_claims(jwt_data, Duration::from_hours(TOKEN_EXPIRATION_TIME));

    Ok(key_pair.sign(claims)?)
}

pub(crate) async fn retrieve_token(
    service_account: &ServiceAccount,
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
