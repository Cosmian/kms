use jwt_simple::{
    algorithms::RSAKeyPairLike,
    prelude::{Claims, Duration, RS256KeyPair},
};
use serde::{Deserialize, Serialize};

use super::{service_account::ServiceAccount, GoogleApiError};

#[derive(Serialize, Deserialize, Debug)]
pub struct GoogleAuthResponse {
    pub access_token: String,
    pub expires_in: u32,
    pub token_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct GoogleAuthRequest {
    grant_type: String,
    assertion: String,
}

const GRANT_TYPE_SERVICE_ACCOUNT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
impl GoogleAuthRequest {
    pub fn new(assertion: String) -> Self {
        Self {
            grant_type: GRANT_TYPE_SERVICE_ACCOUNT.to_string(),
            assertion,
        }
    }
}

pub const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.settings.basic";
pub const GOOGLE_AUD_VALUE: &str = "https://oauth2.googleapis.com/token";
// Token expiration time in hours
const TOKEN_EXPIRATION_TIME: u64 = 1;

#[derive(Serialize, Deserialize)]
struct JwtAuth {
    aud: String,
    iss: String,
    scope: String,
    sub: String,
}

pub fn create_jwt(
    service_account: &ServiceAccount,
    user_email: &str,
) -> Result<String, GoogleApiError> {
    let key_pair = RS256KeyPair::from_pem(&service_account.private_key)?;
    let jwt_data = JwtAuth {
        aud: GOOGLE_AUD_VALUE.to_string(),
        iss: service_account.client_email.clone(),
        scope: GMAIL_SCOPE.to_string(),
        sub: user_email.to_string().clone(),
    };

    let claims = Claims::with_custom_claims(jwt_data, Duration::from_hours(TOKEN_EXPIRATION_TIME));

    let token = key_pair.sign(claims)?;
    Ok(token)
}

pub async fn retrieve_token(
    service_account: &ServiceAccount,
    user_email: &str,
) -> Result<String, GoogleApiError> {
    let jwt = create_jwt(service_account, user_email)?;

    let client = reqwest::Client::new();

    // GoogleAuthResponse
    let response_text = client
        .post(&service_account.token_uri)
        .form(&GoogleAuthRequest::new(jwt))
        .send()
        .await?
        .text()
        .await?;
    let response: GoogleAuthResponse = serde_json::from_str(&response_text)?;
    Ok(response.access_token)
}
