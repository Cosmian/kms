use crate::error::CliError;

use super::service_account::ServiceAccount;

use jwt::{SignWithKey, PKeyWithDigest};

use std::{collections::BTreeMap};

use chrono::{Duration, Utc};

use openssl::{pkey::PKey, hash::MessageDigest};
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize)]
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

pub const GMAIL_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const GOOGLE_AUD_VALUE: &str = "https://oauth2.googleapis.com/token";


pub fn create_jwt(service_account: &ServiceAccount, user_email: &str) -> Result<String, CliError> {
    let private_key = PKey::private_key_from_pem(service_account.private_key.as_bytes()).unwrap();
    let key_with_digest = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: private_key,
    };

    let mut claims: BTreeMap<&str, &str> = BTreeMap::new();

    claims.insert("iss", &service_account.client_email);
    claims.insert("scope", GMAIL_SCOPE);
    claims.insert("aud", GOOGLE_AUD_VALUE);

    let now = Utc::now();
    let now_timestamp = now.timestamp().to_string();
    claims.insert("iat", &now_timestamp);

    let exp_time = now + Duration::hours(1);

    let exp_time_timestamp = exp_time.timestamp().to_string();
    claims.insert("exp", &exp_time_timestamp);
    claims.insert("sub", user_email);

    Ok(claims.sign_with_key(&key_with_digest).unwrap())
}

pub async fn retrieve_token(service_account: &ServiceAccount, user_email: &str) -> Result<String, CliError> {
    let jwt = create_jwt(service_account, user_email)?;

    let client = reqwest::Client::new();

    // GoogleAuthResponse
    let response_text = client
        .post(&service_account.token_uri)
        .form(&GoogleAuthRequest::new(jwt))
        .send()
        .await.unwrap()
        .text()
        .await.unwrap();

    let response: GoogleAuthResponse = serde_json::from_str(&response_text)?;
    Ok(response.access_token)
}
