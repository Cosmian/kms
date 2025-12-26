use std::sync::Arc;

use serde::Deserialize;

use crate::{
    config::{IdpAuthConfig, ProxyParams},
    error::KmsError,
    middlewares::{JwksManager, JwtConfig},
    result::KResult,
    routes::google_cse::{self, GoogleCseConfig},
};

// Default Google JWT issuer URI
pub(crate) const GOOGLE_JWT_ISSUER_URI: &str = "https://accounts.google.com";

// Default Google JWT Set URI
pub(crate) const GOOGLE_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

pub(crate) async fn generate_google_jwt() -> KResult<String> {
    #[derive(Deserialize)]
    struct RefreshToken {
        pub id_token: String,
    }

    let client_id = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_ID").map_err(|e| {
        KmsError::ServerError(format!("Failed to get TEST_GOOGLE_OAUTH_CLIENT_ID: {e}"))
    })?;
    let client_secret = std::env::var("TEST_GOOGLE_OAUTH_CLIENT_SECRET").map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_CLIENT_SECRET: {e}"
        ))
    })?;
    let refresh_token = std::env::var("TEST_GOOGLE_OAUTH_REFRESH_TOKEN").map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to get TEST_GOOGLE_OAUTH_REFRESH_TOKEN: {e}"
        ))
    })?;

    assert!(!client_id.is_empty());
    assert!(!client_secret.is_empty());
    assert!(!refresh_token.is_empty());

    let res = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await?;

    let id_token = res.json::<RefreshToken>().await?.id_token;

    tracing::debug!("ID token: {id_token:?}");

    Ok(id_token)
}

pub(crate) async fn google_cse_auth(
    proxy_params: Option<&ProxyParams>,
) -> KResult<GoogleCseConfig> {
    let mut uris = google_cse::list_jwks_uri(None);

    uris.push(IdpAuthConfig::uri(
        GOOGLE_JWT_ISSUER_URI,
        Some(GOOGLE_JWKS_URI),
    ));
    let jwks_manager = Arc::new(JwksManager::new(uris, proxy_params).await?);
    let jwt_config = JwtConfig {
        jwt_issuer_uri: GOOGLE_JWT_ISSUER_URI.to_owned(),
        jwks: jwks_manager.clone(),
        jwt_audience: None,
    };

    Ok(GoogleCseConfig {
        authentication: vec![jwt_config].into(),
        authorization: google_cse::jwt_authorization_config(&jwks_manager),
    })
}
