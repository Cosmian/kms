use std::collections::HashMap;

use actix_session::Session;
use actix_web::{get, web, HttpRequest, HttpResponse};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope,
};
use url::Url;

use crate::config::OidcConfig;

#[get("/login_flow")]
pub(crate) async fn login(
    session: Session,
    oidc_config: web::Data<OidcConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let Ok(http_client) = oauth2::reqwest::ClientBuilder::new().build() else {
        return HttpResponse::InternalServerError().body("Failed to build HTTP client")
    };

    let issuer_url = match &oidc_config.ui_oidc_issuer_url {
        Some(url) => match IssuerUrl::new(url.clone()) {
            Ok(valid_url) => valid_url,
            Err(_) => return HttpResponse::InternalServerError().body("Invalid issuer URL"),
        },
        None => return HttpResponse::InternalServerError().body("Issuer URL is missing"),
    };

    let Ok(redirect_url) = RedirectUrl::new(format!("{}/ui/callback", kms_url.as_str())) else {
        return HttpResponse::InternalServerError().body("Invalid Redirect URL")
    };

    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => ClientId::new(id.clone()),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let Ok(provider_metadata) =
        CoreProviderMetadata::discover_async(issuer_url, &http_client).await
    else {
        return HttpResponse::InternalServerError().body("Failed to fetch provider metadata")
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        oidc_config
            .ui_oidc_client_secret
            .clone()
            .map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_url);

    let (auth_url, csrf_token, _nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_owned()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    if let Err(e) = session.insert("pkce_verifier", pkce_verifier) {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to insert pkce_verifier: {e:?}"));
    }
    if let Err(e) = session.insert("csrf_token", csrf_token.secret()) {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to insert csrf_token: {e:?}"));
    }

    // Redirect to Identity Provider
    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish()
}

#[get("/callback")]
pub(crate) async fn callback(
    req: HttpRequest,
    session: Session,
    oidc_config: web::Data<OidcConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let Ok(query) = web::Query::<HashMap<String, String>>::from_query(req.query_string()) else {
        return HttpResponse::BadRequest().body("Invalid query parameters")
    };

    // Retrieve stored values
    let stored_pkce_verifier = match session.get::<String>("pkce_verifier") {
        Ok(Some(v)) => Some(PkceCodeVerifier::new(v)),
        Ok(None) => return HttpResponse::BadRequest().body("Missing PKCE verifier"),
        Err(_) => {
            return HttpResponse::InternalServerError().body("Failed to retrieve PKCE verifier")
        }
    };

    let stored_csrf_token = match session.get::<String>("csrf_token") {
        Ok(Some(csrf_token)) => Some(csrf_token),
        Ok(None) => return HttpResponse::BadRequest().body("Missing CSRF token"),
        Err(_) => return HttpResponse::InternalServerError().body("Failed to retrieve CSRF token"),
    };

    // Validate CSRF token
    let Some(received_csrf_token) = query.get("state") else {
        return HttpResponse::BadRequest().body("Missing state parameter")
    };
    if Some(received_csrf_token) != stored_csrf_token.as_ref() {
        return HttpResponse::BadRequest().body("CSRF token mismatch");
    }

    // Extract authorization code
    let auth_code = match query.get("code") {
        Some(code) => AuthorizationCode::new(code.to_owned()),
        None => return HttpResponse::BadRequest().body("Missing authorization code"),
    };

    let Ok(http_client) = oauth2::reqwest::ClientBuilder::new().build() else {
        return HttpResponse::InternalServerError().body("Failed to build HTTP client")
    };

    // Exchange code for tokens
    let issuer_url = match &oidc_config.ui_oidc_issuer_url {
        Some(url) => match IssuerUrl::new(url.clone()) {
            Ok(valid_url) => valid_url,
            Err(_) => return HttpResponse::InternalServerError().body("Invalid issuer URL"),
        },
        None => return HttpResponse::InternalServerError().body("Issuer URL is missing"),
    };

    let Ok(redirect_url) = RedirectUrl::new(format!("{}/ui/callback", kms_url.as_str())) else {
        return HttpResponse::InternalServerError().body("Invalid Redirect URL")
    };

    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => ClientId::new(id.clone()),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let Ok(provider_metadata) =
        CoreProviderMetadata::discover_async(issuer_url, &http_client).await
    else {
        return HttpResponse::InternalServerError().body("Failed to fetch provider metadata")
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        oidc_config
            .ui_oidc_client_secret
            .clone()
            .map(ClientSecret::new),
    )
    .set_redirect_uri(redirect_url);

    if let Some(stored_pkce_verifier) = stored_pkce_verifier {
        let token_request = match client.exchange_code(auth_code) {
            Ok(request) => request,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to exchange auth code: {e}"));
            }
        };

        let token_result = match token_request
            .set_pkce_verifier(stored_pkce_verifier)
            .request_async(&http_client)
            .await
        {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to get token result: {e}"));
            }
        };

        if let Some(id_token) = token_result.extra_fields().id_token() {
            let id_token_str = id_token.to_owned();
            if session.insert("id_token", id_token_str).is_err() {
                return HttpResponse::InternalServerError().body("Failed to store id_token");
            }
        } else {
            return HttpResponse::InternalServerError().json({
                serde_json::json!({
                    "error": "Error getting id_token"
                })
            });
        }
    }

    HttpResponse::Found()
        .append_header(("Location", "/ui"))
        .finish()
}

#[get("/token")]
pub(crate) async fn token(session: Session) -> HttpResponse {
    // Retrieve access token from session
    match session.get::<String>("id_token") {
        Ok(Some(id_token)) => HttpResponse::Ok().json(serde_json::json!({
            "id_token": id_token,
        })),
        Ok(None) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "No ID token found"
        })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to retrieve session data"
        })),
    }
}

#[get("/logout")]
pub(crate) async fn logout(
    session: Session,
    oidc_config: web::Data<OidcConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    session.purge();

    let mut logout_url = match &oidc_config.ui_oidc_logout_url {
        Some(url) => match Url::parse(url) {
            Ok(parsed_url) => parsed_url,
            Err(_) => return HttpResponse::InternalServerError().body("Invalid logout URL"),
        },
        None => return HttpResponse::InternalServerError().body("Logout URL is missing"),
    };

    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => ClientId::new(id.clone()),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let Ok(redirect_url) = RedirectUrl::new(format!("{}/ui/login", kms_url.as_str())) else {
        return HttpResponse::InternalServerError().body("Invalid Redirect URL")
    };

    logout_url
        .query_pairs_mut()
        .append_pair("client_id", client_id.as_str())
        .append_pair("returnTo", &redirect_url);

    HttpResponse::Found()
        .append_header(("Location", logout_url.to_string()))
        .finish()
}

#[get("/auth_method")]
pub(crate) async fn get_auth_method(auth_type: web::Data<Option<String>>) -> HttpResponse {
    let auth_method = auth_type
        .as_ref()
        .as_ref()
        .map_or_else(|| "None".to_owned(), std::clone::Clone::clone);

    HttpResponse::Ok().json(serde_json::json!({ "auth_method": auth_method }))
}

// Function to register all auth routes
pub fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login)
        .service(callback)
        .service(token)
        .service(logout)
        .service(get_auth_method);
}
