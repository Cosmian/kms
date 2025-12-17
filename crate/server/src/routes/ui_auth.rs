use std::collections::HashMap;

use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, get, web};
use alcoholic_jwt::{JWKS, token_kid};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Client;
use serde_json::Value;
use url::Url;

use crate::config::OidcConfig;

fn random_b64url(len_bytes: usize) -> Result<String, ()> {
    let mut buf = vec![0_u8; len_bytes];
    openssl::rand::rand_bytes(&mut buf).map_err(|_e| ())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn pkce_challenge_from_verifier(verifier: &str) -> String {
    let digest = openssl::sha::sha256(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

async fn discover_metadata(client: &Client, issuer: &str) -> Result<Value, String> {
    let base = issuer.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to fetch OIDC discovery: {e}"))?;
    resp.json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse OIDC discovery JSON: {e}"))
}

#[get("/login_flow")]
pub(crate) async fn login(
    session: Session,
    oidc_config: web::Data<OidcConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let Ok(client) = Client::builder().build() else {
        return HttpResponse::InternalServerError().body("Failed to build HTTP client");
    };

    let issuer = match &oidc_config.ui_oidc_issuer_url {
        Some(url) => url.clone(),
        None => return HttpResponse::InternalServerError().body("Issuer URL is missing"),
    };

    let redirect_url = format!("{}/ui/callback", kms_url.as_str());
    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let discovery = match discover_metadata(&client, &issuer).await {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to fetch provider metadata: {e}"));
        }
    };
    let Some(auth_endpoint) = discovery
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
    else {
        return HttpResponse::InternalServerError().body("Missing authorization_endpoint");
    };

    let Ok(pkce_verifier) = random_b64url(32) else {
        return HttpResponse::InternalServerError().body("Failed to create PKCE verifier");
    };
    let pkce_challenge = pkce_challenge_from_verifier(&pkce_verifier);
    let Ok(csrf_token) = random_b64url(16) else {
        return HttpResponse::InternalServerError().body("Failed to create CSRF token");
    };
    let Ok(nonce) = random_b64url(16) else {
        return HttpResponse::InternalServerError().body("Failed to create nonce");
    };

    let mut auth_url = match Url::parse(auth_endpoint) {
        Ok(u) => u,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Invalid authorization endpoint: {e}"));
        }
    };

    auth_url
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_url)
        .append_pair("scope", "openid email")
        .append_pair("state", &csrf_token)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_challenge)
        .append_pair("nonce", &nonce);

    if let Err(e) = session.insert("pkce_verifier", &pkce_verifier) {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to insert pkce_verifier: {e:?}"));
    }
    if let Err(e) = session.insert("csrf_token", &csrf_token) {
        return HttpResponse::InternalServerError()
            .body(format!("Failed to insert csrf_token: {e:?}"));
    }
    if let Err(e) = session.insert("nonce", &nonce) {
        return HttpResponse::InternalServerError().body(format!("Failed to insert nonce: {e:?}"));
    }

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
        return HttpResponse::BadRequest().body("Invalid query parameters");
    };

    // Retrieve stored values
    let stored_pkce_verifier = match session.get::<String>("pkce_verifier") {
        Ok(Some(v)) => Some(v),
        Ok(None) => return HttpResponse::BadRequest().body("Missing PKCE verifier"),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to retrieve PKCE verifier: {e}"));
        }
    };

    let stored_csrf_token = match session.get::<String>("csrf_token") {
        Ok(Some(csrf_token)) => Some(csrf_token),
        Ok(None) => return HttpResponse::BadRequest().body("Missing CSRF token"),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to retrieve CSRF token: {e}"));
        }
    };

    let stored_nonce = match session.get::<String>("nonce") {
        Ok(Some(nonce)) => nonce,
        Ok(None) => return HttpResponse::BadRequest().body("Missing nonce"),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to retrieve nonce: {e}"));
        }
    };

    // Validate CSRF token
    let Some(received_csrf_token) = query.get("state") else {
        return HttpResponse::BadRequest().body("Missing state parameter");
    };
    if Some(received_csrf_token) != stored_csrf_token.as_ref() {
        return HttpResponse::BadRequest().body("CSRF token mismatch");
    }

    // Extract authorization code
    let auth_code = match query.get("code") {
        Some(code) => code.to_owned(),
        None => return HttpResponse::BadRequest().body("Missing authorization code"),
    };
    let Ok(client) = Client::builder().build() else {
        return HttpResponse::InternalServerError().body("Failed to build HTTP client");
    };

    // Exchange code for tokens
    let Some(url) = &oidc_config.ui_oidc_issuer_url else {
        return HttpResponse::InternalServerError().body("Issuer URL is missing");
    };
    let issuer = url.clone();
    let redirect_url = format!("{}/ui/callback", kms_url.as_str());

    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };
    let discovery = match discover_metadata(&client, &issuer).await {
        Ok(v) => v,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Failed to fetch provider metadata: {e}"));
        }
    };
    let Some(token_endpoint) = discovery.get("token_endpoint").and_then(|v| v.as_str()) else {
        return HttpResponse::InternalServerError().body("Missing token_endpoint");
    };

    if let Some(verifier) = stored_pkce_verifier {
        // Exchange code for tokens
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".to_owned(), "authorization_code".to_owned()),
            ("code".to_owned(), auth_code.clone()),
            ("redirect_uri".to_owned(), redirect_url.clone()),
            ("client_id".to_owned(), client_id.clone()),
            ("code_verifier".to_owned(), verifier.clone()),
        ];
        if let Some(secret) = oidc_config.ui_oidc_client_secret.clone() {
            form.push(("client_secret".to_owned(), secret));
        }
        let resp = match client.post(token_endpoint).form(&form).send().await {
            Ok(r) => r,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to exchange auth code: {e}"));
            }
        };
        let json: Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to parse token response: {e}"));
            }
        };
        let Some(id_token_str) = json.get("id_token").and_then(|v| v.as_str()) else {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "No id_token in response" }));
        };

        // Verify ID Token
        let Some(jwks_uri) = discovery.get("jwks_uri").and_then(|v| v.as_str()) else {
            return HttpResponse::InternalServerError().body("Missing jwks_uri in discovery");
        };
        let jwks_json = match client.get(jwks_uri).send().await {
            Ok(r) => r,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to fetch JWKS: {e}"));
            }
        };
        let jwks_val: Value = match jwks_json.json().await {
            Ok(v) => v,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .body(format!("Failed to parse JWKS: {e}"));
            }
        };
        let jwks: JWKS = match serde_json::from_value(jwks_val) {
            Ok(j) => j,
            Err(_) => {
                return HttpResponse::InternalServerError().body("Invalid JWKS format");
            }
        };

        // Select key by kid
        let kid = match token_kid(id_token_str) {
            Ok(Some(k)) => k,
            Ok(None) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": "No kid in id_token" }));
            }
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": format!("Failed to parse kid: {e}") }));
            }
        };
        let Some(jwk) = jwks.find(&kid) else {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Key not found in JWKS" }));
        };

        let validations = vec![
            #[cfg(all(not(test), not(feature = "insecure")))]
            alcoholic_jwt::Validation::Issuer(issuer.clone()),
            #[cfg(all(not(test), not(feature = "insecure")))]
            alcoholic_jwt::Validation::NotExpired,
            alcoholic_jwt::Validation::Audience(client_id.clone()),
        ];

        let valid = match alcoholic_jwt::validate(id_token_str, jwk, validations) {
            Ok(v) => v,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": format!("Token validation failed: {e}") }));
            }
        };
        let claims = valid.claims;
        // Check nonce
        let nonce_claim = claims.get("nonce").and_then(|v| v.as_str());
        if nonce_claim != Some(stored_nonce.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Nonce mismatch"
            }));
        }

        // Extract email
        let user_email = claims
            .get("email")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        if session.insert("id_token", id_token_str).is_err() {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to store id_token"
            }));
        }

        if let Some(user_id) = user_email {
            if session.insert("user_id", user_id).is_err() {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to store user_id"
                }));
            }
        }
    }

    HttpResponse::Found()
        .append_header(("Location", "/ui/locate"))
        .finish()
}

#[get("/token")]
pub(crate) async fn token(session: Session) -> HttpResponse {
    // Retrieve id_token and user_id from session
    match (
        session.get::<String>("id_token"),
        session.get::<String>("user_id"),
    ) {
        (Ok(Some(id_token)), Ok(Some(user_id))) => HttpResponse::Ok().json(serde_json::json!({
            "id_token": id_token,
            "user_id": user_id,
        })),
        (Ok(None), _) | (_, Ok(None)) => HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "No ID token or user ID found"
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
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

    let Some(url) = &oidc_config.ui_oidc_logout_url else {
        return HttpResponse::InternalServerError().body("Logout URL is missing");
    };
    let mut logout_url = match Url::parse(url) {
        Ok(parsed_url) => parsed_url,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Invalid logout URL: {e}"));
        }
    };

    let client_id = match &oidc_config.ui_oidc_client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };
    let redirect_url = format!("{}/ui/login", kms_url.as_str());

    logout_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
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
