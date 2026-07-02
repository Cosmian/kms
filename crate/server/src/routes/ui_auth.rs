use std::collections::HashMap;

use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, get, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde_json::Value;
use url::Url;

use crate::config::OidcRuntimeConfig;

fn random_b64url(len_bytes: usize) -> Result<String, ()> {
    let mut buf = vec![0_u8; len_bytes];
    openssl::rand::rand_bytes(&mut buf).map_err(|_e| ())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn pkce_challenge_from_verifier(verifier: &str) -> String {
    let digest = openssl::sha::sha256(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[get("/login_flow")]
pub(crate) async fn login(
    session: Session,
    oidc_runtime: web::Data<OidcRuntimeConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let Some(ref discovered) = oidc_runtime.discovered else {
        return HttpResponse::InternalServerError()
            .body("OIDC is not configured or discovery failed at startup");
    };

    let client_id = match &oidc_runtime.config.ui_oidc_client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let redirect_url = format!("{}/ui/callback", kms_url.as_str());

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

    let mut auth_url = match Url::parse(&discovered.authorization_endpoint) {
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
    oidc_runtime: web::Data<OidcRuntimeConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let Some(ref discovered) = oidc_runtime.discovered else {
        return HttpResponse::InternalServerError()
            .body("OIDC is not configured or discovery failed at startup");
    };

    let Ok(query) = web::Query::<HashMap<String, String>>::from_query(req.query_string()) else {
        return HttpResponse::BadRequest().body("Invalid query parameters");
    };

    // Retrieve stored values.
    // PKCE is mandatory for the UI login flow: the login_flow handler always generates
    // and stores a verifier, so Ok(None) here means the session was lost or tampered.
    let pkce_verifier = match session.get::<String>("pkce_verifier") {
        Ok(Some(v)) => v,
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

    let client_id = match &oidc_runtime.config.ui_oidc_client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let issuer = match &oidc_runtime.config.ui_oidc_issuer_url {
        Some(url) => url.clone(),
        None => return HttpResponse::InternalServerError().body("Issuer URL is missing"),
    };

    let redirect_url = format!("{}/ui/callback", kms_url.as_str());

    // Disable redirect following to prevent SSRF via crafted 3xx responses (A10-3).
    let Ok(client) = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return HttpResponse::InternalServerError().body("Failed to build HTTP client");
    };

    // Exchange code for tokens using the cached token endpoint (no discovery fetch needed).
    let mut form: Vec<(String, String)> = vec![
        ("grant_type".to_owned(), "authorization_code".to_owned()),
        ("code".to_owned(), auth_code),
        ("redirect_uri".to_owned(), redirect_url),
        ("client_id".to_owned(), client_id.clone()),
        ("code_verifier".to_owned(), pkce_verifier),
    ];
    if let Some(secret) = oidc_runtime.config.ui_oidc_client_secret.clone() {
        form.push(("client_secret".to_owned(), secret));
    }

    let resp = match client
        .post(&discovered.token_endpoint)
        .form(&form)
        .send()
        .await
    {
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

    // Validate the id_token using the JwksManager. The authorization_endpoint and
    // token_endpoint were discovered and cached once at startup, but the signing
    // keys themselves are looked up dynamically here: if the `kid` isn't found in
    // the cached JWKS (e.g. the IdP rotated its signing keys since startup), force
    // a refresh and retry once before failing. `JwksManager::refresh()` is
    // internally throttled (60s) so this is safe even under repeated invalid-kid
    // probing. Mirrors the retry pattern used by the Cosmian auth middleware
    // (`cosmian_auth_token.rs`).
    let header = match decode_header(id_token_str) {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": format!("Failed to decode token header: {e}") }));
        }
    };

    let Some(kid) = header.kid else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "No kid in id_token" }));
    };

    let jwk = match discovered.jwks_manager.find(&kid) {
        Ok(Some(k)) => Some(k),
        Ok(None) => {
            // Key unknown: the IdP may have rotated its signing keys since startup.
            // Force a refresh (throttled to 60s) and retry once.
            if let Err(e) = discovered.jwks_manager.refresh().await {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": format!("JWKS refresh failed: {e}") }));
            }
            match discovered.jwks_manager.find(&kid) {
                Ok(k) => k,
                Err(e) => {
                    return HttpResponse::InternalServerError().json(
                        serde_json::json!({ "error": format!("JWKS lookup failed: {e}") }),
                    );
                }
            }
        }
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": format!("JWKS lookup failed: {e}") }));
        }
    };
    let Some(jwk) = jwk else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Key not found in JWKS" }));
    };

    let decoding_key = match DecodingKey::from_jwk(&jwk) {
        Ok(key) => key,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": format!("Failed to build decoding key: {e}") }));
        }
    };

    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[&client_id]);

    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        validation.set_issuer(&[&issuer]);
        validation.validate_exp = true;
    }

    #[cfg(any(test, feature = "insecure"))]
    {
        drop(issuer); // not used in insecure/test builds
        validation.validate_exp = false;
    }

    let claims = match decode::<Value>(id_token_str, &decoding_key, &validation) {
        Ok(v) => v.claims,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": format!("Token validation failed: {e}") }));
        }
    };

    // Validate nonce to prevent authorization code injection.
    let nonce_claim = claims.get("nonce").and_then(|v| v.as_str());
    if nonce_claim != Some(stored_nonce.as_str()) {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({ "error": "Nonce mismatch" }));
    }

    // Extract the user identity (email claim). The id_token is intentionally not
    // stored in the session — the BFF pattern requires only the user_id to be kept.
    // All subsequent API requests from the UI are authenticated via the session cookie.
    let Some(user_id) = claims.get("email").and_then(|v| v.as_str()).map(str::to_owned) else {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Missing email claim in id_token" }));
    };

    if session.insert("user_id", &user_id).is_err() {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Failed to store user_id in session" }));
    }

    HttpResponse::Found()
        .append_header(("Location", "/ui/locate"))
        .finish()
}

#[get("/whoami")]
pub(crate) async fn whoami(session: Session) -> HttpResponse {
    match session.get::<String>("user_id") {
        Ok(Some(user_id)) => {
            HttpResponse::Ok().json(serde_json::json!({ "user_id": user_id }))
        }
        Ok(None) => HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "No active session" })),
        Err(_) => HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Failed to read session" })),
    }
}

#[get("/logout")]
pub(crate) async fn logout(
    session: Session,
    oidc_runtime: web::Data<OidcRuntimeConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    session.purge();

    // TODO: when ui_oidc_logout_url is None (e.g. Cosmian auth or unconfigured OIDC),
    // purge session and redirect to /ui/login instead of returning 500.
    let Some(url) = &oidc_runtime.config.ui_oidc_logout_url else {
        return HttpResponse::InternalServerError().body("Logout URL is missing");
    };
    let mut logout_url = match Url::parse(url) {
        Ok(parsed_url) => parsed_url,
        Err(e) => {
            return HttpResponse::InternalServerError().body(format!("Invalid logout URL: {e}"));
        }
    };

    let client_id = match &oidc_runtime.config.ui_oidc_client_id {
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
        .service(whoami)
        .service(logout)
        .service(get_auth_method);
}
