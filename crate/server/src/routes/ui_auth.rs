use std::collections::HashMap;

use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::config::{AuthVerifierRuntimeConfig, OidcRuntimeConfig};

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
    // probing. Mirrors the retry pattern used by the Auth Verifier middleware
    // (`auth_verifier/token.rs`).
    let header = match decode_header(id_token_str) {
        Ok(h) => h,
        Err(e) => {
            return HttpResponse::Unauthorized().json(
                serde_json::json!({ "error": format!("Failed to decode token header: {e}") }),
            );
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
                    return HttpResponse::InternalServerError()
                        .json(serde_json::json!({ "error": format!("JWKS lookup failed: {e}") }));
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
            let msg = format!("Failed to build decoding key: {e}");
            return HttpResponse::Unauthorized().json(serde_json::json!({ "error": msg }));
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
        return HttpResponse::BadRequest().json(serde_json::json!({ "error": "Nonce mismatch" }));
    }

    // Extract the user identity (email claim). The id_token is intentionally not
    // stored in the session — the BFF pattern requires only the user_id to be kept.
    // All subsequent API requests from the UI are authenticated via the session cookie.
    let Some(user_id) = claims
        .get("email")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
    else {
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

/// Session cookie name set by the Auth Verifier server on a successful
/// `/login` call. Carries a JWT (`sub` = username); mirrors the constant of the same
/// name in `ckms login cosmian` (`kms/crate/clients/client/src/http_client/login.rs`).
const AUTH_VERIFIER_SESSION_COOKIE: &str = "_ea_";

/// Request body for `POST /ui/login_as`.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthVerifierLoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

/// Mirrors the Auth Verifier server's `AuthenticationResult` shape
/// (see `authentication/client/src/models/login.rs`). Duplicated here — rather than
/// depending on the `authentication` crate — the same way `ckms login cosmian`
/// (`kms/crate/clients/client/src/http_client/login.rs`) already does.
#[derive(Debug, Deserialize)]
struct AuthVerifierAuthenticationResult {
    next_step: AuthVerifierAuthenticationNextStep,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum AuthVerifierAuthenticationNextStep {
    Authenticated,
    TotpRequired,
    ChangePassword,
}

/// Response body for `POST /ui/login_as`. Mirrors the AS's `next_step` values so the
/// frontend can reuse the same state machine as `ckms login cosmian`'s TOTP handling.
#[derive(Debug, Serialize)]
struct AuthVerifierLoginResponse {
    next_step: &'static str,
}

/// BFF proxy login for the Auth Verifier server ("AS" / "SA").
///
/// The browser posts `{ username, password, totp_code? }`; this handler replays the
/// login as HTTP Basic auth against `{auth_verifier_url}/login?realm={realm}` —
/// mirroring `auth_verifier_login()` in `kms/crate/clients/client/src/http_client/login.rs` —
/// then validates the JWT the AS returns via `Set-Cookie: _ea_=<jwt>` using the same
/// JWKS-backed trust logic as the bearer-token `AuthVerifier` middleware
/// (`verify_auth_verifier_jwt_subject`). Only the resulting `sub` (username) is stored in the
/// session; the JWT itself never reaches the browser, keeping the same BFF guarantee
/// as the OIDC flow (`callback`, above).
#[post("/login_as")]
pub(crate) async fn login_as(
    session: Session,
    body: web::Json<AuthVerifierLoginRequest>,
    auth_verifier_runtime: web::Data<AuthVerifierRuntimeConfig>,
) -> HttpResponse {
    let config = &auth_verifier_runtime.config;
    if !config.ui_login_enabled() {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "The Auth Verifier server is not configured for the Web UI" }),
        );
    }
    let Some(ref jwks_manager) = auth_verifier_runtime.jwks_manager else {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "The Auth Verifier server JWKS manager is not available" }),
        );
    };
    // Guaranteed non-empty by `ui_login_enabled()`.
    let (Some(server_url), Some(realm)) = (
        config.auth_verifier_url.as_deref(),
        config.auth_verifier_realm.as_deref(),
    ) else {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "The Auth Verifier server is not configured for the Web UI" }),
        );
    };

    let Ok(mut url) = Url::parse(server_url.trim_end_matches('/')) else {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Invalid Auth Verifier server URL" }));
    };
    {
        let Ok(mut segments) = url.path_segments_mut() else {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({ "error": "Invalid Auth Verifier server URL: cannot be a base" }),
            );
        };
        segments.push("login");
    }
    url.query_pairs_mut().append_pair("realm", realm);

    let client = match Client::builder()
        .danger_accept_invalid_certs(config.auth_verifier_accept_invalid_certs)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": format!("Failed to build HTTP client: {e}") }));
        }
    };

    let request_body = body.totp_code.as_deref().map_or_else(
        || "{}".to_owned(),
        |code| serde_json::json!({ "totp_code": code }).to_string(),
    );

    let response = match client
        .post(url)
        .basic_auth(&body.username, Some(&body.password))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::BadGateway().json(
                serde_json::json!({ "error": format!("Failed to reach the Auth Verifier server: {e}") }),
            );
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        return HttpResponse::Unauthorized().json(
            serde_json::json!({ "error": format!("Auth Verifier server rejected the login ({status})") }),
        );
    }

    // Extract the session JWT from Set-Cookie before consuming the body.
    let session_token = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .find_map(|value| {
            let raw = value.to_str().ok()?;
            let (name, cookie_value) = raw.split(';').next()?.split_once('=')?;
            (name.trim() == AUTH_VERIFIER_SESSION_COOKIE).then(|| cookie_value.trim().to_owned())
        });

    let body_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({ "error": format!("Failed to read login response: {e}") }),
            );
        }
    };
    let result: AuthVerifierAuthenticationResult = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => {
            return HttpResponse::InternalServerError().json(
                serde_json::json!({ "error": format!("Failed to parse login response: {e}") }),
            );
        }
    };

    match result.next_step {
        AuthVerifierAuthenticationNextStep::TotpRequired => HttpResponse::Ok().json(AuthVerifierLoginResponse {
            next_step: "TotpRequired",
        }),
        AuthVerifierAuthenticationNextStep::ChangePassword => HttpResponse::Forbidden().json(
            serde_json::json!({ "error": "Your password has expired. Please change it via the Auth Verifier server before logging in." }),
        ),
        AuthVerifierAuthenticationNextStep::Authenticated => {
            let Some(token) = session_token else {
                return HttpResponse::InternalServerError().json(
                    serde_json::json!({ "error": format!("Auth Verifier server did not set the `{AUTH_VERIFIER_SESSION_COOKIE}` session cookie") }),
                );
            };

            let user_id = match crate::middlewares::verify_auth_verifier_jwt_subject(jwks_manager, &token).await
            {
                Ok(sub) => sub,
                Err(e) => {
                    return HttpResponse::Unauthorized().json(
                        serde_json::json!({ "error": format!("Failed to validate the Auth Verifier server token: {e}") }),
                    );
                }
            };

            if session.insert("user_id", &user_id).is_err() {
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({ "error": "Failed to store user_id in session" }));
            }

            HttpResponse::Ok().json(AuthVerifierLoginResponse {
                next_step: "Authenticated",
            })
        }
    }
}

#[get("/whoami")]
pub(crate) async fn whoami(session: Session) -> HttpResponse {
    match session.get::<String>("user_id") {
        Ok(Some(user_id)) => HttpResponse::Ok().json(serde_json::json!({ "user_id": user_id })),
        Ok(None) => {
            HttpResponse::Unauthorized().json(serde_json::json!({ "error": "No active session" }))
        }
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

    // When no OIDC logout URL is configured (e.g. the session was established via the
    // Auth Verifier server, or OIDC simply isn't set up), there is no external
    // IdP session to terminate: just drop the local session (done above) and send the
    // browser back to the login page.
    let Some(url) = &oidc_runtime.config.ui_oidc_logout_url else {
        return HttpResponse::Found()
            .append_header(("Location", "/ui/login"))
            .finish();
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
        .service(login_as)
        .service(whoami)
        .service(logout)
        .service(get_auth_method);
}

#[cfg(test)]
mod tests {
    use actix_web::{App, test, web};

    use super::get_auth_method;

    #[actix_web::test]
    async fn test_auth_method_returns_cosmian_when_configured() {
        let auth_type: Option<String> = Some("AUTH_VERIFIER".to_owned());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth_type))
                .service(get_auth_method),
        )
        .await;

        let req = test::TestRequest::get().uri("/auth_method").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body.get("auth_method").and_then(|v| v.as_str()),
            Some("AUTH_VERIFIER")
        );
    }

    #[actix_web::test]
    async fn test_auth_method_returns_none_when_not_configured() {
        let auth_type: Option<String> = None;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth_type))
                .service(get_auth_method),
        )
        .await;

        let req = test::TestRequest::get().uri("/auth_method").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body.get("auth_method").and_then(|v| v.as_str()),
            Some("None")
        );
    }
}
