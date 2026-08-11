use std::collections::HashMap;

use actix_session::Session;
use actix_web::{HttpRequest, HttpResponse, get, post, web};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
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

/// Claims encoded in the OIDC `state` parameter.
///
/// Per RFC 7636 §4.3, the `code_verifier` must survive the round-trip to the
/// `IdP` and back. Encoding it in `state` as a signed JWT avoids relying on the
/// KMS session cookie being returned on the cross-site POST→redirect chain
/// from the `IdP` (SameSite=Lax cookies are withheld by browsers in that context
/// per RFC 6265bis §5.2.2).
///
/// RFC 6749 §4.1.1 guarantees the authorization server returns `state`
/// unchanged, so this JWT is the right carrier.
#[derive(Debug, Serialize, Deserialize)]
struct OidcStateClaims {
    /// PKCE code verifier (RFC 7636 §4.1).
    pkce_verifier: String,
    /// Nonce for ID-token replay prevention (`OpenID` Connect Core §3.1.2.1).
    nonce: String,
    /// Expiry — 10 minutes from issuance (generous to handle slow logins).
    exp: usize,
}

impl OidcStateClaims {
    fn encode(pkce_verifier: String, nonce: String, key: &[u8; 32]) -> Result<String, String> {
        let exp = usize::try_from((chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp())
            .map_err(|e| format!("Failed to compute OIDC state JWT expiry: {e}"))?;
        let claims = Self {
            pkce_verifier,
            nonce,
            exp,
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(key),
        )
        .map_err(|e| format!("Failed to encode OIDC state JWT: {e}"))
    }

    fn decode(state: &str, key: &[u8; 32]) -> Result<Self, String> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        decode::<Self>(state, &DecodingKey::from_secret(key), &validation)
            .map(|t| t.claims)
            .map_err(|e| format!("Invalid OIDC state JWT: {e}"))
    }
}

#[get("/login_flow")]
pub(crate) async fn login(
    _session: Session,
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
    let Ok(nonce) = random_b64url(16) else {
        return HttpResponse::InternalServerError().body("Failed to create nonce");
    };

    // Encode {pkce_verifier, nonce} in the `state` parameter as a signed HS256 JWT.
    // This avoids storing them in the session cookie, which browsers withhold on
    // the cross-site POST→redirect chain from the IdP (SameSite=Lax, RFC 6265bis §5.2.2).
    // RFC 6749 §4.1.1 guarantees the AS returns `state` unchanged.
    let state =
        match OidcStateClaims::encode(pkce_verifier, nonce.clone(), &discovered.state_hmac_key) {
            Ok(s) => s,
            Err(e) => return HttpResponse::InternalServerError().body(e),
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
        .append_pair("state", &state)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce_challenge)
        .append_pair("nonce", &nonce); // echoed in ID token; verified in callback via state JWT

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

    // Extract the authorization code (or OAuth error).
    if let Some(err) = query.get("error") {
        let desc = query.get("error_description").map_or("", String::as_str);
        return HttpResponse::BadRequest()
            .body(format!("Authorization error from IdP: {err} — {desc}"));
    }
    let auth_code = match query.get("code") {
        Some(code) => code.to_owned(),
        None => return HttpResponse::BadRequest().body("Missing authorization code"),
    };

    // Decode the `state` JWT to recover the PKCE verifier and nonce.
    // This avoids the SameSite=Lax session-cookie issue (RFC 6265bis §5.2.2):
    // browsers withhold Lax cookies on the cross-site POST→redirect chain that
    // brings us back from the IdP. The state JWT is returned unchanged by the
    // AS per RFC 6749 §4.1.2 and is HMAC-signed so it cannot be forged.
    let received_state = match query.get("state") {
        Some(s) => s.as_str(),
        None => return HttpResponse::BadRequest().body("Missing state parameter"),
    };
    let state_claims = match OidcStateClaims::decode(received_state, &discovered.state_hmac_key) {
        Ok(c) => c,
        Err(e) => return HttpResponse::BadRequest().body(e),
    };
    let pkce_verifier = state_claims.pkce_verifier;
    let stored_nonce = state_claims.nonce;

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
    // Accept invalid TLS certs when the IdP uses a self-signed certificate (dev/test only).
    let Ok(client) = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(discovered.accept_invalid_certs)
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
        // Surface any error Auth0 returned to make debugging easier.
        let auth0_error = json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        let auth0_desc = json
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "No id_token in response",
            "auth0_error": auth0_error,
            "auth0_error_description": auth0_desc,
        }));
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

    // Extract the user identity from the id_token.
    // Prefer `sub` (used by auth-verifier OIDC OP, where sub = username), then fall
    // back to `email` (used by cloud IdPs such as Auth0 / Azure AD / Google).
    // The id_token is intentionally NOT stored in the session — the BFF pattern keeps
    // only the user_id; all subsequent UI requests are authenticated via the session cookie.
    let user_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .or_else(|| {
            claims
                .get("email")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        });
    let Some(user_id) = user_id else {
        return HttpResponse::InternalServerError()
            .json(serde_json::json!({ "error": "Missing sub and email claims in id_token" }));
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
pub(crate) async fn get_auth_method(auth_methods: web::Data<Vec<String>>) -> HttpResponse {
    let methods = auth_methods.get_ref();
    // The singular `auth_method` is kept for backward compatibility: it is the
    // highest-priority configured method (`auth_methods[0]`), or `"None"` when no
    // method is configured. New clients read the ordered `auth_methods` array to
    // render the multi-method login page (primary + secondary actions).
    let primary = methods
        .first()
        .cloned()
        .unwrap_or_else(|| "None".to_owned());

    HttpResponse::Ok().json(serde_json::json!({
        "auth_method": primary,
        "auth_methods": methods,
    }))
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
        let auth_methods: Vec<String> = vec!["AUTH_VERIFIER".to_owned()];
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth_methods))
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
        assert_eq!(
            body.get("auth_methods")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["AUTH_VERIFIER"])
        );
    }

    #[actix_web::test]
    async fn test_auth_method_returns_none_when_not_configured() {
        let auth_methods: Vec<String> = Vec::new();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth_methods))
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
        assert_eq!(
            body.get("auth_methods").and_then(|v| v.as_array()),
            Some(&vec![])
        );
    }

    #[actix_web::test]
    async fn test_auth_method_returns_ordered_list_when_multiple_configured() {
        // Priority order is JWT > AUTH_VERIFIER > CERT. The singular `auth_method`
        // must equal the first (primary) entry.
        let auth_methods: Vec<String> = vec![
            "JWT".to_owned(),
            "AUTH_VERIFIER".to_owned(),
            "CERT".to_owned(),
        ];
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth_methods))
                .service(get_auth_method),
        )
        .await;

        let req = test::TestRequest::get().uri("/auth_method").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(
            body.get("auth_method").and_then(|v| v.as_str()),
            Some("JWT")
        );
        assert_eq!(
            body.get("auth_methods")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>()),
            Some(vec!["JWT", "AUTH_VERIFIER", "CERT"])
        );
    }
}
