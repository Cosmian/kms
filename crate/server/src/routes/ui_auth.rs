use std::{collections::HashMap, sync::Arc};

use actix_web::{
    HttpRequest, HttpResponse, get,
    http::header::{self, SET_COOKIE},
    post, web,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::KmsRng;
use cosmian_logger::{debug, warn};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::{
    config::{AuthVerifierRuntimeConfig, OidcRuntimeConfig},
    core::KMS,
    middlewares::{
        AUTH_VERIFIER_SESSION_COOKIE, JwtConfig, JwtTokenHeaders, LoginAsLimiter, UiSession,
        UiSessionCookie, UserId, authenticate_auth_verifier_session_cookie,
        hardened_client_builder, reject_reserved_service_identity, request_cookie,
        validate_jwt_svid,
    },
};

fn random_b64url(rng: &KmsRng, len_bytes: usize) -> Result<String, ()> {
    let mut buf = vec![0_u8; len_bytes];
    rng.fill_bytes(&mut buf).map_err(|_e| ())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn pkce_challenge_from_verifier(verifier: &str) -> String {
    let digest = openssl::sha::sha256(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[get("/login_flow")]
pub(crate) async fn login(
    session_cookie: web::Data<UiSessionCookie>,
    oidc_runtime: web::Data<OidcRuntimeConfig>,
    kms_url: web::Data<String>,
    kms: web::Data<Arc<KMS>>,
) -> HttpResponse {
    let Some(ref discovered) = oidc_runtime.discovered else {
        return HttpResponse::InternalServerError()
            .body("OIDC is not configured or discovery failed at startup");
    };

    let client_id = match &oidc_runtime.config.client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let redirect_url = format!("{}/ui/callback", kms_url.as_str());

    let Ok(pkce_verifier) = random_b64url(&kms.rng, 32) else {
        return HttpResponse::InternalServerError().body("Failed to create PKCE verifier");
    };
    let pkce_challenge = pkce_challenge_from_verifier(&pkce_verifier);
    let Ok(csrf_token) = random_b64url(&kms.rng, 16) else {
        return HttpResponse::InternalServerError().body("Failed to create CSRF token");
    };
    let Ok(nonce) = random_b64url(&kms.rng, 16) else {
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

    // A new login drops whatever the browser presented before: only these values are kept.
    let session = UiSession {
        pkce_verifier: Some(pkce_verifier),
        csrf_token: Some(csrf_token),
        nonce: Some(nonce),
        user_id: None,
    };
    let Ok(set_cookie) = session_cookie.set_cookie(&session) else {
        return HttpResponse::InternalServerError().body("Failed to create the session cookie");
    };

    HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .insert_header((SET_COOKIE, set_cookie))
        .finish()
}

#[get("/callback")]
pub(crate) async fn callback(
    req: HttpRequest,
    session_cookie: web::Data<UiSessionCookie>,
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
    // and stores a verifier, so a missing value means the session was lost or tampered.
    let stored = session_cookie.read(req.headers()).await.unwrap_or_default();
    let Some(pkce_verifier) = stored.pkce_verifier else {
        return HttpResponse::BadRequest().body("Missing PKCE verifier");
    };
    let Some(stored_csrf_token) = stored.csrf_token else {
        return HttpResponse::BadRequest().body("Missing CSRF token");
    };
    let Some(stored_nonce) = stored.nonce else {
        return HttpResponse::BadRequest().body("Missing nonce");
    };

    // Validate CSRF token
    let Some(received_csrf_token) = query.get("state") else {
        return HttpResponse::BadRequest().body("Missing state parameter");
    };
    if *received_csrf_token != stored_csrf_token {
        return HttpResponse::BadRequest().body("CSRF token mismatch");
    }

    // Extract authorization code
    let auth_code = match query.get("code") {
        Some(code) => code.to_owned(),
        None => return HttpResponse::BadRequest().body("Missing authorization code"),
    };

    let client_id = match &oidc_runtime.config.client_id {
        Some(id) => id.clone(),
        None => return HttpResponse::InternalServerError().body("Client ID is missing"),
    };

    let issuer = match &oidc_runtime.config.issuer_url {
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
    if let Some(secret) = oidc_runtime.config.client_secret.clone() {
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

    // RFC 7515 §4.1.11: `jsonwebtoken` ignores `crit`, so enforce it here.
    if let Err(e) =
        JwtTokenHeaders::from_token(id_token_str).and_then(|h| h.reject_unsupported_extensions())
    {
        return HttpResponse::Unauthorized().json(serde_json::json!({ "error": e.to_string() }));
    }

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
    validation.algorithms = vec![header.alg];
    validation.set_audience(&[&client_id]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

    #[cfg(all(not(test), not(feature = "insecure")))]
    {
        validation.set_issuer(&[&issuer]);
        validation.validate_exp = true;
    }

    #[cfg(any(test, feature = "insecure"))]
    {
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
    let Some(email) = claims.get("email").and_then(Value::as_str) else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Missing email claim in id_token" }));
    };
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(verified)) => *verified,
        Some(Value::String(verified)) => verified == "true",
        _ => false,
    };
    if !email_verified {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "JWT email is not verified (email_verified must be true)"
        }));
    }
    if email.trim().is_empty() {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Empty email claim in id_token" }));
    }
    let user_id = if oidc_runtime
        .primary_jwt_issuer
        .as_ref()
        .is_some_and(|primary| primary != &issuer)
    {
        format!("{email}#{issuer}")
    } else {
        email.to_owned()
    };
    let Ok(user_id) = UserId::try_new(user_id.as_str()) else {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": "Empty email claim in id_token" }));
    };
    if let Err(error) = reject_reserved_service_identity(&user_id) {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({ "error": format!("Forbidden user identity: {error}") }));
    }

    // A brand-new cookie: the one-time PKCE verifier, state and nonce are not carried over.
    let Some(set_cookie) = login_cookie(&session_cookie, user_id) else {
        return session_store_failure();
    };

    HttpResponse::Found()
        .append_header(("Location", "/ui/locate"))
        .insert_header((SET_COOKIE, set_cookie))
        .finish()
}

/// Request body for `POST /ui/login_as`.
#[derive(Debug, Deserialize)]
pub(crate) struct AuthVerifierLoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

/// Request body for `POST /ui/login_svid`.
#[derive(Debug, Deserialize)]
pub(crate) struct JwtSvidLoginRequest {
    jwt_svid: String,
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

/// Longest accepted `username` of `POST /ui/login_as`.
const MAX_LOGIN_USERNAME_BYTES: usize = 256;

/// `429` of `POST /ui/login_as`, with the `Retry-After` (seconds or HTTP date) when known.
fn too_many_login_attempts(retry_after: Option<&str>) -> HttpResponse {
    let mut response = HttpResponse::TooManyRequests();
    if let Some(retry_after) = retry_after {
        response.insert_header((header::RETRY_AFTER, retry_after));
    }
    response.json(serde_json::json!({ "error": "Too many login attempts" }))
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
    req: HttpRequest,
    session_cookie: web::Data<UiSessionCookie>,
    body: web::Json<AuthVerifierLoginRequest>,
    auth_verifier_runtime: web::Data<AuthVerifierRuntimeConfig>,
    limiter: web::Data<LoginAsLimiter>,
) -> HttpResponse {
    // Bounds the limiter's per-username keys: a longer name is never a real account.
    if body.username.len() > MAX_LOGIN_USERNAME_BYTES {
        let error = serde_json::json!({ "error": "Username too long" });
        return HttpResponse::BadRequest().json(error);
    }
    // Every attempt is counted, before any credential is relayed upstream.
    let client_ip = limiter.client_ip(&req);
    if let Err(retry_after) = limiter.check(client_ip, &body.username) {
        warn!("login_as: too many attempts from {client_ip}");
        return too_many_login_attempts(Some(&retry_after.to_string()));
    }
    let config = &auth_verifier_runtime.config;
    if !config.ui_login_enabled() {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "The Auth Verifier server is not configured for the Web UI" }),
        );
    }
    let Some(auth_verifier) = &auth_verifier_runtime.auth_verifier else {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "The Auth Verifier server validator is not available" }),
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

    let client = match hardened_client_builder(config.auth_verifier_accept_invalid_certs).build() {
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

    // The Auth Verifier throttles too: tell the browser to back off instead of reporting bad credentials.
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok());
        return too_many_login_attempts(retry_after);
    }
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

            let user_id = match crate::middlewares::verify_auth_verifier_jwt_subject(auth_verifier, &token, Some(realm)).await
            {
                Ok(sub) => sub,
                Err(e) => {
                    return HttpResponse::Unauthorized().json(
                        serde_json::json!({ "error": format!("Failed to validate the Auth Verifier server token: {e}") }),
                    );
                }
            };
            let Ok(user_id) = UserId::try_new(user_id.as_str()) else {
                return HttpResponse::Unauthorized().json(
                    serde_json::json!({ "error": "Empty subject claim in Auth Verifier token" }),
                );
            };
            if let Err(error) = reject_reserved_service_identity(&user_id) {
                return HttpResponse::Unauthorized().json(
                    serde_json::json!({ "error": format!("Forbidden user identity: {error}") }),
                );
            }

            let Some(set_cookie) = login_cookie(&session_cookie, user_id) else {
                return session_store_failure();
            };

            HttpResponse::Ok()
                .insert_header((SET_COOKIE, set_cookie))
                .json(AuthVerifierLoginResponse {
                    next_step: "Authenticated",
                })
        }
    }
}

/// SPIFFE JWT-SVID session login, meant for a gateway / BFF in front of the Web UI.
///
/// The caller posts `{ "jwt_svid": "<token>" }` with a JWT-SVID minted by SPIRE (Workload
/// API or `spire-server jwt mint`). The token is validated against the SPIFFE-enabled JWT
/// issuers configured via `--jwt-auth-provider` + `--jwt-svid-auth` — the same
/// configuration used for bearer-token API/KMIP authentication — and its `sub` MUST be a
/// `spiffe://` ID (a token that only carries an `email` claim is rejected). On success the
/// `sub` claim (`spiffe://<trust-domain>/<path>`) becomes the session's `user_id`, exactly
/// like the OIDC `callback` and Auth Verifier `login_as` flows above.
#[post("/login_svid")]
pub(crate) async fn login_svid(
    session_cookie: web::Data<UiSessionCookie>,
    body: web::Json<JwtSvidLoginRequest>,
    jwt_configurations: web::Data<Arc<Vec<JwtConfig>>>,
) -> HttpResponse {
    if !jwt_configurations.iter().any(|c| c.accept_spiffe_subject) {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "SPIFFE JWT-SVID login is not enabled on this server" }),
        );
    }

    let authenticated = match validate_jwt_svid(&jwt_configurations, body.jwt_svid.trim()).await {
        Ok(user) => user,
        Err(e) => {
            return HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": format!("{e}") }));
        }
    };

    // Every login issues a brand-new sealed cookie and keeps nothing from a cookie presented
    // before authentication, so session fixation is impossible.
    let Some(set_cookie) = login_cookie(&session_cookie, authenticated.username) else {
        return session_store_failure();
    };

    HttpResponse::Ok()
        .insert_header((SET_COOKIE, set_cookie))
        .json(serde_json::json!({ "next_step": "Authenticated" }))
}

#[get("/whoami")]
pub(crate) async fn whoami(
    req: HttpRequest,
    session_cookie: web::Data<UiSessionCookie>,
    auth_verifier_runtime: web::Data<AuthVerifierRuntimeConfig>,
) -> HttpResponse {
    // Same precedence as the API middlewares: the Auth Verifier cookie wins over the KMS session.
    if let Some(user_id) = auth_verifier_session_user(&req, &auth_verifier_runtime).await {
        return HttpResponse::Ok().json(serde_json::json!({ "user_id": user_id }));
    }
    session_cookie
        .read(req.headers())
        .await
        .and_then(|s| s.user_id)
        .map_or_else(
            || {
                HttpResponse::Unauthorized()
                    .json(serde_json::json!({ "error": "No active session" }))
            },
            |user_id| HttpResponse::Ok().json(serde_json::json!({ "user_id": user_id })),
        )
}

/// The user of a valid Auth Verifier SAML session cookie, when SAML sign-on is enabled.
async fn auth_verifier_session_user(
    req: &HttpRequest,
    auth_verifier_runtime: &AuthVerifierRuntimeConfig,
) -> Option<UserId> {
    let realm = auth_verifier_runtime.config.saml_session_realm()?;
    let auth_verifier = auth_verifier_runtime.auth_verifier.as_ref()?;
    let cookie = request_cookie(req.headers(), AUTH_VERIFIER_SESSION_COOKIE)?;
    authenticate_auth_verifier_session_cookie(auth_verifier, cookie, realm)
        .await
        .inspect_err(|e| debug!("Auth Verifier session cookie rejected: {e}"))
        .ok()
}

/// Start SAML single sign-on through the Auth Verifier server.
///
/// Redirects the browser to the Auth Verifier SAML login of the configured realm, which
/// must be reverse-proxied on the KMS public origin so that the `_ea_` session cookie it
/// sets is sent back to the KMS. After sign-in the browser returns to the Web UI.
#[get("/login_saml")]
pub(crate) async fn login_saml(
    session_cookie: web::Data<UiSessionCookie>,
    auth_verifier_runtime: web::Data<AuthVerifierRuntimeConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    let Some(realm) = auth_verifier_runtime.config.saml_session_realm() else {
        return HttpResponse::InternalServerError().json(
            serde_json::json!({ "error": "SAML single sign-on is not configured on this server" }),
        );
    };
    match saml_login_url(kms_url.as_str(), realm) {
        Ok(url) => {
            // Drop any previous KMS session so it cannot outlive the SAML identity switch.
            HttpResponse::Found()
                .insert_header((header::LOCATION, url.as_str()))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .insert_header((SET_COOKIE, session_cookie.removal_cookie()))
                .finish()
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": e })),
    }
}

/// `{origin}/saml/{realm}/login?return_to={kms_public_url}/ui/locate`.
///
/// The Auth Verifier binds its SAML login cookie to the `/saml/` path, so the SAML
/// routes live at the root of the KMS origin even when `kms_public_url` has a path.
fn saml_login_url(kms_public_url: &str, realm: &str) -> Result<Url, String> {
    let return_to = format!("{}/ui/locate", kms_public_url.trim_end_matches('/'));
    let mut url = Url::parse(kms_public_url).map_err(|e| format!("Invalid KMS public URL: {e}"))?;
    url.set_query(None);
    url.set_fragment(None);
    url.path_segments_mut()
        .map_err(|()| "Invalid KMS public URL: cannot be a base".to_owned())?
        .clear()
        .extend(["saml", realm, "login"]);
    url.query_pairs_mut().append_pair("return_to", &return_to);
    Ok(url)
}

#[get("/logout")]
pub(crate) async fn logout(
    req: HttpRequest,
    session_cookie: web::Data<UiSessionCookie>,
    oidc_runtime: web::Data<OidcRuntimeConfig>,
    auth_verifier_runtime: web::Data<AuthVerifierRuntimeConfig>,
    kms_url: web::Data<String>,
) -> HttpResponse {
    // Server-side revocation: a copy of the cookie kept elsewhere stops working too.
    session_cookie.revoke(req.headers()).await;
    let mut response = HttpResponse::Found();
    response.append_header((SET_COOKIE, session_cookie.removal_cookie()));
    if end_auth_verifier_session(&req, &auth_verifier_runtime).await {
        response.append_header((SET_COOKIE, expired_auth_verifier_session_cookie()));
    }

    // When no OIDC logout URL is configured (e.g. the session was established via the
    // Auth Verifier server, or OIDC simply isn't set up), there is no external
    // IdP session to terminate: just drop the local session (done above) and send the
    // browser back to the login page.
    let Some(url) = &oidc_runtime.config.logout_url else {
        return response.append_header(("Location", "/ui/login")).finish();
    };
    let mut logout_url = match Url::parse(url) {
        Ok(parsed_url) => parsed_url,
        Err(e) => {
            return HttpResponse::InternalServerError()
                .append_header((SET_COOKIE, session_cookie.removal_cookie()))
                .body(format!("Invalid logout URL: {e}"));
        }
    };

    let client_id = match &oidc_runtime.config.client_id {
        Some(id) => id.clone(),
        None => {
            return HttpResponse::InternalServerError()
                .append_header((SET_COOKIE, session_cookie.removal_cookie()))
                .body("Client ID is missing");
        }
    };
    let redirect_url = format!("{}/ui/login", kms_url.as_str());

    logout_url
        .query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("returnTo", &redirect_url);

    response
        .append_header(("Location", logout_url.to_string()))
        .finish()
}

/// Revoke the browser's Auth Verifier SAML session, if any, on the Auth Verifier.
///
/// Returns `true` when the browser holds a valid session of the SAML realm, so the caller
/// expires the `_ea_` cookie. Any other cookie (garbage, another realm of the same Auth
/// Verifier) is neither forwarded to the Auth Verifier nor expired. Revocation is best
/// effort: logout still succeeds locally if the Auth Verifier cannot be reached.
async fn end_auth_verifier_session(
    req: &HttpRequest,
    auth_verifier_runtime: &AuthVerifierRuntimeConfig,
) -> bool {
    let Some(server_url) = auth_verifier_runtime.config.auth_verifier_url.as_deref() else {
        return false;
    };
    if auth_verifier_session_user(req, auth_verifier_runtime)
        .await
        .is_none()
    {
        return false;
    }
    let Some(cookie) = request_cookie(req.headers(), AUTH_VERIFIER_SESSION_COOKIE) else {
        return false;
    };
    if let Err(e) = revoke_auth_verifier_session(
        server_url,
        auth_verifier_runtime
            .config
            .auth_verifier_accept_invalid_certs,
        cookie,
    )
    .await
    {
        warn!("Logout: failed to revoke the Auth Verifier session: {e}");
    }
    // The session is gone (or the Auth Verifier unreachable): stop trusting it at once here.
    if let Some(auth_verifier) = &auth_verifier_runtime.auth_verifier {
        auth_verifier.forget_session(cookie);
    }
    true
}

/// `DELETE {auth_verifier_url}/sessions`, authenticated by the session cookie itself.
/// The Auth Verifier identifies a session by the SHA-256 of its cookie value.
async fn revoke_auth_verifier_session(
    server_url: &str,
    accept_invalid_certs: bool,
    token: &str,
) -> Result<(), String> {
    let mut url = Url::parse(server_url.trim_end_matches('/'))
        .map_err(|e| format!("invalid Auth Verifier server URL: {e}"))?;
    url.path_segments_mut()
        .map_err(|()| "invalid Auth Verifier server URL: cannot be a base".to_owned())?
        .push("sessions");
    let session_id = hex::encode(openssl::sha::sha256(token.as_bytes()));

    let response = hardened_client_builder(accept_invalid_certs)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))?
        .delete(url)
        .header(
            reqwest::header::COOKIE,
            format!("{AUTH_VERIFIER_SESSION_COOKIE}={token}"),
        )
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "session_ids": [session_id] }).to_string())
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("Auth Verifier answered {}", response.status()));
    }
    Ok(())
}

/// Removal cookie for the Auth Verifier session; must match the name and path it was set with.
fn expired_auth_verifier_session_cookie() -> String {
    format!(
        "{AUTH_VERIFIER_SESSION_COOKIE}=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; \
         Secure; HttpOnly; SameSite=Strict"
    )
}

/// `Set-Cookie` value of a session holding only the authenticated `user_id`.
fn login_cookie(session_cookie: &UiSessionCookie, user_id: UserId) -> Option<String> {
    session_cookie
        .set_cookie(&UiSession {
            user_id: Some(user_id),
            ..UiSession::default()
        })
        .ok()
}

fn session_store_failure() -> HttpResponse {
    HttpResponse::InternalServerError()
        .json(serde_json::json!({ "error": "Failed to store user_id in session" }))
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
        .service(login_saml)
        .service(login_svid)
        .service(whoami)
        .service(logout)
        .service(get_auth_method);
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use actix_web::{
        App,
        dev::ServiceResponse,
        http::{
            StatusCode,
            header::{self, HeaderMap, HeaderValue},
        },
        test, web,
    };
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use url::{Url, form_urlencoded};

    use super::{
        URL_SAFE_NO_PAD, callback, get_auth_method, login, login_as, login_saml, login_svid,
        logout, pkce_challenge_from_verifier, saml_login_url, whoami,
    };
    use crate::{
        config::{
            AuthVerifierConfig, AuthVerifierRuntimeConfig, OidcConfig, OidcDiscoveredEndpoints,
            OidcRuntimeConfig,
        },
        middlewares::{
            AUTH_VERIFIER_SESSION_COOKIE, JwksManager, JwtConfig, LoginAsLimiter, UiSession,
            UserId,
            auth_verifier_test_helpers::{auth_verifier_token, live_auth_verifier},
            test_session_cookie_pair, test_ui_session_cookie,
        },
        tests::test_utils::{https_clap_config, test_kms_with_config},
    };

    const KMS_URL: &str = "https://kms.example.com";

    async fn saml_runtime(saml_realm: Option<&str>) -> AuthVerifierRuntimeConfig {
        AuthVerifierRuntimeConfig {
            config: AuthVerifierConfig {
                // Unroutable: logout revocation must stay best effort.
                auth_verifier_url: Some("https://127.0.0.1:9".to_owned()),
                auth_verifier_saml_realm: saml_realm.map(str::to_owned),
                ..AuthVerifierConfig::default()
            },
            auth_verifier: Some(live_auth_verifier().await),
        }
    }

    #[actix_web::test]
    async fn saml_login_url_targets_origin_root_and_returns_to_ui() {
        assert_eq!(
            saml_login_url("https://kms.example.com/kms/", "my realm/x").map(String::from),
            Ok("https://kms.example.com/saml/my%20realm%2Fx/login?return_to=https%3A%2F%2Fkms.example.com%2Fkms%2Fui%2Flocate".to_owned())
        );
    }

    #[actix_web::test]
    async fn login_saml_redirects_to_auth_verifier_saml_login() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(Some("kms-saml")).await))
                .app_data(web::Data::new(KMS_URL.to_owned()))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(login_saml),
        )
        .await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/login_saml").to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some(
                "https://kms.example.com/saml/kms-saml/login?return_to=https%3A%2F%2Fkms.example.com%2Fui%2Flocate"
            )
        );
    }

    #[actix_web::test]
    async fn login_saml_fails_when_not_configured() {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(None).await))
                .app_data(web::Data::new(KMS_URL.to_owned()))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(login_saml),
        )
        .await;
        let resp = test::call_service(
            &app,
            test::TestRequest::get().uri("/login_saml").to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn whoami_status(
        saml_realm: Option<&str>,
        token: &str,
    ) -> (StatusCode, serde_json::Value) {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(saml_realm).await))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(whoami),
        )
        .await;
        let req = test::TestRequest::get()
            .uri("/whoami")
            .insert_header((
                header::COOKIE,
                format!("{AUTH_VERIFIER_SESSION_COOKIE}={token}"),
            ))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status();
        (status, test::read_body_json(resp).await)
    }

    #[actix_web::test]
    async fn whoami_resolves_user_from_auth_verifier_session_cookie() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let (status, body) = whoami_status(Some("kms-saml"), &token).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body.get("user_id").and_then(|v| v.as_str()),
            Some("alice@example.com")
        );
    }

    #[actix_web::test]
    async fn whoami_rejects_cookie_of_another_realm_or_when_saml_disabled() {
        let other_realm = auth_verifier_token("alice@example.com", Some("other-app"));
        assert_eq!(
            whoami_status(Some("kms-saml"), &other_realm).await.0,
            StatusCode::UNAUTHORIZED
        );
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        assert_eq!(
            whoami_status(None, &token).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    /// The `_ea_` removal `Set-Cookie` of `GET /logout` for a request carrying `token`, if any.
    async fn logout_removal_cookie(token: String) -> Option<String> {
        let resp = logout_response(Some(format!("{AUTH_VERIFIER_SESSION_COOKIE}={token}"))).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with(&format!("{AUTH_VERIFIER_SESSION_COOKIE}=")))
    }

    /// An OIDC runtime with default settings and no discovery document.
    fn default_oidc_runtime() -> OidcRuntimeConfig {
        OidcRuntimeConfig {
            config: OidcConfig::default(),
            discovered: None,
            primary_jwt_issuer: None,
        }
    }

    /// `GET /logout` carrying the given `Cookie` header, if any.
    async fn logout_response(
        cookie: Option<String>,
    ) -> actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody> {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(Some("kms-saml")).await))
                .app_data(web::Data::new(default_oidc_runtime()))
                .app_data(web::Data::new(KMS_URL.to_owned()))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(logout),
        )
        .await;
        let mut req = test::TestRequest::get().uri("/logout");
        if let Some(cookie) = cookie {
            req = req.insert_header((header::COOKIE, cookie));
        }
        test::call_service(&app, req.to_request()).await
    }

    fn set_cookies<B>(resp: &actix_web::dev::ServiceResponse<B>) -> Vec<String> {
        resp.headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|v| v.to_str().ok())
            .map(str::to_owned)
            .collect()
    }

    #[actix_web::test]
    async fn logout_expires_auth_verifier_session_cookie() {
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        let removal = logout_removal_cookie(token)
            .await
            .expect("logout must expire the Auth Verifier session cookie");
        assert!(removal.starts_with("_ea_=;"), "{removal}");
        assert!(removal.contains("Path=/"), "{removal}");
        assert!(removal.contains("Max-Age=0"), "{removal}");
    }

    #[actix_web::test]
    async fn logout_expires_kms_session_cookie() {
        let resp = logout_response(None).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let removal = set_cookies(&resp)
            .into_iter()
            .find(|c| c.starts_with("auth_session=;"))
            .expect("logout must expire the KMS session cookie");
        assert!(removal.contains("Max-Age=0"), "{removal}");
    }

    #[actix_web::test]
    async fn logout_revokes_the_kms_session_cookie() {
        let codec = web::Data::new(test_ui_session_cookie());
        let cookie = test_session_cookie_pair(&codec, "alice@example.com");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(None).await))
                .app_data(web::Data::new(default_oidc_runtime()))
                .app_data(web::Data::new(KMS_URL.to_owned()))
                .app_data(codec.clone())
                .service(whoami)
                .service(logout),
        )
        .await;
        let request = |uri: &str| {
            test::TestRequest::get()
                .uri(uri)
                .insert_header((header::COOKIE, cookie.clone()))
                .to_request()
        };

        let resp = test::call_service(&app, request("/whoami")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = test::call_service(&app, request("/logout")).await;
        assert_eq!(resp.status(), StatusCode::FOUND);

        // A copy of the cookie kept by the browser (or an attacker) is dead server-side.
        let resp = test::call_service(&app, request("/whoami")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// A mock Auth Verifier on a loopback port answering every request with `status_line` and
    /// `extra_headers` (each ending in CRLF). Returns the port and the count of requests seen.
    async fn mock_login_upstream(
        status_line: &'static str,
        extra_headers: &'static str,
    ) -> (u16, Arc<AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local address").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0_u8; 8192];
                let _read = stream.read(&mut buf).await.unwrap_or(0);
                counter.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: 2\r\n\
                     Connection: close\r\n\r\n{{}}"
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("mock Auth Verifier response");
            }
        });
        (port, hits)
    }

    /// `POST /login_as` as `username` from `peer`.
    async fn post_login_as<S, B>(app: &S, peer: &str, username: &str) -> ServiceResponse<B>
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = ServiceResponse<B>,
                Error = actix_web::Error,
            >,
    {
        let request = test::TestRequest::post()
            .uri("/login_as")
            .peer_addr(peer.parse().expect("socket address"))
            .set_json(serde_json::json!({ "username": username, "password": "pw" }))
            .to_request();
        test::call_service(app, request).await
    }

    async fn login_as_app(
        port: u16,
        trusted_proxies: Vec<ipnet::IpNet>,
    ) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    > {
        let runtime = AuthVerifierRuntimeConfig {
            config: AuthVerifierConfig {
                auth_verifier_url: Some(format!("http://127.0.0.1:{port}")),
                auth_verifier_realm: Some("kms".to_owned()),
                ..AuthVerifierConfig::default()
            },
            auth_verifier: Some(live_auth_verifier().await),
        };
        test::init_service(
            App::new()
                .app_data(web::Data::new(runtime))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .app_data(web::Data::new(LoginAsLimiter::new(trusted_proxies)))
                .service(login_as),
        )
        .await
    }

    #[actix_web::test]
    async fn login_as_is_rate_limited_before_reaching_the_auth_verifier() {
        let (port, hits) = mock_login_upstream("401 Unauthorized", "").await;
        let app = login_as_app(port, Vec::new()).await;

        for attempt in 1..=5 {
            let resp = post_login_as(&app, "10.0.0.1:4000", "u1").await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attempt {attempt}");
        }
        let resp = post_login_as(&app, "10.0.0.1:4000", "u1").await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        assert!(retry_after.is_some_and(|secs| secs >= 1), "{retry_after:?}");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            5,
            "the 6th attempt was relayed"
        );

        // Another user from another IP is still served.
        let resp = post_login_as(&app, "10.0.0.2:4000", "u2").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(hits.load(Ordering::SeqCst), 6);
    }

    #[actix_web::test]
    async fn login_as_rejects_an_oversized_username_without_relaying_it() {
        let (port, hits) = mock_login_upstream("401 Unauthorized", "").await;
        let app = login_as_app(port, Vec::new()).await;

        let resp = post_login_as(&app, "10.0.0.1:4000", &"a".repeat(10_000)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// Behind a trusted reverse proxy each end user has their own per-IP quota; from an
    /// untrusted peer, `X-Forwarded-For` is ignored.
    #[actix_web::test]
    async fn login_as_throttles_per_forwarded_client_behind_a_trusted_proxy() {
        let (port, _hits) = mock_login_upstream("401 Unauthorized", "").await;
        let trusted = login_as_app(port, vec!["10.0.0.0/8".parse().expect("cidr")]).await;
        let request = |peer: &str, client: String, user: String| {
            test::TestRequest::post()
                .uri("/login_as")
                .peer_addr(peer.parse().expect("socket address"))
                .insert_header(("X-Forwarded-For", client))
                .set_json(serde_json::json!({ "username": user, "password": "pw" }))
                .to_request()
        };

        // 11 distinct users behind one trusted proxy, each from a distinct client: all served.
        for i in 0..11 {
            let req = request("10.0.0.1:4000", format!("203.0.113.{i}"), format!("u{i}"));
            let resp = test::call_service(&trusted, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "client {i}");
        }

        // Same 11 users, an untrusted peer forging X-Forwarded-For: one shared bucket of 10.
        let untrusted = login_as_app(port, Vec::new()).await;
        let mut last = StatusCode::OK;
        for i in 0..11 {
            let req = request("192.0.2.9:4000", format!("203.0.113.{i}"), format!("u{i}"));
            last = test::call_service(&untrusted, req).await.status();
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[actix_web::test]
    async fn login_as_relays_an_upstream_429() {
        let (port, _hits) =
            mock_login_upstream("429 Too Many Requests", "Retry-After: 7\r\n").await;
        let app = login_as_app(port, Vec::new()).await;

        let resp = post_login_as(&app, "10.0.0.1:4000", "u1").await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("7")
        );
    }

    #[actix_web::test]
    async fn whoami_resolves_user_from_kms_session_cookie() {
        let session = UiSession {
            user_id: Some(UserId::from("alice@example.com")),
            ..UiSession::default()
        };
        let set_cookie = test_ui_session_cookie()
            .set_cookie(&session)
            .expect("session cookie");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(saml_runtime(None).await))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(whoami),
        )
        .await;

        let with_cookie = test::TestRequest::get()
            .uri("/whoami")
            .insert_header((
                header::COOKIE,
                set_cookie.split(';').next().expect("name=value").to_owned(),
            ))
            .to_request();
        let resp = test::call_service(&app, with_cookie).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["user_id"], "alice@example.com");

        let anonymous = test::TestRequest::get().uri("/whoami").to_request();
        let resp = test::call_service(&app, anonymous).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Logout must neither call the Auth Verifier nor expire cookies it cannot attribute to
    /// a valid session of the SAML realm (other realm, or garbage).
    #[actix_web::test]
    async fn logout_ignores_cookie_that_is_not_a_valid_saml_realm_session() {
        let other_realm = auth_verifier_token("alice@example.com", Some("other-app"));
        assert_eq!(logout_removal_cookie(other_realm).await, None);
        assert_eq!(logout_removal_cookie("not-a-jwt".to_owned()).await, None);
    }

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

    const OIDC_CLIENT_ID: &str = "kms-ui";
    const OIDC_ISSUER: &str = "https://idp.example.com/";
    const OIDC_EMAIL: &str = "alice@example.com";
    const IDP_SECRET: &[u8] = b"idp-signing-secret-for-the-tests";
    const SPIFFE_ID: &str = "spiffe://example.org/ns/ui/sa/gateway";

    /// What the mock `IdP` saw, the nonce it puts in the `id_token` it issues, and the
    /// claims overriding its complete default claim set (a `null` value removes the claim).
    #[derive(Default)]
    struct IdpState {
        nonce: std::sync::Mutex<String>,
        token_form: std::sync::Mutex<String>,
        claims: std::sync::Mutex<serde_json::Map<String, serde_json::Value>>,
    }

    /// One HTTP/1.1 request: its request line and its body.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> (String, String) {
        let mut data = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.expect("read request");
            data.extend(chunk.iter().take(read));
            let text = String::from_utf8_lossy(&data).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let length = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if body.len() >= length || read == 0 {
                    let line = head.lines().next().unwrap_or_default();
                    return (line.to_owned(), body.to_owned());
                }
            } else if read == 0 {
                return (String::new(), String::new());
            }
        }
    }

    /// A mock `IdP` on a random local port: `GET /jwks` serves its signing key, any other
    /// request is the token endpoint and answers with an `id_token` carrying `state.nonce`,
    /// every claim an OIDC `IdP` issues (`iss`, `sub`, `aud`, `exp`, a verified `email`),
    /// then `state.claims`.
    async fn mock_idp(state: Arc<IdpState>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    let (request_line, body) = read_request(&mut stream).await;
                    let answer: serde_json::Value = if request_line.starts_with("GET /jwks") {
                        serde_json::json!({ "keys": [{
                            "kty": "oct", "kid": "idp-key", "alg": "HS256",
                            "k": URL_SAFE_NO_PAD.encode(IDP_SECRET),
                        }]})
                    } else {
                        *state.token_form.lock().expect("lock") = body;
                        let nonce = state.nonce.lock().expect("lock").clone();
                        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
                        header.kid = Some("idp-key".to_owned());
                        let mut claims = serde_json::json!({
                            "iss": OIDC_ISSUER, "sub": "alice-subject", "aud": OIDC_CLIENT_ID,
                            "email": OIDC_EMAIL, "email_verified": true,
                            "nonce": nonce, "exp": 4_102_444_800_u64,
                        });
                        let claims_map = claims.as_object_mut().expect("claims object");
                        for (name, value) in state.claims.lock().expect("lock").iter() {
                            if value.is_null() {
                                claims_map.remove(name);
                            } else {
                                claims_map.insert(name.clone(), value.clone());
                            }
                        }
                        let id_token = jsonwebtoken::encode(
                            &header,
                            &claims,
                            &jsonwebtoken::EncodingKey::from_secret(IDP_SECRET),
                        )
                        .expect("sign id_token");
                        serde_json::json!({ "id_token": id_token })
                    };
                    let payload = answer.to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("write response");
                });
            }
        });
        port
    }

    /// The `auth_session=<value>` pair of the `Set-Cookie` header of `resp`.
    fn session_pair<B>(resp: &ServiceResponse<B>) -> String {
        set_cookies(resp)
            .into_iter()
            .find(|c| c.starts_with("auth_session="))
            .and_then(|c| c.split(';').next().map(str::to_owned))
            .expect("an auth_session Set-Cookie")
    }

    /// The session sealed in an `auth_session=<value>` pair, read with the test key.
    async fn opened(pair: &str) -> Option<UiSession> {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(pair).expect("header"));
        test_ui_session_cookie().read(&headers).await
    }

    fn get(uri: &str, cookie: Option<&str>) -> actix_http::Request {
        let request = test::TestRequest::get().uri(uri);
        match cookie {
            Some(cookie) => request.insert_header((header::COOKIE, cookie.to_owned())),
            None => request,
        }
        .to_request()
    }

    /// The `login_flow`/`callback`/`whoami` handlers configured for the mock `IdP` on `port`,
    /// the KMS trusting `primary_jwt_issuer` as its first JWT provider.
    async fn oidc_app(
        port: u16,
        primary_jwt_issuer: Option<&str>,
    ) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
    > {
        let jwks_manager = Arc::new(
            JwksManager::new(vec![format!("http://127.0.0.1:{port}/jwks")], None)
                .await
                .expect("jwks manager"),
        );
        let kms = test_kms_with_config(https_clap_config())
            .await
            .expect("kms");
        test::init_service(
            App::new()
                .app_data(web::Data::new(OidcRuntimeConfig {
                    config: OidcConfig {
                        client_id: Some(OIDC_CLIENT_ID.to_owned()),
                        issuer_url: Some(OIDC_ISSUER.to_owned()),
                        ..OidcConfig::default()
                    },
                    discovered: Some(OidcDiscoveredEndpoints {
                        authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
                        token_endpoint: format!("http://127.0.0.1:{port}/token"),
                        jwks_manager,
                    }),
                    primary_jwt_issuer: primary_jwt_issuer.map(str::to_owned),
                }))
                .app_data(web::Data::new(saml_runtime(None).await))
                .app_data(web::Data::new(KMS_URL.to_owned()))
                .app_data(web::Data::new(kms))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(login)
                .service(callback)
                .service(whoami),
        )
        .await
    }

    /// `GET /login_flow`: the `state`, `nonce` and `code_challenge` sent to the `IdP`, and the
    /// flow cookie sealing them.
    async fn begin_oidc_login<S, B>(app: &S) -> (String, String, String, String)
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = ServiceResponse<B>,
                Error = actix_web::Error,
            >,
        B: actix_web::body::MessageBody,
    {
        let resp = test::call_service(app, get("/login_flow", None)).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = Url::parse(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .expect("location"),
        )
        .expect("authorization url");
        let param = |name: &str| {
            location
                .query_pairs()
                .find(|(key, _)| key == name)
                .map_or_else(
                    || panic!("{name} in the authorization url"),
                    |(_, value)| value.into_owned(),
                )
        };
        let (state, nonce, challenge) = (param("state"), param("nonce"), param("code_challenge"));
        let flow_cookie = session_pair(&resp);
        assert!(
            !flow_cookie.contains(&state) && !flow_cookie.contains(&nonce),
            "flow values must not appear in clear in the cookie"
        );
        (state, nonce, challenge, flow_cookie)
    }

    /// The whole OIDC browser flow through the real `login_flow`, `callback` and `whoami`
    /// handlers with a mock `IdP`: the PKCE verifier, state and nonce travel in the sealed
    /// cookie, and the cookie issued at login holds nothing but the user.
    #[actix_web::test]
    async fn oidc_login_round_trips_through_the_sealed_session_cookie() {
        let idp = Arc::new(IdpState::default());
        let port = mock_idp(idp.clone()).await;
        let app = oidc_app(port, None).await;

        // login_flow: redirect to the IdP, flow values sealed in the cookie.
        let (state, nonce, challenge, flow_cookie) = begin_oidc_login(&app).await;

        // callback refusals: no cookie, forged state, nonce not the one of the login.
        let url = format!("/callback?state={state}&code=auth-code");
        let resp = test::call_service(&app, get(&url, None)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = test::call_service(
            &app,
            get("/callback?state=forged&code=auth-code", Some(&flow_cookie)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        *idp.nonce.lock().expect("lock") = "another-nonce".to_owned();
        let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
        let (status, cookies) = (resp.status(), set_cookies(&resp));
        let body = test::read_body(resp).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body:?}");
        assert!(cookies.is_empty(), "a refused login sets no session");

        // callback success: user stored, nothing of the login flow carried over.
        *idp.nonce.lock().expect("lock") = nonce;
        let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/ui/locate")
        );
        let session_cookie = session_pair(&resp);
        assert_eq!(
            opened(&session_cookie).await,
            Some(UiSession {
                user_id: Some(UserId::from(OIDC_EMAIL)),
                ..UiSession::default()
            })
        );

        // The code exchange carried the verifier matching the challenge sent to the IdP.
        let form = idp.token_form.lock().expect("lock").clone();
        let form: HashMap<_, _> = form_urlencoded::parse(form.as_bytes())
            .into_owned()
            .collect();
        assert_eq!(
            pkce_challenge_from_verifier(form.get("code_verifier").expect("code_verifier")),
            challenge
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some(OIDC_CLIENT_ID)
        );
        assert_eq!(
            form.get("redirect_uri").map(String::as_str),
            Some("https://kms.example.com/ui/callback")
        );

        // whoami: the login cookie authenticates, the pre-login flow cookie does not.
        let resp = test::call_service(&app, get("/whoami", Some(&session_cookie))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["user_id"], OIDC_EMAIL);
        let resp = test::call_service(&app, get("/whoami", Some(&flow_cookie))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// F-046 / F-014: the `id_token` must carry `iss`, `aud` and `sub`, and a verified email
    /// (`email_verified: true`); any of them missing (or the email unverified) refuses the
    /// login with 401 and no session, while the complete token still logs in, nonce check
    /// intact.
    #[actix_web::test]
    async fn oidc_callback_requires_iss_aud_sub_and_a_verified_email() {
        let idp = Arc::new(IdpState::default());
        let port = mock_idp(idp.clone()).await;
        let app = oidc_app(port, None).await;
        let (state, nonce, _, flow_cookie) = begin_oidc_login(&app).await;
        *idp.nonce.lock().expect("lock") = nonce.clone();
        let url = format!("/callback?state={state}&code=auth-code");

        for (name, value) in [
            ("exp", serde_json::Value::Null),
            ("iss", serde_json::Value::Null),
            ("aud", serde_json::Value::Null),
            ("sub", serde_json::Value::Null),
            ("email", serde_json::Value::Null),
            ("email", serde_json::json!("")),
            ("email_verified", serde_json::json!(false)),
            ("email_verified", serde_json::json!("false")),
            ("email_verified", serde_json::Value::Null),
        ] {
            *idp.claims.lock().expect("lock") =
                serde_json::Map::from_iter([(name.to_owned(), value.clone())]);
            let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
            let (status, cookies) = (resp.status(), set_cookies(&resp));
            let body = test::read_body(resp).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}={value}: {body:?}");
            assert!(
                cookies.is_empty(),
                "{name}={value}: a refused login sets no session"
            );
        }

        // The complete token: the nonce is still checked, then the login succeeds.
        idp.claims.lock().expect("lock").clear();
        *idp.nonce.lock().expect("lock") = "another-nonce".to_owned();
        let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        *idp.nonce.lock().expect("lock") = nonce;
        let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            opened(&session_pair(&resp)).await,
            Some(UiSession {
                user_id: Some(UserId::from(OIDC_EMAIL)),
                ..UiSession::default()
            })
        );
    }

    /// F-014: the UI identity is namespaced `email#issuer` unless the UI `IdP` is the first
    /// JWT provider (or no JWT provider is configured), so it matches the identity the same
    /// user gets with a bearer token and a secondary `IdP` cannot take over a primary user.
    #[actix_web::test]
    async fn oidc_login_namespaces_the_identity_unless_the_idp_is_the_primary_jwt_issuer() {
        for (primary_jwt_issuer, expected) in [
            (None, OIDC_EMAIL.to_owned()),
            (Some(OIDC_ISSUER), OIDC_EMAIL.to_owned()),
            (
                Some("https://primary-idp.example.com/"),
                format!("{OIDC_EMAIL}#{OIDC_ISSUER}"),
            ),
        ] {
            let idp = Arc::new(IdpState::default());
            let port = mock_idp(idp.clone()).await;
            let app = oidc_app(port, primary_jwt_issuer).await;
            let (state, nonce, _, flow_cookie) = begin_oidc_login(&app).await;
            *idp.nonce.lock().expect("lock") = nonce;
            let url = format!("/callback?state={state}&code=auth-code");
            let resp = test::call_service(&app, get(&url, Some(&flow_cookie))).await;
            assert_eq!(resp.status(), StatusCode::FOUND, "{primary_jwt_issuer:?}");
            assert_eq!(
                opened(&session_pair(&resp)).await,
                Some(UiSession {
                    user_id: Some(UserId::from(expected.as_str())),
                    ..UiSession::default()
                }),
                "{primary_jwt_issuer:?}"
            );
        }
    }

    /// SPIFFE JWT-SVID login through `login_svid`: a fresh cookie holding only the SPIFFE ID,
    /// whatever session cookie the browser presented, and no cookie for a rejected token.
    #[actix_web::test]
    async fn svid_login_issues_a_fresh_cookie_and_ignores_the_presented_one() {
        let jwt_configs = Arc::new(vec![JwtConfig {
            jwt_issuer_uri: "https://issuer.example.com".to_owned(),
            jwt_audience: Some(vec!["cosmian-kms".to_owned()]),
            issuer_namespace: None,
            jwks: Arc::new(JwksManager::new(vec![], None).await.expect("jwks manager")),
            accept_spiffe_subject: true,
        }]);
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(jwt_configs))
                .app_data(web::Data::new(saml_runtime(None).await))
                .app_data(web::Data::new(test_ui_session_cookie()))
                .service(login_svid)
                .service(whoami),
        )
        .await;
        let post = |token: &str, cookie: &str| {
            test::TestRequest::post()
                .uri("/login_svid")
                .insert_header((header::COOKIE, cookie.to_owned()))
                .set_json(serde_json::json!({ "jwt_svid": token }))
                .to_request()
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("test-kid".to_owned());
        // Test builds decode tokens without checking the signature (see `jwt_token_auth`).
        let svid = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "sub": SPIFFE_ID, "aud": ["cosmian-kms"] }),
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .expect("sign svid");

        // A pre-login cookie planted by an attacker: it must not survive the login.
        let planted = test_ui_session_cookie()
            .set_cookie(&UiSession {
                pkce_verifier: Some("planted".to_owned()),
                ..UiSession::default()
            })
            .expect("planted cookie");
        let planted = planted.split(';').next().expect("name=value");

        let resp = test::call_service(&app, post("not-a-jwt", planted)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            set_cookies(&resp).is_empty(),
            "a rejected SVID sets no session"
        );

        let resp = test::call_service(&app, post(&svid, planted)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let session_cookie = session_pair(&resp);
        assert_eq!(
            opened(&session_cookie).await,
            Some(UiSession {
                user_id: Some(UserId::from(SPIFFE_ID)),
                ..UiSession::default()
            })
        );
        let resp = test::call_service(&app, get("/whoami", Some(&session_cookie))).await;
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["user_id"], SPIFFE_ID);
    }
}
