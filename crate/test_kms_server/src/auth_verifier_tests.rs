//! Integration tests for the Auth Verifier + KMS Web UI login flow.
//!
//! These tests spin up:
//!   1. A minimal **mock auth-verifier** HTTP server (Actix-web) that:
//!      - Serves a JWKS document at `GET /.well-known/jwks.json`.
//!      - Accepts `POST /login?realm=<realm>` with HTTP Basic auth and responds
//!        with `{"next_step":"Authenticated"}` plus `Set-Cookie: _ea_=<jwt>`.
//!   2. The **KMS server** over HTTPS, configured to use the mock as its
//!      `auth_verifier_url`.
//!
//! The tests then call `POST /ui/login_as` on the KMS and verify the full
//! browser-facing BFF login flow:
//!   - The response is `200 OK` with `{"next_step":"Authenticated"}`.
//!   - The KMS sets a session cookie (`auth_session`).
//!   - `GET /ui/whoami` with that cookie returns the expected username.
//!
//! Because the KMS server is compiled with the `insecure` feature (see
//! `test_kms_server/Cargo.toml`), JWT signature verification is bypassed —
//! the mock auth-verifier returns a minimal HS256-signed JWT that carries the
//! required `sub` and `exp` claims; no asymmetric key material is needed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result
)]

use std::{net::TcpListener, time::Duration};

use actix_web::{App, HttpRequest, HttpResponse, post, web};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    init_test_logging,
    test_server::{TestClientOptions, start_test_server_with_patch, test_config_path},
};

// ── JWT helpers ───────────────────────────────────────────────────────────────

/// Claims used by the mock auth-verifier when it issues the session JWT.
#[derive(Debug, Serialize, Deserialize)]
struct MockAuthVerifierClaims {
    sub: String,
    exp: u64,
}

/// Cookie name that the auth-verifier sets after a successful login — must
/// match the constant in `crate/server/src/routes/ui_auth.rs`.
const AUTH_VERIFIER_SESSION_COOKIE: &str = "_ea_";

/// Encode a minimal JWT carrying `sub=username` that the KMS will accept in
/// insecure/test builds (signature is never verified in that mode).
fn make_jwt(username: &str) -> String {
    let claims = MockAuthVerifierClaims {
        sub: username.to_owned(),
        // Far-future expiry — tests must not depend on wall-clock time.
        exp: 9_999_999_999,
    };
    // HS256 with a throwaway secret.  The KMS server in insecure mode calls
    // `dangerous::insecure_decode`, which skips all signature/algorithm checks.
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret-not-used-in-verification"),
    )
    .expect("test JWT encoding must not fail")
}

// ── Mock auth-verifier HTTP server ────────────────────────────────────────────

/// State injected into the mock server handlers.
#[derive(Clone, Debug)]
struct MockState {
    /// The username that will be returned in the JWT `sub` claim on login.
    username: String,
}

/// `POST /login?realm=<realm>` — accepts any credentials (Basic auth is
/// required by the real auth-verifier but not validated here) and responds
/// with a session cookie containing a signed JWT and a JSON body with
/// `next_step: "Authenticated"`.
#[post("/login")]
async fn mock_login(req: HttpRequest, state: web::Data<MockState>) -> HttpResponse {
    // Basic-auth header is required by the BFF proxy; just verify it is present.
    let has_basic_auth = req
        .headers()
        .get(actix_web::http::header::AUTHORIZATION)
        .map_or(false, |v| {
            v.to_str().map_or(false, |s| s.starts_with("Basic "))
        });
    if !has_basic_auth {
        return HttpResponse::Unauthorized().body("missing Basic auth");
    }

    let jwt = make_jwt(&state.username);
    // Cookies: Secure is NOT set — the mock serves plain HTTP.
    // HttpOnly and Path are set to match real auth-verifier behaviour.
    let cookie = format!("{AUTH_VERIFIER_SESSION_COOKIE}={jwt}; Path=/; HttpOnly");
    HttpResponse::Ok()
        .append_header(("Set-Cookie", cookie))
        .json(json!({ "next_step": "Authenticated" }))
}

/// `GET /.well-known/jwks.json` — returns an empty key set.  Since the KMS
/// server runs with the `insecure` feature, JWKS key material is never used
/// for actual verification; the endpoint just needs to be reachable at
/// startup so `JwksManager::new_with_options` does not error out.
async fn mock_jwks() -> HttpResponse {
    HttpResponse::Ok().json(json!({ "keys": [] }))
}

/// Spawn the mock auth-verifier on `port` and return the `actix_server::ServerHandle`
/// so the caller can stop it cleanly.
async fn start_mock_auth_verifier(port: u16, username: String) -> actix_server::ServerHandle {
    let state = web::Data::new(MockState { username });

    let server = actix_web::HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(mock_login)
            .route("/.well-known/jwks.json", web::get().to(mock_jwks))
    })
    .bind(("127.0.0.1", port))
    .unwrap_or_else(|e| panic!("mock auth-verifier bind to :{port} failed: {e}"))
    .run();

    let handle = server.handle();
    tokio::spawn(server);

    // Small delay to ensure the server is accepting connections before callers
    // try to connect.
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle
}

// ── Free port allocation ──────────────────────────────────────────────────────

fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("must bind to free port");
    l.local_addr().unwrap().port()
    // `l` is dropped, freeing the port.  There is a small TOCTOU window, but
    // it is acceptable for tests running on a loopback interface.
}

// ── The actual integration test ───────────────────────────────────────────────

/// Full WebUI login flow via the Auth Verifier, with KMS served over HTTPS.
///
/// Verifies:
/// 1. `GET /ui/auth_method` → `"AUTH_VERIFIER"` (so the frontend shows the
///    username/password form).
/// 2. `POST /ui/login_as` with valid credentials → `200 OK`,
///    `next_step: "Authenticated"`, and a session cookie is set.
/// 3. `GET /ui/whoami` with the session cookie → `200 OK`, correct `user_id`.
#[tokio::test]
async fn test_webui_login_via_auth_verifier_over_https() {
    init_test_logging();

    let mock_port = free_port();
    let test_username = "alice@example.com".to_owned();

    // ── 1. Start the mock auth-verifier ──────────────────────────────────────
    let mock_handle = start_mock_auth_verifier(mock_port, test_username.clone()).await;

    // ── 2. Start the KMS server (HTTPS) ──────────────────────────────────────
    // Load from auth_verifier.toml (which now has TLS) and patch:
    //   - HTTP port: dynamic allocation to avoid collisions.
    //   - auth_verifier_url: points to our mock on mock_port.
    //   - ui_session_salt: a fixed test value so the session key is stable
    //     across the test's request/response cycle (same process, no restart).
    //   - ui_index_html_folder: a temp dir with a minimal index.html so the
    //     server registers the /ui/* API routes (auth_method, login_as, whoami).
    let config_path = test_config_path("auth_verifier.toml");
    let mock_url = format!("http://127.0.0.1:{mock_port}");

    // Create a throwaway UI folder with an index.html so the server registers
    // the /ui API routes (guarded by `index.html exists` in start_kms_server).
    let ui_tmp =
        std::env::temp_dir().join(format!("kms_test_auth_verifier_ui_{}", std::process::id()));
    std::fs::create_dir_all(&ui_tmp).expect("must create temp UI dir");
    std::fs::write(ui_tmp.join("index.html"), "<html><body>test</body></html>")
        .expect("must write temp index.html");
    let ui_tmp_str = ui_tmp
        .to_str()
        .expect("temp dir path must be valid UTF-8")
        .to_owned();

    let ctx = start_test_server_with_patch(
        &config_path,
        move |cfg| {
            // Override the auth-verifier URL to point at our mock.
            cfg.auth_verifier.auth_verifier_url = Some(mock_url.clone());
            cfg.auth_verifier.auth_verifier_realm = Some("_".to_owned());
            cfg.auth_verifier.auth_verifier_accept_invalid_certs = true;
            // Disable Google CSE — not needed here and avoids extra I/O.
            cfg.google_cse_config.google_cse_enable = false;
            // Set a stable session salt so the cookie key is deterministic
            // within this test process.
            cfg.ui_config.ui_session_salt = Some("test-session-salt-32bytes-xxxxxyz".to_owned());
            // Point at the temp UI folder so the /ui/* API routes are registered.
            cfg.ui_config.ui_index_html_folder = Some(ui_tmp_str.clone());
        },
        TestClientOptions {
            send_jwt: false,
            send_client_cert: false,
            send_api_token: false,
            ..Default::default()
        },
    )
    .await
    .expect("KMS server with auth-verifier must start");

    let kms_port = ctx.server_port;
    let base = format!("https://127.0.0.1:{kms_port}");

    // Build a reqwest client that:
    // • Accepts the self-signed KMS test certificate.
    // • Stores cookies across requests (needed for the session cookie).
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .expect("test reqwest client must build");

    // ── 3. GET /ui/auth_method ──────────────────────────────────────────────
    let auth_method_resp = client
        .get(format!("{base}/ui/auth_method"))
        .send()
        .await
        .expect("GET /ui/auth_method must succeed");

    assert_eq!(
        auth_method_resp.status(),
        200,
        "GET /ui/auth_method must return 200"
    );
    let auth_method_body: serde_json::Value = auth_method_resp.json().await.unwrap();
    assert_eq!(
        auth_method_body["auth_method"], "AUTH_VERIFIER",
        "auth_method must be AUTH_VERIFIER when auth_verifier is configured"
    );

    // ── 4. POST /ui/login_as ─────────────────────────────────────────────────
    let login_resp = client
        .post(format!("{base}/ui/login_as"))
        .json(&json!({
            "username": test_username,
            "password": "password123"
        }))
        .send()
        .await
        .expect("POST /ui/login_as must not fail at the transport level");

    assert_eq!(
        login_resp.status(),
        200,
        "POST /ui/login_as must return 200 OK; body: {}",
        login_resp.text().await.unwrap_or_default()
    );

    // Check the JSON body.
    // (We already consumed the body in the assert above if it failed, but on
    // success we need to re-read from the cloned response — re-issue the
    // request if we lost the body.)
    let login_body: serde_json::Value = client
        .post(format!("{base}/ui/login_as"))
        .json(&json!({
            "username": test_username,
            "password": "password123"
        }))
        .send()
        .await
        .expect("second POST /ui/login_as for body read")
        .json()
        .await
        .expect("must parse JSON");
    assert_eq!(
        login_body["next_step"], "Authenticated",
        "login response must carry next_step: Authenticated"
    );

    // ── 5. GET /ui/whoami ────────────────────────────────────────────────────
    // The cookie jar now holds the `auth_session` cookie set by the second
    // POST /ui/login_as response.
    let whoami_resp = client
        .get(format!("{base}/ui/whoami"))
        .send()
        .await
        .expect("GET /ui/whoami must succeed");

    assert_eq!(
        whoami_resp.status(),
        200,
        "GET /ui/whoami must return 200 OK after a successful login"
    );
    let whoami_body: serde_json::Value = whoami_resp
        .json()
        .await
        .expect("GET /ui/whoami must return valid JSON");
    assert_eq!(
        whoami_body["user_id"], test_username,
        "whoami must return the authenticated username"
    );

    // ── Cleanup ──────────────────────────────────────────────────────────────
    mock_handle.stop(false).await;
    ctx.stop_server()
        .await
        .expect("KMS server must stop cleanly");
}
