//! Integration test for the Auth Verifier + KMS Web UI login flow.
//!
//! ## Design
//!
//! This test is **`#[ignore]`d** — it requires two already-running servers:
//!
//! 1. A Cosmian Authentication Verifier with the default seeded credentials
//!    (`admin` / `change_me`, realm `_`).
//! 2. A KMS server with `[auth_verifier]` configured to point at server 1.
//!
//! Both servers are started by `.mise/scripts/test/test_ui_auth.sh`, which
//! exports `PLAYWRIGHT_BASE_URL=http://localhost:<KMS_PORT>` and then calls:
//! ```sh
//! cargo test -p test_kms_server -- --ignored test_webui_login_via_auth_verifier
//! ```
//!
//! ## Running manually
//!
//! When both servers are already running, invoke with:
//! ```sh
//! PLAYWRIGHT_BASE_URL=http://localhost:9998 \
//!   cargo test -p test_kms_server -- --ignored test_webui_login_via_auth_verifier
//! ```

#![allow(clippy::expect_used, clippy::unwrap_used)]

/// `WebUI` login flow via the Auth Verifier.
///
/// Verifies the full BFF flow end-to-end against an already-running KMS that
/// is configured with `[auth_verifier]`:
///
/// 1. `GET /ui/auth_method` → `{ "auth_method": "AUTH_VERIFIER" }`.
/// 2. `POST /ui/login_as` with `admin`/`change_me` →
///    `200 OK`, `{ "next_step": "Authenticated" }`, session cookie set.
/// 3. `GET /ui/whoami` → `{ "user_id": "admin" }`.
///
/// Requires `PLAYWRIGHT_BASE_URL` to be set to the KMS base URL.
/// Normally invoked by `.mise/scripts/test/test_ui_auth.sh`.
#[ignore = "requires running KMS+auth-verifier; invoke via .mise/scripts/test/test_ui_auth.sh"]
#[tokio::test]
async fn test_webui_login_via_auth_verifier() {
    let base_url = std::env::var("PLAYWRIGHT_BASE_URL")
        .expect("PLAYWRIGHT_BASE_URL must point to the KMS server (e.g. http://localhost:9998)");

    // Accept self-signed certs in case the KMS runs with TLS; store cookies
    // so the session established by login_as is visible to whoami.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .expect("build test client");

    // ── 1. GET /ui/auth_method ────────────────────────────────────────────────
    let auth_method_resp = client
        .get(format!("{base_url}/ui/auth_method"))
        .send()
        .await
        .expect("GET /ui/auth_method");
    assert_eq!(auth_method_resp.status(), 200, "GET /ui/auth_method → 200");

    let auth_method_body: serde_json::Value = auth_method_resp.json().await.expect("json body");
    assert_eq!(
        auth_method_body.get("auth_method").and_then(|v| v.as_str()),
        Some("AUTH_VERIFIER"),
        "auth_method must be AUTH_VERIFIER"
    );

    // ── 2. POST /ui/login_as (admin / change_me) ──────────────────────────────
    // The auth-verifier's admin realm has `allow_expired_passwords = true`, so
    // the seeded `admin`/`change_me` account (change_password=true) is fully
    // usable and returns `Authenticated`, not `ChangePassword`.
    let login_resp = client
        .post(format!("{base_url}/ui/login_as"))
        .json(&serde_json::json!({
            "username": "admin",
            "password": "change_me"
        }))
        .send()
        .await
        .expect("POST /ui/login_as");

    let login_status = login_resp.status();
    let login_body: serde_json::Value = login_resp.json().await.expect("json body");
    assert_eq!(
        login_status, 200,
        "POST /ui/login_as → 200; body: {login_body}"
    );
    assert_eq!(
        login_body.get("next_step").and_then(|v| v.as_str()),
        Some("Authenticated"),
        "next_step must be Authenticated"
    );

    // ── 3. GET /ui/whoami ─────────────────────────────────────────────────────
    let whoami_resp = client
        .get(format!("{base_url}/ui/whoami"))
        .send()
        .await
        .expect("GET /ui/whoami");
    assert_eq!(whoami_resp.status(), 200, "GET /ui/whoami → 200");

    let whoami_body: serde_json::Value = whoami_resp.json().await.expect("json body");
    assert_eq!(
        whoami_body.get("user_id").and_then(|v| v.as_str()),
        Some("admin"),
        "whoami user_id must be admin"
    );
}
