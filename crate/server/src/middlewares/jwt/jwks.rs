//! JWKS (JSON Web Key Set) Manager
//!
//! This module provides functionality for managing and refreshing JSON Web Key Sets (JWKS),
//! which are essential for JWT token signature verification. The manager caches key sets
//! and refreshes them periodically to ensure up-to-date validation.

use std::{collections::HashMap, sync::RwLock};

use chrono::{DateTime, Duration, Utc};
use cosmian_logger::trace;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use reqwest::{Client, header::HeaderValue};
use serde_json::{Value, json};

use crate::{config::ProxyParams, error::KmsError, kms_bail, kms_error, result::KResult};

static REFRESH_INTERVAL: i64 = 60; // in secs

#[derive(Debug)]
pub struct JwksManager {
    pub(crate) uris: Vec<String>,
    pub(crate) jwks: RwLock<HashMap<String, JwkSet>>,
    pub(crate) last_update: RwLock<Option<DateTime<Utc>>>,
    /// Tracks the last time `force_refresh` was actually executed, for cooldown.
    pub(crate) last_force_refresh: RwLock<Option<DateTime<Utc>>>,
    pub(crate) proxy_params: Option<ProxyParams>,
    /// When `true`, the JWKS fetch client skips TLS certificate verification.
    /// Only set this for development/test environments (e.g. self-signed certs).
    pub(crate) accept_invalid_certs: bool,
}

impl JwksManager {
    pub async fn new(uris: Vec<String>, server_params: Option<&ProxyParams>) -> KResult<Self> {
        Self::new_with_options(uris, server_params, false).await
    }

    /// Create a new `JwksManager` with an explicit `accept_invalid_certs` flag.
    ///
    /// Set `accept_invalid_certs = true` only in development/test when the JWKS server
    /// uses a self-signed certificate.
    pub async fn new_with_options(
        uris: Vec<String>,
        server_params: Option<&ProxyParams>,
        accept_invalid_certs: bool,
    ) -> KResult<Self> {
        let jwks_manager = Self {
            uris,
            jwks: HashMap::new().into(),
            last_update: None.into(),
            last_force_refresh: None.into(),
            proxy_params: server_params.cloned(),
            accept_invalid_certs,
        };
        jwks_manager.refresh().await?;

        Ok(jwks_manager)
    }

    /// Lock `jwks` to replace it
    fn set_jwks(&self, new_jwks: HashMap<String, JwkSet>) -> KResult<()> {
        let mut jwks = self.jwks.write().map_err(|e| {
            KmsError::ServerError(format!("cannot lock JWKS for write. Error: {e:?}"))
        })?;
        *jwks = new_jwks;
        Ok(())
    }

    /// Find the key identifier `kid` in each registered JWKS
    pub fn find(&self, kid: &str) -> KResult<Option<Jwk>> {
        Ok(self
            .jwks
            .read()
            .map_err(|e| KmsError::ServerError(format!("cannot lock JWKS for read. Error: {e:?}")))?
            .iter()
            .find_map(|(_, jwks)| {
                jwks.keys
                    .iter()
                    .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            })
            .cloned())
    }

    /// Return all JWKs from all registered JWKS sets, regardless of `kid`.
    ///
    /// Used by the Auth Verifier middleware where tokens are issued without a `kid`
    /// header field and the verifier must try every available public key until one
    /// validates the signature.
    pub fn find_any(&self) -> KResult<Vec<Jwk>> {
        Ok(self
            .jwks
            .read()
            .map_err(|e| KmsError::ServerError(format!("cannot lock JWKS for read. Error: {e:?}")))?
            .values()
            .flat_map(|jwks| jwks.keys.iter().cloned())
            .collect())
    }

    /// Fetch again all JWKS using the `uris`.
    ///
    /// The threshold to refresh JWKS is set to `REFRESH_INTERVAL`.
    pub async fn refresh(&self) -> KResult<()> {
        self.refresh_internal(false).await
    }

    /// Force a JWKS refresh, bypassing the `REFRESH_INTERVAL` throttle.
    ///
    /// Intended for the narrow case where the cache is known to be empty (e.g. the
    /// initial fetch at startup failed): a throttled [`refresh`](Self::refresh) call
    /// could otherwise be a no-op for up to `REFRESH_INTERVAL` seconds — because
    /// `last_update` may have already been set by a previous (failed) attempt — leaving
    /// callers unable to validate any token in the meantime.
    ///
    /// A 5-second cooldown prevents repeated callers from hammering the JWKS endpoint.
    pub async fn force_refresh(&self) -> KResult<()> {
        // Apply a 5-second cooldown to prevent abuse
        let can_force = {
            let mut last_force = self.last_force_refresh.write().map_err(|e| {
                KmsError::ServerError(format!("cannot lock last_force_refresh: {e:?}"))
            })?;
            let now = Utc::now();
            let can = last_force.is_none_or(|lf| (lf + Duration::seconds(5)) < now);
            if can {
                *last_force = Some(now);
            }
            can
        };
        if !can_force {
            trace!("force_refresh: cooldown active, skipping");
            return Ok(());
        }
        self.refresh_internal(true).await
    }

    async fn refresh_internal(&self, force: bool) -> KResult<()> {
        let refresh_is_allowed = {
            let mut last_update = self.last_update.write().map_err(|e| {
                KmsError::ServerError(format!("cannot lock last_update for write. Error: {e:?}"))
            })?;

            let can_be_refreshed = force
                || last_update
                    .is_none_or(|lu| (lu + Duration::seconds(REFRESH_INTERVAL)) < Utc::now());

            if can_be_refreshed {
                *last_update = Some(Utc::now());
            }
            can_be_refreshed
        };

        if refresh_is_allowed {
            tracing::info!("Refreshing JWKS");
            let refreshed_jwks =
                Self::fetch_all(&self.uris, &self.proxy_params, self.accept_invalid_certs).await;
            self.set_jwks(refreshed_jwks)?;
        }

        Ok(())
    }

    /// Refresh the JWK Set by making an external HTTP call to all the `uris`.
    ///
    /// The JWK Sets are fetched in parallel and warn about failures
    /// without stopping the whole fetch process.
    async fn fetch_all(
        uris: &[String],
        proxy_params: &Option<ProxyParams>,
        accept_invalid_certs: bool,
    ) -> HashMap<String, JwkSet> {
        // Create a vector of futures to fetch JWKS from each URI
        let jwks_downloads: Vec<_> = uris
            .iter()
            .map(|uri| parse_jwks(uri, proxy_params, accept_invalid_certs))
            .collect();
        // Use `join_all` to fetch all JWKS in parallel
        futures::future::join_all(jwks_downloads)
            .await
            .into_iter()
            .filter(|res| {
                // log errors and filter them out
                res.as_ref()
                    .map_err(|e| {
                        tracing::warn!("Fetch JWKS: {e}");
                    })
                    .is_ok()
            })
            .flatten()
            .collect::<HashMap<_, _>>()
    }
}

/// Fetch a JWKS from the provided URI and parse it.
///
/// This function will log errors for invalid JWKs
/// but it will not stop the process if one fails.
/// It returns a tuple of the URI and the parsed JWKS.
async fn parse_jwks(
    jwks_uri: &String,
    proxy_params: &Option<ProxyParams>,
    accept_invalid_certs: bool,
) -> KResult<(String, JwkSet)> {
    tracing::debug!("fetching {jwks_uri}");
    // Fetch the JWKS from the provided URI,
    // Disable redirect following to prevent SSRF via crafted 3xx responses (A10-2).
    let mut client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(accept_invalid_certs);

    // Configure the client with proxy settings if available
    if let Some(proxy_params) = proxy_params {
        let mut proxy = reqwest::Proxy::all(proxy_params.url.clone())
            .map_err(|e| kms_error!("Failed to configure the HTTPS proxy for JWKS fetch: {e}"))?;
        if let Some(username) = &proxy_params.basic_auth_username {
            proxy = proxy.basic_auth(
                username,
                &proxy_params.basic_auth_password.clone().unwrap_or_default(),
            );
        } else if let Some(custom_auth_header) = &proxy_params.custom_auth_header {
            proxy =
                proxy.custom_http_auth(HeaderValue::from_str(custom_auth_header).map_err(|e| {
                    kms_error!("Failed to set custom HTTP auth header for JWKS fetch: {e}")
                })?);
        }
        if !proxy_params.exclusion_list.is_empty() {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
                &proxy_params.exclusion_list.join(","),
            ));
        }
        client = client.proxy(proxy);
    }

    let response = client
        .build()?
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| kms_error!("Failed to fetch JWKS from {jwks_uri}: {e}"))?;
    // Check if the response status is successful
    let json_value = response
        .json::<Value>()
        .await
        .map_err(|e| kms_error!("Failed to parse JWKS response from {jwks_uri}: {e}"))?;
    // Ensure that the JSON value contains the "keys" field
    let Some(keys) = json_value.get("keys") else {
        kms_bail!("JSON key 'keys' not found in JWKS at {jwks_uri}");
    };
    // Ensure that the keys are an array of valid JWKs
    let jwks = match keys {
        Value::Array(array) => array
            .clone()
            .into_iter()
            .filter(|v| match serde_json::from_value::<Jwk>(v.clone()) {
                Ok(_jwk) => {
                    // Too invasive trace
                    // trace!("Found valid JWK in JWKS at `{jwks_uri}`: {jwk:#?}");
                    true
                }
                Err(e) => {
                    trace!("Ignoring invalid JWK in JWKS at `{jwks_uri}`: {e}: {v:#?}",);
                    false
                }
            })
            .collect::<Vec<Value>>(),
        _ => vec![],
    };
    // If no valid JWKs are found, return an error
    if jwks.is_empty() {
        kms_bail!("No valid JWK found in JWKS at `{jwks_uri}`");
    }
    // Attempt to deserialize the JWKS from the JSON value
    let jwks = json!({"keys": Value::Array(jwks)});
    let jwks = serde_json::from_value::<JwkSet>(jwks.clone()).map_err(|e| {
        kms_error!("Failed to reconstruct JWKS from array of JWK at `{jwks_uri}`: {e}: {jwks:#?}")
    })?;
    Ok((jwks_uri.clone(), jwks))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    // RFC 7517 Appendix A.1 — RSA public key used as a stable test fixture.
    const SAMPLE_RSA_JWK_KID: &str = "test-key-rfc7517";
    const SAMPLE_JWKS: &str = r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key-rfc7517","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhmstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}]}"#;

    /// Spawn an async one-shot HTTP/1.1 server on a random port.
    ///
    /// The server runs as a `tokio::spawn` task on the **same** event-loop as
    /// the test, avoiding the race between a std-thread and the tokio runtime
    /// (which causes `hyper::Error(UnexpectedMessage)` when the server writes a
    /// response before the client has sent the request).
    ///
    /// The server reads the incoming request (to drain the socket buffer) and
    /// then writes a complete HTTP/1.1 response with the provided `body`.
    async fn one_shot_http_server(body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap(); // drain HTTP request headers
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        port
    }

    /// A valid JWKS with a single RFC 7517 RSA key is fetched and parsed correctly.
    #[actix_web::test]
    async fn test_parse_jwks_valid_rsa_key() {
        let port = one_shot_http_server(SAMPLE_JWKS).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let (res_url, jwks) = parse_jwks(&url, &None, false).await.unwrap();

        assert_eq!(res_url, url);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys.first().and_then(|k| k.common.key_id.as_deref()),
            Some(SAMPLE_RSA_JWK_KID)
        );
    }

    /// A response without the "keys" field returns an error.
    #[actix_web::test]
    async fn test_parse_jwks_missing_keys_field() {
        let port = one_shot_http_server(r#"{"not_keys": []}"#).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let err = parse_jwks(&url, &None, false).await.unwrap_err();

        assert!(
            err.to_string().contains("JSON key 'keys' not found"),
            "unexpected error: {err}"
        );
    }

    /// A response with an empty "keys" array returns an error.
    #[actix_web::test]
    async fn test_parse_jwks_empty_keys_array() {
        let port = one_shot_http_server(r#"{"keys": []}"#).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let err = parse_jwks(&url, &None, false).await.unwrap_err();

        assert!(
            err.to_string().contains("No valid JWK found"),
            "unexpected error: {err}"
        );
    }

    /// Spawn a one-shot HTTP server that immediately returns a 307 redirect.
    ///
    /// Used to verify that `parse_jwks` does **not** follow redirects
    /// (OWASP A10-2 SSRF / CIS 13.10 guard).
    async fn one_shot_redirect_server(redirect_to: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 4096];
            let _ = stream.read(&mut buf).await.unwrap();
            let response = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {redirect_to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        port
    }

    /// SR1: A JWKS URI that responds with a 307 redirect must NOT be followed.
    ///
    /// `reqwest` is configured with `Policy::none()` so the redirect response
    /// is returned as-is. Parsing the empty body as JSON fails, preventing any
    /// request from reaching the attacker-controlled destination.
    ///
    /// NIST SP 800-204B SI-10 · CIS 13.10 · OWASP A10-2 (SSRF)
    #[actix_web::test]
    async fn sr01_jwks_redirect_is_not_followed() {
        // Target that must never receive a request from the KMS server.
        let attacker_port = one_shot_http_server(SAMPLE_JWKS).await;
        let attacker_url = format!("http://127.0.0.1:{attacker_port}/secret");

        // Redirecting server: returns 307 → attacker_url.
        let redirect_port = one_shot_redirect_server(attacker_url).await;
        let jwks_url = format!("http://127.0.0.1:{redirect_port}/jwks.json");

        let err = parse_jwks(&jwks_url, &None, false).await.unwrap_err();

        // The JSON parse of the empty 307 body must fail — not a successful JWKS fetch.
        assert!(
            !err.to_string().is_empty(),
            "Expected an error when a 307 redirect is returned, got Ok"
        );
        // Specifically we expect a JSON-parse or JWKS-content error, not a network error
        // to the attacker URL (which would mean the redirect was followed).
        let msg = err.to_string();
        assert!(
            msg.contains("parse JWKS") || msg.contains("JSON key") || msg.contains("No valid JWK"),
            "Expected JWKS parse error (not a followed-redirect network error), got: {msg}"
        );
    }

    /// SR2: A JWKS URI that serves valid JWKS without any redirect succeeds.
    ///
    /// Baseline / control: the no-redirect happy-path continues to work.
    #[actix_web::test]
    async fn sr02_jwks_direct_response_succeeds() {
        let port = one_shot_http_server(SAMPLE_JWKS).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let (res_url, jwks) = parse_jwks(&url, &None, false).await.unwrap();

        assert_eq!(res_url, url);
        assert_eq!(jwks.keys.len(), 1);
    }

    /// Invalid JWK entries in the array are silently skipped;
    /// the function succeeds as long as at least one valid entry remains.
    #[actix_web::test]
    async fn test_parse_jwks_skips_invalid_keys_keeps_valid() {
        const MIXED_JWKS: &str = r#"{"keys":[{"invalid":"key"},{"kty":"RSA","use":"sig","kid":"valid-key","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhmstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256"}]}"#;
        let port = one_shot_http_server(MIXED_JWKS).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let (_, jwks) = parse_jwks(&url, &None, false).await.unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys.first().and_then(|k| k.common.key_id.as_deref()),
            Some("valid-key")
        );
    }

    const ROTATED_KID: &str = "rotated-key";
    const SAMPLE_JWKS_ROTATED: &str = r#"{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"test-key-rfc7517","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhmstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"},{"kty":"RSA","use":"sig","alg":"RS256","kid":"rotated-key","n":"z1w8bgnfcHdRTvvQjMKYaquO0oofsRncnRncgAdVU89zjWyR-dccgBuWU97zwv2SL8bQGGyBIfDadzOAxjRi_5CKGDPfcXLSYijBZBjGW5o4pmlkjnttnu64u___4uKgQ01_FEX3hEr2M7uUpce_CKFCPfcXMSXkCaCiGW5o5pnmlkjntou65v___5vLhR12_GFY4iF3N8vVqde_DLGDQfdXNTYkjCbDjHX6p5qomlljon76w___6wMiS23_HGZ5jG4O9wWrfe_EMHER0geYOUZlkDcEjIT7q6rpnmkkpo87x___7xNjT34_IHa6kH5P0xXsgf_FNIFS1hfZPVaMmlEdFkJZ8r7sqonlmqp98y___8yOkU45_JIb7lI6Q1yYtg_GOJGT2ifaQWbNnmFegkKZ9s8trpomnrq09z___9zPlV56_KJc8mJ7R2zZuh_HPKHU3jgbRXcOnpGfhlLZ-t9uspqnsr10","e":"AQAB"}]}"#;

    /// Spawn a persistent (multi-request) HTTP/1.1 server on a random port that serves
    /// `initial_body` for every request until `rotated` is set to `true` (using
    /// `Ordering::SeqCst`), after which it serves `rotated_body`.
    ///
    /// Used to simulate an `IdP` rotating its JWKS signing keys between the initial
    /// `JwksManager::new()` fetch and a later `refresh()` call.
    async fn rotating_jwks_http_server(
        initial_body: &'static str,
        rotated_body: &'static str,
        rotated: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = vec![0_u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let body = if rotated.load(std::sync::atomic::Ordering::SeqCst) {
                    rotated_body
                } else {
                    initial_body
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        port
    }

    /// Regression test for the "refresh-on-miss" behavior relied upon by
    /// `routes::ui_auth::callback`: when the `IdP` rotates its signing keys, a
    /// `JwksManager::refresh()` call must be able to pick up the new key so that
    /// login succeeds without restarting the server.
    #[actix_web::test]
    async fn test_refresh_on_miss_picks_up_rotated_key() {
        let rotated = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let port =
            rotating_jwks_http_server(SAMPLE_JWKS, SAMPLE_JWKS_ROTATED, rotated.clone()).await;
        let url = format!("http://127.0.0.1:{port}/jwks.json");

        let manager = JwksManager::new(vec![url], None)
            .await
            .expect("failed to build JwksManager");

        // Only the original key is served initially: the rotated `kid` is missing.
        assert!(manager.find(SAMPLE_RSA_JWK_KID).unwrap().is_some());
        assert!(manager.find(ROTATED_KID).unwrap().is_none());

        // Simulate the IdP rotating its signing keys.
        rotated.store(true, std::sync::atomic::Ordering::SeqCst);

        // Bypass the manager's internal 60s refresh throttle directly via the
        // `pub(crate)` `last_update` field (same-crate test), so the test doesn't
        // have to wait for the throttle to naturally expire. This exercises the
        // exact `refresh()` codepath used by the refresh-on-miss retry in
        // `routes::ui_auth::callback`.
        *manager.last_update.write().unwrap() = None;
        manager.refresh().await.expect("refresh should succeed");

        // The rotated key must now be discoverable, without any server restart.
        assert!(
            manager.find(ROTATED_KID).unwrap().is_some(),
            "rotated key should be discoverable after refresh-on-miss"
        );
    }
}
