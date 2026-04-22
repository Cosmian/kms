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
    pub(crate) proxy_params: Option<ProxyParams>,
}

impl JwksManager {
    pub async fn new(uris: Vec<String>, server_params: Option<&ProxyParams>) -> KResult<Self> {
        let jwks_manager = Self {
            uris,
            jwks: HashMap::new().into(),
            last_update: None.into(),
            proxy_params: server_params.cloned(),
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

    /// Fetch again all JWKS using the `uris`.
    ///
    /// The threshold to refresh JWKS is set to `REFRESH_INTERVAL`.
    pub async fn refresh(&self) -> KResult<()> {
        let refresh_is_allowed = {
            let mut last_update = self.last_update.write().map_err(|e| {
                KmsError::ServerError(format!("cannot lock last_update for write. Error: {e:?}"))
            })?;

            let can_be_refreshed = last_update
                .is_none_or(|lu| (lu + Duration::seconds(REFRESH_INTERVAL)) < Utc::now());

            if can_be_refreshed {
                *last_update = Some(Utc::now());
            }
            can_be_refreshed
        };

        if refresh_is_allowed {
            tracing::info!("Refreshing JWKS");
            let refreshed_jwks = Self::fetch_all(&self.uris, &self.proxy_params).await;
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
    ) -> HashMap<String, JwkSet> {
        // Create a vector of futures to fetch JWKS from each URI
        let jwks_downloads: Vec<_> = uris
            .iter()
            .map(|uri| parse_jwks(uri, proxy_params))
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
) -> KResult<(String, JwkSet)> {
    tracing::debug!("fetching {jwks_uri}");
    // Fetch the JWKS from the provided URI,
    // Disable redirect following to prevent SSRF via crafted 3xx responses (A10-2).
    let mut client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none());

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

        let (res_url, jwks) = parse_jwks(&url, &None).await.unwrap();

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

        let err = parse_jwks(&url, &None).await.unwrap_err();

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

        let err = parse_jwks(&url, &None).await.unwrap_err();

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

        let err = parse_jwks(&jwks_url, &None).await.unwrap_err();

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

        let (res_url, jwks) = parse_jwks(&url, &None).await.unwrap();

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

        let (_, jwks) = parse_jwks(&url, &None).await.unwrap();

        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys.first().and_then(|k| k.common.key_id.as_deref()),
            Some("valid-key")
        );
    }
}
