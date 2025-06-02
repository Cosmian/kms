//! JWKS (JSON Web Key Set) Manager
//!
//! This module provides functionality for managing and refreshing JSON Web Key Sets (JWKS),
//! which are essential for JWT token signature verification. The manager caches key sets
//! and refreshes them periodically to ensure up-to-date validation.

use std::{collections::HashMap, sync::RwLock};

use alcoholic_jwt::{JWK, JWKS};
use chrono::{DateTime, Duration, Utc};
use reqwest::{Client, header::HeaderValue};
use serde_json::{Value, json};

use crate::{config::ProxyParams, error::KmsError, kms_bail, kms_error, result::KResult};

static REFRESH_INTERVAL: i64 = 60; // in secs

#[derive(Debug)]
pub struct JwksManager {
    uris: Vec<String>,
    jwks: RwLock<HashMap<String, JWKS>>,
    last_update: RwLock<Option<DateTime<Utc>>>,
    proxy_params: Option<ProxyParams>,
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
    fn set_jwks(&self, new_jwks: HashMap<String, JWKS>) -> KResult<()> {
        let mut jwks = self.jwks.write().map_err(|e| {
            KmsError::ServerError(format!("cannot lock JWKS for write. Error: {e:?}"))
        })?;
        *jwks = new_jwks;
        Ok(())
    }

    /// Find the key identifier `kid` in each registered JWKS
    pub fn find(&self, kid: &str) -> KResult<Option<JWK>> {
        Ok(self
            .jwks
            .read()
            .map_err(|e| KmsError::ServerError(format!("cannot lock JWKS for read. Error: {e:?}")))?
            .iter()
            .find_map(|(_, jwks)| jwks.find(kid))
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
    ) -> HashMap<String, JWKS> {
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
                //log errors and filter them out
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
) -> KResult<(String, JWKS)> {
    tracing::debug!("fetching {jwks_uri}");
    // Fetch the JWKS from the provided URI,
    let mut client = Client::builder();

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
            ))
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
            .filter(|v| match serde_json::from_value::<JWK>(v.clone()) {
                Ok(jwk) => {
                    tracing::debug!("Found valid JWK in JWKS at `{jwks_uri}`: {jwk:#?}");
                    true
                }
                Err(e) => {
                    tracing::debug!("Ignoring invalid JWK in JWKS at `{jwks_uri}`: {e}: {v:#?}",);
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
    let jwks = serde_json::from_value::<JWKS>(jwks.clone()).map_err(|e| {
        kms_error!("Failed to reconstruct JWKS from array of JWK at `{jwks_uri}`: {e}: {jwks:#?}")
    })?;
    Ok((jwks_uri.clone(), jwks))
}
