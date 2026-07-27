//! Vault token validation middleware for the KMS Vault-compatible API.
//!
//! Reads `X-Vault-Token` from the request header, computes `SHA-256(token)`,
//! and checks a 30-second in-memory cache.  On a cache miss, calls
//! `GET /v1/auth/token/lookup-self` on the auth-verifier instance and
//! caches the result.  Injects [`VaultAuthenticatedUser`] into request extensions.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use actix_web::{
    Error, HttpMessage,
    body::{BoxBody, MessageBody},
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    middleware::{Next, from_fn},
};
use cosmian_logger::{debug, trace, warn};
use dashmap::DashMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

/// The `X-Vault-Token` header name.
pub(crate) const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Authenticated user info extracted from a Vault token.
#[derive(Debug, Clone)]
pub(crate) struct VaultAuthenticatedUser {
    pub(crate) entity: String,
    #[allow(dead_code)] // populated from auth-verifier; available for future policy enforcement
    pub(crate) policies: Vec<String>,
}

/// Single entry in the token validation cache.
#[derive(Clone)]
struct CacheEntry {
    user: VaultAuthenticatedUser,
    expires_at: Instant,
}

/// Shared cache of validated Vault tokens.
///
/// Key: SHA-256 of the raw token bytes (32 bytes → stored as `[u8; 32]`).
/// Value: cached lookup result + expiry time.
pub(crate) struct VaultTokenCache {
    inner: DashMap<[u8; 32], CacheEntry>,
    ttl: Duration,
}

impl VaultTokenCache {
    pub(crate) fn new(ttl_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        })
    }

    fn lookup(&self, hash: &[u8; 32]) -> Option<VaultAuthenticatedUser> {
        if let Some(entry) = self.inner.get(hash) {
            if entry.expires_at > Instant::now() {
                return Some(entry.user.clone());
            }
        }
        // Expired — remove
        self.inner.remove(hash);
        None
    }

    fn insert(&self, hash: [u8; 32], user: VaultAuthenticatedUser) {
        self.inner.insert(
            hash,
            CacheEntry {
                user,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

/// Minimal response shape from `GET /v1/auth/token/lookup-self`.
#[derive(Deserialize)]
struct LookupSelfResponse {
    data: LookupSelfData,
}

#[derive(Deserialize)]
struct LookupSelfData {
    entity_id: String,
    #[serde(default)]
    policies: Vec<String>,
}

/// Validate a raw token against the auth-verifier and return the entity info.
async fn validate_against_auth_verifier(
    token: &str,
    auth_verifier_url: &Url,
    client: &reqwest::Client,
) -> Result<VaultAuthenticatedUser, String> {
    let url = auth_verifier_url
        .join("/v1/auth/token/lookup-self")
        .map_err(|e| format!("invalid auth_verifier_url: {e}"))?;

    let resp = client
        .get(url)
        .header(VAULT_TOKEN_HEADER, token)
        .send()
        .await
        .map_err(|e| format!("auth-verifier lookup-self HTTP error: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!(
            "auth-verifier lookup-self returned HTTP {}",
            resp.status()
        ));
    }

    let body: LookupSelfResponse = resp
        .json()
        .await
        .map_err(|e| format!("auth-verifier lookup-self parse error: {e}"))?;

    Ok(VaultAuthenticatedUser {
        entity: body.data.entity_id,
        policies: body.data.policies,
    })
}

/// Creates the Vault token authentication middleware for KMS vault scopes.
///
/// Middleware order (last `.wrap()` runs first):
/// - Reads `X-Vault-Token`
/// - Checks/updates the 30-second in-memory cache
/// - On miss: calls auth-verifier `lookup-self`
/// - Injects `VaultAuthenticatedUser` into extensions
pub(crate) fn vault_token_middleware<S, B>(
    cache: Arc<VaultTokenCache>,
    auth_verifier_url: Url,
    client: Arc<reqwest::Client>,
) -> impl Transform<S, ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error, InitError = ()>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    from_fn(move |req: ServiceRequest, next: Next<B>| {
        let cache = cache.clone();
        let auth_verifier_url = auth_verifier_url.clone();
        let client = client.clone();

        async move {
            // Extract raw token from header
            let raw_token = if let Some(v) = req.headers().get(VAULT_TOKEN_HEADER) {
                if let Ok(s) = v.to_str() {
                    s.to_owned()
                } else {
                    debug!("vault_token_middleware: non-ASCII X-Vault-Token header");
                    return Ok(req
                        .into_response(
                            actix_web::HttpResponse::Forbidden()
                                .json(serde_json::json!({"errors": ["invalid token"]})),
                        )
                        .map_into_boxed_body());
                }
            } else {
                trace!("vault_token_middleware: missing X-Vault-Token header");
                return Ok(req
                    .into_response(
                        actix_web::HttpResponse::Forbidden()
                            .json(serde_json::json!({"errors": ["missing X-Vault-Token"]})),
                    )
                    .map_into_boxed_body());
            };

            let hash_bytes: [u8; 32] = Sha256::digest(raw_token.as_bytes()).into();

            // Cache hit path
            if let Some(user) = cache.lookup(&hash_bytes) {
                req.extensions_mut().insert(user);
                return next
                    .call(req)
                    .await
                    .map(ServiceResponse::map_into_boxed_body);
            }

            // Cache miss — call auth-verifier
            match validate_against_auth_verifier(&raw_token, &auth_verifier_url, &client).await {
                Ok(user) => {
                    debug!("vault_token_middleware: validated entity={}", user.entity);
                    cache.insert(hash_bytes, user.clone());
                    req.extensions_mut().insert(user);
                    next.call(req)
                        .await
                        .map(ServiceResponse::map_into_boxed_body)
                }
                Err(e) => {
                    warn!("vault_token_middleware: validation failed: {e}");
                    Ok(req
                        .into_response(
                            actix_web::HttpResponse::Forbidden()
                                .json(serde_json::json!({"errors": ["permission denied"]})),
                        )
                        .map_into_boxed_body())
                }
            }
        }
    })
}
