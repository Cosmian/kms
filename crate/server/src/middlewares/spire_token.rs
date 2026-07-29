//! SPIRE app-token validation middleware for the KMS SPIRE-compatible API.
//!
//! Reads `X-Vault-Token` from the request header (wire protocol header used by
//! the SPIRE vault plugin), computes `SHA-256(token)`, and checks a 30-second
//! in-memory cache.  On a cache miss, calls
//! `GET /auth/token/lookup-self` on the auth-verifier instance and
//! caches the result.  Injects both [`SpireAuthenticatedUser`] and
//! [`AuthenticatedUser`] into request extensions so that the KMS permission
//! system correctly attributes requests to the caller instead of falling back
//! to `default_username`.

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

use super::AuthenticatedUser;

/// The `X-Vault-Token` header name (wire protocol used by the SPIRE vault plugin).
pub(crate) const VAULT_TOKEN_HEADER: &str = "X-Vault-Token";

/// Authenticated user info extracted from a SPIRE app token.
#[derive(Debug, Clone)]
pub(crate) struct SpireAuthenticatedUser {
    pub(crate) entity: String,
    #[allow(dead_code)] // populated from auth-verifier; available for future policy enforcement
    pub(crate) policies: Vec<String>,
}

/// Single entry in the token validation cache.
#[derive(Clone)]
struct CacheEntry {
    user: SpireAuthenticatedUser,
    expires_at: Instant,
}

/// Shared cache of validated SPIRE app tokens.
///
/// Key: SHA-256 of the raw token bytes (32 bytes → stored as `[u8; 32]`).
/// Value: cached lookup result + expiry time.
pub(crate) struct SpireTokenCache {
    inner: DashMap<[u8; 32], CacheEntry>,
    ttl: Duration,
    max_entries: usize,
}

/// Number of cached entries that triggers an opportunistic sweep of expired
/// entries on `insert`. This bounds resident memory to roughly the number of
/// *unexpired* tokens rather than every token ever validated, without needing a
/// background sweeper task.
const DEFAULT_MAX_ENTRIES: usize = 100_000;

impl SpireTokenCache {
    pub(crate) fn new(ttl_secs: u64) -> Arc<Self> {
        Self::with_max_entries(ttl_secs, DEFAULT_MAX_ENTRIES)
    }

    fn with_max_entries(ttl_secs: u64, max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
            max_entries,
        })
    }

    /// Remove every expired entry from the cache.
    ///
    /// Called opportunistically from `insert` once the cache grows past
    /// `max_entries`, so a token that validates once and is never presented
    /// again (client crash, superseded login, revoked token) cannot linger past
    /// its TTL. Failed validations are never cached, so only genuine expiries
    /// are swept here.
    fn evict_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, entry| entry.expires_at > now);
    }

    pub(super) fn lookup(&self, hash: &[u8; 32]) -> Option<SpireAuthenticatedUser> {
        if let Some(entry) = self.inner.get(hash) {
            if entry.expires_at > Instant::now() {
                return Some(entry.user.clone());
            }
        }
        // Expired — remove
        self.inner.remove(hash);
        None
    }

    pub(super) fn insert(&self, hash: [u8; 32], user: SpireAuthenticatedUser) {
        // Opportunistically bound memory: purge accumulated expired entries
        // before the map can grow without limit.
        if self.inner.len() >= self.max_entries {
            self.evict_expired();
        }
        self.inner.insert(
            hash,
            CacheEntry {
                user,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }
}

/// Minimal response shape from `GET /auth/token/lookup-self`.
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
) -> Result<SpireAuthenticatedUser, String> {
    let url = auth_verifier_url
        .join("/auth/token/lookup-self")
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

    Ok(SpireAuthenticatedUser {
        entity: body.data.entity_id,
        policies: body.data.policies,
    })
}

/// Creates the SPIRE app-token authentication middleware for KMS SPIRE-compatible scopes.
///
/// Middleware order (last `.wrap()` runs first):
/// - Reads `X-Vault-Token` (wire protocol header used by the SPIRE vault plugin)
/// - Checks/updates the 30-second in-memory cache
/// - On miss: calls auth-verifier `GET /auth/token/lookup-self`
/// - Injects both [`SpireAuthenticatedUser`] and [`AuthenticatedUser`] into extensions
pub(crate) fn spire_token_middleware<S, B>(
    cache: Arc<SpireTokenCache>,
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
                    debug!("spire_token_middleware: non-ASCII X-Vault-Token header");
                    return Ok(req
                        .into_response(
                            actix_web::HttpResponse::Forbidden()
                                .json(serde_json::json!({"errors": ["invalid token"]})),
                        )
                        .map_into_boxed_body());
                }
            } else {
                trace!("spire_token_middleware: missing X-Vault-Token header");
                return Ok(req
                    .into_response(
                        actix_web::HttpResponse::Forbidden()
                            .json(serde_json::json!({"errors": ["missing X-Vault-Token"]})),
                    )
                    .map_into_boxed_body());
            };

            let hash_bytes: [u8; 32] = Sha256::digest(raw_token.as_bytes()).into();

            // Cache hit path
            if let Some(ref user) = cache.lookup(&hash_bytes) {
                req.extensions_mut().insert(AuthenticatedUser {
                    username: user.entity.clone(),
                });
                req.extensions_mut().insert(user.clone());
                return next
                    .call(req)
                    .await
                    .map(ServiceResponse::map_into_boxed_body);
            }

            // Cache miss — call auth-verifier
            match validate_against_auth_verifier(&raw_token, &auth_verifier_url, &client).await {
                Ok(user) => {
                    debug!("spire_token_middleware: validated entity={}", user.entity);
                    cache.insert(hash_bytes, user.clone());
                    req.extensions_mut().insert(AuthenticatedUser {
                        username: user.entity.clone(),
                    });
                    req.extensions_mut().insert(user);
                    next.call(req)
                        .await
                        .map(ServiceResponse::map_into_boxed_body)
                }
                Err(e) => {
                    warn!("spire_token_middleware: validation failed: {e}");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::Duration;

    use actix_web::{App, HttpMessage, HttpResponse, web};
    use sha2::{Digest, Sha256};

    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────

    fn compute_hash(token: &str) -> [u8; 32] {
        Sha256::digest(token.as_bytes()).into()
    }

    fn make_cache_with_user(entity: &str) -> (Arc<SpireTokenCache>, [u8; 32], String) {
        let cache = SpireTokenCache::new(30);
        let token = format!("test-token-{entity}");
        let hash = compute_hash(&token);
        cache.insert(
            hash,
            SpireAuthenticatedUser {
                entity: entity.to_owned(),
                policies: vec!["default".into()],
            },
        );
        (cache, hash, token)
    }

    // ── Cache unit tests ─────────────────────────────────────────────────

    /// Insert → lookup returns the user.
    #[test]
    fn cache_insert_then_lookup() {
        let (cache, hash, _token) = make_cache_with_user("entity-001");
        let found = cache.lookup(&hash).expect("should find inserted user");
        assert_eq!(found.entity, "entity-001");
        assert_eq!(found.policies, vec!["default"]);
    }

    /// Lookup for an unknown hash returns None.
    #[test]
    fn cache_lookup_miss_returns_none() {
        let cache = SpireTokenCache::new(30);
        let unknown_hash = compute_hash("no-such-token");
        assert!(cache.lookup(&unknown_hash).is_none());
    }

    /// A second lookup after the TTL has passed returns None.
    #[test]
    fn cache_entry_expires_after_ttl() {
        let cache = SpireTokenCache::new(1); // 1-second TTL
        let hash = compute_hash("expire-me");
        cache.insert(
            hash,
            SpireAuthenticatedUser {
                entity: "ephemeral".into(),
                policies: vec![],
            },
        );
        assert!(
            cache.lookup(&hash).is_some(),
            "should be found before expiry"
        );
        std::thread::sleep(Duration::from_secs(2));
        assert!(cache.lookup(&hash).is_none(), "should be expired after TTL");
    }

    /// Insert, then lookup with a different hash returns None.
    #[test]
    fn cache_lookup_wrong_hash_returns_none() {
        let (cache, _hash, _token) = make_cache_with_user("alice");
        let wrong_hash = compute_hash("bob-token");
        assert!(cache.lookup(&wrong_hash).is_none());
    }

    /// Once the cache grows past `max_entries`, the next insert sweeps expired
    /// entries so tokens that were never looked up again cannot linger forever.
    #[test]
    fn cache_evicts_expired_entries_when_over_capacity() {
        // ttl = 0 → every inserted entry is immediately expired; cap = 3.
        let cache = SpireTokenCache::with_max_entries(0, 3);
        for i in 0..3 {
            cache.insert(
                compute_hash(&format!("stale-{i}")),
                SpireAuthenticatedUser {
                    entity: format!("e{i}"),
                    policies: vec![],
                },
            );
        }
        assert_eq!(cache.inner.len(), 3, "cap reached with stale entries");

        // The 4th insert trips the sweep, purging the 3 expired entries first.
        cache.insert(
            compute_hash("stale-3"),
            SpireAuthenticatedUser {
                entity: "e3".into(),
                policies: vec![],
            },
        );
        assert_eq!(
            cache.inner.len(),
            1,
            "expired entries swept, only the newest insert remains"
        );
    }

    // ── Middleware unit tests ────────────────────────────────────────────

    /// Cache-hit path: the middleware injects **both** [`SpireAuthenticatedUser`]
    /// and [`AuthenticatedUser`] into request extensions.
    #[actix_web::test]
    async fn middleware_cache_hit_injects_both_user_types() {
        let (cache, _hash, token) = make_cache_with_user("spire-entity-42");

        // Dummy URL and client — won't be used on cache hit.
        let dummy_url = url::Url::parse("http://127.0.0.1:1").unwrap();
        let client = Arc::new(reqwest::Client::new());

        let app = actix_web::test::init_service(
            App::new()
                .wrap(spire_token_middleware(
                    cache.clone(),
                    dummy_url,
                    client.clone(),
                ))
                .route(
                    "/test",
                    web::get().to(|req: actix_web::HttpRequest| async move {
                        let extensions = req.extensions();
                        let spire = extensions
                            .get::<SpireAuthenticatedUser>()
                            .expect("SpireAuthenticatedUser missing");
                        let auth = extensions
                            .get::<AuthenticatedUser>()
                            .expect("AuthenticatedUser missing");
                        assert_eq!(spire.entity, "spire-entity-42");
                        assert_eq!(auth.username, "spire-entity-42");
                        HttpResponse::Ok().body("ok")
                    }),
                ),
        )
        .await;

        let req = actix_web::test::TestRequest::get()
            .uri("/test")
            .insert_header((VAULT_TOKEN_HEADER, token.as_str()))
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);
    }

    /// Requests without the `X-Vault-Token` header are rejected with 403.
    #[actix_web::test]
    async fn middleware_missing_header_returns_403() {
        let cache = SpireTokenCache::new(30);
        let dummy_url = url::Url::parse("http://127.0.0.1:1").unwrap();
        let client = Arc::new(reqwest::Client::new());

        let app = actix_web::test::init_service(
            App::new()
                .wrap(spire_token_middleware(
                    cache.clone(),
                    dummy_url,
                    client.clone(),
                ))
                .route("/test", web::get().to(|| async { "should not reach" })),
        )
        .await;

        let req = actix_web::test::TestRequest::get()
            .uri("/test")
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 403);
    }

    /// Requests with unknown tokens that miss the cache AND the auth-verifier
    /// are rejected with 403 (cache-miss + unreachable auth-verifier).
    #[actix_web::test]
    async fn middleware_cache_miss_unreachable_auth_verifier_returns_403() {
        let cache = SpireTokenCache::new(30);
        // Use a non-routable address so the HTTP call fails fast.
        let bad_url = url::Url::parse("http://127.0.0.1:1").unwrap();
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .unwrap(),
        );

        let app = actix_web::test::init_service(
            App::new()
                .wrap(spire_token_middleware(
                    cache.clone(),
                    bad_url,
                    client.clone(),
                ))
                .route("/test", web::get().to(|| async { "should not reach" })),
        )
        .await;

        let req = actix_web::test::TestRequest::get()
            .uri("/test")
            .insert_header((VAULT_TOKEN_HEADER, "unknown-token-not-in-cache"))
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 403);
    }

    /// Multiple cache hits with different tokens inject the correct,
    /// per-token entity IDs — verifying no cross-contamination between
    /// cached entries.
    #[actix_web::test]
    async fn middleware_two_different_tokens_get_correct_users() {
        let (cache, _hash1, token1) = make_cache_with_user("alice");
        let token2 = "bob-token".to_owned();
        let hash2 = compute_hash(&token2);
        cache.insert(
            hash2,
            SpireAuthenticatedUser {
                entity: "bob".into(),
                policies: vec!["admin".into()],
            },
        );

        let dummy_url = url::Url::parse("http://127.0.0.1:1").unwrap();
        let client = Arc::new(reqwest::Client::new());

        let app = actix_web::test::init_service(
            App::new()
                .wrap(spire_token_middleware(
                    cache.clone(),
                    dummy_url,
                    client.clone(),
                ))
                .route(
                    "/whoami",
                    web::get().to(|req: actix_web::HttpRequest| async move {
                        let extensions = req.extensions();
                        let auth = extensions.get::<AuthenticatedUser>().unwrap();
                        HttpResponse::Ok().body(auth.username.clone())
                    }),
                ),
        )
        .await;

        // Alice
        let req = actix_web::test::TestRequest::get()
            .uri("/whoami")
            .insert_header((VAULT_TOKEN_HEADER, token1.as_str()))
            .to_request();
        let body = actix_web::test::call_and_read_body(&app, req).await;
        assert_eq!(body, &b"alice"[..]);

        // Bob
        let req = actix_web::test::TestRequest::get()
            .uri("/whoami")
            .insert_header((VAULT_TOKEN_HEADER, token2.as_str()))
            .to_request();
        let body = actix_web::test::call_and_read_body(&app, req).await;
        assert_eq!(body, &b"bob"[..]);
    }
}
