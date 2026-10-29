//! Live-session check of Auth Verifier tokens.
//!
//! Every Auth Verifier JWT is the value of an `_ea_` session cookie whose session lives in
//! the Auth Verifier session store (keyed by the SHA-256 of the token), which ends it on
//! logout, admin revocation or idle timeout. The signature and `exp` of the token cannot
//! reflect that, so a token is only accepted while `GET {auth_verifier_url}/whoami`,
//! authenticated by the token as `_ea_` cookie, succeeds. Live sessions are cached for
//! [`SESSION_CACHE_TTL`]: a revocation done elsewhere takes effect at the KMS within it.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use url::Url;

use super::token::AUTH_VERIFIER_SESSION_COOKIE;
use crate::{
    config::AuthVerifierConfig, error::KmsError, middlewares::JwksManager, result::KResult,
};

/// How long a session the Auth Verifier confirmed live is trusted without asking again.
const SESSION_CACHE_TTL: Duration = Duration::from_secs(30);

/// Cache size that triggers a sweep of expired entries, bounding memory without a task.
const MAX_CACHED_SESSIONS: usize = 100_000;

/// Trust material of the Auth Verifier server: the JWKS that signs its tokens and the
/// session store that says whether a token's session is still live.
pub struct AuthVerifierValidator {
    pub(crate) jwks: Arc<JwksManager>,
    whoami_url: Url,
    client: reqwest::Client,
    /// SHA-256 of a token → end of the trust period of its live session.
    live_sessions: DashMap<[u8; 32], Instant>,
    ttl: Duration,
}

impl fmt::Debug for AuthVerifierValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthVerifierValidator")
            .field("jwks", &self.jwks)
            .field("whoami_url", &self.whoami_url.as_str())
            .finish_non_exhaustive()
    }
}

impl AuthVerifierValidator {
    /// Build the validator of the Auth Verifier at `config.auth_verifier_url`.
    ///
    /// # Errors
    /// When the server URL is missing or invalid, or the HTTP client cannot be built.
    pub(crate) fn new(jwks: Arc<JwksManager>, config: &AuthVerifierConfig) -> KResult<Self> {
        let server_url = config.auth_verifier_url.as_deref().ok_or_else(|| {
            KmsError::ServerError(
                "Auth Verifier is enabled but no server URL is configured".to_owned(),
            )
        })?;
        let mut whoami_url = Url::parse(server_url.trim_end_matches('/'))
            .map_err(|e| KmsError::ServerError(format!("invalid auth_verifier_url: {e}")))?;
        whoami_url
            .path_segments_mut()
            .map_err(|()| {
                KmsError::ServerError("invalid auth_verifier_url: cannot be a base".to_owned())
            })?
            .push("whoami");
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.auth_verifier_accept_invalid_certs)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            jwks,
            whoami_url,
            client,
            live_sessions: DashMap::new(),
            ttl: SESSION_CACHE_TTL,
        })
    }

    /// Fail closed unless the Auth Verifier session of `token` is still live.
    ///
    /// Call only once the token signature is verified, so that unauthenticated callers
    /// cannot make the KMS query the Auth Verifier.
    pub(crate) async fn ensure_live_session(&self, token: &str) -> KResult<()> {
        let session = openssl::sha::sha256(token.as_bytes());
        let now = Instant::now();
        if self
            .live_sessions
            .get(&session)
            .is_some_and(|trusted_until| *trusted_until > now)
        {
            return Ok(());
        }
        let response = self
            .client
            .get(self.whoami_url.clone())
            .header(
                reqwest::header::COOKIE,
                format!("{AUTH_VERIFIER_SESSION_COOKIE}={token}"),
            )
            .send()
            .await
            .map_err(|e| {
                KmsError::Unauthorized(format!("Auth Verifier: cannot check the session: {e}"))
            })?;
        if !response.status().is_success() {
            self.live_sessions.remove(&session);
            return Err(KmsError::Unauthorized(format!(
                "Auth Verifier: the session has ended (logout, revocation or idle timeout): {}",
                response.status()
            )));
        }
        if self.live_sessions.len() >= MAX_CACHED_SESSIONS {
            self.live_sessions
                .retain(|_, trusted_until| *trusted_until > now);
        }
        self.live_sessions.insert(session, now + self.ttl);
        Ok(())
    }

    /// Stop trusting the cached session of `token`, e.g. once the KMS logout revoked it.
    pub(crate) fn forget_session(&self, token: &str) {
        self.live_sessions
            .remove(&openssl::sha::sha256(token.as_bytes()));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)] // tests: a panic is the failure signal
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use crate::middlewares::auth_verifier_test_helpers::{auth_verifier_token, mock_auth_verifier};

    #[tokio::test]
    async fn live_session_is_accepted_and_ended_session_rejected() {
        let live = Arc::new(AtomicBool::new(true));
        let validator = mock_auth_verifier(live.clone()).await;
        let token = auth_verifier_token("alice@example.com", Some("kms-saml"));
        validator
            .ensure_live_session(&token)
            .await
            .expect("a live session must be accepted");

        // Cached: a revocation takes effect at the KMS once the cache entry expires...
        live.store(false, Ordering::SeqCst);
        validator
            .ensure_live_session(&token)
            .await
            .expect("a recently confirmed session is cached");
        // ... or at once when the KMS itself ended it (logout).
        validator.forget_session(&token);
        validator
            .ensure_live_session(&token)
            .await
            .expect_err("an ended session must be rejected");
    }

    #[tokio::test]
    async fn ended_session_is_rejected_once_the_cache_expires() {
        let live = Arc::new(AtomicBool::new(true));
        let mut validator = Arc::into_inner(mock_auth_verifier(live.clone()).await)
            .expect("sole owner of the validator");
        validator.ttl = Duration::ZERO;
        let token = auth_verifier_token("alice@example.com", None);
        validator
            .ensure_live_session(&token)
            .await
            .expect("a live session must be accepted");
        live.store(false, Ordering::SeqCst);
        validator
            .ensure_live_session(&token)
            .await
            .expect_err("a revoked session must be rejected after the cache TTL");
    }
}
