//! Encrypted Web UI session cookie (`auth_session`).
//!
//! The whole session ([`UiSession`]) lives in the cookie: AES-256-GCM sealed under a server
//! key, with the cookie name as AAD and a server-enforced expiry inside the sealed payload.
//! The browser can neither read nor forge it. The server enforces an absolute lifetime, an
//! idle timeout (sliding, refreshed by [`UiSessionCookie::read_with_refresh`]) and a logout
//! revocation list kept in the KMS database ([`SessionRevocations`]), so that a logout on
//! one instance is honored by every instance sharing the database.
//!
//! The IV is generated inside the `OpenSSL` provider DRBG (mandatory in FIPS mode, and
//! fork-safe), never by this module.

use std::sync::Arc;

use actix_web::http::header::{self, HeaderMap};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::{
    KmsRng,
    symmetric::symmetric_ciphers::{SymCipher, aes_gcm_encrypt_generated_iv, decrypt},
};
use cosmian_logger::{debug, warn};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{core::KMS, error::KmsError, middlewares::UserId, result::KResult};

/// Name of the KMS session cookie; also the AES-GCM AAD, binding a sealed value to this cookie.
const UI_SESSION_COOKIE: &str = "auth_session";

/// Lifetime of a session, enforced by the server (sealed `exp`) and advertised as `Max-Age`.
const UI_SESSION_TTL_SECS: i64 = 24 * 60 * 60;

/// A session unused for longer than this is rejected, whatever its remaining lifetime.
const UI_SESSION_IDLE_SECS: i64 = 60 * 60;

/// A session whose last activity is at least this old is re-issued with a fresh `last`.
const UI_SESSION_REFRESH_SECS: i64 = 5 * 60;

/// Largest cookie value parsed: a browser caps a cookie near 4 KiB, a longer one is hostile.
const MAX_COOKIE_VALUE_LEN: usize = 4096;

/// AES-GCM IV length in bytes (96 bits, NIST SP 800-38D).
const GCM_IV_LEN: usize = 12;

/// AES-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// State kept in the session cookie.
///
/// `Debug` is hand-written: the OIDC values of a login in progress must never reach a log.
#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UiSession {
    /// The authenticated user, once logged in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) user_id: Option<UserId>,
    /// OIDC PKCE verifier of the login in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pkce_verifier: Option<String>,
    /// OIDC `state` of the login in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) csrf_token: Option<String>,
    /// OIDC nonce of the login in progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<String>,
}

impl std::fmt::Debug for UiSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UiSession")
            .field("user_id", &self.user_id)
            .finish_non_exhaustive()
    }
}

/// The sealed payload: the session, its random id, and its times (Unix seconds).
#[derive(Serialize, Deserialize)]
struct SealedSession {
    /// Absolute expiry.
    exp: i64,
    /// Random 128-bit session id (32 lowercase hex chars); the key of the revocation list.
    sid: String,
    /// Issue time.
    iat: i64,
    /// Last activity, advanced by the sliding refresh; drives the idle timeout.
    last: i64,
    #[serde(flatten)]
    session: UiSession,
}

/// Where logout revocations are kept: the database shared by every KMS instance.
#[async_trait(?Send)]
pub(crate) trait SessionRevocations: Send + Sync {
    /// Refuse the session `sid` until `expires_at` (Unix seconds).
    async fn revoke(&self, sid: &str, expires_at: i64) -> KResult<()>;

    /// Whether the session `sid` was revoked.
    async fn is_revoked(&self, sid: &str) -> KResult<bool>;
}

#[async_trait(?Send)]
impl SessionRevocations for KMS {
    async fn revoke(&self, sid: &str, expires_at: i64) -> KResult<()> {
        Ok(self
            .database
            .revoke_ui_session(sid, expires_at, now())
            .await?)
    }

    async fn is_revoked(&self, sid: &str) -> KResult<bool> {
        Ok(self.database.is_ui_session_revoked(sid).await?)
    }
}

/// Seals and opens the session cookie. Registered once as actix `app_data`.
pub(crate) struct UiSessionCookie {
    key: Zeroizing<[u8; 32]>,
    secure: bool,
    revocations: Arc<dyn SessionRevocations>,
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A fresh random session id.
fn new_sid() -> KResult<String> {
    let mut raw = [0_u8; 16];
    KmsRng::new().fill_bytes(&mut raw)?;
    Ok(hex::encode(raw))
}

impl UiSessionCookie {
    /// `secure` adds the `Secure` attribute (public URL is `https://` or TLS is configured).
    pub(crate) fn new(
        key: Zeroizing<[u8; 32]>,
        secure: bool,
        revocations: Arc<dyn SessionRevocations>,
    ) -> Self {
        Self {
            key,
            secure,
            revocations,
        }
    }

    /// `Set-Cookie` value carrying `session` in a new session, valid for 24 hours.
    pub(crate) fn set_cookie(&self, session: &UiSession) -> KResult<String> {
        let now = now();
        let sealed = SealedSession {
            exp: now.saturating_add(UI_SESSION_TTL_SECS),
            sid: new_sid()?,
            iat: now,
            last: now,
            session: session.clone(),
        };
        self.set_cookie_value(&sealed, UI_SESSION_TTL_SECS)
    }

    /// `Set-Cookie` value of `sealed`, advertised for `max_age` seconds.
    fn set_cookie_value(&self, sealed: &SealedSession, max_age: i64) -> KResult<String> {
        let value = self.seal(sealed)?;
        Ok(format!(
            "{UI_SESSION_COOKIE}={value}; Max-Age={max_age}{}",
            self.attributes()
        ))
    }

    /// `Set-Cookie` value that makes the browser drop the session cookie.
    pub(crate) fn removal_cookie(&self) -> String {
        format!(
            "{UI_SESSION_COOKIE}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT{}",
            self.attributes()
        )
    }

    /// The session carried by the request, or `None` when the cookie is absent, tampered with,
    /// sealed under another key, expired, idle for too long or revoked by logout.
    pub(crate) async fn read(&self, headers: &HeaderMap) -> Option<UiSession> {
        self.read_sealed(headers).await.map(|sealed| sealed.session)
    }

    /// Like [`Self::read`], plus a refreshed `Set-Cookie` (same `sid`, `iat` and `exp`, `last`
    /// moved to now) once the session has been idle for [`UI_SESSION_REFRESH_SECS`]: the idle
    /// timeout then slides with the activity, with at most one new cookie per refresh period.
    pub(crate) async fn read_with_refresh(
        &self,
        headers: &HeaderMap,
    ) -> Option<(UiSession, Option<String>)> {
        let mut sealed = self.read_sealed(headers).await?;
        let now = now();
        let refreshed = if now.saturating_sub(sealed.last) >= UI_SESSION_REFRESH_SECS {
            sealed.last = now;
            match self.set_cookie_value(&sealed, sealed.exp.saturating_sub(now)) {
                Ok(set_cookie) => Some(set_cookie),
                Err(e) => {
                    warn!("UI session cookie refresh failed: {e}");
                    None
                }
            }
        } else {
            None
        };
        Some((sealed.session, refreshed))
    }

    /// Revokes the logged-in session carried by the request, so that its cookie is refused by
    /// every KMS instance until its expiry even if a copy of it was kept. Best effort: a
    /// failure to record the revocation is logged, and the browser cookie is dropped anyway.
    pub(crate) async fn revoke(&self, headers: &HeaderMap) {
        let Some(value) = request_cookie(headers, UI_SESSION_COOKIE) else {
            return;
        };
        let Ok(sealed) = self.unseal(value) else {
            return;
        };
        if sealed.session.user_id.is_none() || sealed.exp <= now() {
            return;
        }
        if let Err(e) = self.revocations.revoke(&sealed.sid, sealed.exp).await {
            warn!("UI session revocation failed: {e}");
        }
    }

    async fn read_sealed(&self, headers: &HeaderMap) -> Option<SealedSession> {
        let value = request_cookie(headers, UI_SESSION_COOKIE)?;
        let sealed = match self.open(value) {
            Ok(sealed) => sealed,
            Err(reason) => {
                debug!("UI session cookie rejected: {reason}");
                return None;
            }
        };
        // Only a logged-in session can be revoked: skip the lookup during the login flow.
        if sealed.session.user_id.is_some() {
            match self.revocations.is_revoked(&sealed.sid).await {
                Ok(false) => {}
                Ok(true) => {
                    debug!("UI session cookie rejected: revoked");
                    return None;
                }
                Err(e) => {
                    warn!("UI session revocation lookup failed, refusing the session: {e}");
                    return None;
                }
            }
        }
        Some(sealed)
    }

    /// Cookie value: `base64url(iv || ciphertext || tag)` of the sealed session.
    fn seal(&self, sealed: &SealedSession) -> KResult<String> {
        let json = Zeroizing::new(serde_json::to_vec(sealed)?);
        let (iv, ciphertext, tag) = aes_gcm_encrypt_generated_iv(
            SymCipher::Aes256Gcm,
            &*self.key,
            UI_SESSION_COOKIE.as_bytes(),
            &json,
        )?;
        let mut raw = Vec::with_capacity(iv.len() + ciphertext.len() + tag.len());
        raw.extend_from_slice(&iv);
        raw.extend_from_slice(&ciphertext);
        raw.extend_from_slice(&tag);
        let value = URL_SAFE_NO_PAD.encode(raw);
        // `open` refuses longer values: never issue a cookie the next request cannot use.
        if value.len() > MAX_COOKIE_VALUE_LEN {
            return Err(KmsError::ServerError(
                "the UI session cookie exceeds the maximum size".to_owned(),
            ));
        }
        Ok(value)
    }

    /// Authenticates and parses a cookie value, whatever its age or revocation state. The
    /// error is a static reason, never the cookie content.
    fn unseal(&self, value: &str) -> Result<SealedSession, &'static str> {
        if value.len() > MAX_COOKIE_VALUE_LEN {
            return Err("value too long");
        }
        let raw = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_e| "invalid base64")?;
        let (iv, rest) = raw.split_first_chunk::<GCM_IV_LEN>().ok_or("too short")?;
        let (ciphertext, tag) = rest.split_last_chunk::<GCM_TAG_LEN>().ok_or("too short")?;
        if ciphertext.is_empty() {
            return Err("too short");
        }
        let json = decrypt(
            SymCipher::Aes256Gcm,
            &*self.key,
            iv,
            UI_SESSION_COOKIE.as_bytes(),
            ciphertext,
            tag,
            None,
        )
        .map_err(|_e| "authentication failed")?;
        serde_json::from_slice(&json).map_err(|_e| "invalid JSON")
    }

    /// Inverse of [`Self::seal`], refusing an expired or idle session. Revocation is checked
    /// by [`Self::read_sealed`].
    fn open(&self, value: &str) -> Result<SealedSession, &'static str> {
        let sealed = self.unseal(value)?;
        let now = now();
        if sealed.exp <= now {
            return Err("expired");
        }
        if now.saturating_sub(sealed.last) > UI_SESSION_IDLE_SECS {
            return Err("idle");
        }
        Ok(sealed)
    }

    const fn attributes(&self) -> &'static str {
        if self.secure {
            "; Path=/; HttpOnly; SameSite=Lax; Secure"
        } else {
            "; Path=/; HttpOnly; SameSite=Lax"
        }
    }
}

/// Value of the cookie `name` among the `Cookie` request headers (RFC 6265 §5.4): the first
/// pair whose trimmed name matches exactly, with one pair of surrounding quotes removed.
pub(crate) fn request_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(candidate, _)| candidate.trim() == name)
        .map(|(_, value)| {
            let value = value.trim();
            value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value)
        })
}

/// In-memory revocation store standing in for the database, for tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryRevocations(std::sync::Mutex<std::collections::HashSet<String>>);

#[cfg(test)]
impl MemoryRevocations {
    fn sids(&self) -> std::sync::MutexGuard<'_, std::collections::HashSet<String>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
#[async_trait(?Send)]
impl SessionRevocations for MemoryRevocations {
    async fn revoke(&self, sid: &str, _expires_at: i64) -> KResult<()> {
        self.sids().insert(sid.to_owned());
        Ok(())
    }

    async fn is_revoked(&self, sid: &str) -> KResult<bool> {
        Ok(self.sids().contains(sid))
    }
}

/// Codec with a fixed key, no `Secure` attribute and its own revocation store, for tests.
#[cfg(test)]
pub(crate) fn test_ui_session_cookie() -> UiSessionCookie {
    test_ui_session_cookie_with(Arc::new(MemoryRevocations::default()))
}

/// Like [`test_ui_session_cookie`], with the given revocation store (shared between
/// "instances" to model one database).
#[cfg(test)]
pub(crate) fn test_ui_session_cookie_with(
    revocations: Arc<dyn SessionRevocations>,
) -> UiSessionCookie {
    UiSessionCookie::new(Zeroizing::new([0x42; 32]), false, revocations)
}

/// The `name=value` request cookie of a new session of `user` issued by `codec`, for tests.
#[cfg(test)]
pub(crate) fn test_session_cookie_pair(codec: &UiSessionCookie, user: &str) -> String {
    let session = UiSession {
        user_id: Some(UserId::from(user)),
        ..UiSession::default()
    };
    codec
        .set_cookie(&session)
        .expect("session cookie")
        .split(';')
        .next()
        .expect("name=value")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use actix_web::http::header::HeaderValue;

    use super::*;

    fn alice() -> UiSession {
        UiSession {
            user_id: Some(UserId::from("alice@example.com")),
            ..UiSession::default()
        }
    }

    fn headers(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie).expect("header"),
        );
        headers
    }

    /// The `value` of a `Set-Cookie: auth_session=<value>; ...`.
    fn value_of(set_cookie: &str) -> &str {
        set_cookie
            .strip_prefix("auth_session=")
            .and_then(|v| v.split(';').next())
            .expect("auth_session set-cookie")
    }

    async fn read_value(codec: &UiSessionCookie, value: &str) -> Option<UiSession> {
        codec
            .read(&headers(&format!("{UI_SESSION_COOKIE}={value}")))
            .await
    }

    #[actix_web::test]
    async fn sealed_session_round_trips() {
        let codec = test_ui_session_cookie();
        let set_cookie = codec.set_cookie(&alice()).expect("set_cookie");
        assert_eq!(
            read_value(&codec, value_of(&set_cookie)).await,
            Some(alice()),
            "the sealed session is read back unchanged"
        );
    }

    #[actix_web::test]
    async fn invalid_values_are_rejected() {
        let codec = test_ui_session_cookie();
        let other = UiSessionCookie::new(
            Zeroizing::new([0x24; 32]),
            false,
            Arc::new(MemoryRevocations::default()),
        );
        let set_cookie = codec.set_cookie(&alice()).expect("set_cookie");
        let value = value_of(&set_cookie);

        let mut flipped = value.to_owned();
        let last = flipped.pop().expect("non-empty value");
        flipped.push(if last == 'A' { 'B' } else { 'A' });

        let foreign = other.set_cookie(&alice()).expect("foreign cookie");
        for bad in [
            flipped.as_str(),
            value_of(&foreign),
            "garbage",
            "",
            &"A".repeat(5000),
        ] {
            assert_eq!(read_value(&codec, bad).await, None, "accepted {bad:.20}");
        }
    }

    /// A sealed session of `alice` issued by `codec` with explicit times.
    fn seal_at(codec: &UiSessionCookie, exp: i64, last: i64) -> String {
        codec
            .seal(&SealedSession {
                exp,
                sid: new_sid().expect("sid"),
                iat: last,
                last,
                session: alice(),
            })
            .expect("seal")
    }

    #[actix_web::test]
    async fn expiry_is_enforced_by_the_server() {
        let codec = test_ui_session_cookie();
        let now = now();
        let expired = seal_at(&codec, now - 1, now - 10);
        let live = seal_at(&codec, now + 60, now);
        assert_eq!(read_value(&codec, &expired).await, None);
        assert_eq!(read_value(&codec, &live).await, Some(alice()));
    }

    #[actix_web::test]
    async fn idle_sessions_are_rejected() {
        let codec = test_ui_session_cookie();
        let now = now();
        let idle = seal_at(&codec, now + 600, now - UI_SESSION_IDLE_SECS - 1);
        let active = seal_at(&codec, now + 600, now - UI_SESSION_IDLE_SECS + 60);
        assert_eq!(read_value(&codec, &idle).await, None);
        assert_eq!(read_value(&codec, &active).await, Some(alice()));
    }

    #[test]
    fn session_ids_are_random_hex() {
        let codec = test_ui_session_cookie();
        let sid_of = || {
            let set_cookie = codec.set_cookie(&alice()).expect("set_cookie");
            codec.unseal(value_of(&set_cookie)).expect("unseal").sid
        };
        let (a, b) = (sid_of(), sid_of());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
    }

    #[actix_web::test]
    async fn a_revoked_session_is_rejected_but_other_sessions_are_not() {
        let codec = test_ui_session_cookie();
        let revoked = codec.set_cookie(&alice()).expect("set_cookie");
        let other = codec.set_cookie(&alice()).expect("set_cookie");
        let revoked_headers = headers(&format!("auth_session={}", value_of(&revoked)));
        assert_eq!(codec.read(&revoked_headers).await, Some(alice()));

        codec.revoke(&revoked_headers).await;

        assert_eq!(
            codec.read(&revoked_headers).await,
            None,
            "revoked cookie replayed"
        );
        assert_eq!(codec.read_with_refresh(&revoked_headers).await, None);
        assert_eq!(read_value(&codec, value_of(&other)).await, Some(alice()));
    }

    #[actix_web::test]
    async fn a_logout_on_one_instance_revokes_the_session_on_every_instance() {
        let database = Arc::new(MemoryRevocations::default());
        let (node_a, node_b) = (
            test_ui_session_cookie_with(database.clone()),
            test_ui_session_cookie_with(database),
        );
        let set_cookie = node_a.set_cookie(&alice()).expect("set_cookie");
        let request = headers(&format!("auth_session={}", value_of(&set_cookie)));
        assert_eq!(node_b.read(&request).await, Some(alice()));

        node_a.revoke(&request).await;

        assert_eq!(node_b.read(&request).await, None, "replayed on node B");
    }

    #[actix_web::test]
    async fn revoking_a_session_without_a_user_records_nothing() {
        let revocations = Arc::new(MemoryRevocations::default());
        let codec = test_ui_session_cookie_with(revocations.clone());
        let pending = codec.set_cookie(&UiSession::default()).expect("set_cookie");
        codec
            .revoke(&headers(&format!("auth_session={}", value_of(&pending))))
            .await;
        assert!(revocations.0.lock().expect("lock").is_empty());
    }

    /// A revocation store that is down.
    struct UnavailableRevocations;

    #[async_trait(?Send)]
    impl SessionRevocations for UnavailableRevocations {
        async fn revoke(&self, _sid: &str, _expires_at: i64) -> KResult<()> {
            Err(KmsError::ServerError("database down".to_owned()))
        }

        async fn is_revoked(&self, _sid: &str) -> KResult<bool> {
            Err(KmsError::ServerError("database down".to_owned()))
        }
    }

    #[actix_web::test]
    async fn an_unavailable_revocation_store_refuses_logged_in_sessions_only() {
        let codec = test_ui_session_cookie_with(Arc::new(UnavailableRevocations));
        let logged_in = codec.set_cookie(&alice()).expect("set_cookie");
        let pending = codec.set_cookie(&UiSession::default()).expect("set_cookie");
        assert_eq!(read_value(&codec, value_of(&logged_in)).await, None);
        assert_eq!(
            read_value(&codec, value_of(&pending)).await,
            Some(UiSession::default()),
            "a login in progress needs no revocation lookup"
        );
    }

    #[actix_web::test]
    async fn refresh_keeps_the_session_identity_and_expiry() {
        let codec = test_ui_session_cookie();
        let now = now();
        let issued = SealedSession {
            exp: now + 600,
            sid: new_sid().expect("sid"),
            iat: now - 1000,
            last: now - UI_SESSION_REFRESH_SECS - 1,
            session: alice(),
        };
        let value = codec.seal(&issued).expect("seal");

        let (session, refreshed) = codec
            .read_with_refresh(&headers(&format!("auth_session={value}")))
            .await
            .expect("live session");
        assert_eq!(session, alice());
        let refreshed = refreshed.expect("an old session is refreshed");
        let reopened = codec.unseal(value_of(&refreshed)).expect("unseal");
        assert_eq!(
            (reopened.sid, reopened.iat, reopened.exp),
            (issued.sid, issued.iat, issued.exp)
        );
        assert!(reopened.last >= now, "last was not advanced");
        assert!(refreshed.contains("Max-Age="), "{refreshed}");

        let fresh = codec.set_cookie(&alice()).expect("set_cookie");
        let (_, not_refreshed) = codec
            .read_with_refresh(&headers(&format!("auth_session={}", value_of(&fresh))))
            .await
            .expect("live session");
        assert_eq!(not_refreshed, None, "a recent session is not re-issued");
    }

    #[test]
    fn each_cookie_uses_a_fresh_iv() {
        let codec = test_ui_session_cookie();
        let a = codec.set_cookie(&alice()).expect("set_cookie");
        let b = codec.set_cookie(&alice()).expect("set_cookie");
        assert_ne!(value_of(&a), value_of(&b));
    }

    #[test]
    fn a_cookie_the_reader_would_refuse_is_never_issued() {
        let huge = UiSession {
            user_id: Some(UserId::from("a".repeat(5000))),
            ..UiSession::default()
        };
        test_ui_session_cookie()
            .set_cookie(&huge)
            .expect_err("an oversized cookie must be refused");
    }

    #[test]
    fn cookie_attributes() {
        let secure = UiSessionCookie::new(
            Zeroizing::new([0x42; 32]),
            true,
            Arc::new(MemoryRevocations::default()),
        )
        .set_cookie(&alice())
        .expect("set_cookie");
        for attribute in [
            "; Secure",
            "; HttpOnly",
            "; SameSite=Lax",
            "; Path=/",
            "Max-Age=86400",
        ] {
            assert!(
                secure.contains(attribute),
                "missing {attribute} in {secure}"
            );
        }
        let plain = test_ui_session_cookie()
            .set_cookie(&alice())
            .expect("set_cookie");
        assert!(!plain.contains("Secure"));

        let removal = test_ui_session_cookie().removal_cookie();
        assert!(removal.starts_with("auth_session=;"), "{removal}");
        assert!(removal.contains("Max-Age=0"), "{removal}");
    }

    #[test]
    fn request_cookie_parsing() {
        assert_eq!(
            request_cookie(&headers("a=1; auth_session=x"), "auth_session"),
            Some("x")
        );
        assert_eq!(
            request_cookie(&headers("auth_session=\"x\""), "auth_session"),
            Some("x")
        );
        assert_eq!(
            request_cookie(&headers("xauth_session=1"), "auth_session"),
            None
        );

        let mut two = headers("a=1");
        two.append(header::COOKIE, HeaderValue::from_static("auth_session=x"));
        assert_eq!(request_cookie(&two, "auth_session"), Some("x"));
    }
}
