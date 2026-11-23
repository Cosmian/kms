//! Encrypted, stateless Web UI session cookie (`auth_session`).
//!
//! The whole session ([`UiSession`]) lives in the cookie: AES-256-GCM sealed under a server
//! key, with the cookie name as AAD and a server-enforced expiry inside the sealed payload.
//! The browser can neither read nor forge it, and nothing is stored on the server.
//!
//! The IV is generated inside the `OpenSSL` provider DRBG (mandatory in FIPS mode, and
//! fork-safe), never by this module.

use actix_web::http::header::{self, HeaderMap};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::symmetric::symmetric_ciphers::{
    SymCipher, aes_gcm_encrypt_generated_iv, decrypt,
};
use cosmian_logger::debug;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{middlewares::UserId, result::KResult};

/// Name of the KMS session cookie; also the AES-GCM AAD, binding a sealed value to this cookie.
const UI_SESSION_COOKIE: &str = "auth_session";

/// Lifetime of a session, enforced by the server (sealed `exp`) and advertised as `Max-Age`.
const UI_SESSION_TTL_SECS: i64 = 24 * 60 * 60;

/// Largest cookie value parsed: a browser caps a cookie near 4 KiB, a longer one is hostile.
const MAX_COOKIE_VALUE_LEN: usize = 4096;

/// AES-GCM IV length in bytes (96 bits, NIST SP 800-38D).
const GCM_IV_LEN: usize = 12;

/// AES-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// State kept in the session cookie.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// The sealed payload: the session and its expiry (Unix seconds).
#[derive(Serialize, Deserialize)]
struct SealedSession {
    exp: i64,
    #[serde(flatten)]
    session: UiSession,
}

/// Seals and opens the session cookie. Registered once as actix `app_data`.
pub(crate) struct UiSessionCookie {
    key: Zeroizing<[u8; 32]>,
    secure: bool,
}

impl UiSessionCookie {
    /// `secure` adds the `Secure` attribute (public URL is `https://` or TLS is configured).
    pub(crate) const fn new(key: Zeroizing<[u8; 32]>, secure: bool) -> Self {
        Self { key, secure }
    }

    /// `Set-Cookie` value carrying `session`, valid for 24 hours.
    pub(crate) fn set_cookie(&self, session: &UiSession) -> KResult<String> {
        let exp = time::OffsetDateTime::now_utc().unix_timestamp() + UI_SESSION_TTL_SECS;
        let value = self.seal(session, exp)?;
        Ok(format!(
            "{UI_SESSION_COOKIE}={value}; Max-Age={UI_SESSION_TTL_SECS}{}",
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
    /// sealed under another key or expired.
    pub(crate) fn read(&self, headers: &HeaderMap) -> Option<UiSession> {
        let value = request_cookie(headers, UI_SESSION_COOKIE)?;
        match self.open(value) {
            Ok(session) => Some(session),
            Err(reason) => {
                debug!("UI session cookie rejected: {reason}");
                None
            }
        }
    }

    /// Cookie value: `base64url(iv || ciphertext || tag)` of the sealed session.
    fn seal(&self, session: &UiSession, exp: i64) -> KResult<String> {
        let json = Zeroizing::new(serde_json::to_vec(&SealedSession {
            exp,
            session: session.clone(),
        })?);
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
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Inverse of [`Self::seal`]; the error is a static reason, never the cookie content.
    fn open(&self, value: &str) -> Result<UiSession, &'static str> {
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
        let sealed: SealedSession = serde_json::from_slice(&json).map_err(|_e| "invalid JSON")?;
        if sealed.exp <= time::OffsetDateTime::now_utc().unix_timestamp() {
            return Err("expired");
        }
        Ok(sealed.session)
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

/// Codec with a fixed key and no `Secure` attribute, for tests.
#[cfg(test)]
pub(crate) fn test_ui_session_cookie() -> UiSessionCookie {
    UiSessionCookie::new(Zeroizing::new([0x42; 32]), false)
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

    fn read_value(codec: &UiSessionCookie, value: &str) -> Option<UiSession> {
        codec.read(&headers(&format!("{UI_SESSION_COOKIE}={value}")))
    }

    #[test]
    fn sealed_session_round_trips() {
        let codec = test_ui_session_cookie();
        let set_cookie = codec.set_cookie(&alice()).expect("set_cookie");
        assert_eq!(
            read_value(&codec, value_of(&set_cookie)),
            Some(alice()),
            "the sealed session is read back unchanged"
        );
    }

    #[test]
    fn invalid_values_are_rejected() {
        let codec = test_ui_session_cookie();
        let other = UiSessionCookie::new(Zeroizing::new([0x24; 32]), false);
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
            assert_eq!(read_value(&codec, bad), None, "accepted {bad:.20}");
        }
    }

    #[test]
    fn expiry_is_enforced_by_the_server() {
        let codec = test_ui_session_cookie();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let expired = codec.seal(&alice(), now - 1).expect("seal");
        let live = codec.seal(&alice(), now + 60).expect("seal");
        assert_eq!(read_value(&codec, &expired), None);
        assert_eq!(read_value(&codec, &live), Some(alice()));
    }

    #[test]
    fn each_cookie_uses_a_fresh_iv() {
        let codec = test_ui_session_cookie();
        let a = codec.set_cookie(&alice()).expect("set_cookie");
        let b = codec.set_cookie(&alice()).expect("set_cookie");
        assert_ne!(value_of(&a), value_of(&b));
    }

    #[test]
    fn cookie_attributes() {
        let secure = UiSessionCookie::new(Zeroizing::new([0x42; 32]), true)
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
