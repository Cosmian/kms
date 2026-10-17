//! JWT Configuration Module
//!
//! This module contains configuration structures and validation logic for JWT (JSON Web Token)
//! authentication. It defines the claims and headers structures, and provides utilities for
//! processing and validating JWT tokens.

use std::{fmt, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cosmian_logger::trace;
#[cfg(not(feature = "insecure"))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(not(feature = "insecure"))]
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, SeqAccess, Visitor},
};

use super::JwksManager;
use crate::{error::KmsError, kms_ensure, result::KResult};

/// Asymmetric JWT algorithms that the KMS server accepts.
///
/// HS* algorithms are explicitly excluded: when an attacker obtains the RSA
/// public key from the JWKS endpoint they could forge HS256 tokens by using
/// the public key as the HMAC secret (algorithm-confusion attack).
/// Only RS*, ES*, and PS* families are accepted.
#[cfg(not(feature = "insecure"))]
pub(crate) const ALLOWED_JWT_ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// Verify that `alg` is an accepted asymmetric algorithm.
///
/// Returns `Err(KmsError::Unauthorized)` for `HS*`, `none`, or any other
/// symmetric / unknown algorithm to prevent algorithm-confusion attacks.
#[cfg(not(feature = "insecure"))]
fn check_jwt_algorithm(alg: Algorithm) -> KResult<()> {
    if ALLOWED_JWT_ALGORITHMS.contains(&alg) {
        Ok(())
    } else {
        Err(KmsError::Unauthorized(format!(
            "JWT algorithm {alg:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted"
        )))
    }
}

fn deserialize_aud<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AudVisitor;

    impl<'de> Visitor<'de> for AudVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or an array of strings for 'aud'")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(vec![v.to_owned()]))
        }

        fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let values: Vec<String> =
                Deserialize::deserialize(de::value::SeqAccessDeserializer::new(seq))?;
            Ok(Some(values))
        }
    }

    deserializer.deserialize_any(AudVisitor)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct UserClaim {
    pub email: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    #[serde(deserialize_with = "deserialize_aud")]
    pub aud: Option<Vec<String>>,
    pub iat: Option<usize>,
    pub exp: Option<usize>,
    pub nbf: Option<usize>,
    pub jti: Option<String>,
    // Google CSE
    pub role: Option<String>,
    // Google CSE
    pub resource_name: Option<String>,
    // Google CSE
    pub perimeter_id: Option<String>,
    // Google CSE
    pub kacls_url: Option<String>,
    // Google CSE
    pub spki_hash: Option<String>,
    // Google CSE
    pub spki_hash_algorithm: Option<String>,
    // Google CSE
    pub message_id: Option<String>,
    // Google CSE
    pub email_type: Option<String>,
    // Google CSE
    pub google_email: Option<String>,
}

/// Registered JOSE header parameters (RFC 7515 §4.1) of a JWT.
///
/// Parsed from the raw first segment of the compact token so that parameters
/// unknown to the `jsonwebtoken` crate (notably `crit`) are visible to the
/// server and can be enforced by [`JwtTokenHeaders::validate`].
#[derive(Debug, Deserialize)]
pub(crate) struct JwtTokenHeaders {
    typ: Option<String>,
    cty: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    x5t: Option<String>,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
    crit: Option<Vec<String>>,
}

impl JwtTokenHeaders {
    /// Parse the JOSE header of a compact-serialized JWT.
    pub(crate) fn from_token(token: &str) -> KResult<Self> {
        let segment = token
            .split('.')
            .next()
            .filter(|segment| !segment.is_empty())
            .ok_or_else(|| KmsError::Unauthorized("JWT headers are missing".to_owned()))?;
        let raw = URL_SAFE_NO_PAD
            .decode(segment)
            .map_err(|err| KmsError::Unauthorized(format!("JWT headers are malformed: {err:?}")))?;
        serde_json::from_slice(&raw)
            .map_err(|err| KmsError::Unauthorized(format!("JWT headers are malformed: {err:?}")))
    }

    /// Reject JOSE header extensions this server does not implement, whatever the
    /// authenticator:
    /// - `crit` must be absent: RFC 7515 §4.1.11 requires rejecting tokens that
    ///   carry critical extensions the recipient does not understand, and none is
    ///   implemented (`jsonwebtoken` parses `crit` but never enforces it);
    /// - `cty` must not announce a nested JWT (RFC 7519 §5.2), which is not supported.
    pub(crate) fn reject_unsupported_extensions(&self) -> KResult<()> {
        if let Some(crit) = &self.crit {
            return Err(KmsError::Unauthorized(format!(
                "Unsupported critical JWT header parameters: {crit:?}"
            )));
        }
        if self
            .cty
            .as_deref()
            .is_some_and(|cty| cty.eq_ignore_ascii_case("JWT"))
        {
            return Err(KmsError::Unauthorized(
                "Nested JWTs (cty=JWT) are not supported".to_owned(),
            ));
        }
        Ok(())
    }

    /// Enforce the header rules of the JWKS-keyed authenticators:
    /// - `alg` and `kid` must be present and non-blank (the key is always selected
    ///   from the configured JWKS, never from the token);
    /// - unsupported extensions are rejected, see
    ///   [`JwtTokenHeaders::reject_unsupported_extensions`].
    ///
    /// Embedded key material (`x5u`, `x5c`, `x5t`) is never trusted; its presence is
    /// only logged.
    pub(crate) fn validate(&self) -> KResult<()> {
        kms_ensure!(
            self.alg
                .as_deref()
                .is_some_and(|alg| !alg.trim().is_empty()),
            KmsError::Unauthorized("No 'alg' header present in token".to_owned())
        );
        kms_ensure!(
            self.kid
                .as_deref()
                .is_some_and(|kid| !kid.trim().is_empty()),
            KmsError::Unauthorized("No 'kid' header present in token".to_owned())
        );
        self.reject_unsupported_extensions()?;
        if self.x5u.is_some() || self.x5c.is_some() || self.x5t.is_some() {
            trace!(
                "ignoring embedded key material in JWT headers (x5u: {:?}, x5c: {} cert(s), \
                 x5t: {:?}); the key is taken from the configured JWKS",
                self.x5u,
                self.x5c.as_ref().map_or(0, Vec::len),
                self.x5t
            );
        }
        trace!(
            "valid_jwt headers: typ={:?} alg={:?} kid={:?}",
            self.typ, self.alg, self.kid
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct JwtConfig {
    pub jwt_issuer_uri: String,
    pub jwt_audience: Option<Vec<String>>,
    pub jwks: Arc<JwksManager>,
    /// When `true`, a token from this issuer that has no `email` claim is authenticated
    /// using its `sub` claim, provided `sub` starts with `spiffe://` (SPIFFE JWT-SVID).
    /// Defaults to `false` so existing OIDC/IdP issuers keep requiring `email`. Only set
    /// from the operator-controlled `--jwt-svid-auth` flag; Google CSE issuers never set it.
    pub accept_spiffe_subject: bool,
}

impl JwtConfig {
    /// Decode a JWT bearer header
    pub(crate) fn decode_bearer_header(&self, authorization_content: &str) -> KResult<UserClaim> {
        let (scheme, token) = authorization_content.split_once(' ').ok_or_else(|| {
            KmsError::Unauthorized("Bad authorization header content (missing bearer)".to_owned())
        })?;
        kms_ensure!(
            scheme.eq_ignore_ascii_case("Bearer"),
            KmsError::Unauthorized("Bad authorization header content (bad bearer)".to_owned())
        );

        self.validate_authentication_token(token, true)
    }

    /// Decode and validate a json web token (JWT)
    pub(crate) fn validate_authentication_token(
        &self,
        token: &str,
        validate_subject: bool,
    ) -> KResult<UserClaim> {
        kms_ensure!(
            !token.is_empty(),
            KmsError::Unauthorized("token is empty".to_owned())
        );
        trace!(
            "validating authentication token, expected JWT issuer: {}",
            self.jwt_issuer_uri
        );

        // In test/insecure mode, skip all JWT validation (signature, expiry, issuer, audience).
        // This allows tests to supply arbitrary tokens without a live JWKS endpoint.
        #[cfg(any(test, feature = "insecure"))]
        {
            let _ = validate_subject; // unused when validation is disabled
            let token_data = dangerous::insecure_decode::<UserClaim>(token)
                .map_err(|e| KmsError::Unauthorized(format!("Cannot validate token: {e}")))?;
            Ok(token_data.claims)
        }

        // In production, fully validate: issuer, expiry, audience, and signature via JWKS.
        #[cfg(all(not(test), not(feature = "insecure")))]
        {
            self.validate_signed_token(token, validate_subject)
        }
    }

    /// Fully validate a JWT: algorithm allow-list, `kid` lookup in the JWKS, signature,
    /// issuer, expiry and (when configured) audience.
    ///
    /// This is the production validation path. It is compiled in every build except
    /// `insecure` so that unit tests can exercise it directly even though
    /// [`Self::validate_authentication_token`] short-circuits to an unverified decode
    /// under `cfg(test)`.
    #[cfg(not(feature = "insecure"))]
    pub(crate) fn validate_signed_token(
        &self,
        token: &str,
        validate_subject: bool,
    ) -> KResult<UserClaim> {
        let header = decode_header(token)
            .map_err(|e| KmsError::Unauthorized(format!("Failed to decode token header: {e}")))?;

        // RFC 7515 §4.1.11: `jsonwebtoken` ignores `crit`, so enforce it here.
        JwtTokenHeaders::from_token(token)?.reject_unsupported_extensions()?;

        // Reject symmetric / unknown algorithms before touching the JWKS key material.
        check_jwt_algorithm(header.alg)?;

        let mut validation = Validation::new(header.alg);
        // Explicitly pin the allowed algorithms to the single pre-validated algorithm.
        // This prevents jsonwebtoken from accepting any algorithm not in the allowlist.
        validation.algorithms = vec![header.alg];
        validation.set_issuer(&[&self.jwt_issuer_uri]);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        if validate_subject {
            // Require both subject and expiration in production
            validation.set_required_spec_claims(&["sub", "exp"]);
        } else {
            // At minimum, always require expiration
            validation.set_required_spec_claims(&["exp"]);
        }
        if let Some(jwt_audience) = &self.jwt_audience {
            validation.set_audience(jwt_audience.as_slice());
        } else {
            // jsonwebtoken 10.x rejects tokens that carry an `aud` claim when no
            // expected audience is configured in the Validation struct (InvalidAudience).
            // When the server does not restrict by audience, skip audience validation.
            validation.validate_aud = false;
        }

        // OIDC/IdP tokens are required to carry a `kid` so we can look up the exact
        // signing key in the JWKS.  Auth-verifier tokens intentionally omit `kid`
        // (they are validated by the dedicated `AuthVerifier` middleware which tries
        // every key in the JWKS).  Return `Unauthorized` here so the middleware chain
        // falls through to the next authenticator rather than logging a noisy error.
        let Some(kid) = header.kid else {
            return Err(KmsError::Unauthorized(
                "No 'kid' claim present in token — not an OIDC token".to_owned(),
            ));
        };

        let jwk = self.jwks.find(&kid)?.ok_or_else(|| {
            KmsError::Unauthorized(format!(
                "Specified key not found in set. Looking for kid `{kid}`"
            ))
        })?;

        trace!("JWK has been found:\n{jwk:?}");

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            KmsError::Unauthorized(format!("Failed to build decoding key from JWK: {e}"))
        })?;

        let token_data = decode::<UserClaim>(token, &decoding_key, &validation)
            .map_err(|e| KmsError::Unauthorized(format!("Cannot validate token: {e}")))?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod jwt_headers_tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::JwtTokenHeaders;
    fn token_with_header(header: &str) -> String {
        format!("{}.e30.c2ln", URL_SAFE_NO_PAD.encode(header))
    }

    fn rejection(header: &str) -> String {
        let headers = JwtTokenHeaders::from_token(&token_with_header(header)).unwrap();
        headers
            .validate()
            .err()
            .map_or_else(String::new, |error| error.to_string())
    }

    /// A regular Google-style header validates.
    #[test]
    fn valid_header_is_accepted() {
        let headers = JwtTokenHeaders::from_token(&token_with_header(
            r#"{"alg":"RS256","typ":"JWT","kid":"k1"}"#,
        ))
        .unwrap();
        headers.validate().unwrap();
    }

    /// `alg` and `kid` are mandatory and must not be blank.
    #[test]
    fn missing_or_blank_alg_and_kid_are_rejected() {
        assert!(rejection(r#"{"kid":"k1"}"#).contains("'alg'"));
        assert!(rejection(r#"{"alg":"RS256"}"#).contains("'kid'"));
        assert!(rejection(r#"{"alg":"RS256","kid":"  "}"#).contains("'kid'"));
        assert!(rejection(r#"{"alg":"","kid":"k1"}"#).contains("'alg'"));
    }

    /// Any `crit` parameter is rejected (RFC 7515 §4.1.11): no extension is understood.
    #[test]
    fn crit_is_rejected() {
        let message = rejection(r#"{"alg":"RS256","kid":"k1","crit":["b64"],"b64":false}"#);
        assert!(message.contains("critical"), "{message}");
    }

    /// The extension check shared by every authenticator must not require `kid`
    /// (auth-verifier tokens carry none) but must still reject `crit` and nested JWTs.
    #[test]
    fn extension_check_is_independent_of_kid() {
        let check = |header: &str| {
            JwtTokenHeaders::from_token(&token_with_header(header))
                .unwrap()
                .reject_unsupported_extensions()
                .err()
                .map_or_else(String::new, |error| error.to_string())
        };
        assert!(check(r#"{"alg":"RS256"}"#).is_empty());
        assert!(check(r#"{"alg":"RS256","crit":["exp"]}"#).contains("critical"));
        assert!(check(r#"{"alg":"RS256","cty":"JWT"}"#).contains("Nested"));
    }

    /// Nested JWTs are not supported, whatever the case of `cty`.
    #[test]
    fn nested_jwt_is_rejected() {
        assert!(rejection(r#"{"alg":"RS256","kid":"k1","cty":"jwt"}"#).contains("Nested"));
        // other content types are not nested JWTs
        assert!(rejection(r#"{"alg":"RS256","kid":"k1","cty":"application/json"}"#).is_empty());
    }

    /// Embedded key material and unknown parameters do not affect validation.
    #[test]
    fn embedded_key_material_is_tolerated() {
        let message = rejection(
            r#"{"alg":"ES256","kid":"k1","x5u":"https://e.example/c.pem","x5c":["QUJD"],"x5t":"t","unknown":1}"#,
        );
        assert!(message.is_empty(), "{message}");
    }

    /// Structurally invalid tokens never produce headers.
    #[test]
    fn malformed_tokens_are_rejected() {
        for token in ["", ".e30.c2ln", "!!!.e30.c2ln", "bm90LWpzb24.e30.c2ln"] {
            let result = JwtTokenHeaders::from_token(token);
            assert!(result.is_err(), "{token:?} must be rejected");
        }
    }
}

#[cfg(test)]
#[cfg(not(feature = "insecure"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states
)]
mod tests {
    use jsonwebtoken::Algorithm;

    use super::ALLOWED_JWT_ALGORITHMS;
    use crate::error::KmsError;

    fn check_alg(alg: Algorithm) -> crate::result::KResult<()> {
        if ALLOWED_JWT_ALGORITHMS.contains(&alg) {
            Ok(())
        } else {
            Err(KmsError::Unauthorized(format!(
                "JWT algorithm {alg:?} is not permitted; only asymmetric algorithms (RS*, ES*, PS*) are accepted"
            )))
        }
    }

    /// A1–A3: Symmetric HS* algorithms must all be rejected (algorithm-confusion attack vector).
    #[test]
    fn a01_hs256_is_rejected() {
        assert!(
            !ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::HS256),
            "HS256 must not be in the allowlist (algorithm-confusion risk)"
        );
        assert!(check_alg(Algorithm::HS256).is_err());
    }

    #[test]
    fn a02_hs384_is_rejected() {
        assert!(!ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::HS384));
        assert!(check_alg(Algorithm::HS384).is_err());
    }

    #[test]
    fn a03_hs512_is_rejected() {
        assert!(!ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::HS512));
        assert!(check_alg(Algorithm::HS512).is_err());
    }

    /// A4–A6: Representative asymmetric algorithms must be accepted.
    #[test]
    fn a04_rs256_is_accepted() {
        assert!(
            ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::RS256),
            "RS256 must be in the allowlist"
        );
        assert!(check_alg(Algorithm::RS256).is_ok());
    }

    #[test]
    fn a05_es256_is_accepted() {
        assert!(ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::ES256));
        assert!(check_alg(Algorithm::ES256).is_ok());
    }

    #[test]
    fn a06_ps256_is_accepted() {
        assert!(ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::PS256));
        assert!(check_alg(Algorithm::PS256).is_ok());
    }

    /// Full coverage: every algorithm in the allowlist must be accepted.
    #[test]
    fn all_allowlisted_algorithms_are_accepted() {
        for &alg in ALLOWED_JWT_ALGORITHMS {
            assert!(
                check_alg(alg).is_ok(),
                "Expected {alg:?} to be accepted but it was rejected"
            );
        }
    }

    /// Error message quality: rejection must mention "not permitted".
    #[test]
    #[allow(clippy::unwrap_used)]
    fn rejection_error_message_quality() {
        let result = check_alg(Algorithm::HS256);
        assert!(result.is_err());
        let msg = result.expect_err("HS256 must be rejected").to_string();
        assert!(
            msg.contains("not permitted"),
            "error message should mention 'not permitted', got: {msg}"
        );
    }
}
