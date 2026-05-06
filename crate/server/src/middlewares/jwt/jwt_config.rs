//! JWT Configuration Module
//!
//! This module contains configuration structures and validation logic for JWT (JSON Web Token)
//! authentication. It defines the claims and headers structures, and provides utilities for
//! processing and validating JWT tokens.

use std::{fmt, sync::Arc};

use cosmian_logger::trace;
#[cfg(not(feature = "insecure"))]
use jsonwebtoken::Algorithm;
#[cfg(any(test, feature = "insecure"))]
use jsonwebtoken::dangerous;
#[cfg(all(not(test), not(feature = "insecure")))]
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
#[cfg(all(not(test), not(feature = "insecure")))]
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

#[derive(Debug, Deserialize)]
#[expect(dead_code)]
pub(crate) struct JwtTokenHeaders {
    typ: Option<String>,
    cty: Option<String>,
    alg: Option<String>,
    kid: Option<String>,
    x5t: Option<String>,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
    crit: Option<String>,
}

#[derive(Debug)]
pub struct JwtConfig {
    pub jwt_issuer_uri: String,
    pub jwt_audience: Option<Vec<String>>,
    pub jwks: Arc<JwksManager>,
}

impl JwtConfig {
    /// Decode a JWT bearer header
    pub(crate) fn decode_bearer_header(&self, authorization_content: &str) -> KResult<UserClaim> {
        let bearer: Vec<&str> = authorization_content.splitn(2, ' ').collect();
        kms_ensure!(
            bearer.first().ok_or_else(|| KmsError::Unauthorized(
                "Bad authorization header content (missing bearer)".to_owned()
            ))? == &"Bearer"
                && bearer.get(1).is_some(),
            KmsError::Unauthorized("Bad authorization header content (bad bearer)".to_owned())
        );

        let token: &str = bearer.get(1).ok_or_else(|| {
            KmsError::Unauthorized("Bad authorization header content (missing token)".to_owned())
        })?;
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
            let header = decode_header(token).map_err(|e| {
                KmsError::Unauthorized(format!("Failed to decode token header: {e}"))
            })?;

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

            let kid = header.kid.ok_or_else(|| {
                KmsError::Unauthorized("No 'kid' claim present in token".to_owned())
            })?;

            let jwk = self.jwks.find(&kid)?.ok_or_else(|| {
                // Only log JWKS on error
                KmsError::Unauthorized(format!(
                    "Specified key not found in set. Looking for kid `{kid}` in JWKS:\n{:?}",
                    self.jwks
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
}

#[cfg(test)]
#[cfg(not(feature = "insecure"))]
#[expect(clippy::unwrap_used)]
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
        check_alg(Algorithm::RS256).unwrap()
    }

    #[test]
    fn a05_es256_is_accepted() {
        assert!(ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::ES256));
        check_alg(Algorithm::ES256).unwrap()
    }

    #[test]
    fn a06_ps256_is_accepted() {
        assert!(ALLOWED_JWT_ALGORITHMS.contains(&Algorithm::PS256));
        check_alg(Algorithm::PS256).unwrap()
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
    fn rejection_error_message_quality() {
        let result = check_alg(Algorithm::HS256);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not permitted"),
            "error message should mention 'not permitted', got: {msg}"
        );
    }
}
