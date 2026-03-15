//! JWT Configuration Module
//!
//! This module contains configuration structures and validation logic for JWT (JSON Web Token)
//! authentication. It defines the claims and headers structures, and provides utilities for
//! processing and validating JWT tokens.

use std::{fmt, sync::Arc};

use cosmian_logger::trace;
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

            let mut validation = Validation::new(header.alg);
            validation.set_issuer(&[&self.jwt_issuer_uri]);
            validation.validate_exp = true;
            validation.required_spec_claims.clear();
            if validate_subject {
                validation.set_required_spec_claims(&["sub"]);
            }
            if let Some(jwt_audience) = &self.jwt_audience {
                validation.set_audience(jwt_audience.as_slice());
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
