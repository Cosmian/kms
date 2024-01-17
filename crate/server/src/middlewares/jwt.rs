use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use actix_rt::task;
use alcoholic_jwt::{token_kid, JWKS};
use serde::{Deserialize, Serialize};

use super::JwksManager;
use crate::{config::JwtAuthConfig, error::KmsError, kms_ensure, result::KResult};

#[derive(Debug, Deserialize, Serialize)]
pub struct UserClaim {
    pub email: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
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
}

#[derive(Debug, Deserialize)]
pub struct JwtTokenHeaders {
    pub typ: Option<String>,
    pub cty: Option<String>,
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub x5t: Option<String>,
    pub x5u: Option<String>,
    pub x5c: Option<Vec<String>>,
    pub crit: Option<String>,
}

#[derive(Debug)]
pub struct JwtConfig {
    pub jwt_issuer_uri: String,
    pub jwt_audience: Option<String>,
    pub jwks: Arc<JwksManager>,
}

impl JwtConfig {
    /// Decode a JWT bearer header
    pub fn decode_bearer_header(&self, authorization_content: &str) -> KResult<UserClaim> {
        let bearer: Vec<&str> = authorization_content.splitn(2, ' ').collect();
        kms_ensure!(
            bearer.len() == 2 && bearer[0] == "Bearer",
            KmsError::Unauthorized("Bad authorization header content (bad bearer)".to_owned())
        );

        let token: &str = bearer[1];
        self.decode_authentication_token(token)
    }

    /// Decode a json web token (JWT)
    pub fn decode_authentication_token(&self, token: &str) -> KResult<UserClaim> {
        kms_ensure!(
            !token.is_empty(),
            KmsError::Unauthorized("token is empty".to_owned())
        );
        tracing::trace!(
            "validating authentication token, expected JWT issuer: {}",
            self.jwt_issuer_uri.to_string()
        );

        let mut validations = vec![
            #[cfg(not(test))]
            alcoholic_jwt::Validation::Issuer(self.jwt_issuer_uri.to_string()),
            alcoholic_jwt::Validation::SubjectPresent,
            #[cfg(not(feature = "insecure"))]
            alcoholic_jwt::Validation::NotExpired,
        ];
        if let Some(jwt_audience) = &self.jwt_audience {
            validations.push(alcoholic_jwt::Validation::Audience(
                jwt_audience.to_string(),
            ));
        }

        // If a JWKS contains multiple keys, the correct KID first
        // needs to be fetched from the token headers.
        let kid = token_kid(token)
            .map_err(|e| KmsError::Unauthorized(format!("Failed to decode kid: {e}")))?
            .ok_or_else(|| KmsError::Unauthorized("No 'kid' claim present in token".to_string()))?;

        // tracing::trace!("JWKS:\n{:?}", self.jwks);

        // let jwk = {
        //     let jwk = self
        //         .jwks
        //         .read()
        //         .expect("cannot lock jwks for read")
        //         .find(&kid)
        //         .cloned();
        //     match jwk {
        //         Some(jwk) => jwk,
        //         None => {
        //             tracing::trace!("refreshing jwks");
        //             let jwks_uri = get_jwks_uri(application);

        //             // refresh JWKS
        //             self.refresh_jwk_set(&jwks_uri)
        //                 .await
        //                 .context(&format!("Failed to fetch JWKS at: {jwks_uri}"))?;

        //             // retry auth
        //             let jwks = self.jwks.read().expect("cannot lock jwks for read");
        //             tracing::trace!("find '{kid:?}' in new jwks:\n{jwks:#?}");
        //             jwks.find(&kid).cloned().ok_or_else(|| {
        //                 KmsError::Unauthorized("Specified key not found in set".to_string())
        //             })?
        //         }
        //     }
        // };

        // tracing::trace!("JWK has been found:\n{jwk:?}");

        let valid_jwt = {
            // let jwks = self.jwks.read().expect("cannot lock jwks for read");
            let jwk = self
                .jwks
                .find(&kid)
                .or_else(|| {
                    self.jwks.refresh();
                    self.jwks.find(&kid)
                })
                .ok_or_else(|| {
                    KmsError::Unauthorized("Specified key not found in set".to_string())
                })?;

            alcoholic_jwt::validate(token, &jwk, validations)
                .map_err(|err| KmsError::Unauthorized(format!("Cannot validate token: {err:?}")))?
        };

        let payload = serde_json::from_value(valid_jwt.claims)
            .map_err(|err| KmsError::Unauthorized(format!("JWT claims is malformed: {err:?}")))?;

        Ok(payload)
    }

    // /// Refresh the JWK set by making an external HTTP call to the `jwks_uri`.
    // ///
    // /// This function is blocking until the request for the JWKS returns.
    // pub async fn refresh_jwk_set(&self, jwks_uri: &str) -> KResult<()> {
    //     let jwks_uri = jwks_uri.to_owned();

    //     let new_jwks = task::spawn_blocking(move || JwtAuthConfig::request_jwks(&jwks_uri))
    //         .await
    //         .map_err(|e| KmsError::Unauthorized(format!("cannot request JWKS: {e}")))??;

    //     {
    //         let mut jwks = self.jwks.write().expect("cannot lock jwks for write");
    //         *jwks = new_jwks;
    //     }
    //     Ok(())
    // }
}
