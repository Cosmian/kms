use std::{collections::HashMap, sync::RwLock};

use actix_rt::task;
use alcoholic_jwt::{JWK, JWKS};

use crate::{config::JwtAuthConfig, error::KmsError, result::KResult};

#[derive(Debug)]
pub struct JwksManager {
    uris: Vec<String>,
    jwks: RwLock<HashMap<String, JWKS>>,
}

impl JwksManager {
    pub async fn new(uris: Vec<String>) -> KResult<Self> {
        tracing::info!("Init JWKS");

        let uris_spawn = uris.clone();
        let jwks = task::spawn_blocking(move || Self::fetch_all(&uris_spawn))
            .await
            .map_err(|e| KmsError::Unauthorized(format!("cannot request JWKS: {e}")))?;

        Ok(Self {
            uris,
            jwks: RwLock::new(jwks),
        })
    }

    /// Lock `jwks` to replace it
    fn set_jwks(&self, new_jwks: HashMap<String, JWKS>) {
        let mut jwks = self.jwks.write().expect("cannot lock JWKS for write");
        *jwks = new_jwks;
    }

    /// Find the key identifier `kid` in each registered JWKS
    pub fn find(&self, kid: &str) -> Option<JWK> {
        self.jwks
            .read()
            .expect("cannot lock JWKS for read")
            .iter()
            .find_map(|(_, jwks)| jwks.find(kid))
            .cloned()
    }

    /// Fetch again all JWKS using the `uris`.
    ///
    /// TODO: add a timer to avoid flooding attack,
    /// or refresh automatically in a separate thread
    /// the JWKS every 1 minute?
    pub async fn refresh(&self) -> KResult<()> {
        tracing::info!("Refreshing JWKS");

        let uris = self.uris.to_vec();
        let refreshed_jwks = task::spawn_blocking(move || Self::fetch_all(&uris))
            .await
            .map_err(|e| KmsError::Unauthorized(format!("cannot request JWKS: {e}")))?;
        self.set_jwks(refreshed_jwks);
        Ok(())
    }

    /// Refresh the JWK set by making an external HTTP call to the `jwks_uri`.
    ///
    /// This function is blocking until the request for the JWKS returns.
    fn fetch_all(uris: &[String]) -> HashMap<String, JWKS> {
        uris.iter()
            .flat_map(|jwks_uri| match JwtAuthConfig::request_jwks(jwks_uri) {
                Err(e) => {
                    tracing::error!("cannot fetch JWKS for `{jwks_uri}`: {e}");
                    None
                }
                Ok(jwks) => Some((jwks_uri.clone(), jwks)),
            })
            .collect::<HashMap<_, _>>()
    }
}
