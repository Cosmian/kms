use std::{collections::HashMap, sync::RwLock};

use alcoholic_jwt::{JWK, JWKS};

use crate::config::JwtAuthConfig;

#[derive(Debug)]
pub struct JwksManager {
    uris: Vec<String>,
    jwks: RwLock<HashMap<String, JWKS>>,
}

impl JwksManager {
    pub fn new(uris: Vec<String>) -> Self {
        let jwks = Self::fetch_all(&uris);

        Self {
            uris,
            jwks: RwLock::new(jwks),
        }
    }

    /// Find the key identifier `kid` in
    /// each registered JWKS.
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
    pub fn refresh(&self) {
        tracing::info!("Refreshing JWKS");

        let refreshed_jwks = Self::fetch_all(&self.uris);

        {
            let mut jwks = self.jwks.write().expect("cannot lock JWKS for write");
            *jwks = refreshed_jwks;
        }
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
