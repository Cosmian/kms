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
    /// TODO: add a timer to avoid flooding attack
    pub fn refresh(&self) {
        tracing::info!("Refreshing JWKS");

        let refreshed_jwks = Self::fetch_all(&self.uris);

        {
            let mut jwks = self.jwks.write().expect("cannot lock JWKS for write");
            *jwks = refreshed_jwks;
        }

        // {
        //     let mut jwks = self.jwks.write().expect("cannot lock JWKS for write");
        //     (*jwks)[] = new_jwks;
        // }

        // jwks_uris.iter().for_each(|jwks_uri| {
        //     match JwtAuthConfig::request_jwks(&jwks_uri) {
        //         Ok(jwks) =>,
        //         Err(e) => warn!("unable to refresh JWKS URI: {jwks_uri}")
        //     }
        // });
    }

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
