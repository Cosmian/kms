use std::{collections::HashMap, sync::RwLock};

use alcoholic_jwt::{JWK, JWKS};
use futures::StreamExt;

use crate::result::KResult;

#[derive(Debug)]
pub struct JwksManager {
    uris: Vec<String>,
    jwks: RwLock<HashMap<String, JWKS>>,
}

impl JwksManager {
    pub async fn new(uris: Vec<String>) -> KResult<Self> {
        let jwks_manager = Self {
            uris,
            jwks: HashMap::new().into(),
        };
        jwks_manager.refresh().await?;

        Ok(jwks_manager)
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

        let refreshed_jwks = Self::fetch_all(&self.uris).await;
        self.set_jwks(refreshed_jwks);
        Ok(())
    }

    /// Refresh the JWK Set by making an external HTTP call to all the `uris`.
    ///
    /// The JWK Sets are fetched in parallel and warns about failures
    /// without stopping the whole fetch process.
    async fn fetch_all(uris: &[String]) -> HashMap<String, JWKS> {
        let client = reqwest::Client::new();

        futures::stream::iter(uris)
            .map(|jwks_uri| {
                let client = &client;
                let jwks_uri = jwks_uri.clone();
                async move {
                    tracing::info!("Fetching {jwks_uri}...");
                    match client.get(jwks_uri.clone()).send().await {
                        Ok(resp) => match resp.json::<JWKS>().await {
                            Ok(jwks) => {
                                tracing::info!("Done {jwks_uri}...");
                                Some((jwks_uri, jwks))
                            }
                            Err(e) => {
                                tracing::warn!("Unable to get content as JWKS `{jwks_uri}`: {e}");
                                None
                            }
                        },
                        Err(e) => {
                            tracing::warn!("Unable to download JWKS `{jwks_uri}`: {e}");
                            None
                        }
                    }
                }
            })
            .buffer_unordered(4)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>()
    }
}
