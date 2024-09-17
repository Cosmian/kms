use std::{collections::HashMap, sync::RwLock};

use alcoholic_jwt::{JWK, JWKS};
use chrono::{DateTime, Duration, Utc};

use crate::{error::KmsError, result::KResult};

static REFRESH_INTERVAL: i64 = 60; // in secs

#[derive(Debug)]
pub struct JwksManager {
    uris: Vec<String>,
    jwks: RwLock<HashMap<String, JWKS>>,
    last_update: RwLock<Option<DateTime<Utc>>>,
}

impl JwksManager {
    pub async fn new(uris: Vec<String>) -> KResult<Self> {
        let jwks_manager = Self {
            uris,
            jwks: HashMap::new().into(),
            last_update: None.into(),
        };
        jwks_manager.refresh().await?;

        Ok(jwks_manager)
    }

    /// Lock `jwks` to replace it
    fn set_jwks(&self, new_jwks: HashMap<String, JWKS>) -> KResult<()> {
        let mut jwks = self.jwks.write().map_err(|e| {
            KmsError::ServerError(format!("cannot lock JWKS for write. Error: {e:?}"))
        })?;
        *jwks = new_jwks;
        Ok(())
    }

    /// Find the key identifier `kid` in each registered JWKS
    pub fn find(&self, kid: &str) -> KResult<Option<JWK>> {
        Ok(self
            .jwks
            .read()
            .map_err(|e| KmsError::ServerError(format!("cannot lock JWKS for read. Error: {e:?}")))?
            .iter()
            .find_map(|(_, jwks)| jwks.find(kid))
            .cloned())
    }

    /// Fetch again all JWKS using the `uris`.
    ///
    /// The threshold to refresh JWKS is set to `REFRESH_INTERVAL`.
    pub async fn refresh(&self) -> KResult<()> {
        let refresh_is_allowed = {
            let mut last_update = self.last_update.write().map_err(|e| {
                KmsError::ServerError(format!("cannot lock last_update for write. Error: {e:?}"))
            })?;

            let can_be_refreshed = last_update.map_or(true, |lu| {
                (lu + Duration::seconds(REFRESH_INTERVAL)) < Utc::now()
            });

            if can_be_refreshed {
                *last_update = Some(Utc::now());
            }
            can_be_refreshed
        };

        if refresh_is_allowed {
            tracing::info!("Refreshing JWKS");
            let refreshed_jwks = Self::fetch_all(&self.uris).await;
            self.set_jwks(refreshed_jwks)?;
        }

        Ok(())
    }

    /// Refresh the JWK Set by making an external HTTP call to all the `uris`.
    ///
    /// The JWK Sets are fetched in parallel and warns about failures
    /// without stopping the whole fetch process.
    async fn fetch_all(uris: &[String]) -> HashMap<String, JWKS> {
        let client = reqwest::Client::new();

        let jwks_downloads = uris
            .iter()
            .map(|jwks_uri| {
                let client = &client;
                let jwks_uri = jwks_uri.clone();
                async move {
                    tracing::debug!("fetching {jwks_uri}");
                    match client.get(&jwks_uri).send().await {
                        Ok(resp) => match resp.json::<JWKS>().await {
                            Ok(jwks) => {
                                tracing::info!("+ fetched {jwks_uri}");
                                Some((jwks_uri, jwks))
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Unable to get content as JWKS for `{jwks_uri}`: {e}"
                                );
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
            .collect::<Vec<_>>();

        futures::future::join_all(jwks_downloads)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>()
    }
}
