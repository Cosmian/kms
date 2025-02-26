use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_findex::{
    generic_decode, generic_encode, Findex, IndexADT, MemoryEncryptionLayer, Value,
};
use cosmian_findex_client::{FindexRestClient, KmsEncryptionLayer, RestClient};
use cosmian_findex_structs::{Keyword, Keywords, SearchResults};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;
use tokio::sync::Semaphore;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    actions::findex_server::findex::retrieve_key_from_kms,
    error::{result::CosmianResult, CosmianError},
};

/// Calculates maximum concurrent operations based on CPU cores and implicitly on maximum available file descriptors on Unix systems.
///
/// # Returns
///
/// Returns usize value representing concurrent operation limit (CPU cores * 4)
///
/// # Implementation constraints
///
/// - Must works cross-platform
/// - Must adapt to maximum available CPU cores
/// - Must optimize maximum the number concurrent network calls while avoiding resource exhaustion
/// - Keeps concurrent operations within safe bounds (e.g. file descriptors on Unix systems)
/// - Must be bound between 1 and 128
/// - For the record, 256 has proven to be an instable value: Github runners are not able to handle it
fn get_semaphore_limit() -> usize {
    let res = (std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get) * 4)
        .clamp(1, 128);
    debug!("Semaphore limit: {res}");
    res
}

pub enum FindexKeys {
    ClientSideEncryption {
        seed_key_id: String,
        index_id: Uuid,
    },
    ServerSideEncryption {
        hmac_key_id: String,
        aes_xts_key_id: String,
        index_id: Uuid,
    },
}

#[derive(Clone)]
pub enum FindexInstance<const WORD_LENGTH: usize> {
    ClientSideEncryption(
        Findex<
            WORD_LENGTH,
            Value,
            String,
            MemoryEncryptionLayer<WORD_LENGTH, FindexRestClient<WORD_LENGTH>>,
        >,
    ),
    ServerSideEncryption(
        Findex<
            WORD_LENGTH,
            Value,
            String,
            KmsEncryptionLayer<WORD_LENGTH, FindexRestClient<WORD_LENGTH>>,
        >,
    ),
}

impl<const WORD_LENGTH: usize> FindexInstance<WORD_LENGTH> {
    /// Instantiates a new Findex instance.
    /// If a seed key is provided, the client side encryption is used.
    /// Otherwise, the KMS server-side encryption is used.
    ///
    /// # Errors
    /// - If the seed key cannot be retrieved from the KMS
    /// - If the HMAC key ID or the AES XTS key ID cannot be retrieved from the KMS
    pub async fn instantiate_findex(
        rest_client: RestClient,
        kms_client: KmsClient,
        findex_keys: FindexKeys,
    ) -> CosmianResult<Self> {
        match findex_keys {
            FindexKeys::ClientSideEncryption {
                seed_key_id,
                index_id,
            } => {
                let memory = FindexRestClient::new(rest_client.clone(), index_id);
                trace!("Using client side encryption");
                let seed = retrieve_key_from_kms(&seed_key_id, kms_client).await?;
                let encryption_layer = MemoryEncryptionLayer::<WORD_LENGTH, _>::new(&seed, memory);
                Ok(Self::ClientSideEncryption(Findex::new(
                    encryption_layer,
                    generic_encode,
                    generic_decode,
                )))
            }
            FindexKeys::ServerSideEncryption {
                hmac_key_id,
                aes_xts_key_id,
                index_id,
            } => {
                let memory = FindexRestClient::new(rest_client.clone(), index_id);

                trace!("Using KMS server side encryption");
                let encryption_layer = KmsEncryptionLayer::<WORD_LENGTH, _>::new(
                    kms_client,
                    hmac_key_id,
                    aes_xts_key_id,
                    memory,
                );
                Ok(Self::ServerSideEncryption(Findex::new(
                    encryption_layer,
                    generic_encode,
                    generic_decode,
                )))
            }
        }
    }

    /// Search multiple keywords. Returned results are the intersection of all search results (logical AND).
    ///
    /// # Errors
    /// - If any of the concurrent search operations fail:
    /// - If the semaphore acquisition fails due to system resource exhaustion
    pub async fn search(&self, keywords: &[String]) -> CosmianResult<SearchResults> {
        let lowercase_keywords = keywords
            .iter()
            .map(|kw| kw.to_lowercase())
            .collect::<Vec<_>>();

        let semaphore = Arc::new(Semaphore::new(get_semaphore_limit()));

        let mut handles = lowercase_keywords
            .iter()
            .map(|kw| {
                let semaphore = semaphore.clone();
                let keyword = Keyword::from(kw.as_ref());
                let findex_instance = self.clone();
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.map_err(|e| {
                        CosmianError::Default(format!(
                            "Acquire error while trying to ask for permit: {e:?}"
                        ))
                    })?;
                    Ok::<_, CosmianError>(match findex_instance {
                        Self::ClientSideEncryption(findex) => findex.search(&keyword).await?,
                        Self::ServerSideEncryption(findex) => findex.search(&keyword).await?,
                    })
                })
            })
            .collect::<Vec<_>>();

        if let Some(initial_handle) = handles.pop() {
            let mut acc_results = initial_handle
                .await
                .map_err(|e| CosmianError::Default(e.to_string()))??;
            for h in handles {
                // The empty set is the fixed point of the intersection.
                if acc_results.is_empty() {
                    break;
                }
                let next_search_result = h
                    .await
                    .map_err(|e| CosmianError::Default(e.to_string()))??;
                acc_results.retain(|item| next_search_result.contains(item));
            }
            Ok(SearchResults(acc_results))
        } else {
            Ok(SearchResults(HashSet::new()))
        }
    }

    /// Insert new indexes or delete indexes
    ///
    /// # Errors
    /// - If insert new indexes fails
    /// - or if delete indexes fails
    pub async fn insert_or_delete(
        &self,
        bindings: HashMap<Keyword, HashSet<Value>>,
        is_insert: bool,
    ) -> CosmianResult<Keywords> {
        let semaphore = Arc::new(Semaphore::new(get_semaphore_limit()));
        let written_keywords = bindings.keys().cloned().collect::<Vec<_>>();

        let handles = bindings
            .into_iter()
            .map(|(kw, vs)| {
                let findex = self.clone();
                let semaphore = semaphore.clone();
                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.map_err(|e| {
                        CosmianError::Default(format!(
                            "Acquire error while trying to ask for permit: {e:?}"
                        ))
                    })?;
                    match findex {
                        Self::ClientSideEncryption(findex) => {
                            if is_insert {
                                findex.insert(kw, vs).await?;
                            } else {
                                findex.delete(kw, vs).await?;
                            }
                        }
                        Self::ServerSideEncryption(findex) => {
                            if is_insert {
                                findex.insert(kw, vs).await?;
                            } else {
                                findex.delete(kw, vs).await?;
                            }
                        }
                    }
                    Ok::<_, CosmianError>(())
                })
            })
            .collect::<Vec<_>>();

        for h in handles {
            h.await
                .map_err(|e| CosmianError::Default(e.to_string()))??;
        }

        Ok(Keywords::from(written_keywords))
    }
}
