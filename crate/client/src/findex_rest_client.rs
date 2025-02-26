use crate::{error::ClientError, handle_error, RestClient};
use base64::{engine::general_purpose, Engine};
use cosmian_findex::{Address, MemoryADT, ADDRESS_LENGTH};
use cosmian_findex_structs::{Addresses, Bindings, Guard, OptionalWords};
use tracing::{trace, warn};

use uuid::Uuid;

#[derive(Clone)]
pub struct FindexRestClient<const WORD_LENGTH: usize> {
    pub rest_client: RestClient,
    pub index_id: Uuid,
}

impl<const WORD_LENGTH: usize> FindexRestClient<WORD_LENGTH> {
    #[must_use]
    pub const fn new(rest_client: RestClient, index_id: Uuid) -> Self {
        Self {
            rest_client,
            index_id,
        }
    }
}

impl<const WORD_LENGTH: usize> MemoryADT for FindexRestClient<WORD_LENGTH> {
    type Address = Address<ADDRESS_LENGTH>;
    type Word = [u8; WORD_LENGTH];
    type Error = ClientError;

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<[u8; WORD_LENGTH]>>, ClientError> {
        let endpoint = format!("/indexes/{}/batch_read", self.index_id);
        let server_url = format!("{}{}", self.rest_client.http_client.server_url, endpoint);

        trace!(
            "Initiating batch_read of {} addresses for index {} at server_url: {}",
            addresses.len(),
            self.index_id,
            server_url
        );

        let response = self
            .rest_client
            .http_client
            .client
            .post(&server_url)
            .body(Addresses::new(addresses).serialize()?)
            .send()
            .await?;

        if !response.status().is_success() {
            warn!("batch_read failed on server url {:?}.", server_url);
            let err = handle_error(&endpoint, response).await?;
            return Err(ClientError::RequestFailed(err));
        }

        let words: OptionalWords<WORD_LENGTH> =
            OptionalWords::deserialize(&response.bytes().await?)?;

        trace!(
            "batch_read successful on server url {}. result: {}",
            &server_url,
            words
        );

        Ok(words.into_inner())
    }

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<[u8; WORD_LENGTH]>, ClientError> {
        let endpoint = format!("/indexes/{}/guarded_write", self.index_id);
        let server_url = format!("{}{}", self.rest_client.http_client.server_url, &endpoint);

        trace!(
            "Initiating guarded_write of {} values for index {} at server_url: {}",
            bindings.len(),
            self.index_id,
            &server_url
        );

        // BEGIN TODO: using `Serializable` avoids re-coding vector
        // concatenation. Anyway, this should be abstracted away in a function.
        let guard_bytes = Guard::new(guard.0, guard.1).serialize()?;
        let bindings_bytes = Bindings::new(bindings).serialize()?;
        let mut request_bytes = Vec::with_capacity(guard_bytes.len() + bindings_bytes.len());
        request_bytes.extend_from_slice(&guard_bytes);
        request_bytes.extend_from_slice(&bindings_bytes);
        // END TODO

        let response = self
            .rest_client
            .http_client
            .client
            .post(&server_url)
            .body(request_bytes)
            .send()
            .await?;

        if !response.status().is_success() {
            warn!("guarded_write failed on server url {}.", server_url);
            let err = handle_error(&endpoint, response).await?;
            return Err(ClientError::RequestFailed(err));
        }

        let guard = {
            let bytes = response.bytes().await?;
            let words: Vec<_> = OptionalWords::deserialize(&bytes)?.into();
            words.into_iter().next().ok_or_else(|| {
                ClientError::RequestFailed(
                    "Unexpected response from server. Expected 1 word, got None".to_owned(),
                )
            })
        }?;

        trace!(
            "guarded_write successful on server url {}. guard: {}",
            server_url,
            guard.map_or("None".to_owned(), |g| general_purpose::STANDARD.encode(g))
        );

        Ok(guard)
    }
}
