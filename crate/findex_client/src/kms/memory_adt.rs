use cosmian_findex::{ADDRESS_LENGTH, Address, MemoryADT};
use tracing::trace;

use super::KmsEncryptionLayer;
use crate::ClientError;

impl<
    const WORD_LENGTH: usize,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> MemoryADT for KmsEncryptionLayer<WORD_LENGTH, Memory>
{
    type Address = Address<ADDRESS_LENGTH>;
    type Error = ClientError;
    type Word = [u8; WORD_LENGTH];

    async fn guarded_write(
        &self,
        guard: (Self::Address, Option<Self::Word>),
        bindings: Vec<(Self::Address, Self::Word)>,
    ) -> Result<Option<Self::Word>, Self::Error> {
        trace!("guarded_write: guard: {:?}", guard);
        let (address, optional_word) = guard;

        // Split bindings into two vectors
        let (mut bindings, mut bindings_words): (Vec<_>, Vec<_>) = bindings.into_iter().unzip();
        trace!("guarded_write: bindings_addresses: {bindings:?}");
        trace!("guarded_write: bindings_words: {bindings_words:?}");

        // Compute HMAC of all addresses together (including the guard address)
        bindings.push(address); // size: n+1
        let mut tokens = self.hmac(bindings).await?;
        trace!("guarded_write: tokens: {tokens:?}");

        // Put apart the last token
        let token = tokens
            .pop()
            .ok_or_else(|| ClientError::Default("No token found".to_owned()))?;

        let (ciphertexts_and_tokens, old) = if let Some(word) = optional_word {
            // Zip words and tokens
            bindings_words.push(word); // size: n+1
            tokens.push(token.clone()); // size: n+1

            // Bulk Encrypt
            let mut ciphertexts = self.encrypt(&bindings_words, &tokens).await?;
            trace!("guarded_write: ciphertexts: {ciphertexts:?}");

            // Pop the old value
            let old = ciphertexts
                .pop()
                .ok_or_else(|| ClientError::Default("No ciphertext found".to_owned()))?;

            // Zip ciphertexts and tokens
            (ciphertexts.into_iter().zip(tokens), Some(old))
        } else {
            // Bulk Encrypt
            let ciphertexts = self.encrypt(&bindings_words, &tokens).await?;
            trace!("guarded_write: ciphertexts: {ciphertexts:?}");

            // Zip ciphertexts and tokens
            (ciphertexts.into_iter().zip(tokens), None)
        };

        //
        // Send bindings to server
        let cur = self
            .mem
            .guarded_write(
                (token.clone(), old),
                ciphertexts_and_tokens
                    .into_iter()
                    .map(|(w, a)| (a, w))
                    .collect(),
            )
            .await
            .map_err(|e| ClientError::Default(format!("Memory error: {e}")))?;

        //
        // Decrypt the current value (if any)
        let res = match cur {
            Some(ctx) => Some(
                *self
                    .decrypt(&[ctx], &[token])
                    .await?
                    .first()
                    .ok_or_else(|| ClientError::Default("No plaintext found".to_owned()))?,
            ),
            None => None,
        };
        trace!("guarded_write: res: {res:?}");

        Ok(res)
    }

    async fn batch_read(
        &self,
        addresses: Vec<Self::Address>,
    ) -> Result<Vec<Option<Self::Word>>, Self::Error> {
        trace!("batch_read: Addresses: {:?}", addresses);

        // Compute HMAC of all addresses
        let tokens = self.hmac(addresses).await?;
        trace!("batch_read: tokens: {:?}", tokens);

        // Read encrypted values server-side
        let ciphertexts = self
            .mem
            .batch_read(tokens.clone())
            .await
            .map_err(|e| ClientError::Default(format!("Memory error: {e}")))?;
        trace!("batch_read: ciphertexts: {ciphertexts:?}");

        // Track the positions of None values and bulk ciphertexts and tokens
        let (stripped_ciphertexts, stripped_tokens, none_positions): (Vec<_>, Vec<_>, Vec<_>) =
            ciphertexts
                .into_iter()
                .zip(tokens.into_iter())
                .enumerate()
                .fold(
                    (vec![], vec![], vec![]),
                    |(mut ctxs, mut ts, mut ns), (i, (c, t))| {
                        match c {
                            Some(cipher) => {
                                ctxs.push(cipher);
                                ts.push(t);
                            }
                            None => ns.push(i),
                        }
                        (ctxs, ts, ns)
                    },
                );

        // Recover plaintext-words
        let words = self
            .decrypt(&stripped_ciphertexts, &stripped_tokens)
            .await?;
        trace!("batch_read: words: {:?}", words);

        let mut res = words.into_iter().map(Some).collect::<Vec<_>>();
        for i in none_positions {
            res.insert(i, None);
        }
        trace!("batch_read: res: {:?}", res);

        Ok(res)
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn, clippy::indexing_slicing)]
mod tests {
    use std::sync::Arc;

    use cosmian_findex::{
        InMemory,
        test_utils::{test_guarded_write_concurrent, test_single_write_and_read, test_wrong_guard},
    };
    use cosmian_findex_structs::CUSTOM_WORD_LENGTH;
    use cosmian_kms_client::{
        KmsClient, KmsClientConfig,
        kmip_2_1::{
            extra::tagging::EMPTY_TAGS, kmip_types::CryptographicAlgorithm,
            requests::symmetric_key_create_request,
        },
    };
    use cosmian_logger::log_init;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use test_kms_server::start_default_test_kms_server;
    use tokio::task;

    use super::*;
    use crate::ClientResult;

    async fn create_test_layer<const WORD_LENGTH: usize>(
        kms_config: KmsClientConfig,
    ) -> ClientResult<
        KmsEncryptionLayer<WORD_LENGTH, InMemory<Address<ADDRESS_LENGTH>, [u8; WORD_LENGTH]>>,
    > {
        let memory = InMemory::default();
        let kms_client = KmsClient::new_with_config(kms_config)?;

        let k_p = kms_client
            .create(symmetric_key_create_request(
                None,
                256,
                CryptographicAlgorithm::SHAKE256,
                EMPTY_TAGS,
                false,
                None,
            )?)
            .await?
            .unique_identifier
            .to_string();

        let k_xts = kms_client
            .create(symmetric_key_create_request(
                None,
                512,
                CryptographicAlgorithm::AES,
                EMPTY_TAGS,
                false,
                None,
            )?)
            .await?
            .unique_identifier
            .to_string();

        Ok(KmsEncryptionLayer::<WORD_LENGTH, _>::new(
            kms_client, k_p, k_xts, memory,
        ))
    }

    #[tokio::test]
    #[allow(clippy::panic_in_result_fn, clippy::unwrap_used)]
    async fn test_adt_encrypt_decrypt() -> ClientResult<()> {
        let mut rng = ChaChaRng::from_os_rng();
        let tok = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let ptx = [1; CUSTOM_WORD_LENGTH];

        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let layer = Arc::new(layer);
        let mut handles = vec![];

        handles.push(task::spawn(async move {
            for _ in 0..1_000 {
                let ctx = layer.encrypt(&[ptx], &[tok.clone()]).await?.remove(0);
                let res = layer.decrypt(&[ctx], &[tok.clone()]).await?.remove(0);
                assert_eq!(ptx, res);
                assert_eq!(ptx.len(), res.len());
            }
            Ok::<(), ClientError>(())
        }));

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_single_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = ChaChaRng::from_os_rng();

        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr.clone(), None), vec![(
                    header_addr.clone(),
                    [2; CUSTOM_WORD_LENGTH]
                ),])
                .await?,
            None
        );

        assert_eq!(
            vec![Some([2; CUSTOM_WORD_LENGTH])],
            layer.batch_read(vec![header_addr,]).await?
        );
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_twice_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = ChaChaRng::from_os_rng();
        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr.clone(), None), vec![
                    (header_addr.clone(), [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1.clone(), [1; CUSTOM_WORD_LENGTH]),
                ])
                .await?,
            None
        );

        assert_eq!(
            vec![Some([2; CUSTOM_WORD_LENGTH]), Some([1; CUSTOM_WORD_LENGTH])],
            layer.batch_read(vec![header_addr, val_addr_1,]).await?
        );
        Ok(())
    }

    /// Ensures a transaction can express a vector push operation:
    /// - the counter is correctly incremented and all values are written;
    /// - using the wrong value in the guard fails the operation and returns the current value.
    #[tokio::test]
    async fn test_vector_push() -> ClientResult<()> {
        log_init(None);
        let mut rng = ChaChaRng::from_os_rng();
        let ctx = start_default_test_kms_server().await;
        let layer = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        let header_addr = Address::<ADDRESS_LENGTH>::random(&mut rng);

        let val_addr_1 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_2 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_3 = Address::<ADDRESS_LENGTH>::random(&mut rng);
        let val_addr_4 = Address::<ADDRESS_LENGTH>::random(&mut rng);

        assert_eq!(
            layer
                .guarded_write((header_addr.clone(), None), vec![
                    (header_addr.clone(), [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1.clone(), [1; CUSTOM_WORD_LENGTH]),
                    (val_addr_2.clone(), [1; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            None
        );

        assert_eq!(
            layer
                .guarded_write((header_addr.clone(), None), vec![
                    (header_addr.clone(), [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_1.clone(), [3; CUSTOM_WORD_LENGTH]),
                    (val_addr_2.clone(), [3; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            Some([2; CUSTOM_WORD_LENGTH])
        );

        assert_eq!(
            layer
                .guarded_write((header_addr.clone(), Some([2; CUSTOM_WORD_LENGTH])), vec![
                    (header_addr.clone(), [4; CUSTOM_WORD_LENGTH]),
                    (val_addr_3.clone(), [2; CUSTOM_WORD_LENGTH]),
                    (val_addr_4.clone(), [2; CUSTOM_WORD_LENGTH])
                ])
                .await?,
            Some([2; CUSTOM_WORD_LENGTH])
        );

        assert_eq!(
            vec![
                Some([4; CUSTOM_WORD_LENGTH]),
                Some([1; CUSTOM_WORD_LENGTH]),
                Some([1; CUSTOM_WORD_LENGTH]),
                Some([2; CUSTOM_WORD_LENGTH]),
                Some([2; CUSTOM_WORD_LENGTH])
            ],
            layer
                .batch_read(vec![
                    header_addr,
                    val_addr_1,
                    val_addr_2,
                    val_addr_3,
                    val_addr_4
                ])
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_sequential_read_write() -> ClientResult<()> {
        log_init(None);
        let ctx = start_default_test_kms_server().await;
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;

        test_single_write_and_read::<CUSTOM_WORD_LENGTH, _>(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_sequential_wrong_guard() -> ClientResult<()> {
        let ctx = start_default_test_kms_server().await;
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;
        test_wrong_guard::<CUSTOM_WORD_LENGTH, _>(&memory, rand::random()).await;
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_read_write() -> ClientResult<()> {
        log_init(None);
        let ctx = start_default_test_kms_server().await;
        let memory = create_test_layer(ctx.owner_client_conf.kms_config.clone()).await?;
        test_guarded_write_concurrent::<CUSTOM_WORD_LENGTH, _>(&memory, rand::random()).await;
        Ok(())
    }
}
