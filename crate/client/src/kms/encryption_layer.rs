use cosmian_findex::{Address, MemoryADT, ADDRESS_LENGTH};
use cosmian_kms_cli::reexport::cosmian_kms_client::kmip_2_1::{
    kmip_messages::MessageResponse, kmip_types::ResultStatusEnumeration,
};
use cosmian_kms_cli::reexport::cosmian_kms_client::KmsClient;
use tracing::trace;

use crate::{ClientError, ClientResult};

/// The encryption layers is built on top of an encrypted memory implementing the `MemoryADT` and
/// exposes a plaintext virtual memory interface implementing the `MemoryADT`.
///
/// This type is thread-safe.
#[derive(Clone)]
pub struct KmsEncryptionLayer<
    const WORD_LENGTH: usize,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>>,
> {
    pub(crate) kms_client: KmsClient,
    pub(crate) hmac_key_id: String,
    pub(crate) aes_xts_key_id: String,
    pub(crate) mem: Memory,
}

impl<
        const WORD_LENGTH: usize,
        Memory: Send
            + Sync
            + Clone
            + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    > KmsEncryptionLayer<WORD_LENGTH, Memory>
{
    /// Instantiates a new memory encryption layer.
    pub const fn new(
        kms_client: KmsClient,
        hmac_key_id: String,
        aes_xts_key_id: String,
        mem: Memory,
    ) -> Self {
        Self {
            kms_client,
            hmac_key_id,
            aes_xts_key_id,
            mem,
        }
    }

    fn extract_words(message_response: &MessageResponse) -> ClientResult<Vec<[u8; WORD_LENGTH]>> {
        if !message_response
            .items
            .iter()
            .all(|item| item.result_status == ResultStatusEnumeration::Success)
        {
            return Err(ClientError::Default(
                "One or more operations failed in the batch".to_owned(),
            ));
        }
        message_response
            .extract_items_data()?
            .into_iter()
            .map(|c| {
                c.as_slice()
                    .try_into()
                    .map_err(|e| ClientError::Default(format!("Conversion error: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Compute multiple HMAC on given memory addresses.
    pub(crate) async fn hmac(
        &self,
        addresses: Vec<Memory::Address>,
    ) -> ClientResult<Vec<Memory::Address>> {
        let tokens = self
            .kms_client
            .message(self.build_mac_message_request(&addresses)?)
            .await?
            .extract_items_data()?
            .into_iter()
            .map(|mac| {
                // Truncate to the first ADDRESS_LENGTH bytes
                mac.get(0..ADDRESS_LENGTH)
                    .ok_or_else(|| {
                        ClientError::Default(format!(
                            "Could not extract first {ADDRESS_LENGTH} bytes of the computed HMAC"
                        ))
                    })?
                    .try_into()
                    .map(|array: [u8; ADDRESS_LENGTH]| Address::from(array))
                    .map_err(|e| ClientError::Default(format!("Conversion error: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        trace!("hmac: tokens: {:?}", tokens);
        Ok(tokens)
    }

    /// Bulk encrypts the given words using AES-XTS-512 and the given memory addresses as tweak.
    pub(crate) async fn encrypt(
        &self,
        words: &[[u8; WORD_LENGTH]],
        tokens: &[Memory::Address],
    ) -> ClientResult<Vec<[u8; WORD_LENGTH]>> {
        Self::extract_words(
            &self
                .kms_client
                .message(self.build_encrypt_message_request(words, tokens)?)
                .await?,
        )
    }

    /// Decrypts these ciphertexts using the given addresses as tweak.
    pub(crate) async fn decrypt(
        &self,
        words: &[[u8; WORD_LENGTH]],
        tokens: &[Memory::Address],
    ) -> ClientResult<Vec<[u8; WORD_LENGTH]>> {
        Self::extract_words(
            &self
                .kms_client
                .message(self.build_decrypt_message_request(words, tokens)?)
                .await?,
        )
    }
}
