use cosmian_findex::{Address, MemoryADT, ADDRESS_LENGTH};
use cosmian_kms_cli::reexport::cosmian_kms_client::kmip_2_1::{
    kmip_messages::{Message, MessageBatchItem, MessageHeader},
    kmip_operations::{Decrypt, Encrypt, Mac, Operation},
    kmip_types::{
        BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, HashingAlgorithm,
        ProtocolVersion, UniqueIdentifier,
    },
    requests::encrypt_request,
};

use crate::ClientResult;

use super::KmsEncryptionLayer;

impl<
        const WORD_LENGTH: usize,
        Memory: Send
            + Sync
            + Clone
            + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
    > KmsEncryptionLayer<WORD_LENGTH, Memory>
{
    fn build_message_request(items: Vec<MessageBatchItem>) -> ClientResult<Message> {
        let items_number = u32::try_from(items.len())?;
        Ok(Message {
            header: MessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 1,
                    protocol_version_minor: 0,
                },
                maximum_response_size: Some(9999),
                batch_count: items_number,
                ..MessageHeader::default()
            },
            items,
        })
    }

    fn build_mac_request(&self, data: Vec<u8>) -> Mac {
        Mac {
            unique_identifier: Some(UniqueIdentifier::TextString(self.hmac_key_id.clone())),
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA3256),
                ..CryptographicParameters::default()
            },
            data: Some(data),
            ..Default::default()
        }
    }

    pub(crate) fn build_mac_message_request(
        &self,
        addresses: &[Memory::Address],
    ) -> ClientResult<Message> {
        let items = addresses
            .iter()
            .map(|address| {
                MessageBatchItem::new(Operation::Mac(self.build_mac_request(address.to_vec())))
            })
            .collect();
        Self::build_message_request(items)
    }

    fn build_encrypt_request(&self, plaintext: Vec<u8>, nonce: Vec<u8>) -> ClientResult<Encrypt> {
        Ok(encrypt_request(
            &self.aes_xts_key_id,
            None,
            plaintext,
            None,
            Some(nonce),
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::XTS),
                ..CryptographicParameters::default()
            }),
        )?)
    }

    pub(crate) fn build_encrypt_message_request(
        &self,
        words: &[[u8; WORD_LENGTH]],
        tokens: &[Memory::Address],
    ) -> ClientResult<Message> {
        let items = words
            .iter()
            .zip(tokens)
            .map(|(word, address)| {
                self.build_encrypt_request(word.to_vec(), address.to_vec())
                    .map(|encrypt_request| {
                        MessageBatchItem::new(Operation::Encrypt(encrypt_request))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::build_message_request(items)
    }

    fn build_decrypt_request(&self, ciphertext: Vec<u8>, nonce: Vec<u8>) -> Decrypt {
        Decrypt {
            unique_identifier: Some(UniqueIdentifier::TextString(self.aes_xts_key_id.clone())),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::XTS),
                ..CryptographicParameters::default()
            }),
            data: Some(ciphertext),
            iv_counter_nonce: Some(nonce),
            ..Default::default()
        }
    }

    pub(crate) fn build_decrypt_message_request(
        &self,
        words: &[[u8; WORD_LENGTH]],
        tokens: &[Memory::Address],
    ) -> ClientResult<Message> {
        let items = words
            .iter()
            .zip(tokens)
            .map(|(word, address)| {
                MessageBatchItem::new(Operation::Decrypt(
                    self.build_decrypt_request(word.to_vec(), address.to_vec()),
                ))
            })
            .collect::<Vec<_>>();
        Self::build_message_request(items)
    }
}
