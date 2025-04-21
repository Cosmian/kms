use cosmian_findex::{ADDRESS_LENGTH, Address, MemoryADT};
use cosmian_kms_client::{
    cosmian_kmip::kmip_0::{
        kmip_messages::{RequestMessage, RequestMessageBatchItemVersioned, RequestMessageHeader},
        kmip_types::{BlockCipherMode, HashingAlgorithm, ProtocolVersion},
    },
    kmip_2_1::{
        kmip_messages::RequestMessageBatchItem,
        kmip_operations::{Decrypt, Encrypt, Mac, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, OperationEnumeration, UniqueIdentifier,
        },
        requests::encrypt_request,
    },
};

use super::KmsEncryptionLayer;
use crate::ClientResult;

impl<
    const WORD_LENGTH: usize,
    Memory: Send + Sync + Clone + MemoryADT<Address = Address<ADDRESS_LENGTH>, Word = [u8; WORD_LENGTH]>,
> KmsEncryptionLayer<WORD_LENGTH, Memory>
{
    fn build_message_request(
        items: Vec<RequestMessageBatchItemVersioned>,
    ) -> ClientResult<RequestMessage> {
        let items_number = i32::try_from(items.len())?;
        Ok(RequestMessage {
            request_header: RequestMessageHeader {
                protocol_version: ProtocolVersion {
                    protocol_version_major: 2,
                    protocol_version_minor: 1,
                },
                maximum_response_size: Some(9999),
                batch_count: items_number,
                ..RequestMessageHeader::default()
            },
            batch_item: items,
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
    ) -> ClientResult<RequestMessage> {
        let items = addresses
            .iter()
            .map(|address| {
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                    operation: OperationEnumeration::MAC,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Mac(self.build_mac_request(address.to_vec())),
                    message_extension: None,
                })
            })
            .collect();
        Self::build_message_request(items)
    }

    fn build_encrypt_request(&self, plaintext: Vec<u8>, nonce: Vec<u8>) -> ClientResult<Encrypt> {
        Ok(encrypt_request(
            &self.aes_xts_key_id,
            None,
            plaintext,
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
    ) -> ClientResult<RequestMessage> {
        let items = words
            .iter()
            .zip(tokens)
            .map(|(word, address)| {
                self.build_encrypt_request(word.to_vec(), address.to_vec())
                    .map(|encrypt_request| {
                        RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                            operation: OperationEnumeration::Encrypt,
                            ephemeral: None,
                            unique_batch_item_id: None,
                            request_payload: Operation::Encrypt(encrypt_request),
                            message_extension: None,
                        })
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
            i_v_counter_nonce: Some(nonce),
            ..Default::default()
        }
    }

    pub(crate) fn build_decrypt_message_request(
        &self,
        words: &[[u8; WORD_LENGTH]],
        tokens: &[Memory::Address],
    ) -> ClientResult<RequestMessage> {
        let items = words
            .iter()
            .zip(tokens)
            .map(|(word, address)| {
                RequestMessageBatchItemVersioned::V21(RequestMessageBatchItem {
                    operation: OperationEnumeration::Decrypt,
                    ephemeral: None,
                    unique_batch_item_id: None,
                    request_payload: Operation::Decrypt(
                        self.build_decrypt_request(word.to_vec(), address.to_vec()),
                    ),
                    message_extension: None,
                })
            })
            .collect::<Vec<_>>();
        Self::build_message_request(items)
    }
}
