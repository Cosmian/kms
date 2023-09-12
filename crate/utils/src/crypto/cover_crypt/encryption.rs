use cloudproof::reexport::{
    cover_crypt::{
        abe_policy::{AccessPolicy, Policy},
        core::SYM_KEY_LENGTH,
        Covercrypt, EncryptedHeader, MasterPublicKey,
    },
    crypto_core::{bytes_ser_de::Serializable, SymmetricKey},
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        data_to_encrypt::DataToEncrypt,
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
    },
};
use tracing::{debug, trace};

use crate::{
    crypto::cover_crypt::attributes::policy_from_attributes, error::KmipUtilsError,
    EncryptionSystem,
};

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct CoverCryptEncryption {
    cover_crypt: Covercrypt,
    public_key_uid: String,
    public_key_bytes: Vec<u8>,
    policy: Policy,
}

impl CoverCryptEncryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<Self, KmipUtilsError> {
        let (public_key_bytes, public_key_attributes) =
            public_key.key_block()?.key_bytes_and_attributes()?;

        let policy = policy_from_attributes(public_key_attributes.ok_or_else(|| {
            KmipUtilsError::Kmip(
                ErrorReason::Attribute_Not_Found,
                "the master public key does not have attributes with the Policy".to_string(),
            )
        })?)?;

        trace!(
            "Instantiated hybrid CoverCrypt encipher for public key id: {public_key_uid}, policy: \
             {policy:#?}"
        );

        Ok(Self {
            cover_crypt,
            public_key_uid: public_key_uid.into(),
            public_key_bytes,
            policy,
        })
    }

    /// Encrypt multiple payloads using LEB128
    ///
    /// A custom protocol is used to serialize these data.
    ///
    /// Bulk encryption / decryption scheme
    ///
    /// ENC request
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    ///
    /// ENC response
    /// | EH | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (encrypted)
    ///                             <------------- nb_chunks times ------------>
    ///
    /// DEC request
    /// | nb_chunks (LEB128) | size(EH + chunk_data) (LEB128) | EH | chunk_data (encrypted)
    ///                                                         <----- chunk with EH ----->
    ///                        <---------------------- nb_chunks times ------------------->
    ///
    /// DEC response
    /// | nb_chunks (LEB128) | chunk_size (LEB128) | chunk_data (plaintext)
    ///                        <------------- nb_chunks times ------------>
    fn bulk_encrypt(
        &self,
        mut plaintext: &[u8],
        aead: Option<&[u8]>,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
    ) -> Result<Vec<u8>, KmipUtilsError> {
        let mut encrypted_data = Vec::new();

        // number of chunks of plaintext data to encrypt
        let nb_chunks = leb128::read::unsigned(&mut plaintext).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "expected a LEB128 encoded number (number of encrypted chunks) at the beginning \
                 of the data to encrypt"
                    .to_string(),
            )
        })? as usize;

        leb128::write::unsigned(&mut encrypted_data, nb_chunks as u64).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "Cannot write the number of chunks".to_string(),
            )
        })?;

        for _ in 0..nb_chunks {
            let chunk_size = leb128::read::unsigned(&mut plaintext).map_err(|_| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    "Cannot read the chunk size".to_string(),
                )
            })? as usize;

            #[allow(clippy::needless_borrow)]
            let chunk_data = (&mut plaintext).take(..chunk_size).ok_or_else(|| {
                KmipUtilsError::Kmip(
                    ErrorReason::Internal_Server_Error,
                    "unable to get right chunk slice".to_string(),
                )
            })?;

            // Encrypt the data
            let mut encrypted_block = self
                .cover_crypt
                .encrypt(symmetric_key, chunk_data, aead)
                .map_err(|e| {
                    KmipUtilsError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string())
                })?;

            debug!(
                "Encrypted data with public key {} of len (CT/Enc): {}/{}",
                self.public_key_uid,
                chunk_data.len(),
                encrypted_data.len(),
            );

            leb128::write::unsigned(&mut encrypted_data, encrypted_block.len() as u64).map_err(
                |_| {
                    KmipError::KmipError(
                        ErrorReason::Invalid_Message,
                        "Cannot write the size of encrypted block".to_string(),
                    )
                },
            )?;
            encrypted_data.append(&mut encrypted_block);
        }

        Ok(encrypted_data)
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        aead: Option<&[u8]>,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
    ) -> Result<Vec<u8>, KmipUtilsError> {
        // Encrypt the data
        let encrypted_block = self
            .cover_crypt
            .encrypt(symmetric_key, plaintext, aead)
            .map_err(|e| {
                KmipUtilsError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string())
            })?;

        debug!(
            "Encrypted data with public key {} of len (CT/Enc): {}/{}",
            self.public_key_uid,
            plaintext.len(),
            encrypted_block.len(),
        );

        Ok(encrypted_block)
    }
}

impl EncryptionSystem for CoverCryptEncryption {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
        let authenticated_encryption_additional_data =
            request.authenticated_encryption_additional_data.as_deref();

        let data_to_encrypt =
            DataToEncrypt::try_from_bytes(request.data.as_deref().ok_or_else(|| {
                KmipUtilsError::Kmip(
                    ErrorReason::Invalid_Message,
                    "Missing data to encrypt".to_owned(),
                )
            })?)?;

        let public_key =
            MasterPublicKey::deserialize(self.public_key_bytes.as_slice()).map_err(|e| {
                KmipUtilsError::Kmip(
                    ErrorReason::Codec_Error,
                    format!("cover crypt encipher: failed recovering the public key: {e}"),
                )
            })?;

        let encryption_policy_string =
            data_to_encrypt
                .encryption_policy
                .as_deref()
                .ok_or_else(|| {
                    KmipUtilsError::Kmip(
                        ErrorReason::Invalid_Attribute_Value,
                        "encryption policy missing".to_string(),
                    )
                })?;
        let encryption_policy = AccessPolicy::from_boolean_expression(encryption_policy_string)
            .map_err(|e| {
                KmipUtilsError::Kmip(
                    ErrorReason::Invalid_Attribute_Value,
                    format!("invalid encryption policy: {e}"),
                )
            })?;

        // Generate a symmetric key and encrypt the header
        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &self.policy,
            &public_key,
            &encryption_policy,
            data_to_encrypt.header_metadata.as_deref(),
            authenticated_encryption_additional_data,
        )
        .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string()))?;

        let mut ciphertext = encrypted_header.serialize().map_err(|e| {
            KmipUtilsError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

        let mut encrypted_data = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_encrypt(
                &data_to_encrypt.plaintext,
                authenticated_encryption_additional_data,
                &symmetric_key,
            )?
        } else {
            self.encrypt(
                &data_to_encrypt.plaintext,
                authenticated_encryption_additional_data,
                &symmetric_key,
            )?
        };

        // Concatenate serialized encrypted header with encrypted data
        ciphertext.append(&mut encrypted_data);

        Ok(EncryptResponse {
            unique_identifier: self.public_key_uid.clone(),
            data: Some(ciphertext.to_vec()),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: authenticated_encryption_additional_data
                .map(|aead| aead.to_vec()),
        })
    }
}
