use cloudproof::reexport::{
    cover_crypt::{
        abe_policy::{AccessPolicy, Policy},
        statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey},
        CoverCrypt,
    },
    crypto_core::bytes_ser_de::Serializable,
};
use cosmian_kmip::kmip::{
    data_to_encrypt::DataToEncrypt,
    kmip_objects::Object,
    kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
};
use tracing::{debug, trace};

use crate::{
    crypto::{cover_crypt::attributes::policy_from_attributes, error::CryptoError},
    EncryptionSystem,
};

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct CoverCryptEncryption {
    cover_crypt: CoverCryptX25519Aes256,
    public_key_uid: String,
    public_key_bytes: Vec<u8>,
    policy: Policy,
}

/// Maximum clear text size that can be safely encrypted with AES GCM (using a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

impl CoverCryptEncryption {
    pub fn instantiate(
        cover_crypt: CoverCryptX25519Aes256,
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<Self, CryptoError> {
        let (public_key_bytes, public_key_attributes) =
            public_key.key_block()?.key_bytes_and_attributes()?;

        let policy = policy_from_attributes(public_key_attributes.ok_or_else(|| {
            CryptoError::Kmip(
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
            public_key_bytes: public_key_bytes.to_vec(),
            policy,
        })
    }
}

impl EncryptionSystem for CoverCryptEncryption {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, CryptoError> {
        let authenticated_encryption_additional_data = &request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let data_to_encrypt: DataToEncrypt = DataToEncrypt::try_from_bytes(
            request
                .data
                .as_ref()
                .ok_or_else(|| {
                    CryptoError::Kmip(
                        ErrorReason::Invalid_Message,
                        "Missing data to encrypt".to_owned(),
                    )
                })?
                .as_slice(),
        )?;

        let public_key =
            PublicKey::try_from_bytes(self.public_key_bytes.as_slice()).map_err(|e| {
                CryptoError::Kmip(
                    ErrorReason::Codec_Error,
                    format!("cover crypt encipher: failed recovering the public key: {e}"),
                )
            })?;

        let encryption_policy_string =
            data_to_encrypt.encryption_policy.ok_or(CryptoError::Kmip(
                ErrorReason::Invalid_Attribute_Value,
                "encryption policy missing".to_string(),
            ))?;
        let encryption_policy = AccessPolicy::from_boolean_expression(&encryption_policy_string)
            .map_err(|e| {
                CryptoError::Kmip(
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
            Some(authenticated_encryption_additional_data),
        )
        .map_err(|e| CryptoError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string()))?;

        // Encrypt the data
        let mut encrypted_block = self
            .cover_crypt
            .encrypt(
                &symmetric_key,
                &data_to_encrypt.plaintext,
                Some(authenticated_encryption_additional_data),
            )
            .map_err(|e| CryptoError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string()))?;

        let mut ciphertext = encrypted_header
            .try_to_bytes()
            .map_err(|e| CryptoError::Kmip(ErrorReason::Invalid_Attribute_Value, e.to_string()))?;
        ciphertext.append(&mut encrypted_block);

        debug!(
            "Encrypted data with public key {} of len (CT/Enc): {}/{}",
            &self.public_key_uid,
            data_to_encrypt.plaintext.len(),
            ciphertext.len(),
        );
        Ok(EncryptResponse {
            unique_identifier: self.public_key_uid.clone(),
            data: Some(ciphertext),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: Some(authenticated_encryption_additional_data.clone()),
        })
    }
}
