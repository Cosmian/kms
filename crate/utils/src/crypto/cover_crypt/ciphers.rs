use cosmian_cover_crypt::{
    self,
    abe_policy::Policy,
    statics::{CoverCryptX25519Aes256, EncryptedHeader, PublicKey, UserSecretKey},
    CoverCrypt,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{
            DataToEncrypt, Decrypt, DecryptResponse, DecryptedData, Encrypt, EncryptResponse,
            ErrorReason,
        },
    },
};
use tracing::{debug, trace};

use super::user_key::unwrap_user_decryption_key_object;
use crate::{
    crypto::cover_crypt::attributes::policy_from_attributes,
    kmip_utils::key_bytes_and_attributes_from_key_block, DeCipher, EnCipher,
};

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct CoverCryptHybridCipher {
    cover_crypt: CoverCryptX25519Aes256,
    public_key_uid: String,
    public_key_bytes: Vec<u8>,
    policy: Policy,
}

/// Maximum clear text size that can be safely encrypted with AES GCM (using a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

impl CoverCryptHybridCipher {
    pub fn instantiate(
        cover_crypt: CoverCryptX25519Aes256,
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<Self, KmipError> {
        let (public_key_bytes, public_key_attributes) =
            key_bytes_and_attributes_from_key_block(public_key.key_block()?, public_key_uid)?;

        let policy = policy_from_attributes(public_key_attributes.ok_or_else(|| {
            KmipError::InvalidKmipObject(
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

impl EnCipher for CoverCryptHybridCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let authenticated_encryption_additional_data = &request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let data_to_encrypt: DataToEncrypt = request
            .data
            .as_ref()
            .ok_or_else(|| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Message,
                    "Missing data to encrypt".to_owned(),
                )
            })?
            .as_slice()
            .try_into()?;

        let public_key =
            PublicKey::try_from_bytes(self.public_key_bytes.as_slice()).map_err(|e| {
                KmipError::KmipError(
                    ErrorReason::Codec_Error,
                    format!("cover crypt encipher: failed recovering the public key: {e}"),
                )
            })?;

        let (symmetric_key, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &self.policy,
            &public_key,
            &data_to_encrypt.access_policy,
            data_to_encrypt.metadata.as_deref(),
            Some(authenticated_encryption_additional_data),
        )
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

        let mut encrypted_block = self
            .cover_crypt
            .encrypt(
                &symmetric_key,
                &data_to_encrypt.plaintext,
                Some(authenticated_encryption_additional_data),
            )
            .map_err(|e| {
                KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
            })?;

        let mut ciphertext = encrypted_header.try_to_bytes().map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;
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

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct CoverCryptHybridDecipher {
    cover_crypt: CoverCryptX25519Aes256,
    user_decryption_key_uid: String,
    user_decryption_key_bytes: Vec<u8>,
}

impl CoverCryptHybridDecipher {
    pub fn instantiate(
        cover_crypt: CoverCryptX25519Aes256,
        user_decryption_key_uid: &str,
        user_decryption_key: &Object,
    ) -> Result<Self, KmipError> {
        let (user_decryption_key_bytes, _access_policy, _attributes) =
            unwrap_user_decryption_key_object(user_decryption_key)?;

        debug!(
            "Instantiated hybrid CoverCrypt decipher for user decryption key id: \
             {user_decryption_key_uid}"
        );

        Ok(Self {
            cover_crypt,
            user_decryption_key_uid: user_decryption_key_uid.into(),
            user_decryption_key_bytes,
        })
    }
}

impl DeCipher for CoverCryptHybridDecipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let user_decryption_key = UserSecretKey::try_from_bytes(&self.user_decryption_key_bytes)
            .map_err(|e| {
                KmipError::KmipError(
                    ErrorReason::Codec_Error,
                    format!("cover crypt decipher: failed recovering the user key: {e}"),
                )
            })?;

        let encrypted_bytes = request.data.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Message,
                "The decryption request should contain encrypted data".to_string(),
            )
        })?;

        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        let encrypted_header = EncryptedHeader::read(&mut de).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Message,
                format!("Bad or corrupted encrypted data: {e}"),
            )
        })?;
        let encrypted_block = de.finalize();

        let header_ = encrypted_header
            .decrypt(
                &self.cover_crypt,
                &user_decryption_key,
                request.authenticated_encryption_additional_data.as_deref(),
            )
            .map_err(|e| {
                KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
            })?;

        let cleartext = self
            .cover_crypt
            .decrypt(
                &header_.symmetric_key,
                &encrypted_block,
                request.authenticated_encryption_additional_data.as_deref(),
            )
            .map_err(|e| {
                KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string())
            })?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            cleartext.len(),
            encrypted_bytes.len(),
        );

        let decrypted_data = DecryptedData {
            metadata: header_.metadata,
            plaintext: cleartext,
        };

        Ok(DecryptResponse {
            unique_identifier: self.user_decryption_key_uid.clone(),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}
