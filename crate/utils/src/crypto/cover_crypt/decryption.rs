use cloudproof::reexport::{
    cover_crypt::{Covercrypt, EncryptedHeader, UserSecretKey},
    crypto_core::bytes_ser_de::{Deserializer, Serializable},
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData, ErrorReason},
};
use tracing::{debug, trace};

use super::user_key::unwrap_user_decryption_key_object;
use crate::{error::KmipUtilsError, DecryptionSystem};

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct CovercryptDecryption {
    cover_crypt: Covercrypt,
    user_decryption_key_uid: String,
    user_decryption_key_bytes: Vec<u8>,
}

impl CovercryptDecryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        user_decryption_key_uid: &str,
        user_decryption_key: &Object,
    ) -> Result<Self, KmipUtilsError> {
        trace!("CovercryptDecryption::instantiate entering");
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

impl DecryptionSystem for CovercryptDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        let user_decryption_key = UserSecretKey::deserialize(&self.user_decryption_key_bytes)
            .map_err(|e| {
                KmipUtilsError::Kmip(
                    ErrorReason::Codec_Error,
                    format!("cover crypt decipher: failed recovering the user key: {e}"),
                )
            })?;

        let encrypted_bytes = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::Kmip(
                ErrorReason::Invalid_Message,
                "The decryption request should contain encrypted data".to_string(),
            )
        })?;

        let mut de = Deserializer::new(encrypted_bytes.as_slice());
        let encrypted_header = EncryptedHeader::read(&mut de).map_err(|e| {
            KmipUtilsError::Kmip(
                ErrorReason::Invalid_Message,
                format!("Bad or corrupted encrypted data: {e}"),
            )
        })?;
        let encrypted_block = de.finalize();

        let header = encrypted_header
            .decrypt(
                &self.cover_crypt,
                &user_decryption_key,
                request.authenticated_encryption_additional_data.as_deref(),
            )
            .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

        let cleartext = self
            .cover_crypt
            .decrypt(
                &header.symmetric_key,
                &encrypted_block,
                request.authenticated_encryption_additional_data.as_deref(),
            )
            .map_err(|e| KmipUtilsError::Kmip(ErrorReason::Invalid_Message, e.to_string()))?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            cleartext.len(),
            encrypted_bytes.len(),
        );

        let decrypted_data = DecryptedData {
            metadata: header.metadata.unwrap_or(Vec::default()),
            plaintext: cleartext,
        };

        Ok(DecryptResponse {
            unique_identifier: self.user_decryption_key_uid.clone(),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}
