use abe_gpsw::{
    self,
    core::{
        bilinear_map::bls12_381::Bls12_381,
        gpsw::{AbeScheme, AsBytes, Gpsw},
        policy::{Attribute, Policy},
    },
    interfaces::hybrid_crypto::{
        decrypt_hybrid_block, decrypt_hybrid_header, encrypt_hybrid_block, encrypt_hybrid_header,
    },
};
use cosmian_crypto_base::{
    hybrid_crypto::Metadata, symmetric_crypto::aes_256_gcm_pure::Aes256GcmCrypto,
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
    },
};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use super::user_key::unwrap_user_decryption_key_object;
use crate::{
    crypto::abe::attributes::policy_from_attributes,
    kmip_utils::key_bytes_and_attributes_from_key_block, DeCipher, EnCipher,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DataToEncrypt {
    pub policy_attributes: Vec<Attribute>,
    #[serde(with = "hex")]
    pub data: Vec<u8>,
}

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct AbeHybridCipher {
    public_key_uid: String,
    public_key_bytes: Vec<u8>,
    policy: Policy,
}

/// Maximum clear text size that can be safely encrypted with AES GCM (using a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

impl AbeHybridCipher {
    pub fn instantiate(
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<AbeHybridCipher, KmipError> {
        let (public_key_bytes, public_key_attributes) =
            key_bytes_and_attributes_from_key_block(public_key.key_block()?, public_key_uid)?;

        let policy = policy_from_attributes(&public_key_attributes.ok_or_else(|| {
            KmipError::InvalidKmipObject(
                ErrorReason::Attribute_Not_Found,
                "the master public key does not have attributes with the Policy".to_string(),
            )
        })?)?;

        trace!(
            "Instantiated hybrid ABE cipher for public key id: {}, policy: {:#?}",
            public_key_uid,
            &policy
        );

        Ok(AbeHybridCipher {
            public_key_uid: public_key_uid.into(),
            public_key_bytes,
            policy,
        })
    }
}

impl EnCipher for AbeHybridCipher {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipError> {
        let uid = &request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let data_to_encrypt: DataToEncrypt =
            serde_json::from_slice(request.data.as_ref().ok_or_else(|| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Message,
                    "Missing data to encrypt".to_string(),
                )
            })?)
            .map_err(|_| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Message,
                    "Missing data to encrypt".to_string(),
                )
            })?;

        let public_key =
            <Gpsw<Bls12_381> as AbeScheme>::MasterPublicKey::from_bytes(&self.public_key_bytes)
                .map_err(|e| {
                    KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
                })?;

        // The UID is NOT written in the header and needs to be re-supplied on block decryption
        let mut encrypted_header = encrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &self.policy,
            &public_key,
            &data_to_encrypt.policy_attributes,
            Metadata::default(),
        )
        .map_err(|e| {
            KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
        })?;

        let mut encrypted_block =
            encrypt_hybrid_block::<Gpsw<Bls12_381>, Aes256GcmCrypto, MAX_CLEAR_TEXT_SIZE>(
                &encrypted_header.symmetric_key,
                uid,
                0,
                &data_to_encrypt.data,
            )
            .map_err(|e| {
                KmipError::InvalidKmipValue(ErrorReason::Invalid_Attribute_Value, e.to_string())
            })?;

        let mut ciphertext = (encrypted_header.encrypted_header_bytes.len() as u32) //should not overflow
            .to_be_bytes()
            .to_vec();
        ciphertext.append(&mut encrypted_header.encrypted_header_bytes);
        ciphertext.append(&mut encrypted_block);

        debug!(
            "Encrypted data with public key {} of len (CT/Enc): {}/{}, Attributes: {:?}",
            &self.public_key_uid,
            data_to_encrypt.data.len(),
            ciphertext.len(),
            &data_to_encrypt.policy_attributes
        );
        Ok(EncryptResponse {
            unique_identifier: self.public_key_uid.clone(),
            data: Some(ciphertext),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: Some(uid.to_vec()),
        })
    }
}

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct AbeHybridDecipher {
    user_decryption_key_uid: String,
    user_decryption_key_bytes: Vec<u8>,
}

impl AbeHybridDecipher {
    pub fn instantiate(
        user_decryption_key_uid: &str,
        user_decryption_key: &Object,
    ) -> Result<AbeHybridDecipher, KmipError> {
        let (user_decryption_key_bytes, _access_policy, _attributes) =
            unwrap_user_decryption_key_object(user_decryption_key)?;
        Ok(AbeHybridDecipher {
            user_decryption_key_uid: user_decryption_key_uid.into(),
            user_decryption_key_bytes,
        })
    }
}

impl DeCipher for AbeHybridDecipher {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipError> {
        let encrypted_data = request.data.as_ref().ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Message,
                "The decryption request should have encrypted data".to_string(),
            )
        })?;
        let mut header_length_bytes = [0_u8; 4];
        header_length_bytes.copy_from_slice(&encrypted_data[0..4]);
        let encrypted_header_size: usize = u32::from_be_bytes(header_length_bytes) as usize;

        if encrypted_header_size + 4 >= encrypted_data.len() {
            return Err(KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "Bad or corrupted encrypted data".to_string(),
            ))
        }

        let encrypted_header_bytes = &encrypted_data[4..(4 + encrypted_header_size)];
        let encrypted_block = &encrypted_data[(4 + encrypted_header_size)..];

        let user_decryption_key = <<Gpsw<Bls12_381> as AbeScheme>::UserDecryptionKey>::from_bytes(
            &self.user_decryption_key_bytes,
        )
        .map_err(|e| KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string()))?;

        let header_ = decrypt_hybrid_header::<Gpsw<Bls12_381>, Aes256GcmCrypto>(
            &user_decryption_key,
            encrypted_header_bytes,
        )
        .map_err(|e| KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string()))?;

        // check if the user supplied UID as part of the Decrypt request
        // and use that if so
        let uid = if let Some(uid) = &request.authenticated_encryption_additional_data {
            uid
        } else {
            &header_.meta_data.uid
        };

        let clear_text = decrypt_hybrid_block::<
            Gpsw<Bls12_381>,
            Aes256GcmCrypto,
            MAX_CLEAR_TEXT_SIZE,
        >(&header_.symmetric_key, uid, 0, encrypted_block)
        .map_err(|e| KmipError::InvalidKmipValue(ErrorReason::Invalid_Message, e.to_string()))?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            clear_text.len(),
            encrypted_data.len(),
        );
        Ok(DecryptResponse {
            unique_identifier: self.user_decryption_key_uid.clone(),
            data: Some(clear_text),
            correlation_value: None,
        })
    }
}
