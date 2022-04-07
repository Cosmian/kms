use std::convert::TryFrom;

use cosmian_crypto_base::{
    entropy::gen_bytes,
    symmetric_crypto::{
        aes_256_gcm_pure::{
            self, decrypt_in_place_detached, encrypt_in_place_detached, CsRng, Key, Nonce,
            KEY_LENGTH,
        },
        Key as _, Nonce as _,
    },
};
use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse, ErrorReason},
    kmip_types::{Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType},
};

use crate::{error::LibError, result::LibResult, DeCipher, EnCipher};

/// Generate AES symmetric key for FPE usage: AES-256 bits key
/// `cryptographic_length` is a value in bytes
pub fn create_aes_symmetric_key(cryptographic_length: Option<usize>) -> LibResult<Object> {
    let aes_key_len = cryptographic_length.unwrap_or(KEY_LENGTH);
    // Generate symmetric key
    let mut symmetric_key = vec![0_u8; aes_key_len];
    let symmetric_key_len = i32::try_from(symmetric_key.len()).map_err(|_e| {
        LibError::CryptographicError("AES".to_string(), "Invalid key len".to_string())
    })?;
    gen_bytes(&mut symmetric_key[..])?;

    Ok(Object::SymmetricKey {
        key_block: KeyBlock {
            cryptographic_algorithm: CryptographicAlgorithm::AES,
            key_format_type: KeyFormatType::TransparentSymmetricKey,
            key_compression_type: None,
            key_value: KeyValue::PlainText {
                key_material: KeyMaterial::TransparentSymmetricKey { key: symmetric_key },
                attributes: Some(Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(symmetric_key_len),
                    cryptographic_usage_mask: Some(CryptographicUsageMask::Encrypt),
                    key_format_type: Some(KeyFormatType::TransparentSymmetricKey),
                    ..Attributes::new(ObjectType::SymmetricKey)
                }),
            },
            cryptographic_length: symmetric_key_len,
            key_wrapping_data: None,
        },
    })
}

pub struct AesGcmCipher {
    key_uid: String,
    symmetric_key_key_block: KeyBlock,
}

impl AesGcmCipher {
    pub fn instantiate(uid: &str, symmetric_key: &Object) -> LibResult<AesGcmCipher> {
        let key_block = match symmetric_key {
            Object::SymmetricKey { key_block } => key_block.clone(),
            _ => return Err(LibError::Error("Expected a KMIP Symmetric Key".to_owned())),
        };
        Ok(AesGcmCipher {
            key_uid: uid.into(),
            symmetric_key_key_block: key_block,
        })
    }
}

impl EnCipher for AesGcmCipher {
    fn encrypt(&self, request: &Encrypt) -> LibResult<EncryptResponse> {
        let uid = request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let correlation_value = request.correlation_value.clone().or_else(|| {
            if uid.is_empty() {
                None
            } else {
                Some(uid.clone())
            }
        });

        let mut data = match &request.data {
            None => {
                return Ok(EncryptResponse {
                    unique_identifier: self.key_uid.clone(),
                    data: None,
                    iv_counter_nonce: None,
                    correlation_value,
                    authenticated_encryption_tag: None,
                })
            }
            Some(data) => data.clone(),
        };

        // recover key
        let key_bytes = &self.symmetric_key_key_block.key_bytes()?;
        let key = Key::try_from_slice(key_bytes.as_slice())
            .map_err(|e| LibError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        // supplied Nonce or fresh
        let nonce = match request.iv_counter_nonce.as_ref() {
            Some(v) => Nonce::try_from_slice(v)?,
            None => {
                let mut cs_rng = CsRng::default();
                cs_rng.generate_nonce()
            }
        };

        // Additional data
        let mut ad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                ad.extend(&(block_number as usize).to_le_bytes());
            }
        }

        // now encrypt
        let tag = encrypt_in_place_detached(
            &key,
            &mut data,
            &nonce,
            if ad.is_empty() { None } else { Some(&ad) },
        )?;

        Ok(EncryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(data.clone()),
            iv_counter_nonce: Some(nonce.as_bytes()),
            correlation_value,
            authenticated_encryption_tag: Some(tag),
        })
    }
}

impl DeCipher for AesGcmCipher {
    fn decrypt(&self, request: &Decrypt) -> LibResult<DecryptResponse> {
        let uid = request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let correlation_value = if uid.is_empty() {
            None
        } else {
            Some(uid.clone())
        };

        let mut bytes = match &request.data {
            None => {
                return Ok(DecryptResponse {
                    unique_identifier: self.key_uid.clone(),
                    data: None,
                    correlation_value,
                })
            }
            Some(ciphertext) => ciphertext.clone(),
        };

        // recover key
        let key_bytes = &self.symmetric_key_key_block.key_bytes()?;
        let key: Key = aes_256_gcm_pure::Key::try_from_slice(key_bytes.as_slice())
            .map_err(|e| LibError::KmipError(ErrorReason::Cryptographic_Failure, e.to_string()))?;

        //recover tag
        let tag = request
            .authenticated_encryption_tag
            .clone()
            .unwrap_or_default();

        //recover Nonce
        let nonce_bytes = request.iv_counter_nonce.clone().ok_or_else(|| {
            LibError::KmipError(
                ErrorReason::Cryptographic_Failure,
                "the nonce is mandatory for AES GCM".to_string(),
            )
        })?;
        let nonce = aes_256_gcm_pure::Nonce::try_from_slice(nonce_bytes.as_slice())?;

        // Additional data
        let mut ad = uid;
        // For some unknown reason the block number is appended in little-endian mode
        // see `Block` in crypto_base
        if let Some(cp) = &request.cryptographic_parameters {
            if let Some(block_number) = cp.initial_counter_value {
                ad.extend(&(block_number as usize).to_le_bytes());
            }
        }

        decrypt_in_place_detached(
            &key,
            &mut bytes,
            &tag,
            &nonce,
            if ad.is_empty() { None } else { Some(&ad) },
        )?;

        Ok(DecryptResponse {
            unique_identifier: self.key_uid.clone(),
            data: Some(bytes.clone()),
            correlation_value,
        })
    }
}

#[cfg(test)]
mod tests {
    use cosmian_crypto_base::symmetric_crypto::{aes_256_gcm_pure::CsRng, Nonce as _};
    use cosmian_kmip::kmip::{
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
    };

    use super::{create_aes_symmetric_key, AesGcmCipher};
    use crate::{DeCipher, EnCipher};

    #[test]
    pub fn test_aes() {
        let key = create_aes_symmetric_key(None).unwrap();
        let aes = AesGcmCipher::instantiate("blah", &key).unwrap();
        let mut rng = CsRng::new();
        let data = rng.generate_random_bytes(42);
        let uid = rng.generate_random_bytes(32);
        let nonce = rng.generate_nonce();
        // encrypt
        let enc_res = aes
            .encrypt(&Encrypt {
                unique_identifier: Some("blah".to_owned()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    initial_counter_value: Some(42),
                    ..Default::default()
                }),
                data: Some(data.clone()),
                iv_counter_nonce: Some(nonce.as_bytes()),
                correlation_value: None,
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: Some(uid.clone()),
            })
            .unwrap();
        // decrypt
        let dec_res = aes
            .decrypt(&Decrypt {
                unique_identifier: Some("blah".to_owned()),
                cryptographic_parameters: Some(CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    initial_counter_value: Some(42),
                    ..Default::default()
                }),
                data: Some(enc_res.data.unwrap()),
                iv_counter_nonce: Some(enc_res.iv_counter_nonce.unwrap()),
                init_indicator: None,
                final_indicator: None,
                authenticated_encryption_additional_data: Some(uid),
                authenticated_encryption_tag: Some(enc_res.authenticated_encryption_tag.unwrap()),
            })
            .unwrap();

        assert_eq!(&data, &dec_res.data.unwrap());
    }
}
