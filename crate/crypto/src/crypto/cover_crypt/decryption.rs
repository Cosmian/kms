use cosmian_cover_crypt::{
    api::Covercrypt, CleartextHeader, EncryptedHeader, Error, UserSecretKey,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm, Dem, FixedSizeCBytes, Instantiable, Nonce, Secret, SymmetricKey,
};
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use super::user_key::unwrap_user_decryption_key_object;
use crate::{crypto::DecryptionSystem, error::CryptoError};

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct CovercryptDecryption {
    cover_crypt: Covercrypt,
    user_decryption_key_uid: String,
    user_decryption_key_bytes: Zeroizing<Vec<u8>>,
}

impl CovercryptDecryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        user_decryption_key_uid: &str,
        user_decryption_key: &Object,
    ) -> Result<Self, CryptoError> {
        trace!("CovercryptDecryption::instantiate entering");
        let (user_decryption_key_bytes, _attributes) =
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

    // Decrypt a single payload
    fn decrypt(
        &self,
        encrypted_bytes: &[u8],
        ad: Option<&[u8]>,
        user_decryption_key: &UserSecretKey,
    ) -> Result<(CleartextHeader, Zeroizing<Vec<u8>>), CryptoError> {
        let mut de = Deserializer::new(encrypted_bytes);
        let encrypted_header = EncryptedHeader::read(&mut de)?;

        let plaintext_header = encrypted_header
            .decrypt(&self.cover_crypt, user_decryption_key, ad)?
            .ok_or_else(|| {
                Error::OperationNotPermitted("insufficient rights to open encapsulation".to_owned())
            })?;
        let encrypted_header = EncryptedHeader::deserialize(encrypted_bytes)
            .map_err(|e| CryptoError::Kmip(format!("Bad or corrupted encrypted data: {e}")))?;

        let header = encrypted_header
            .decrypt(&self.cover_crypt, user_decryption_key, ad)
            .map_err(|e| CryptoError::Kmip(e.to_string()))?
            .ok_or_else(|| CryptoError::Default("unable to recover header".to_owned()))?;

        let key = SymmetricKey::derive(&header.secret, &[0_u8])?;
        let nonce = Nonce::try_from_slice(encrypted_bytes)?;
        let cleartext = Aes256Gcm::new(&key)
            .decrypt(&nonce, encrypted_bytes, ad)
            .map_err(Error::CryptoCoreError)
            .map(Zeroizing::new)?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            cleartext.len(),
            encrypted_header.length(),
        );

        Ok((plaintext_header, cleartext))
    }

    // Decrypt multiple LEB128-serialized payloads
    // /
    // / The input encrypted data is serialized using LEB128 (bulk mode).
    // / Each chunk of data is decrypted and serialized back to LEB128.
    // /
    // / Bulk encryption / decryption scheme
    // /
    // / ENC request
    // / | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    // /                           <-------------- `nb_chunks` times ------------>
    // /
    // / ENC response
    // / | EH | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (encrypted)
    // /                                <-------------- `nb_chunks` times ------------>
    // /
    // / DEC request
    // / | `nb_chunks` (LEB128) | size(EH + `chunk_data`) (LEB128) | EH | `chunk_data` (encrypted)
    // /                                                             <------ chunk with EH ------>
    // /                          <------------------------ `nb_chunks` times ------------------->
    // /
    // / DEC response
    // / | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    // /                           <------------- `nb_chunks` times ------------->
    // /
    fn bulk_decrypt(
        &self,
        encrypted_bytes: &[u8],
        ad: Option<&[u8]>,
        user_decryption_key: &UserSecretKey,
    ) -> Result<(CleartextHeader, Zeroizing<Vec<u8>>), CryptoError> {
        let mut de = Deserializer::new(encrypted_bytes);
        let mut ser = Serializer::new();

        // number of chunks of encrypted data to decrypt
        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|e| {
                CryptoError::Kmip(format!(
                    "size of vector is too big for architecture: {len} bytes. Error: {e:?}"
                ))
            })?
        };

        let mut cleartext_header = CleartextHeader {
            secret: Secret::default(),
            metadata: vec![0_u8].into(),
        };

        for _ in 0..nb_chunks {
            let chunk_data = de.read_vec_as_ref()?;

            let encrypted_header = EncryptedHeader::deserialize(chunk_data).map_err(|e| {
                CryptoError::Kmip(format!("Bad or corrupted bulk encrypted data: {e}"))
            })?;

            let header = encrypted_header
                .decrypt(&self.cover_crypt, user_decryption_key, ad)
                .map_err(|e| CryptoError::Kmip(e.to_string()))?
                .ok_or_else(|| CryptoError::Default("unable to recover header 147".to_owned()))?;

            cleartext_header = header;

            debug!(
                "Decrypted bulk data with user key {} of len (CT/Enc): {}/{}",
                self.user_decryption_key_uid,
                cleartext_header.length(),
                encrypted_bytes.len(),
            );

            ser.write_vec(
                &cleartext_header.metadata.clone().ok_or_else(|| {
                    CryptoError::Default("unable to recover header 162".to_owned())
                })?,
            )?;
        }

        Ok((cleartext_header, ser.finalize()))
    }
}

impl DecryptionSystem for CovercryptDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, CryptoError> {
        let user_decryption_key = UserSecretKey::deserialize(&self.user_decryption_key_bytes)
            .map_err(|e| {
                CryptoError::Kmip(format!(
                    "cover crypt decipher: failed recovering the user key: {e}"
                ))
            })?;

        let encrypted_bytes = request.data.as_ref().ok_or_else(|| {
            CryptoError::Kmip("The decryption request should contain encrypted data".to_owned())
        })?;

        let ad = request.ad.as_ref().ok_or_else(|| {
            CryptoError::Kmip("The decryption request should contain ad".to_owned())
        })?;

        // let mut de = Deserializer::new(encrypted_bytes);
        // let encrypted_header = EncryptedHeader::read(&mut de)?;
        // println!("USK :{user_decryption_key:?}");

        // let plaintext = encrypted_header
        //     .decrypt(&self.cover_crypt, &user_decryption_key, Some(ad))?
        //     .ok_or_else(|| {
        //         Error::OperationNotPermitted("insufficient rights to open encapsulation".to_owned())
        //     })?;

        let (header, plaintext) = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_decrypt(encrypted_bytes.as_slice(), Some(ad), &user_decryption_key)?
        } else {
            self.decrypt(encrypted_bytes.as_slice(), Some(ad), &user_decryption_key)?
        };

        // Declaring a vector and then zeroizing it is fine since it represents
        // a unique pointer to data on the heap.
        let decrypted_data: Vec<u8> = DecryptedData {
            metadata: header.metadata.unwrap_or_default(),
            plaintext,
        }
        .try_into()?;

        Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.user_decryption_key_uid.clone()),
            data: Some(Zeroizing::from(decrypted_data)),
            correlation_value: None,
        })
    }
}
