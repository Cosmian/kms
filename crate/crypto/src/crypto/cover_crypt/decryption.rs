use cosmian_cover_crypt::{api::Covercrypt, CleartextHeader, EncryptedHeader, UserSecretKey};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable, Serializer};
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

    /// Decrypt a single payload
    fn decrypt(
        &self,
        encrypted_bytes: &[u8],
        ad: Option<&[u8]>,
        user_decryption_key: &UserSecretKey,
    ) -> Result<(CleartextHeader, Zeroizing<Vec<u8>>), CryptoError> {
        let mut de = Deserializer::new(encrypted_bytes);
        let encrypted_header = EncryptedHeader::read(&mut de)
            .map_err(|e| CryptoError::Kmip(format!("Bad or corrupted encrypted data: {e}")))?;
        println!(
            "{:?}",
            encrypted_header.decrypt(&self.cover_crypt, user_decryption_key, ad)?
        );

        let header = encrypted_header
            .decrypt(&self.cover_crypt, user_decryption_key, ad)
            .map_err(|e| CryptoError::Kmip(e.to_string()))?
            .ok_or_else(|| CryptoError::Default("unable to recover NO BULK header".to_owned()))?;

        let cleartext = header.serialize()?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.user_decryption_key_uid,
            cleartext.len(),
            encrypted_bytes.len(),
        );

        Ok((header, cleartext))
    }

    /// Decrypt multiple LEB128-serialized payloads
    ///
    /// The input encrypted data is serialized using LEB128 (bulk mode).
    /// Each chunk of data is decrypted and serialized back to LEB128.
    ///
    /// Bulk encryption / decryption scheme
    ///
    /// ENC request
    /// | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    ///                           <-------------- `nb_chunks` times ------------>
    ///
    /// ENC response
    /// | EH | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (encrypted)
    ///                                <-------------- `nb_chunks` times ------------>
    ///
    /// DEC request
    /// | `nb_chunks` (LEB128) | size(EH + `chunk_data`) (LEB128) | EH | `chunk_data` (encrypted)
    ///                                                             <------ chunk with EH ------>
    ///                          <------------------------ `nb_chunks` times ------------------->
    ///
    /// DEC response
    /// | `nb_chunks` (LEB128) | `chunk_size` (LEB128) | `chunk_data` (plaintext)
    ///                           <------------- `nb_chunks` times ------------->
    ///
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

        let (mut h, mut c) = (
            CleartextHeader {
                secret: cosmian_crypto_core::Secret::new(),
                metadata: None,
            },
            Zeroizing::from(vec![0_u8]),
        );
        for _ in 0..nb_chunks {
            let chunk_data = de.read_vec_as_ref()?;

            let (encrypted_header, encrypted_block) = {
                let mut de_chunk = Deserializer::new(chunk_data);
                let encrypted_header = EncryptedHeader::read(&mut de_chunk).map_err(|e| {
                    CryptoError::Kmip(format!("Bad or corrupted bulk encrypted data: {e}"))
                })?;
                let encrypted_block = de_chunk.finalize();
                (encrypted_header, encrypted_block)
            };

            let header = encrypted_header
                .decrypt(&self.cover_crypt, user_decryption_key, ad)
                .map_err(|e| CryptoError::Kmip(e.to_string()))?
                .ok_or_else(|| CryptoError::Default("unable to recover BULK header".to_owned()))?;

            let cleartext = header.serialize()?;

            debug!(
                "Decrypted bulk data with user key {} of len (CT/Enc): {}/{}",
                self.user_decryption_key_uid,
                cleartext.len(),
                encrypted_block.len(),
            );

            (h, c) = (header, cleartext);
        }

        Ok((h, c))
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

        let (header, plaintext) = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_decrypt(
                encrypted_bytes.as_slice(),
                request.ad.as_deref(),
                &user_decryption_key,
            )?
        } else {
            self.decrypt(
                encrypted_bytes.as_slice(),
                request.ad.as_deref(),
                &user_decryption_key,
            )?
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
