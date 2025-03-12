use cosmian_cover_crypt::{api::Covercrypt, AccessPolicy, EncryptedHeader, MasterPublicKey};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::zeroize::Zeroizing,
    Aes256Gcm, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
};
use cosmian_kmip::{
    kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
    DataToEncrypt,
};
use tracing::{debug, trace};

use crate::{crypto::EncryptionSystem, error::CryptoError};

const SYM_KEY_LENGTH: usize = 32;
/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct CoverCryptEncryption {
    cover_crypt: Covercrypt,
    public_key_uid: String,
    public_key_bytes: Zeroizing<Vec<u8>>,
}

impl CoverCryptEncryption {
    pub fn instantiate(
        cover_crypt: Covercrypt,
        public_key_uid: &str,
        public_key: &Object,
    ) -> Result<Self, CryptoError> {
        let (public_key_bytes, _) = public_key.key_block()?.key_bytes_and_attributes()?;

        trace!("Instantiated hybrid Covercrypt encipher for public key id: {public_key_uid}");

        Ok(Self {
            cover_crypt,
            public_key_uid: public_key_uid.into(),
            public_key_bytes,
        })
    }

    /// Encrypt multiple LEB128-serialized payloads
    ///
    /// The input plaintext data is serialized using LEB128 (bulk mode).
    /// Each chunk of data is encrypted and serialized back to LEB128.
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
    fn bulk_encrypt(
        &self,
        encrypted_header: &[u8],
        plaintext: &[u8],
        ad: Option<&[u8]>,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut de = Deserializer::new(plaintext);
        let mut ser = Serializer::new();

        // number of chunks of plaintext data to encrypt
        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|e| {
                CryptoError::Kmip(format!(
                    "size of vector is too big for architecture: {len} bytes. Error: {e:?}"
                ))
            })?
        };

        // encrypt each chunk and serialize it
        // a copy of the encrypted header is also serialized, prepending the chunk
        for _ in 0..nb_chunks {
            let chunk_data = de.read_vec_as_ref()?;
            let mut encrypted_block = self.encrypt(chunk_data, ad, symmetric_key)?;
            let mut chunk = encrypted_header.to_vec();
            chunk.append(&mut encrypted_block);
            ser.write_vec(&chunk)?;
        }

        Ok(ser.finalize().to_vec())
    }

    fn encrypt(
        &self,
        plaintext: &[u8],
        ad: Option<&[u8]>,
        symmetric_key: &SymmetricKey<{ SYM_KEY_LENGTH }>,
    ) -> Result<Vec<u8>, CryptoError> {
        // Encrypt the data
        let aes256gcm = Aes256Gcm::new(symmetric_key);
        let nonce = Nonce::new(&mut *self.cover_crypt.rng());
        let mut ciphertext = aes256gcm.encrypt(&nonce, plaintext, ad)?;
        let mut res =
            Vec::with_capacity(plaintext.len() + Aes256Gcm::MAC_LENGTH + Aes256Gcm::NONCE_LENGTH);
        res.extend(nonce.0);
        res.append(&mut ciphertext);
        debug!(
            "Encrypted data with auth data {:?} of len (Plain/Enc): {}/{}",
            ad,
            plaintext.len(),
            res.len(),
        );
        Ok(res)
    }
}

impl EncryptionSystem for CoverCryptEncryption {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, CryptoError> {
        let authenticated_encryption_additional_data =
            request.authenticated_encryption_additional_data.as_deref();

        trace!(
            "CoverCryptEncryption: encrypt: authenticated_encryption_additional_data: \
             {authenticated_encryption_additional_data:?}",
        );
        let data_to_encrypt = DataToEncrypt::try_from_bytes(
            request
                .data
                .as_deref()
                .ok_or_else(|| CryptoError::Kmip("Missing data to encrypt".to_owned()))?,
        )?;

        let public_key =
            MasterPublicKey::deserialize(self.public_key_bytes.as_slice()).map_err(|e| {
                CryptoError::Kmip(format!(
                    "cover crypt encrypt: failed recovering the public key: {e}"
                ))
            })?;

        let encryption_policy_string = data_to_encrypt
            .encryption_policy
            .as_deref()
            .ok_or_else(|| CryptoError::Kmip("encryption policy missing".to_owned()))?;
        trace!(
            "CoverCryptEncryption: encrypt: encryption_policy_string: {encryption_policy_string}",
        );
        // Generate a symmetric key and encrypt the header
        let (secret, encrypted_header) = EncryptedHeader::generate(
            &self.cover_crypt,
            &public_key,
            &AccessPolicy::parse(encryption_policy_string)?,
            data_to_encrypt.header_metadata.as_deref(),
            authenticated_encryption_additional_data,
        )
        .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        let mut encrypted_header = encrypted_header
            .serialize()
            .map_err(|e| CryptoError::Kmip(e.to_string()))?;

        let symmetric_key = SymmetricKey::derive(
            &secret,
            authenticated_encryption_additional_data.unwrap_or_default(),
        )?;

        let encrypted_data = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_encrypt(
                &encrypted_header,
                &data_to_encrypt.plaintext,
                authenticated_encryption_additional_data,
                &symmetric_key,
            )?
        } else {
            let mut encrypted_data = self.encrypt(
                &data_to_encrypt.plaintext,
                authenticated_encryption_additional_data,
                &symmetric_key,
            )?;
            debug!(
                "Encrypted bytes len: {}, Encrypted header len: {}, Encrypted data len: {}",
                encrypted_header.len() + encrypted_data.len(),
                encrypted_header.len(),
                encrypted_data.len(),
            );
            encrypted_header.append(&mut encrypted_data);
            encrypted_header.to_vec()
        };

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.public_key_uid.clone()),
            data: Some(encrypted_data),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: authenticated_encryption_additional_data
                .map(<[u8]>::to_vec),
        })
    }
}
