use cloudproof::reexport::{
    cover_crypt::{
        abe_policy::{AccessPolicy, Policy},
        core::SYM_KEY_LENGTH,
        Covercrypt, EncryptedHeader, MasterPublicKey,
    },
    crypto_core::{
        bytes_ser_de::{Deserializer, Serializable, Serializer},
        SymmetricKey,
    },
};
use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse, ErrorReason},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
    },
};
use tracing::{debug, trace};

use crate::{
    crypto::{
        cover_crypt::attributes::policy_from_attributes, generic::data_to_encrypt::DataToEncrypt,
    },
    error::KmipUtilsError,
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

    /// Encrypt multiple LEB128-serialized payloads
    ///
    /// The input plaintext data is serialized using LEB128 (bulk mode).
    /// Each chunk of data is encrypted and serialized back to LEB128.
    fn bulk_encrypt(
        &self,
        plaintext: &[u8],
        aead: Option<&[u8]>,
        symmetric_key: &SymmetricKey<SYM_KEY_LENGTH>,
    ) -> Result<Vec<u8>, KmipUtilsError> {
        let mut de = Deserializer::new(plaintext);
        let mut ser = Serializer::new();

        // number of chunks of plaintext data to encrypt
        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|_| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    format!("size of vector is too big for architecture: {len} bytes"),
                )
            })?
        };

        // encrypt every chunk and serialize them
        for _ in 0..nb_chunks {
            let chunk_data = de.read_vec_as_ref()?;
            let encrypted_block = self.encrypt(chunk_data, aead, symmetric_key)?;
            ser.write_vec(&encrypted_block)?;
        }

        Ok(ser.finalize().to_vec())
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
                .map(<[u8]>::to_vec),
        })
    }
}
