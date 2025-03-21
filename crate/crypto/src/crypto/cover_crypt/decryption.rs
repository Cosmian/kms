use cosmian_cover_crypt::{api::Covercrypt, traits::KemAc, Error, UserSecretKey, XEnc};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm, Dem, FixedSizeCBytes, Instantiable, Nonce, SymmetricKey,
};
use cosmian_kmip::kmip_2_1::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse},
    kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
};
use tracing::{debug, trace};
use zeroize::Zeroizing;

use super::user_key::unwrap_user_decryption_key_object;
use crate::{
    crypto::DecryptionSystem,
    error::{result::CryptoResult, CryptoError},
};

/// Decrypt a single block of data encrypted using an hybrid encryption mode
/// Cannot be used as a stream decipher
pub struct CovercryptDecryption {
    cover_crypt: Covercrypt,
    usk_uid: String,
    usk_bytes: Zeroizing<Vec<u8>>,
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
            usk_uid: user_decryption_key_uid.into(),
            usk_bytes: user_decryption_key_bytes,
        })
    }

    fn single_decrypt(
        &self,
        encrypted_bytes: &[u8],
        ad: Option<&[u8]>,
        usk: &UserSecretKey,
    ) -> CryptoResult<Zeroizing<Vec<u8>>> {
        trace!("CovercryptDecryption: decrypt: ad: {ad:?}");

        let mut de = Deserializer::new(encrypted_bytes);

        trace!(
            "CovercryptDecryption: encrypted_bytes len: {}",
            encrypted_bytes.len()
        );

        let enc = XEnc::read(&mut de)?;

        trace!("encrypted_header parsed");

        let seed = self.cover_crypt.decaps(usk, &enc)?.ok_or_else(|| {
            Error::OperationNotPermitted("insufficient rights to open encapsulation".to_owned())
        })?;

        let key = SymmetricKey::derive(&seed, b"Covercrypt AEAD key")?;
        // The rest of the bytes is the encrypted payload.
        let ctx = de.finalize();
        let ptx = aead_decrypt(&key, &ctx, ad)?;

        debug!(
            "Decrypted data with user key {} of len (Plain/Enc): {}/{}",
            &self.usk_uid,
            ptx.len(),
            enc.length(),
        );

        Ok(ptx)
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
        usk: &UserSecretKey,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let mut de = Deserializer::new(encrypted_bytes);
        let mut ser = Serializer::new();

        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|e| {
                CryptoError::Kmip(format!(
                    "size of vector is too big for architecture: {len} bytes. Error: {e:?}"
                ))
            })?
        };

        for _ in 0..nb_chunks {
            let ctx = de.read_vec_as_ref()?;
            // TODO: the encapsulation is opened each time here while its
            // bulk-encrypt counterpart associates the same encapsulation to
            // each DEM ciphertext. This incurs a significant performance
            // penalty and must be addressed. However, since the Covercrypt bulk
            // data system must be replaced by the generic one, I propose to
            // deal with both issues at once in a later time.
            let ptx = self.single_decrypt(ctx, ad, usk)?;
            ser.write_vec(&ptx)?;
        }

        Ok(ser.finalize())
    }
}

impl DecryptionSystem for CovercryptDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, CryptoError> {
        let usk = UserSecretKey::deserialize(&self.usk_bytes).map_err(|e| {
            CryptoError::Kmip(format!(
                "cover crypt decrypt: failed recovering the user key: {e}"
            ))
        })?;

        let ctx = request.data.as_ref().ok_or_else(|| {
            CryptoError::Kmip("The decryption request should contain encrypted data".to_owned())
        })?;

        let ptx = if let Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
            ..
        }) = request.cryptographic_parameters
        {
            self.bulk_decrypt(
                ctx.as_slice(),
                request.authenticated_encryption_additional_data.as_deref(),
                &usk,
            )?
        } else {
            self.single_decrypt(
                ctx.as_slice(),
                request.authenticated_encryption_additional_data.as_deref(),
                &usk,
            )?
        };

        Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.usk_uid.clone()),
            data: Some(ptx),
            correlation_value: None,
        })
    }
}

fn aead_decrypt(
    key: &SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>,
    ctx: &[u8],
    ad: Option<&[u8]>,
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    #![allow(clippy::indexing_slicing)]
    if ctx.len() < Aes256Gcm::NONCE_LENGTH {
        return Err(CryptoError::Default("encrypted block too short".to_owned()));
    }
    let nonce = Nonce::try_from_slice(&ctx[..Aes256Gcm::NONCE_LENGTH])?;
    Aes256Gcm::new(key)
        .decrypt(&nonce, &ctx[Aes256Gcm::NONCE_LENGTH..], ad)
        .map(Zeroizing::new)
        .map_err(CryptoError::from)
}
