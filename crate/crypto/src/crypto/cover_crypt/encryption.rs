use cosmian_cover_crypt::{AccessPolicy, MasterPublicKey, api::Covercrypt, traits::KemAc};
use cosmian_crypto_core::{
    Aes256Gcm, Dem, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::zeroize::Zeroizing,
};
use cosmian_kmip::{
    DataToEncrypt,
    kmip_2_1::{
        kmip_objects::Object,
        kmip_operations::{Encrypt, EncryptResponse},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier},
    },
};
use tracing::{debug, trace};

use crate::{crypto::EncryptionSystem, error::CryptoError};

/// Encrypt a single block of data using a KEM-DEM cryptosystem
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
    /// The input plaintext data is serialized using LEB128 (bulk mode).  Each
    /// chunk of data is encrypted and serialized back to LEB128.
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
        mpk: &MasterPublicKey,
        ptx: &[u8],
        ad: Option<&[u8]>,
        ap: &AccessPolicy,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut de = Deserializer::new(ptx);
        let mut ser = Serializer::new();

        let (seed, enc) = self.cover_crypt.encaps(mpk, ap)?;
        let key = SymmetricKey::derive(&seed, b"Covercrypt AEAD key")?;
        let enc = enc.serialize()?;

        trace!("CoverCryptEncryption: encrypt: encryption_policy: {ap:?}",);

        let nb_chunks = {
            let len = de.read_leb128_u64()?;
            ser.write_leb128_u64(len)?;
            usize::try_from(len).map_err(|e| {
                CryptoError::Kmip(format!(
                    "size of vector is too big for architecture: {len} bytes. Error: {e:?}"
                ))
            })?
        };

        // Encrypt each chunk and serialize it along with a copy of the
        // Covecrypt encapsulation.
        for _ in 0..nb_chunks {
            let ptx = de.read_vec_as_ref()?;
            let ctx = self.aead_encrypt(&key, ptx, ad)?;
            let res = [&**enc, &ctx].concat();
            ser.write_vec(&res)?;
        }

        Ok(ser.finalize().to_vec())
    }

    fn single_encrypt(
        &self,
        mpk: &MasterPublicKey,
        ptx: &[u8],
        ad: Option<&[u8]>,
        ap: &AccessPolicy,
    ) -> Result<Vec<u8>, CryptoError> {
        let (seed, enc) = self.cover_crypt.encaps(mpk, ap)?;
        let key = SymmetricKey::derive(&seed, b"Covercrypt AEAD key")?;
        let enc = enc.serialize()?;
        trace!("CoverCryptEncryption: encrypt: encryption_policy: {ap:?}",);
        let ctx = self.aead_encrypt(&key, ptx, ad)?;
        Ok([&**enc, &ctx].concat())
    }

    fn aead_encrypt(
        &self,
        key: &SymmetricKey<{ Aes256Gcm::KEY_LENGTH }>,
        ptx: &[u8],
        ad: Option<&[u8]>,
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = Nonce::new(&mut *self.cover_crypt.rng());
        let ctx = Aes256Gcm::new(key).encrypt(&nonce, ptx, ad)?;
        let res = [&nonce.0, &*ctx].concat();
        debug!(
            "Encrypted data with auth data {:?} of len (Plain/Enc): {}/{}",
            ad,
            ptx.len(),
            res.len(),
        );
        Ok(res)
    }
}

impl EncryptionSystem for CoverCryptEncryption {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, CryptoError> {
        let ad = request.authenticated_encryption_additional_data.as_deref();

        trace!("CoverCryptEncryption: encrypt: authenticated_encryption_additional_data: {ad:?}",);

        let encrypted_data =
            request
                .data
                .as_deref()
                .map(|data| -> Result<_, _> {
                    let ptx = DataToEncrypt::try_from_bytes(data)?;
                    let mpk = MasterPublicKey::deserialize(self.public_key_bytes.as_slice())
                        .map_err(|e| {
                            CryptoError::Kmip(format!(
                                "Covercrypt encrypt: failed recovering the master public key: {e}"
                            ))
                        })?;

                    let ap = AccessPolicy::parse(ptx.encryption_policy.as_deref().ok_or_else(
                        || CryptoError::Kmip("encryption policy missing".to_owned()),
                    )?)?;

                    if let Some(CryptographicParameters {
                        cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCryptBulk),
                        ..
                    }) = request.cryptographic_parameters
                    {
                        self.bulk_encrypt(&mpk, &ptx.plaintext, ad, &ap)
                    } else {
                        self.single_encrypt(&mpk, &ptx.plaintext, ad, &ap)
                    }
                })
                .transpose()?;

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.public_key_uid.clone()),
            data: encrypted_data,
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: ad.map(<[u8]>::to_vec),
        })
    }
}
