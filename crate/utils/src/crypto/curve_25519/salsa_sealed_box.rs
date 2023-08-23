//! ECIES encryption and decryption
//! This module implements the NaCL Salsa Sealed Box encryption scheme, also found in libsodium.
//! It is an hybrid encryption scheme using X25519 for the KEM and Salsa 20 Poly1305 for the DEM.
//! This scheme does not support additional authenticated data.

use std::sync::{Arc, Mutex};

use cloudproof::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesSalsaSealBox, FixedSizeCBytes,
    X25519PrivateKey, X25519PublicKey,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData, Encrypt, EncryptResponse},
};
use tracing::{debug, trace};

use crate::{
    crypto::curve_25519::{CURVE_25519_PRIVATE_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH},
    error::{result::CryptoResultHelper, KmipUtilsError},
    DecryptionSystem, EncryptionSystem,
};

/// Encrypt a single block of data using a Salsa Sealed Box
/// Cannot be used as a stream cipher
pub struct EciesEncryption {
    rng: Arc<Mutex<CsRng>>,
    public_key_uid: String,
    public_key: X25519PublicKey,
}

impl EciesEncryption {
    pub fn instantiate(public_key_uid: &str, public_key: &Object) -> Result<Self, KmipUtilsError> {
        let rng = CsRng::from_entropy();

        let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] = public_key
            .key_block()?
            .key_bytes()?
            .try_into()
            .map_err(|_| {
                KmipUtilsError::ConversionError("invalid X25519 public key length".to_string())
            })?;
        let public_key = X25519PublicKey::try_from_bytes(public_key_bytes)?;

        trace!("Instantiated hybrid ECIES encipher for public key id: {public_key_uid}");

        Ok(Self {
            rng: Arc::new(Mutex::new(rng)),
            public_key_uid: public_key_uid.into(),
            public_key,
        })
    }
}

impl EncryptionSystem for EciesEncryption {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
        if request
            .authenticated_encryption_additional_data
            .as_deref()
            .is_some()
        {
            return Err(KmipUtilsError::NotSupported(
                "ECIES Sealed Box does not support additional authenticated data".to_string(),
            ))
        }

        let plaintext = request.data.clone().context("missing plaintext data")?;

        let mut rng = self.rng.lock().unwrap();

        let ciphertext = EciesSalsaSealBox::encrypt(&mut *rng, &self.public_key, &plaintext, None)?;

        debug!(
            "Encrypted data with public key {} of len (CT/Enc): {}/{}",
            &self.public_key_uid,
            plaintext.len(),
            ciphertext.len(),
        );
        Ok(EncryptResponse {
            unique_identifier: self.public_key_uid.clone(),
            data: Some(ciphertext),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }
}

/// Decrypt a single block of data encrypted using a Salsa Sealed Box
/// Cannot be used as a stream decipher
pub struct EciesDecryption {
    private_key_uid: String,
    private_key: X25519PrivateKey,
}

impl EciesDecryption {
    pub fn instantiate(
        private_key_uid: &str,
        private_key: &Object,
    ) -> Result<Self, KmipUtilsError> {
        let private_key_bytes: [u8; CURVE_25519_PRIVATE_KEY_LENGTH] = private_key
            .key_block()?
            .key_bytes()?
            .try_into()
            .map_err(|_| {
                KmipUtilsError::ConversionError(
                    "invalid Curve 25519 private key length".to_string(),
                )
            })?;
        let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes)?;

        debug!("Instantiated ECIES decipher for user decryption key id: {private_key_uid}");

        Ok(Self {
            private_key_uid: private_key_uid.into(),
            private_key,
        })
    }
}

impl DecryptionSystem for EciesDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        let ciphertext = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::NotSupported(
                "the decryption request should contain encrypted data".to_string(),
            )
        })?;

        // Decrypt the encrypted message
        let plaintext = EciesSalsaSealBox::decrypt(&self.private_key, ciphertext, None)?;

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.private_key_uid,
            plaintext.len(),
            ciphertext.len(),
        );

        let decrypted_data = DecryptedData {
            metadata: vec![],
            plaintext,
        };

        Ok(DecryptResponse {
            unique_identifier: self.private_key_uid.clone(),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}
