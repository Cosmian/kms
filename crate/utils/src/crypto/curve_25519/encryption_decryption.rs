use std::sync::{Arc, Mutex};

use cloudproof::reexport::crypto_core::{
    asymmetric_crypto::{
        curve25519::{X25519KeyPair, X25519PrivateKey, X25519PublicKey},
        DhKeyPair,
    },
    bytes_ser_de::Serializable,
    reexport::rand_core::SeedableRng,
    CsRng,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData, Encrypt, EncryptResponse},
};
use tracing::{debug, trace};

use crate::{
    crypto::ecies::{ecies_decrypt, ecies_encrypt},
    error::{result::CryptoResultHelper, KmipUtilsError},
};
// use super::user_key::unwrap_user_decryption_key_object;
use crate::{DecryptionSystem, EncryptionSystem};

/// Encrypt a single block of data using an hybrid encryption mode
/// Cannot be used as a stream cipher
pub struct EciesEncryption {
    rng: Arc<Mutex<CsRng>>,
    public_key_uid: String,
    public_key: X25519PublicKey,
}

/// Maximum clear text size that can be safely encrypted with AES GCM (using a single random nonce)
pub const MAX_CLEAR_TEXT_SIZE: usize = 1_usize << 30;

impl EciesEncryption {
    pub fn instantiate(public_key_uid: &str, public_key: &Object) -> Result<Self, KmipUtilsError> {
        let rng = CsRng::from_entropy();

        let public_key_bytes = public_key.key_block()?.key_bytes()?;
        let public_key = X25519PublicKey::try_from_bytes(&public_key_bytes)?;

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
        let authenticated_encryption_additional_data = &request
            .authenticated_encryption_additional_data
            .clone()
            .unwrap_or_default();

        let plaintext = request.data.clone().context("missing plaintext data")?;

        let mut rng = self.rng.lock().unwrap();

        let ciphertext = ecies_encrypt::<
            CsRng,
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            &mut rng,
            &self.public_key,
            &plaintext,
            None,
            request.authenticated_encryption_additional_data.as_deref(),
        )
        .unwrap();

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
            authenticated_encryption_tag: Some(authenticated_encryption_additional_data.clone()),
        })
    }
}

/// Decrypt a single block of data encrypted using ECIES
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
        let private_key_bytes = private_key.key_block()?.key_bytes()?;
        let private_key = X25519PrivateKey::try_from_bytes(&private_key_bytes)?;

        debug!("Instantiated ECIES decipher for user decryption key id: {private_key_uid}");

        Ok(Self {
            private_key_uid: private_key_uid.into(),
            private_key,
        })
    }
}

impl DecryptionSystem for EciesDecryption {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        let encrypted_bytes = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::NotSupported(
                "the decryption request should contain encrypted data".to_string(),
            )
        })?;

        // Decrypt the encrypted message
        let plaintext = ecies_decrypt::<
            X25519KeyPair,
            { X25519KeyPair::PUBLIC_KEY_LENGTH },
            { X25519KeyPair::PRIVATE_KEY_LENGTH },
        >(
            &self.private_key,
            encrypted_bytes,
            None,
            request.authenticated_encryption_additional_data.as_deref(),
        )
        .unwrap();

        debug!(
            "Decrypted data with user key {} of len (CT/Enc): {}/{}",
            &self.private_key_uid,
            plaintext.len(),
            encrypted_bytes.len(),
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
