#[cfg(not(feature = "fips"))]
use cloudproof::reexport::crypto_core::{
    Ecies, EciesSalsaSealBox, Ed25519PrivateKey, X25519PrivateKey,
};
use cosmian_kmip::kmip::{
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData},
    kmip_types::UniqueIdentifier,
};
use openssl::pkey::{Id, PKey, Private};
use tracing::{debug, trace};
use zeroize::Zeroizing;

#[cfg(not(feature = "fips"))]
use crate::crypto::elliptic_curves::operation::{
    ED25519_PRIVATE_KEY_LENGTH, X25519_PRIVATE_KEY_LENGTH,
};
use crate::{
    crypto::{
        hybrid_encryption::{ecies::ecies_decrypt, rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_decrypt},
        wrap::rsa_oaep_aes_kwp::ckm_rsa_aes_key_unwrap,
    },
    error::KmipUtilsError,
    kmip_utils_bail, DecryptionSystem,
};

/// Decrypt a single block of data encrypted using a ECIES scheme or RSA hybrid system
/// Cannot be used as a stream decipher
pub struct HybridDecryptionSystem {
    private_key: PKey<Private>,
    private_key_uid: Option<String>,
    key_unwrapping: bool,
}

impl HybridDecryptionSystem {
    pub fn new(
        private_key_uid: Option<String>,
        private_key: PKey<Private>,
        key_unwrapping: bool,
    ) -> Self {
        trace!("Instantiated hybrid decryption system for private key id: {private_key_uid:?}");
        Self {
            private_key,
            private_key_uid,
            key_unwrapping,
        }
    }
}

impl DecryptionSystem for HybridDecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        trace!("decrypt");
        let ciphertext = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::NotSupported(
                "the decryption request should contain encrypted data".to_string(),
            )
        })?;

        // Convert the Pkey to a crypto_core curve and perform decryption
        // Note: All conversions below will go once we move to full openssl
        let plaintext = match self.private_key.id() {
            Id::EC => Zeroizing::new(ecies_decrypt(&self.private_key, ciphertext)?),
            Id::RSA => {
                if self.key_unwrapping {
                    Zeroizing::from(ckm_rsa_aes_key_unwrap(&self.private_key, ciphertext)?)
                } else {
                    Zeroizing::from(rsa_oaep_aes_gcm_decrypt(
                        &self.private_key,
                        ciphertext,
                        request.authenticated_encryption_additional_data.as_deref(),
                    )?)
                }
            }
            #[cfg(not(feature = "fips"))]
            Id::ED25519 => {
                let raw_bytes = self.private_key.raw_private_key()?;
                let private_key_bytes: [u8; ED25519_PRIVATE_KEY_LENGTH] = raw_bytes.try_into()?;
                let private_key = Ed25519PrivateKey::try_from_bytes(private_key_bytes)?;
                let private_key = X25519PrivateKey::from_ed25519_private_key(&private_key);
                Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
            }
            #[cfg(not(feature = "fips"))]
            Id::X25519 => {
                let raw_bytes = self.private_key.raw_private_key()?;
                let private_key_bytes: [u8; X25519_PRIVATE_KEY_LENGTH] = raw_bytes.try_into()?;
                let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes)?;
                Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
            }
            x => {
                kmip_utils_bail!("private key id not supported yet: {:?}", x);
            }
        };

        debug!(
            "Decrypted data with user key {:?} of len (plaintext/ciphertext): {}/{}",
            &self.private_key_uid,
            plaintext.len(),
            ciphertext.len(),
        );

        let decrypted_data = DecryptedData {
            metadata: vec![],
            plaintext: plaintext.to_vec(),
        };

        Ok(DecryptResponse {
            unique_identifier: UniqueIdentifier::TextString(
                self.private_key_uid.clone().unwrap_or_default(),
            ),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}
