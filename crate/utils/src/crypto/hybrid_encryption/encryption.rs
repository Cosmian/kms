#[cfg(not(feature = "fips"))]
use std::sync::{Arc, Mutex};

#[cfg(not(feature = "fips"))]
use cloudproof::reexport::crypto_core::{
    reexport::rand_core::SeedableRng, CsRng, Ecies, EciesSalsaSealBox, Ed25519PublicKey,
    X25519PublicKey,
};
use cosmian_kmip::kmip::{
    kmip_operations::{Encrypt, EncryptResponse},
    kmip_types::UniqueIdentifier,
};
use openssl::{
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::{debug, trace};

use super::{ecies::ecies_encrypt, rsa_oaep_aes_gcm::rsa_oaep_aes_gcm_encrypt};
#[cfg(not(feature = "fips"))]
use crate::crypto::curve_25519::operation::{ED25519_PUBLIC_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH};
use crate::{
    crypto::wrap::rsa_oaep_aes_kwp::ckm_rsa_aes_key_wrap,
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail, EncryptionSystem,
};

/// Encrypt a single block of data using a Salsa Sealed Box
/// Cannot be used as a stream cipher
pub struct HybridEncryptionSystem {
    public_key_uid: String,
    public_key: PKey<Public>,
    key_wrapping: bool,
}

impl HybridEncryptionSystem {
    pub fn new(public_key_uid: &str, public_key: PKey<Public>, key_wrapping: bool) -> Self {
        trace!("Instantiated hybrid encryption system for public key id: {public_key_uid}");

        Self {
            public_key_uid: public_key_uid.into(),
            public_key,
            key_wrapping,
        }
    }

    pub fn instantiate_with_certificate(
        certificate_uid: &str,
        certificate_value: &[u8],
        key_wrapping: bool,
    ) -> Result<Self, KmipUtilsError> {
        debug!("instantiate_with_certificate: entering");

        debug!("instantiate_with_certificate: parsing");
        let cert = X509::from_der(certificate_value)
            .map_err(|e| KmipUtilsError::ConversionError(format!("invalid X509 DER: {e:?}")))?;

        debug!("instantiate_with_certificate: get the public key of the certificate");
        let public_key = cert.public_key().map_err(|e| {
            KmipUtilsError::ConversionError(format!("invalid public key: error: {e:?}"))
        })?;

        Ok(Self {
            public_key_uid: certificate_uid.into(),
            public_key,
            key_wrapping,
        })
    }
}

impl EncryptionSystem for HybridEncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
        let plaintext = request.data.clone().context("missing plaintext data")?;

        #[cfg(not(feature = "fips"))]
        let rng = Arc::new(Mutex::new(CsRng::from_entropy()));
        #[cfg(not(feature = "fips"))]
        let mut rng = rng.lock().expect("RNG lock poisoned");

        // Convert the Pkey to a crypto_core curve and perform emcryption
        // Note: All conversions below will go once we move to full openssl
        let id = self.public_key.id();
        let ciphertext: Vec<u8> = match id {
            Id::EC => ecies_encrypt(&self.public_key, &plaintext)?,
            Id::RSA => {
                if self.key_wrapping {
                    ckm_rsa_aes_key_wrap(self.public_key.clone(), &plaintext)?
                } else {
                    rsa_oaep_aes_gcm_encrypt(
                        self.public_key.clone(),
                        &plaintext,
                        request.authenticated_encryption_additional_data.as_deref(),
                    )?
                }
            }
            #[cfg(not(feature = "fips"))]
            Id::ED25519 => {
                // The raw public key happens to be the (compressed) value of the Montgomery point
                let raw_bytes = self.public_key.raw_public_key()?;
                let public_key_bytes: [u8; ED25519_PUBLIC_KEY_LENGTH] = raw_bytes.try_into()?;
                let public_key = X25519PublicKey::from_ed25519_public_key(
                    &Ed25519PublicKey::try_from_bytes(public_key_bytes)?,
                );
                EciesSalsaSealBox::encrypt(&mut *rng, &public_key, &plaintext, None)?
            }
            #[cfg(not(feature = "fips"))]
            Id::X25519 => {
                // The raw public key happens to be the (compressed) value of the Montgomery point
                let raw_bytes = self.public_key.raw_public_key()?;
                let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] = raw_bytes.try_into()?;
                let public_key = X25519PublicKey::try_from_bytes(public_key_bytes)?;
                EciesSalsaSealBox::encrypt(&mut *rng, &public_key, &plaintext, None)?
            }
            _ => {
                kmip_utils_bail!(
                    "Public key id not supported for Hybrid encryption. FIPS mode may have \
                     prevented this operation: {:?}",
                    id
                );
            }
        };

        debug!(
            "Encrypted data with public key {} of len (plaintext/ciphertext): {}/{}",
            &self.public_key_uid,
            plaintext.len(),
            ciphertext.len(),
        );

        Ok(EncryptResponse {
            unique_identifier: UniqueIdentifier::TextString(self.public_key_uid.clone()),
            data: Some(ciphertext),
            iv_counter_nonce: None,
            correlation_value: None,
            authenticated_encryption_tag: None,
        })
    }
}
