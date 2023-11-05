use std::sync::{Arc, Mutex};

use cloudproof::reexport::crypto_core::{
    reexport::{pkcs8::DecodePublicKey, rand_core::SeedableRng, zeroize::Zeroizing},
    CsRng, Ecies, EciesP192Aes128, EciesP224Aes128, EciesP256Aes128, EciesP384Aes128,
    EciesSalsaSealBox, P192PublicKey, P224PublicKey, P256PublicKey, P384PublicKey,
    RsaKeyWrappingAlgorithm, RsaPublicKey, X25519PublicKey, X25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::kmip_operations::{Encrypt, EncryptResponse};
use openssl::{
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::X509,
};
use tracing::{debug, trace};

use crate::{
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail, EncryptionSystem,
};

/// Encrypt a single block of data using a Salsa Sealed Box
/// Cannot be used as a stream cipher
pub struct HybridEncryptionSystem {
    rng: Arc<Mutex<CsRng>>,
    public_key_uid: String,
    public_key: PKey<Public>,
}

impl HybridEncryptionSystem {
    pub fn new(public_key_uid: &str, public_key: PKey<Public>) -> Self {
        let rng = CsRng::from_entropy();

        trace!("Instantiated hybrid encryption system for public key id: {public_key_uid}");

        Self {
            rng: Arc::new(Mutex::new(rng)),
            public_key_uid: public_key_uid.into(),
            public_key,
        }
    }

    pub fn instantiate_with_certificate(
        certificate_uid: &str,
        certificate_value: &[u8],
    ) -> Result<Self, KmipUtilsError> {
        debug!("instantiate_with_certificate: entering");
        let rng = CsRng::from_entropy();

        debug!("instantiate_with_certificate: parsing");
        let cert = X509::from_pem(certificate_value)
            .map_err(|e| KmipUtilsError::ConversionError(format!("invalid PEM: {e:?}")))?;

        debug!("instantiate_with_certificate: get the public key of the certificate");
        let public_key = cert.public_key().map_err(|e| {
            KmipUtilsError::ConversionError(format!("invalid public key: error: {e:?}"))
        })?;

        Ok(Self {
            rng: Arc::new(Mutex::new(rng)),
            public_key_uid: certificate_uid.into(),
            public_key,
        })
    }
}

impl EncryptionSystem for HybridEncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmipUtilsError> {
        if request
            .authenticated_encryption_additional_data
            .as_deref()
            .is_some()
        {
            kmip_utils_bail!(
                "Hybrid encryption system does not support additional authenticated data"
            )
        }
        let plaintext = request.data.clone().context("missing plaintext data")?;
        let mut rng = self.rng.lock().unwrap();

        // Convert the Pkey to a crypto_core curve and perform emcryption
        // Note: All conversions below will go once we move to full openssl
        let id = self.public_key.id();
        let ciphertext: Vec<u8> = match id {
            Id::EC => encrypt_with_nist_curve(&mut rng, &self.public_key, &plaintext)?,
            Id::ED25519 => {
                kmip_utils_bail!("Hybrid encryption system does not support Ed25519")
            }
            Id::X25519 => {
                trace!("encrypt: X25519");
                // The raw public key happens to be the (compressed) value of the Montgomery point
                let raw_bytes = self.public_key.raw_public_key()?;
                let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] = raw_bytes.try_into()?;
                let public_key = X25519PublicKey::try_from_bytes(public_key_bytes)?;
                EciesSalsaSealBox::encrypt(&mut *rng, &public_key, &plaintext, None)?
            }
            Id::RSA => {
                trace!("encrypt: RSA");
                let spki_bytes = self.public_key.public_key_to_der()?;
                let public_key = RsaPublicKey::from_public_key_der(&spki_bytes)?;
                public_key.wrap_key(
                    &mut *rng,
                    RsaKeyWrappingAlgorithm::Aes256Sha256,
                    &Zeroizing::from(plaintext.clone()),
                )?
            }
            _ => {
                trace!("Not supported");
                kmip_utils_bail!("Public key id not supported yet: {:?}", id);
            }
        };

        debug!(
            "Encrypted data with public key {} of len (plaintext/ciphertext): {}/{}",
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

fn encrypt_with_nist_curve(
    rng: &mut CsRng,
    public_key: &PKey<Public>,
    plaintext: &[u8],
) -> Result<Vec<u8>, KmipUtilsError> {
    debug!("encrypt: NIST curve");
    let spki_bytes = public_key.public_key_to_der()?;
    // Get the NID (Numeric ID) of the curve.
    let ec_key = public_key.ec_key()?;
    let nid = ec_key
        .group()
        .curve_name()
        .ok_or_else(|| KmipUtilsError::ConversionError("invalid curve name".to_string()))?;
    debug!("encrypt: Elliptic curve: {}", nid.long_name()?);
    let ciphertext = match nid {
        Nid::X9_62_PRIME192V1 => {
            let public_key = P192PublicKey::from_public_key_der(&spki_bytes)?;
            EciesP192Aes128::encrypt(rng, &public_key, plaintext, None)?
        }
        Nid::SECP224R1 => {
            let public_key = P224PublicKey::from_public_key_der(&spki_bytes)?;
            EciesP224Aes128::encrypt(rng, &public_key, plaintext, None)?
        }
        Nid::X9_62_PRIME256V1 => {
            let public_key = P256PublicKey::from_public_key_der(&spki_bytes)?;
            EciesP256Aes128::encrypt(rng, &public_key, plaintext, None)?
        }
        Nid::SECP384R1 => {
            let public_key = P384PublicKey::from_public_key_der(&spki_bytes)?;
            EciesP384Aes128::encrypt(rng, &public_key, plaintext, None)?
        }
        _ => {
            kmip_utils_bail!(
                "encrypt: Elliptic curve not supported: {}",
                nid.long_name()?
            );
        }
    };
    Ok(ciphertext)
}
