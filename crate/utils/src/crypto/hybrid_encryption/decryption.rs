#[cfg(not(feature = "fips"))]
use cloudproof::reexport::crypto_core::{
    reexport::{pkcs8::DecodePrivateKey, zeroize::Zeroizing},
    Ecies, EciesP192Aes128, EciesP224Aes128, EciesP256Aes128, EciesP384Aes128, EciesSalsaSealBox,
    Ed25519PrivateKey, P192PrivateKey, P224PrivateKey, P256PrivateKey, P384PrivateKey,
    RsaKeyWrappingAlgorithm, RsaPrivateKey, X25519PrivateKey, CURVE_25519_SECRET_LENGTH,
};
use cosmian_kmip::{
    kmip::{
        kmip_operations::{Decrypt, DecryptResponse, DecryptedData},
        kmip_types::UniqueIdentifier,
    },
    result::KmipResultHelper,
};
use openssl::{
    nid::Nid,
    pkey::{Id, PKey, Private},
};
use tracing::{debug, trace};

use crate::{error::KmipUtilsError, kmip_utils_bail, DecryptionSystem};

/// Decrypt a single block of data encrypted using a ECIES scheme or RSA hybrid system
/// Cannot be used as a stream decipher
pub struct HybridDecryptionSystem {
    private_key: PKey<Private>,
    private_key_uid: Option<String>,
}

impl HybridDecryptionSystem {
    pub fn new(private_key_uid: Option<String>, private_key: PKey<Private>) -> Self {
        trace!("Instantiated hybrid decryption system for private key id: {private_key_uid:?}");
        Self {
            private_key,
            private_key_uid,
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
        let id = self.private_key.id();
        let plaintext = match id {
            Id::EC => decrypt_with_nist_curve(&self.private_key, ciphertext)?,
            Id::ED25519 => {
                debug!("decrypt: match CURVEED25519");
                let raw_bytes = self.private_key.raw_private_key()?;
                let private_key_bytes: [u8; CURVE_25519_SECRET_LENGTH] = raw_bytes.try_into()?;
                let private_key = Ed25519PrivateKey::try_from_bytes(private_key_bytes)?;
                let private_key = X25519PrivateKey::from_ed25519_private_key(&private_key);
                Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
            }
            Id::X25519 => {
                trace!("encrypt: X25519");
                // The raw public key happens to be the (compressed) value of the Montgomery point
                let raw_bytes = self.private_key.raw_private_key()?;
                let private_key_bytes: [u8; CURVE_25519_SECRET_LENGTH] = raw_bytes.try_into()?;
                let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes)?;
                Zeroizing::new(EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?)
            }
            Id::RSA => {
                trace!("encrypt: RSA");
                let der_bytes = self.private_key.private_key_to_pkcs8()?;
                let private_key = RsaPrivateKey::from_pkcs8_der(&der_bytes)?;
                private_key.unwrap_key(RsaKeyWrappingAlgorithm::Aes256Sha256, ciphertext)?
            }
            _ => {
                trace!("Not supported");
                kmip_utils_bail!("Public key id not supported yet: {:?}", id);
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

fn decrypt_with_nist_curve(
    private_key: &PKey<Private>,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KmipUtilsError> {
    trace!("decrypt: NIST curve");
    let pkcs8_der = private_key.private_key_to_pkcs8()?;
    // determine the curve
    let ec_key = private_key
        .ec_key()
        .context("the provided openssl key is not an elliptic curve private key")?;
    let nid = ec_key
        .group()
        .curve_name()
        .ok_or_else(|| KmipUtilsError::ConversionError("invalid curve name".to_string()))?;

    let plaintext = match nid {
        Nid::X9_62_PRIME192V1 => {
            let private_key = P192PrivateKey::from_pkcs8_der(&pkcs8_der)?;
            EciesP192Aes128::decrypt(&private_key, ciphertext, None)?
        }
        Nid::SECP224R1 => {
            let private_key = P224PrivateKey::from_pkcs8_der(&pkcs8_der)?;
            EciesP224Aes128::decrypt(&private_key, ciphertext, None)?
        }
        Nid::X9_62_PRIME256V1 => {
            let private_key = P256PrivateKey::from_pkcs8_der(&pkcs8_der)?;
            EciesP256Aes128::decrypt(&private_key, ciphertext, None)?
        }
        Nid::SECP384R1 => {
            let private_key = P384PrivateKey::from_pkcs8_der(&pkcs8_der)?;
            EciesP384Aes128::decrypt(&private_key, ciphertext, None)?
        }
        _ => {
            kmip_utils_bail!(
                "encrypt: Elliptic curve not supported: {}",
                nid.long_name()?
            );
        }
    };
    Ok(Zeroizing::new(plaintext))
}
