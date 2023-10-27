//! Hybrid encryption system based on either Elliptic Curve Integrated Encryption Scheme (ECIES) or PKCS#11 compatible key wrapping algorithms for RSA.
//! This module uses for ECIES:
//! - the `NaCL` Salsa Sealed Box encryption scheme, also found in libsodium. It is an hybrid encryption scheme using X25519 for the KEM and Salsa 20 Poly1305 for the DEM.
//! - the ECIES scheme with NIST and AES algorithms.
//! This module uses for PKCS#11 RSA hybrid encryption system the suite `Aes256Sha256`
//! These schemes do not support additional authenticated data.
//!
use std::sync::{Arc, Mutex};

use cosmian_crypto_core::{
    reexport::{
        pkcs8::{DecodePrivateKey, DecodePublicKey},
        rand_core::SeedableRng,
        zeroize::Zeroizing,
    },
    CsRng, Ecies, EciesP192Aes128, EciesP224Aes128, EciesP256Aes128, EciesP384Aes128,
    EciesSalsaSealBox, Ed25519PrivateKey, Ed25519PublicKey, P192PrivateKey, P192PublicKey,
    P224PrivateKey, P224PublicKey, P256PrivateKey, P256PublicKey, P384PrivateKey, P384PublicKey,
    RsaKeyWrappingAlgorithm, RsaPrivateKey, RsaPublicKey, X25519PrivateKey, X25519PublicKey,
    CURVE_25519_SECRET_LENGTH, P192_PRIVATE_KEY_LENGTH, P224_PRIVATE_KEY_LENGTH,
    P256_PRIVATE_KEY_LENGTH, P384_PRIVATE_KEY_LENGTH, X25519_PUBLIC_KEY_LENGTH,
};
use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, DecryptedData, Encrypt, EncryptResponse},
    kmip_types::{KeyFormatType, RecommendedCurve},
};
use openssl::{nid::Nid, pkey::Id, x509::X509};
use tracing::{debug, trace};

use crate::{
    error::{result::CryptoResultHelper, KmipUtilsError},
    kmip_utils_bail, DecryptionSystem, EncryptionSystem,
};

/// Encrypt a single block of data using a Salsa Sealed Box
/// Cannot be used as a stream cipher
pub struct HybridEncryptionSystem {
    rng: Arc<Mutex<CsRng>>,
    public_key_uid: String,
    public_key_in_der_bytes: Vec<u8>,
    public_key_id: Id,
    curve_nid: Option<Nid>,
}

impl HybridEncryptionSystem {
    pub fn instantiate(public_key_uid: &str, public_key: &Object) -> Result<Self, KmipUtilsError> {
        let rng = CsRng::from_entropy();

        trace!("Instantiated hybrid encryption system for public key id: {public_key_uid}");

        Ok(Self {
            rng: Arc::new(Mutex::new(rng)),
            public_key_uid: public_key_uid.into(),
            public_key_in_der_bytes: public_key.key_block()?.key_bytes()?,
            public_key_id: Id::X25519,
            curve_nid: None,
        })
    }

    pub fn instantiate_with_certificate(
        certificate_uid: &str,
        certificate_value: &[u8],
    ) -> Result<Self, KmipUtilsError> {
        debug!("instantiate_with_certificate: entering");
        let rng = CsRng::from_entropy();

        debug!("instantiate_with_certificate: parsing");
        let cert = X509::from_der(certificate_value)
            .map_err(|e| KmipUtilsError::ConversionError(format!("invalid PEM: {e:?}")))?;

        debug!("instantiate_with_certificate: get the public key of the certificate");
        let public_key = cert.public_key().map_err(|e| {
            KmipUtilsError::ConversionError(format!("invalid public key: error: {e:?}"))
        })?;
        debug!(
            "instantiate_with_certificate: public_key.id: {:?}",
            public_key.id()
        );

        let (public_key_in_der_bytes, curve_nid) = match public_key.id() {
            Id::EC => {
                debug!("instantiate_with_certificate: EC");
                let ec_public_key = public_key.ec_key()?;
                (
                    ec_public_key.public_key_to_der()?,
                    ec_public_key.group().curve_name(),
                )
            }
            Id::ED25519 => {
                debug!("instantiate_with_certificate: ED25519");
                let public_key = public_key.raw_public_key().map_err(|e| {
                    KmipUtilsError::ConversionError(format!("invalid raw public key: error: {e:?}"))
                })?;

                (public_key, None)
            }
            Id::X25519 => {
                debug!("instantiate_with_certificate: X25519");
                let public_key = public_key.raw_public_key().map_err(|e| {
                    KmipUtilsError::ConversionError(format!("invalid raw public key: error: {e:?}"))
                })?;

                (public_key, None)
            }
            Id::RSA => {
                debug!("instantiate_with_certificate: RSA");
                let public_key = public_key.public_key_to_der().map_err(|e| {
                    KmipUtilsError::ConversionError(format!("invalid raw public key: error: {e:?}"))
                })?;

                (public_key, None)
            }
            _ => {
                kmip_utils_bail!("Public key id not supported yet: {:?}", public_key.id());
            }
        };

        trace!("Instantiated hybrid encryption system for certificate id: {certificate_uid}");

        Ok(Self {
            rng: Arc::new(Mutex::new(rng)),
            public_key_uid: certificate_uid.into(),
            public_key_in_der_bytes,
            public_key_id: public_key.id(),
            curve_nid,
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
            return Err(KmipUtilsError::NotSupported(
                "Hybrid encryption system does not support additional authenticated data"
                    .to_string(),
            ))
        }

        let plaintext = request.data.clone().context("missing plaintext data")?;

        let mut rng = self.rng.lock().unwrap();

        let ciphertext = match self.public_key_id {
            Id::EC => {
                debug!("EC");
                // Get the NID (Numeric ID) of the curve.
                if let Some(nid) = self.curve_nid {
                    debug!("encrypt: Elliptic curve: {}", nid.long_name()?);
                    match nid {
                        Nid::X9_62_PRIME192V1 => {
                            let public_key =
                                P192PublicKey::from_public_key_der(&self.public_key_in_der_bytes)?;
                            EciesP192Aes128::encrypt(&mut *rng, &public_key, &plaintext, None)?
                        }
                        Nid::SECP224R1 => {
                            let public_key =
                                P224PublicKey::from_public_key_der(&self.public_key_in_der_bytes)?;
                            EciesP224Aes128::encrypt(&mut *rng, &public_key, &plaintext, None)?
                        }
                        Nid::X9_62_PRIME256V1 => {
                            let public_key =
                                P256PublicKey::from_public_key_der(&self.public_key_in_der_bytes)?;
                            EciesP256Aes128::encrypt(&mut *rng, &public_key, &plaintext, None)?
                        }
                        Nid::SECP384R1 => {
                            let public_key =
                                P384PublicKey::from_public_key_der(&self.public_key_in_der_bytes)?;
                            EciesP384Aes128::encrypt(&mut *rng, &public_key, &plaintext, None)?
                        }
                        _ => {
                            kmip_utils_bail!(
                                "encrypt: Elliptic curve not supported: {}",
                                nid.long_name()?
                            );
                        }
                    }
                } else {
                    kmip_utils_bail!("encrypt: The EC group does not have a curve NID");
                }
            }
            Id::ED25519 => {
                debug!("encrypt: ED25519");
                let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] =
                    self.public_key_in_der_bytes.clone().try_into()?;
                let ed_public_key = Ed25519PublicKey::try_from_bytes(public_key_bytes)?;
                debug!("encrypt: convert ED25519 public key to X25519 public key");
                let public_key = X25519PublicKey::from_ed25519_public_key(&ed_public_key);
                EciesSalsaSealBox::encrypt(&mut *rng, &public_key, &plaintext, None)?
            }
            Id::X25519 => {
                debug!("encrypt: X25519");
                let public_key_bytes: [u8; X25519_PUBLIC_KEY_LENGTH] =
                    self.public_key_in_der_bytes.clone().try_into()?;
                let public_key = X25519PublicKey::try_from_bytes(public_key_bytes)?;
                EciesSalsaSealBox::encrypt(&mut *rng, &public_key, &plaintext, None)?
            }
            Id::RSA => {
                debug!("encrypt: RSA");
                let public_key = RsaPublicKey::from_public_key_der(&self.public_key_in_der_bytes)?;

                public_key.wrap_key(
                    &mut *rng,
                    RsaKeyWrappingAlgorithm::Aes256Sha256,
                    &Zeroizing::from(plaintext.clone()),
                )?
            }
            _ => {
                debug!("Not supported");
                kmip_utils_bail!("Public key id not supported yet: {:?}", self.public_key_id);
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

/// Decrypt a single block of data encrypted using a ECIES scheme or RSA hybrid system
/// Cannot be used as a stream decipher
pub struct HybridDecryptionSystem {
    pub private_key: Object,
    pub private_key_uid: Option<String>,
}

impl HybridDecryptionSystem {
    fn ecies_decrypt(
        &self,
        recommended_curve: RecommendedCurve,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KmipUtilsError> {
        let plaintext = match recommended_curve {
            RecommendedCurve::P192 => {
                let private_key_bytes: [u8; P192_PRIVATE_KEY_LENGTH] =
                    self.private_key.key_block()?.key_bytes()?.try_into()?;
                let private_key = P192PrivateKey::try_from_bytes(private_key_bytes)?;
                EciesP192Aes128::decrypt(&private_key, ciphertext, None)?
            }
            RecommendedCurve::P224 => {
                let private_key_bytes: [u8; P224_PRIVATE_KEY_LENGTH] =
                    self.private_key.key_block()?.key_bytes()?.try_into()?;
                let private_key = P224PrivateKey::try_from_bytes(private_key_bytes)?;
                EciesP224Aes128::decrypt(&private_key, ciphertext, None)?
            }
            RecommendedCurve::P256 => {
                debug!("decrypt: RecommendedCurve::P256: size: {P256_PRIVATE_KEY_LENGTH}");
                let private_key_bytes: [u8; P256_PRIVATE_KEY_LENGTH] =
                    self.private_key.key_block()?.key_bytes()?.try_into()?;
                debug!("decrypt: converted to slice OK");
                let private_key = P256PrivateKey::try_from_bytes(private_key_bytes)?;
                debug!("decrypt: converted to NIST curve OK");
                EciesP256Aes128::decrypt(&private_key, ciphertext, None)?
            }
            RecommendedCurve::P384 => {
                let private_key_bytes: [u8; P384_PRIVATE_KEY_LENGTH] =
                    self.private_key.key_block()?.key_bytes()?.try_into()?;
                let private_key = P384PrivateKey::try_from_bytes(private_key_bytes)?;
                EciesP384Aes128::decrypt(&private_key, ciphertext, None)?
            }
            RecommendedCurve::CURVEED25519 => {
                debug!("decrypt: match CURVEED25519");
                let private_key_bytes: [u8; CURVE_25519_SECRET_LENGTH] = self
                    .private_key
                    .key_block()?
                    .key_bytes()?
                    .try_into()
                    .map_err(|_| {
                        KmipUtilsError::ConversionError(
                            "invalid Curve Ed25519 private key length".to_string(),
                        )
                    })?;
                let private_key = Ed25519PrivateKey::try_from_bytes(private_key_bytes)?;
                let private_key = X25519PrivateKey::from_ed25519_private_key(&private_key);
                debug!("decrypt: private_key");

                // Decrypt the encrypted message
                EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?
            }
            RecommendedCurve::CURVE25519 => {
                debug!("decrypt: match CURVE25519");
                let private_key_bytes: [u8; CURVE_25519_SECRET_LENGTH] = self
                    .private_key
                    .key_block()?
                    .key_bytes()?
                    .try_into()
                    .map_err(|_| {
                        KmipUtilsError::ConversionError(
                            "invalid Curve 25519 private key length".to_string(),
                        )
                    })?;
                let private_key = X25519PrivateKey::try_from_bytes(private_key_bytes)?;

                // Decrypt the encrypted message
                EciesSalsaSealBox::decrypt(&private_key, ciphertext, None)?
            }
            _ => Err(KmipUtilsError::NotSupported(format!(
                "{recommended_curve:?} curve is not supported",
            )))?,
        };
        Ok(plaintext)
    }
}

impl DecryptionSystem for HybridDecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmipUtilsError> {
        debug!("decrypt: entering");
        let key_format_type = self.private_key.key_block()?.key_format_type;
        debug!("decrypt: key format type: {key_format_type:?}");
        let ciphertext = request.data.as_ref().ok_or_else(|| {
            KmipUtilsError::NotSupported(
                "the decryption request should contain encrypted data".to_string(),
            )
        })?;

        let plaintext = match key_format_type {
            KeyFormatType::ECPrivateKey | KeyFormatType::TransparentECPrivateKey => {
                let recommended_curve = self
                    .private_key
                    .attributes()?
                    .cryptographic_domain_parameters
                    .ok_or(KmipUtilsError::NotSupported(
                        "Private key without cryptographic domain parameters is not supported"
                            .to_string(),
                    ))?
                    .recommended_curve
                    .ok_or(KmipUtilsError::NotSupported(
                        "Private key without recommended_curve is not supported".to_string(),
                    ))?;
                debug!("decrypt: recommended_curve: {:?}", recommended_curve);
                self.ecies_decrypt(recommended_curve, ciphertext)
            }
            KeyFormatType::TransparentRSAPrivateKey => {
                let private_key =
                    RsaPrivateKey::from_pkcs8_der(&self.private_key.key_block()?.key_bytes()?)?;
                Ok(private_key
                    .unwrap_key(RsaKeyWrappingAlgorithm::Aes256Sha256, ciphertext)?
                    .to_vec())
            }
            _ => Err(KmipUtilsError::NotSupported(format!(
                "Key format type is not supported: {key_format_type:?}",
            ))),
        }?;

        debug!(
            "Decrypted data with user key {:?} of len (plaintext/ciphertext): {}/{}",
            &self.private_key_uid,
            plaintext.len(),
            ciphertext.len(),
        );

        let decrypted_data = DecryptedData {
            metadata: vec![],
            plaintext,
        };

        Ok(DecryptResponse {
            unique_identifier: self.private_key_uid.clone().unwrap_or_default(),
            data: Some(decrypted_data.try_into()?),
            correlation_value: None,
        })
    }
}
