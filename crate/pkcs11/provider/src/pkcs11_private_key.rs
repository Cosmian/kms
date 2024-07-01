use cosmian_kmip::kmip::kmip_types::{CryptographicAlgorithm, RecommendedCurve};
use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PrivateKey, RemoteObjectId, RemoteObjectType, SignatureAlgorithm},
    MError, MResult,
};
use p256::pkcs8::DecodePrivateKey;
use pkcs1::{der::Decode, RsaPrivateKey};
use tracing::error;
use zeroize::Zeroizing;

use crate::kms_object::KmsObject;

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub struct Pkcs11PrivateKey {
    id: String,
    object_type: RemoteObjectType,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Zeroizing<Vec<u8>>,
    algorithm: Option<KeyAlgorithm>,
}

impl Pkcs11PrivateKey {
    pub fn new(remote_id: String, remote_object_type: RemoteObjectType) -> Self {
        Self {
            id: remote_id,
            object_type: remote_object_type,
            der_bytes: Zeroizing::new(vec![]),
            algorithm: None,
        }
    }

    pub fn try_from_kms_object(kms_object: KmsObject) -> MResult<Self> {
        let der_bytes = kms_object
            .object
            .key_block()
            .map_err(|e| MError::Cryptography(e.to_string()))?
            .key_bytes()
            .map_err(|e| MError::Cryptography(e.to_string()))?;
        let algorithm = match kms_object
            .attributes
            .cryptographic_algorithm
            .ok_or_else(|| MError::Cryptography("missing cryptographic algorithm".to_string()))?
        {
            CryptographicAlgorithm::RSA => KeyAlgorithm::Rsa,
            CryptographicAlgorithm::ECDH | CryptographicAlgorithm::EC => {
                let curve = kms_object
                    .attributes
                    .cryptographic_domain_parameters
                    .ok_or_else(|| MError::ArgumentsBad)?
                    .recommended_curve
                    .ok_or_else(|| MError::ArgumentsBad)?;
                match curve {
                    RecommendedCurve::P256 => KeyAlgorithm::EccP256,
                    RecommendedCurve::P384 => KeyAlgorithm::EccP384,
                    RecommendedCurve::P521 => KeyAlgorithm::EccP521,
                    RecommendedCurve::CURVE448 => KeyAlgorithm::X448,
                    RecommendedCurve::CURVEED448 => KeyAlgorithm::Ed448,
                    RecommendedCurve::CURVE25519 => KeyAlgorithm::X25519,
                    RecommendedCurve::CURVEED25519 => KeyAlgorithm::Ed25519,
                    _ => {
                        error!("Unsupported curve for EC key");
                        return Err(MError::Cryptography(
                            "unsupported curve for EC key".to_string(),
                        ));
                    }
                }
            }
            x => {
                error!("Unsupported cryptographic algorithm: {:?}", x);
                return Err(MError::Cryptography(format!(
                    "unsupported cryptographic algorithm: {:?}",
                    x
                )));
            }
        };

        Ok(Self {
            id: "".to_string(),
            object_type: RemoteObjectType::PublicKey,
            der_bytes,
            algorithm: Some(algorithm),
        })
    }
}

impl RemoteObjectId for Pkcs11PrivateKey {
    fn remote_id(&self) -> String {
        self.id.clone()
    }

    fn remote_type(&self) -> RemoteObjectType {
        self.object_type.clone()
    }
}

impl PrivateKey for Pkcs11PrivateKey {
    fn private_key_id(&self) -> Vec<u8> {
        self.id.as_bytes().to_vec()
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> MResult<Vec<u8>> {
        error!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.id
        );
        todo!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.id
        )
    }

    fn algorithm(&self) -> MResult<KeyAlgorithm> {
        self.algorithm
            .ok_or_else(|| MError::Cryptography("algorithm not known".to_string()))
    }

    fn rsa_private_key(&self) -> MResult<RsaPrivateKey> {
        match self.algorithm()? {
            KeyAlgorithm::Rsa => RsaPrivateKey::from_der(self.der_bytes.as_ref()).map_err(|e| {
                error!("Failed to parse RSA public key: {:?}", e);
                MError::Cryptography("Failed to parse RSA public key".to_string())
            }),
            _ => {
                error!("Public key is not an RSA key");
                Err(MError::Cryptography(
                    "Public key is not an RSA key".to_string(),
                ))
            }
        }
    }

    fn ec_p256_private_key(&self) -> MResult<p256::SecretKey> {
        match self.algorithm()? {
            KeyAlgorithm::EccP256 => {
                let ec_p256 =
                    p256::SecretKey::from_pkcs8_der(self.der_bytes.as_ref()).map_err(|e| {
                        MError::Cryptography(format!(
                            "Failed to parse EC P256 private key: {:?}",
                            e
                        ))
                    })?;
                Ok(ec_p256)
            }
            _ => {
                error!("Public key is not an EC P256 key");
                Err(MError::Cryptography(
                    "Public key is not an EC P256 key".to_string(),
                ))
            }
        }
    }
}
