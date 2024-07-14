use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PrivateKey, SignatureAlgorithm},
    MError, MResult,
};
use p256::pkcs8::DecodePrivateKey;
use pkcs1::{der::Decode, RsaPrivateKey};
use tracing::error;
use zeroize::Zeroizing;

use crate::kms_object::{key_algorithm_from_attributes, KmsObject};

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub struct Pkcs11PrivateKey {
    remote_id: String,
    algorithm: KeyAlgorithm,
    key_size: usize,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Zeroizing<Vec<u8>>,
}

impl Pkcs11PrivateKey {
    pub fn new(remote_id: String, algorithm: KeyAlgorithm, key_size: usize) -> Self {
        Self {
            remote_id,
            der_bytes: Zeroizing::new(vec![]),
            algorithm,
            key_size,
        }
    }

    pub fn try_from_kms_object(remote_id: String, kms_object: KmsObject) -> MResult<Self> {
        let der_bytes = kms_object
            .object
            .key_block()
            .map_err(|e| MError::Cryptography(e.to_string()))?
            .key_bytes()
            .map_err(|e| MError::Cryptography(e.to_string()))?;
        let key_size = kms_object
            .attributes
            .cryptographic_length
            .ok_or_else(|| MError::Cryptography("missing key size".to_string()))?
            as usize;
        let algorithm = key_algorithm_from_attributes(&kms_object.attributes)?;

        Ok(Self {
            remote_id,
            algorithm,
            key_size,
            der_bytes,
        })
    }
}

// impl RemoteObjectId for Pkcs11PrivateKey {
//     fn remote_id(&self) -> String {
//         self.id.clone()
//     }
//
//     fn remote_type(&self) -> RemoteObjectType {
//         self.object_type.clone()
//     }
// }

impl PrivateKey for Pkcs11PrivateKey {
    fn private_key_id(&self) -> &str {
        &self.remote_id
    }

    fn sign(&self, _algorithm: &SignatureAlgorithm, _data: &[u8]) -> MResult<Vec<u8>> {
        error!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.remote_id
        );
        todo!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.remote_id
        )
    }

    fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    fn key_size(&self) -> usize {
        self.key_size
    }

    fn rsa_private_key(&self) -> MResult<RsaPrivateKey> {
        match self.algorithm {
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

    fn rsa_public_exponent(&self) -> MResult<Vec<u8>> {
        Ok(if self.der_bytes.len() > 0 {
            self.rsa_private_key()?.public_exponent.as_bytes().to_vec()
        } else {
            //TODO: not great but very little chance that 1/ it is different and 2/ it has any effect
            65537_u32.to_be_bytes().to_vec()
        })
    }

    fn ec_p256_private_key(&self) -> MResult<p256::SecretKey> {
        match self.algorithm {
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
