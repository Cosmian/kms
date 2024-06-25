use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PrivateKey, RemoteObjectId, RemoteObjectType, SignatureAlgorithm},
    MResult,
};
use tracing::error;
use zeroize::Zeroizing;

/// A PKCS11 Private Key implementation that may only hold remote
/// references to the actual private key
#[derive(Debug)]
pub struct Pkcs11PrivateKey {
    id: String,
    object_type: RemoteObjectType,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Option<Zeroizing<Vec<u8>>>,
    algorithm: KeyAlgorithm,
}

impl Pkcs11PrivateKey {
    pub fn new(remote_id: String, remote_object_type: RemoteObjectType) -> Self {
        Self {
            id: remote_id,
            object_type: remote_object_type,
            der_bytes: None,
        }
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

    fn label(&self) -> String {
        "PrivateKey".to_string()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> MResult<Vec<u8>> {
        error!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.id
        );
        todo!(
            "sign not implemented for Pkcs11PrivateKey with remote_id: {}",
            self.id
        )
    }

    fn algorithm(&self) -> KeyAlgorithm {
        todo!()
    }
}
