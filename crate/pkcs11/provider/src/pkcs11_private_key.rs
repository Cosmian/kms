use cosmian_pkcs11_module::{
    traits::{KeyAlgorithm, PrivateKey, RemoteObjectId, RemoteObjectType, SignatureAlgorithm},
    MResult,
};
use zeroize::Zeroizing;

/// A PKCS11 data object is a `DataObject` that wraps data from a KMS object
#[derive(Debug)]
pub struct Pkcs11PrivateKey {
    remote_id: String,
    remote_object_type: RemoteObjectType,
    /// DER bytes of the private key - those are lazy loaded
    /// when the private key is used
    der_bytes: Option<Zeroizing<Vec<u8>>>,
}

impl Pkcs11PrivateKey {
    pub fn new(remote_id: String, remote_object_type: RemoteObjectType) -> Self {
        Self {
            remote_id,
            remote_object_type,
        }
    }
}

impl RemoteObjectId for Pkcs11PrivateKey {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn remote_type(&self) -> RemoteObjectType {
        self.remote_object_type.clone()
    }
}

impl PrivateKey for Pkcs11PrivateKey {
    fn private_key_id(&self) -> Vec<u8> {
        self.remote_id.as_bytes().to_vec()
    }

    fn label(&self) -> String {
        "PrivateKey".to_string()
    }

    fn sign(&self, algorithm: &SignatureAlgorithm, data: &[u8]) -> MResult<Vec<u8>> {
        todo!()
    }

    fn algorithm(&self) -> KeyAlgorithm {
        todo!()
    }
}
