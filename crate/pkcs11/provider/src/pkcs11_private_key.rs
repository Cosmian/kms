use cosmian_pkcs11_module::traits::{RemoteObjectId, RemoteObjectType};

/// A PKCS11 data object is a `DataObject` that wraps data from a KMS object
#[derive(Debug)]
pub(crate) struct Pkcs11PrivateKey {
    remote_id: String,
    remote_object_type: RemoteObjectType,
}

impl Pkcs11PrivateKey {
    pub(crate) const fn new(remote_id: String, remote_object_type: RemoteObjectType) -> Self {
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
