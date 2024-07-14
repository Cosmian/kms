use std::ffi::CString;

use cosmian_pkcs11_module::traits::DataObject;
use sha3::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::{error::Pkcs11Error, kms_object::KmsObject};

/// A PKCS11 data object is a `DataObject` that wraps data from a KMS object
#[derive(Debug)]
pub struct Pkcs11DataObject {
    remote_id: String,
    value: Zeroizing<Vec<u8>>,
}

impl TryFrom<KmsObject> for Pkcs11DataObject {
    type Error = Pkcs11Error;

    fn try_from(kms_object: KmsObject) -> Result<Self, Self::Error> {
        Ok(Pkcs11DataObject {
            remote_id: kms_object.remote_id.clone(),
            value: kms_object.object.key_block()?.key_bytes()?,
        })
    }
}

impl Zeroize for Pkcs11DataObject {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl DataObject for Pkcs11DataObject {
    fn remote_id(&self) -> String {
        self.remote_id.clone()
    }

    fn value(&self) -> Zeroizing<Vec<u8>> {
        self.value.clone()
    }

    fn application(&self) -> CString {
        CString::new(b"Cosmian KMS PKCS11 provider").unwrap_or_default()
    }

    fn data_hash(&self) -> Vec<u8> {
        // This is a hash of key material which may be leaked by the application
        // We need pre-image and collision resistance.
        // => use a cryptographic SHA3-256 hash
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(self.value.as_slice());
        let result = hasher.finalize();
        result.to_vec()
    }
}
