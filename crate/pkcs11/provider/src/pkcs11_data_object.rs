use std::ffi::CString;

use cosmian_pkcs11_module::traits::DataObject;
use sha3::Digest;
use zeroize::{Zeroize, Zeroizing};

use crate::{error::Pkcs11Error, kms_object::KmsObject};

/// A PKCS11 data object is a `DataObject` that wraps data from a KMS object
#[derive(Debug)]
pub(crate) struct Pkcs11DataObject {
    value: Zeroizing<Vec<u8>>,
    label: String,
}

impl TryFrom<KmsObject> for Pkcs11DataObject {
    type Error = Pkcs11Error;

    fn try_from(kms_object: KmsObject) -> Result<Self, Self::Error> {
        Ok(Self {
            value: kms_object.object.key_block()?.key_bytes()?,
            label: kms_object.other_tags.join(","),
        })
    }
}

impl Zeroize for Pkcs11DataObject {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl DataObject for Pkcs11DataObject {
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

    fn label(&self) -> String {
        self.label.clone()
    }
}
