use ckms::reexport::cosmian_kms_cli_actions::reexport::cosmian_kmip::kmip_2_1::kmip_objects::Object;
use cosmian_pkcs11_module::{ModuleError, ModuleResult, traits::DataObject};
use zeroize::{Zeroize, Zeroizing};

use crate::{error::Pkcs11Error, kms_object::KmsObject, pkcs11_error};

/// A PKCS11 data object is a `DataObject` that wraps data from a KMS object
#[derive(Debug)]
pub(crate) struct Pkcs11DataObject {
    remote_id: String,
    value: Zeroizing<Vec<u8>>,
}

impl TryFrom<KmsObject> for Pkcs11DataObject {
    type Error = Pkcs11Error;

    fn try_from(kms_object: KmsObject) -> Result<Self, Self::Error> {
        Ok(Self {
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
    fn remote_id(&self) -> &str {
        &self.remote_id
    }

    fn value(&self) -> Zeroizing<Vec<u8>> {
        self.value.clone()
    }

    fn application(&self) -> Vec<u8> {
        b"Cosmian KMS PKCS11 provider".to_vec()
    }
}

impl Pkcs11DataObject {
    pub(crate) fn new(remote_id: String) -> Self {
        Self {
            remote_id,
            value: Zeroizing::new(vec![]),
        }
    }

    pub(crate) fn try_from_kms_object(kms_object: KmsObject) -> ModuleResult<Self> {
        let value = match kms_object.object {
            Object::SecretData(data_object) => {
                let (value, _attrs) =
                    data_object
                        .key_block
                        .key_bytes_and_attributes()
                        .map_err(|e| {
                            ModuleError::Backend(Box::new(pkcs11_error!(format!(
                                "try_from_kms_object: fail convert to key bytes. Error: {e}"
                            ))))
                        })?;
                Ok(value)
            }
            _ => Err(ModuleError::Default("Expected SecretData".to_owned())),
        }?;

        Ok(Self {
            remote_id: kms_object.remote_id,
            value,
        })
    }
}
