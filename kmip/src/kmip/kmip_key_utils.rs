use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{
    error::KmsCommonError,
    kmip::{kmip_operations::ErrorReason, kmip_types::Attributes},
};

#[derive(Serialize, Deserialize)]
pub struct WrappedSymmetricKey {
    pub(crate) attributes: Attributes,
    pub(crate) wrapped_symmetric_key: Vec<u8>,
}

impl WrappedSymmetricKey {
    #[must_use]
    pub fn attributes(&self) -> Attributes {
        self.attributes.clone()
    }

    #[must_use]
    pub fn wrapped_symmetric_key(&self) -> Vec<u8> {
        self.wrapped_symmetric_key.clone()
    }
}

impl TryFrom<&Vec<u8>> for WrappedSymmetricKey {
    type Error = KmsCommonError;

    fn try_from(wrapped_key_bytes: &Vec<u8>) -> Result<Self, KmsCommonError> {
        serde_json::from_slice(wrapped_key_bytes).map_err(|_e| {
            KmsCommonError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                "failed deserializing to an WrappedSymmetricKey".to_string(),
            )
        })
    }
}
