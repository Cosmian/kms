//! This module contains an extension to wrap a key on creation
//! with a given key.
//! The use case is to store a key on the default data store but wrapped by
//! a key stored in an HSM.

use crate::{
    error::KmipError,
    kmip::{extra::VENDOR_ID_COSMIAN, kmip_operations::ErrorReason, kmip_types::Attributes},
};

/// The key to use to wrap the key on creation
const WRAPPING_KEY_ID: &str = "wrapping_key_id";

impl Attributes {
    /// Set the wrapping key id
    pub fn set_wrapping_key_id(&mut self, wrapping_key_id: &str) -> &mut Self {
        self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            WRAPPING_KEY_ID,
            wrapping_key_id.as_bytes().to_vec(),
        )
    }

    /// Extract the wrapping key id
    pub fn extract_wrapping_key_id(&mut self) -> Result<Option<String>, KmipError> {
        let bytes = self.extract_vendor_attribute_value(VENDOR_ID_COSMIAN, WRAPPING_KEY_ID);
        let wrapping_key_id = bytes
            .map(|value| {
                String::from_utf8(value).map_err(|e| {
                    KmipError::InvalidKmipValue(ErrorReason::Codec_Error, e.to_string())
                })
            })
            .transpose()?;
        Ok(wrapping_key_id)
    }
}
