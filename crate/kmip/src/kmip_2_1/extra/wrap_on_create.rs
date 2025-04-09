//! This module contains an extension to wrap a key on creation
//! with a given key.
//! The use case is to store a key on the default data store but wrapped by
//! a key stored in an HSM.

use crate::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN, kmip_attributes::Attributes, kmip_types::VendorAttributeValue,
};

/// The key to use to wrap the key on creation
const WRAPPING_KEY_ID: &str = "wrapping_key_id";

impl Attributes {
    /// Set the wrapping key id
    /// This is the key that will be used to wrap the key on creation
    /// The wrapping key id is stored as a vendor attribute
    ///
    /// # Arguments
    /// * `wrapping_key_id` - The wrapping key id to set
    ///
    /// # Returns
    /// * The wrapping key id if it was set before
    pub fn set_wrapping_key_id(&mut self, wrapping_key_id: &str) -> Option<String> {
        self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            WRAPPING_KEY_ID,
            VendorAttributeValue::TextString(wrapping_key_id.to_owned()),
        )
        .and_then(|val| {
            if let VendorAttributeValue::TextString(val) = val {
                Some(val)
            } else {
                None
            }
        })
    }

    /// Extract the wrapping key id
    ///
    /// # Returns
    /// *  The wrapping key id if it was set before
    /// * `None` if it was not set
    pub fn remove_wrapping_key_id(&mut self) -> Option<String> {
        self.remove_vendor_attribute(VENDOR_ID_COSMIAN, WRAPPING_KEY_ID)
            .and_then(|val| {
                if let VendorAttributeValue::TextString(val) = val {
                    Some(val)
                } else {
                    None
                }
            })
    }
}
