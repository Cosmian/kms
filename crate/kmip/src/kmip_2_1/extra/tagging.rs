use std::collections::HashSet;

use crate::{
    error::KmipError,
    kmip_2_1::{kmip_attributes::Attributes, kmip_types::VendorAttributeValue},
};

pub const VENDOR_ATTR_TAG: &str = "tag";

/// Constant to use to express there are no tags
pub const EMPTY_TAGS: [&str; 0] = [];

/// The Cosmian vendor identification string
pub const VENDOR_ID_COSMIAN: &str = "cosmian";

/// System tag automatically added by the KMS server to symmetric keys on Create/Import
pub const SYSTEM_TAG_SYMMETRIC_KEY: &str = "_kk";
/// System tag automatically added by the KMS server to private keys on Create/Import
pub const SYSTEM_TAG_PRIVATE_KEY: &str = "_sk";
/// System tag automatically added by the KMS server to public keys on Create/Import
pub const SYSTEM_TAG_PUBLIC_KEY: &str = "_pk";
/// System tag automatically added by the KMS server to X.509 certificates on Import/Certify
pub const SYSTEM_TAG_CERTIFICATE: &str = "_cert";
/// System tag automatically added by the KMS server to secret data objects on Create/Import
pub const SYSTEM_TAG_SECRET_DATA: &str = "_sd";
/// System tag automatically added by the KMS server to opaque objects on Import
pub const SYSTEM_TAG_OPAQUE_OBJECT: &str = "_oo";
/// System tag automatically added by the KMS server to `CoverCrypt` user decryption keys
pub const SYSTEM_TAG_COVER_CRYPT_USER_KEY: &str = "_uk";

impl Attributes {
    /// Get the tags from the attributes
    #[must_use]
    pub fn get_tags(&self, vendor_id: &str) -> HashSet<String> {
        self.get_vendor_attribute_value(vendor_id, VENDOR_ATTR_TAG)
            .and_then(|value| {
                if let VendorAttributeValue::TextString(value) = value {
                    serde_json::from_str::<HashSet<String>>(value).ok()
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    /// Set the tags on the attributes
    pub fn set_tags<T: IntoIterator<Item = impl AsRef<str>>>(
        &mut self,
        vendor_id: &str,
        tags: T,
    ) -> Result<(), KmipError> {
        self.set_vendor_attribute(
            vendor_id,
            VENDOR_ATTR_TAG,
            VendorAttributeValue::TextString(serde_json::to_string::<HashSet<String>>(
                &tags
                    .into_iter()
                    .map(|t| t.as_ref().to_owned())
                    .collect::<HashSet<_>>(),
            )?),
        );
        Ok(())
    }

    /// Check that the user tags are valid i.e. they are not empty and do not start with '_'
    pub fn check_user_tags(tags: &HashSet<String>) -> Result<(), KmipError> {
        for tag in tags {
            if tag.starts_with('_') {
                return Err(KmipError::InvalidTag(
                    "user tags cannot start with _".to_owned(),
                ));
            } else if tag.is_empty() {
                return Err(KmipError::InvalidTag("tags cannot be empty".to_owned()));
            }
        }
        Ok(())
    }

    /// Remove the tags from the attributes and return them
    #[must_use]
    pub fn remove_tags(&mut self, vendor_id: &str) -> Option<HashSet<String>> {
        let value = self.remove_vendor_attribute(vendor_id, VENDOR_ATTR_TAG)?;
        if let VendorAttributeValue::TextString(value) = value {
            serde_json::from_str::<HashSet<String>>(&value).ok()
        } else {
            None
        }
    }
}
