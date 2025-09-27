use std::collections::HashSet;

use crate::{
    error::KmipError,
    kmip_2_1::{
        extra::VENDOR_ID_COSMIAN, kmip_attributes::Attributes, kmip_types::VendorAttributeValue,
    },
};

pub const VENDOR_ATTR_TAG: &str = "tag";

/// Constant to use to express there are no tags
pub const EMPTY_TAGS: [&str; 0] = [];

impl Attributes {
    /// Get the tags from the attributes
    #[must_use]
    pub fn get_tags(&self) -> HashSet<String> {
        self.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
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
        tags: T,
    ) -> Result<(), KmipError> {
        self.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
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
    pub fn remove_tags(&mut self) -> Option<HashSet<String>> {
        let value = self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)?;
        if let VendorAttributeValue::TextString(value) = value {
            serde_json::from_str::<HashSet<String>>(&value).ok()
        } else {
            None
        }
    }
}
