use std::collections::HashSet;

use crate::{
    error::KmipError,
    kmip::{extra::VENDOR_ID_COSMIAN, kmip_types::Attributes},
};

pub const VENDOR_ATTR_TAG: &str = "tag";

/// Constant to use to express there are no tags
pub const EMPTY_TAGS: [&str; 0] = [];

impl Attributes {
    /// Get the tags from the attributes
    #[must_use]
    pub fn get_tags(&self) -> HashSet<String> {
        self.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
            .map(|value| serde_json::from_slice::<HashSet<String>>(value).unwrap_or_default())
            .unwrap_or_default()
    }

    /// Set the tags on the attributes
    pub fn set_tags<T: IntoIterator<Item = impl AsRef<str>>>(
        &mut self,
        tags: T,
    ) -> Result<(), KmipError> {
        let va = self.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
        va.attribute_value = serde_json::to_vec::<HashSet<String>>(
            &tags
                .into_iter()
                .map(|t| t.as_ref().to_owned())
                .collect::<HashSet<_>>(),
        )?;
        Ok(())
    }

    /// Check that the user tags are valid i.e. they are not empty and do not start with '_'
    pub fn check_user_tags(tags: &HashSet<String>) -> Result<(), KmipError> {
        for tag in tags {
            if tag.starts_with('_') {
                return Err(KmipError::InvalidTag(
                    "user tags cannot start with _".to_owned(),
                ))
            } else if tag.is_empty() {
                return Err(KmipError::InvalidTag("tags cannot be empty".to_owned()))
            }
        }
        Ok(())
    }

    /// Remove the tags from the attributes and return them
    #[must_use]
    pub fn remove_tags(&mut self) -> Option<HashSet<String>> {
        let tags = self
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
            .map(|value| serde_json::from_slice::<HashSet<String>>(value).unwrap_or_default());
        if tags.is_some() {
            self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
        }
        tags
    }
}
