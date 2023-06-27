use std::collections::HashSet;

use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes};

use crate::kmip_utils::VENDOR_ID_COSMIAN;
pub const VENDOR_ATTR_TAG: &str = "tag";

/// Constant to use to express there are no tags
pub const EMPTY_TAGS: [&str; 0] = [];

/// Get the tags from the attributes
pub fn get_tags(attributes: &Attributes) -> HashSet<String> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
        .map(|value| serde_json::from_slice::<HashSet<String>>(value).unwrap_or_default())
        .unwrap_or(HashSet::new())
}

/// Set the tags on the attributes
pub fn set_tags<T: IntoIterator<Item = impl AsRef<str>>>(
    attributes: &mut Attributes,
    tags: T,
) -> Result<(), KmipError> {
    let va = attributes.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
    va.attribute_value = serde_json::to_vec::<HashSet<String>>(&HashSet::from_iter(
        tags.into_iter().map(|t| t.as_ref().to_owned()),
    ))?;
    Ok(())
}
