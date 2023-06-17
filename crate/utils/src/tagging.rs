use std::collections::HashSet;

use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes};

use crate::kmip_utils::VENDOR_ID_COSMIAN;
pub const VENDOR_ATTR_TAG: &str = "tag";

/// Check if the attributes have a tag
pub fn has_tag(attributes: &Attributes, tag: &str) -> bool {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
        .map(|value| {
            let json = serde_json::from_slice::<HashSet<String>>(value).unwrap_or_default();
            json.contains(tag)
        })
        .unwrap_or(false)
}

/// Set a tag on the attributes
///
/// Returns `true` if the tag already existed
pub fn set_tag(attributes: &mut Attributes, tag: &str) -> Result<bool, KmipError> {
    let va = attributes.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
    let mut json =
        serde_json::from_slice::<HashSet<String>>(&va.attribute_value).unwrap_or_default();
    let existed = json.insert(tag.to_owned());
    va.attribute_value = serde_json::to_vec(&json).unwrap();
    Ok(existed)
}

/// Remove a tag from the attributes
///
/// Returns `true` if the tag existed
pub fn remove_tag(attributes: &mut Attributes, tag: &str) -> Result<bool, KmipError> {
    let va = attributes.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
    let mut json =
        serde_json::from_slice::<HashSet<String>>(&va.attribute_value).unwrap_or_default();
    let existed = json.remove(tag);
    va.attribute_value = serde_json::to_vec(&json).unwrap();
    Ok(existed)
}
