use std::collections::HashSet;

use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes, kmip_bail};
use lazy_static::lazy_static;
use regex::Regex;

use crate::kmip_utils::VENDOR_ID_COSMIAN;
pub const VENDOR_ATTR_TAG: &str = "tag";

lazy_static! {
    static ref TAG_REGEX: Regex = Regex::new("[a-zA-Z0-9_\\-]+").unwrap();
}

/// Check if the attributes have a tag
pub fn has_tag(attributes: &Attributes, tag: &str) -> bool {
    get_tags(attributes).contains(tag)
}

/// Get the tags from the attributes
pub fn get_tags(attributes: &Attributes) -> HashSet<String> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG)
        .map(|value| serde_json::from_slice::<HashSet<String>>(value).unwrap_or_default())
        .unwrap_or(HashSet::new())
}

/// Set a tag on the attributes
///
/// Returns `true` if the tag already existed
pub fn set_tag(attributes: &mut Attributes, tag: &str) -> Result<bool, KmipError> {
    let va = attributes.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
    let mut set =
        serde_json::from_slice::<HashSet<String>>(&va.attribute_value).unwrap_or_default();
    let existed = set.insert(tag.to_owned());
    va.attribute_value = serde_json::to_vec(&set)?;
    Ok(existed)
}

/// Remove a tag from the attributes
///
/// Returns `true` if the tag existed
pub fn remove_tag(attributes: &mut Attributes, tag: &str) -> Result<bool, KmipError> {
    let va = attributes.get_vendor_attribute_mut(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
    let mut set =
        serde_json::from_slice::<HashSet<String>>(&va.attribute_value).unwrap_or_default();
    let existed = set.remove(tag);
    va.attribute_value = serde_json::to_vec(&set)?;
    Ok(existed)
}

pub fn check_tags<'a, I>(tags: I) -> Result<(), KmipError>
where
    I: IntoIterator<Item = &'a String>,
{
    for tag in tags {
        if !TAG_REGEX.is_match(tag) {
            kmip_bail!("Tag {} does not match the pattern [a-zA-Z0-9_\\-]+", tag);
        }
    }
    Ok(())
}
