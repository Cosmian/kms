use std::collections::HashSet;

use cosmian_kmip::{error::KmipError, kmip::kmip_types::Attributes, kmip_bail};
use lazy_static::lazy_static;
use regex::Regex;

use crate::kmip_utils::VENDOR_ID_COSMIAN;
pub const VENDOR_ATTR_TAG: &str = "tag";

/// Constant to use to express there are no tags
pub const EMPTY_TAGS: [&str; 0] = [];

lazy_static! {
    static ref TAG_REGEX: Regex = Regex::new("[a-zA-Z0-9_\\-]+").unwrap();
}

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

// Clear the tags on the attributes
pub fn clear_tags(attributes: &mut Attributes) {
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_TAG);
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
