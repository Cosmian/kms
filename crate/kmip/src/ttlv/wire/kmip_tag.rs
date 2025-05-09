use std::str::FromStr;

use crate::{kmip_1_4, kmip_2_1, ttlv::TtlvError};

/// This trait is used to define the KMIP 1.4 and KMIP 2.1 tags that can be used in TTLV serialization
pub trait KmipTag: Copy + ToString + FromStr {
    /// Get a tag variant from a value
    fn from_u32(tag_value: u32) -> Result<Self, TtlvError>
    where
        Self: Sized;

    /// Convert the tag to an u32 value
    fn to_u32(&self) -> u32;
}

impl KmipTag for kmip_1_4::kmip_types::Tag {
    fn from_u32(tag_value: u32) -> Result<Self, TtlvError> {
        Self::from_repr(tag_value)
            .ok_or_else(|| TtlvError::from(format!("Unknown tag value: {tag_value}")))
    }

    #[allow(clippy::as_conversions)]
    // This conversion is idomatic for items marked with #[repr(u32)]
    fn to_u32(&self) -> u32 {
        *self as u32
    }
}

impl KmipTag for kmip_2_1::kmip_types::Tag {
    fn from_u32(tag_value: u32) -> Result<Self, TtlvError> {
        Self::from_repr(tag_value)
            .ok_or_else(|| TtlvError::from(format!("Unknown tag value: {tag_value}")))
    }

    #[allow(clippy::as_conversions)]
    // This conversion is idomatic for items marked with #[repr(u32)]
    fn to_u32(&self) -> u32 {
        *self as u32
    }
}
