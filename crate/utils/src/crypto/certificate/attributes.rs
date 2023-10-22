use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, VendorAttribute},
    },
};

use crate::kmip_utils::VENDOR_ID_COSMIAN;
pub const VENDOR_ATTR_CERTIFICATE_ID: &str = "certificate_id";
pub const VENDOR_ATTR_CERTIFICATE_SUBJECT: &str = "certificate_subject";
pub const VENDOR_ATTR_CERTIFICATE_CA: &str = "certificate_ca";
pub const VENDOR_ATTR_CERTIFICATE_VALIDITY: &str = "certificate_validity";

/// Convert a key/value pair to a vendor attribute  
fn _as_vendor_attribute(key: &str, value: &str) -> Result<VendorAttribute, KmipError> {
    Ok(VendorAttribute {
        vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
        attribute_name: key.to_string(),
        attribute_value: Vec::<u8>::try_from(value).map_err(|e| {
            KmipError::InvalidKmipValue(
                ErrorReason::Invalid_Attribute_Value,
                format!("failed convert {key} to bytes: {e}"),
            )
        })?,
    })
}

/// Convert certificate_id to a vendor attribute
pub fn certificate_id_as_vendor_attribute(
    certificate_id: &str,
) -> Result<VendorAttribute, KmipError> {
    _as_vendor_attribute(VENDOR_ATTR_CERTIFICATE_ID, certificate_id)
}

/// Convert subject to a vendor attribute
pub fn subject_common_name_as_vendor_attribute(
    subject: &str,
) -> Result<VendorAttribute, KmipError> {
    _as_vendor_attribute(VENDOR_ATTR_CERTIFICATE_SUBJECT, subject)
}

/// Convert ca to a vendor attribute
pub fn ca_subject_common_names_as_vendor_attribute(ca: &str) -> Result<VendorAttribute, KmipError> {
    _as_vendor_attribute(VENDOR_ATTR_CERTIFICATE_CA, ca)
}

/// Extract information (subject, ca, subca, etc) from attributes
fn _from_attributes<'a>(
    key: &'a str,
    attributes: &'a Attributes,
) -> Result<Option<String>, KmipError> {
    if let Some(bytes) = attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, key) {
        Ok(Some(
            std::str::from_utf8(bytes)
                .map_err(|e| {
                    KmipError::InvalidKmipValue(
                        ErrorReason::Invalid_Attribute_Value,
                        format!("failed deserializing {key} from the attributes: {e}"),
                    )
                })?
                .to_string(),
        ))
    } else {
        Ok(None)
    }
}

/// Extract certificate_id from Attributes
pub fn certificate_id_from_attributes(
    attributes: &Attributes,
) -> Result<Option<String>, KmipError> {
    _from_attributes(VENDOR_ATTR_CERTIFICATE_ID, attributes)
}

/// Extract subject common name from attributes
pub fn subject_common_name_from_attributes(
    attributes: &Attributes,
) -> Result<Option<String>, KmipError> {
    _from_attributes(VENDOR_ATTR_CERTIFICATE_SUBJECT, attributes)
}

/// Extract ca from attributes
pub fn ca_subject_common_names_from_attributes(
    attributes: &Attributes,
) -> Result<Option<String>, KmipError> {
    _from_attributes(VENDOR_ATTR_CERTIFICATE_CA, attributes)
}

/// Add or replace certificate fields (subject, ca, subca etc) in attributes in place
pub fn upsert_subject_common_name_in_attributes(
    attributes: &mut Attributes,
    subject: &str,
) -> Result<(), KmipError> {
    let va = subject_common_name_as_vendor_attribute(subject)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_SUBJECT);
    attributes.add_vendor_attribute(va);
    Ok(())
}
pub fn upsert_ca_subject_common_names_in_attributes(
    attributes: &mut Attributes,
    subject: &str,
) -> Result<(), KmipError> {
    let va = ca_subject_common_names_as_vendor_attribute(subject)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_CA);
    attributes.add_vendor_attribute(va);
    Ok(())
}
