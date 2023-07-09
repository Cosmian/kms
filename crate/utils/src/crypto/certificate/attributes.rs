use cosmian_kmip::{
    error::KmipError,
    kmip::{
        kmip_operations::ErrorReason,
        kmip_types::{Attributes, VendorAttribute},
    },
};

pub const VENDOR_ID_COSMIAN: &str = "cosmian";
pub const VENDOR_ATTR_CERTIFICATE_ATTR: &str = "certificate_attributes";
pub const VENDOR_ATTR_CERTIFICATE_SUBJECT: &str = "certificate_subject";
pub const VENDOR_ATTR_CERTIFICATE_CA: &str = "certificate_ca";
pub const VENDOR_ATTR_CERTIFICATE_VALIDITY: &str = "certificate_validity";

/// Convert subject to a vendor attribute
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
pub fn subject_as_vendor_attribute(subject: &str) -> Result<VendorAttribute, KmipError> {
    _as_vendor_attribute(VENDOR_ATTR_CERTIFICATE_SUBJECT, subject)
}
pub fn ca_as_vendor_attribute(ca: &str) -> Result<VendorAttribute, KmipError> {
    _as_vendor_attribute(VENDOR_ATTR_CERTIFICATE_CA, ca)
}

/// Extract information (subject, ca, subca, etc) from attributes
fn _from_attributes<'a>(key: &'a str, attributes: &'a Attributes) -> Result<String, KmipError> {
    if let Some(bytes) = attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, key) {
        Ok(std::str::from_utf8(bytes)
            .map_err(|e| {
                KmipError::InvalidKmipValue(
                    ErrorReason::Invalid_Attribute_Value,
                    format!("failed deserializing {key} from the attributes: {e}"),
                )
            })?
            .to_string())
    } else {
        Err(KmipError::InvalidKmipValue(
            ErrorReason::Invalid_Attribute_Value,
            format!("the attributes do not contain a {key}"),
        ))
    }
}
pub fn subject_from_attributes(attributes: &Attributes) -> Result<String, KmipError> {
    _from_attributes(VENDOR_ATTR_CERTIFICATE_SUBJECT, attributes)
}
pub fn ca_from_attributes(attributes: &Attributes) -> Result<String, KmipError> {
    _from_attributes(VENDOR_ATTR_CERTIFICATE_CA, attributes)
}

/// Add or replace certificate fields (subject, ca, subca etc) in attributes in place
pub fn upsert_subject_in_attributes(
    attributes: &mut Attributes,
    subject: &str,
) -> Result<(), KmipError> {
    let va = subject_as_vendor_attribute(subject)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_SUBJECT);
    attributes.add_vendor_attribute(va);
    Ok(())
}
pub fn upsert_ca_in_attributes(
    attributes: &mut Attributes,
    subject: &str,
) -> Result<(), KmipError> {
    let va = ca_as_vendor_attribute(subject)?;
    attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_CA);
    attributes.add_vendor_attribute(va);
    Ok(())
}

// /// Convert an validity to a vendor attribute
// pub fn validity_as_vendor_attribute(validity: &str) -> Result<VendorAttribute, KmipError> {
//     Ok(VendorAttribute {
//         vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
//         attribute_name: VENDOR_ATTR_CERTIFICATE_VALIDITY.to_owned(),
//         attribute_value: Vec::<u8>::try_from(validity).map_err(|e| {
//             KmipError::InvalidKmipValue(
//                 ErrorReason::Invalid_Attribute_Value,
//                 format!("failed convert the Certificate validity to bytes: {e}"),
//             )
//         })?,
//     })
// }

// /// Extract an `Certificate` validity from attributes
// pub fn validity_from_attributes(attributes: &Attributes) -> Result<&str, KmipError> {
//     if let Some(bytes) =
//         attributes.get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_VALIDITY)
//     {
//         std::str::from_utf8(bytes).map_err(|e| {
//             KmipError::InvalidKmipValue(
//                 ErrorReason::Invalid_Attribute_Value,
//                 format!("failed deserializing the Certificate validity from the attributes: {e}"),
//             )
//         })
//     } else {
//         Err(KmipError::InvalidKmipValue(
//             ErrorReason::Invalid_Attribute_Value,
//             "the attributes do not contain a Certificate validity".to_string(),
//         ))
//     }
// }

// /// Add or replace an `Certificate` validity in attributes in place
// pub fn upsert_validity_in_attributes(
//     attributes: &mut Attributes,
//     validity: &str,
// ) -> Result<(), KmipError> {
//     let va = validity_as_vendor_attribute(validity)?;
//     attributes.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_CERTIFICATE_VALIDITY);
//     attributes.add_vendor_attribute(va);
//     Ok(())
// }
