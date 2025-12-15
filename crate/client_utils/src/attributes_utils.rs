use std::{collections::HashMap, str::FromStr};

use clap::ValueEnum;
use cosmian_kmip::kmip_2_1::{
    extra::{VENDOR_ID_COSMIAN, tagging::VENDOR_ATTR_TAG},
    kmip_attributes::{Attribute, Attributes},
    kmip_types::{CryptographicAlgorithm, Link, LinkType, LinkedObjectIdentifier, Tag},
};
use serde_json::Value;
use strum::{EnumIter, EnumString, IntoEnumIterator};
use time::{OffsetDateTime, format_description::parse};

use crate::{
    error::UtilsError,
    import_utils::{KeyUsage, build_usage_mask_from_key_usage},
};

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq, EnumIter, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum CLinkType {
    /// For Certificate objects: the parent certificate for a certificate in a
    /// certificate chain. For Public Key objects: the corresponding
    /// certificate(s), containing the same public key.
    Certificate,
    /// For a Private Key object: the public key corresponding to the private
    /// key. For a Certificate object: the public key contained in the
    /// certificate.
    PublicKey,
    /// For a Public Key object: the private key corresponding to the public
    /// key.
    PrivateKey,
    /// For a derived Symmetric Key or Secret Data object: the object(s) from
    /// which the current symmetric key was derived.
    DerivationBaseObject,
    /// The symmetric key(s) or Secret Data object(s) that were derived from
    /// the current object.
    DerivedKey,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that resulted from the re-key of the current
    /// key. For a Certificate object: the certificate that resulted from the
    /// re- certify. Note that there SHALL be only one such replacement
    /// object per Managed Object.
    ReplacementObject,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that was re-keyed to obtain the current key.
    /// For a Certificate object: the certificate that was re-certified to
    /// obtain the current certificate.
    ReplacedObject,
    /// For all object types: the container or other parent object corresponding
    /// to the object.
    Parent,
    /// For all object types: the subordinate, derived or other child object
    /// corresponding to the object.
    Child,
    /// For all object types: the previous object to this object.
    Previous,
    /// For all object types: the next object to this object.
    Next,
    PKCS12Certificate,
    PKCS12Password,
    /// For wrapped objects: the object that was used to wrap this object.
    WrappingKey,
    // Extensions 8XXXXXXX
}

impl From<CLinkType> for LinkType {
    fn from(value: CLinkType) -> Self {
        match value {
            CLinkType::Certificate => Self::CertificateLink,
            CLinkType::PublicKey => Self::PublicKeyLink,
            CLinkType::PrivateKey => Self::PrivateKeyLink,
            CLinkType::DerivationBaseObject => Self::DerivationBaseObjectLink,
            CLinkType::DerivedKey => Self::DerivedKeyLink,
            CLinkType::ReplacementObject => Self::ReplacementObjectLink,
            CLinkType::ReplacedObject => Self::ReplacedObjectLink,
            CLinkType::Parent => Self::ParentLink,
            CLinkType::Child => Self::ChildLink,
            CLinkType::Previous => Self::PreviousLink,
            CLinkType::Next => Self::NextLink,
            CLinkType::PKCS12Certificate => Self::PKCS12CertificateLink,
            CLinkType::PKCS12Password => Self::PKCS12PasswordLink,
            CLinkType::WrappingKey => Self::WrappingKeyLink,
        }
    }
}

fn add_if_not_empty(tag: Tag, new_value: &str, results: &mut HashMap<String, Value>) {
    if !new_value.is_empty() {
        results.insert(
            tag.to_string(),
            serde_json::to_value(new_value).unwrap_or_default(),
        );
    }
}

pub fn parse_selected_attributes(
    attributes: &Attributes,
    attribute_tags: &[Tag],
    attribute_link_types: &[CLinkType],
) -> Result<HashMap<String, Value>, UtilsError> {
    let tags = if attribute_tags.is_empty() {
        Tag::iter().collect()
    } else {
        attribute_tags.to_vec()
    };

    let mut results: HashMap<String, Value> = HashMap::new();
    for tag in &tags {
        match tag {
            Tag::ActivationDate => {
                if let Some(v) = attributes.activation_date.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CertificateLength => {
                if let Some(v) = attributes.certificate_length.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CertificateType => {
                if let Some(v) = attributes.certificate_type.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CertificateSubjectC => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_c, &mut results);
                }
            }
            Tag::CertificateSubjectCN => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_cn, &mut results);
                }
            }
            Tag::CertificateSubjectDC => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_dc, &mut results);
                }
            }
            Tag::CertificateSubjectEmail => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_email, &mut results);
                }
            }
            Tag::CertificateSubjectL => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_l, &mut results);
                }
            }
            Tag::CertificateSubjectO => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_o, &mut results);
                }
            }
            Tag::CertificateSubjectOU => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_ou, &mut results);
                }
            }
            Tag::CertificateSubjectST => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_st, &mut results);
                }
            }
            Tag::CertificateSubjectDNQualifier => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_dn_qualifier, &mut results);
                }
            }
            Tag::CertificateSubjectSerialNumber => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_serial_number, &mut results);
                }
            }
            Tag::CertificateSubjectTitle => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_title, &mut results);
                }
            }
            Tag::CertificateSubjectUID => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_subject_uid, &mut results);
                }
            }
            Tag::CertificateIssuerC => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_c, &mut results);
                }
            }
            Tag::CertificateIssuerCN => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_cn, &mut results);
                }
            }
            Tag::CertificateIssuerDC => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_dc, &mut results);
                }
            }
            Tag::CertificateIssuerEmail => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_email, &mut results);
                }
            }
            Tag::CertificateIssuerL => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_l, &mut results);
                }
            }
            Tag::CertificateIssuerO => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_o, &mut results);
                }
            }
            Tag::CertificateIssuerOU => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_ou, &mut results);
                }
            }
            Tag::CertificateIssuerST => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_st, &mut results);
                }
            }
            Tag::CertificateIssuerDNQualifier => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_dn_qualifier, &mut results);
                }
            }
            Tag::CertificateIssuerUID => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_uid, &mut results);
                }
            }
            Tag::CertificateIssuerSerialNumber => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_serial_number, &mut results);
                }
            }
            Tag::CertificateIssuerTitle => {
                if let Some(v) = attributes.certificate_attributes.as_ref() {
                    add_if_not_empty(*tag, &v.certificate_issuer_title, &mut results);
                }
            }
            Tag::CryptographicAlgorithm => {
                if let Some(v) = attributes.cryptographic_algorithm.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CryptographicLength => {
                if let Some(v) = attributes.cryptographic_length.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CryptographicParameters => {
                if let Some(v) = attributes.cryptographic_parameters.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CryptographicDomainParameters => {
                if let Some(v) = attributes.cryptographic_domain_parameters.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::CryptographicUsageMask => {
                if let Some(v) = attributes.cryptographic_usage_mask.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::KeyFormatType => {
                if let Some(v) = attributes.key_format_type.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::ObjectType => {
                if let Some(v) = attributes.object_type.as_ref() {
                    results.insert(tag.to_string(), serde_json::to_value(v).unwrap_or_default());
                }
            }
            Tag::Tag => {
                let tags = attributes.get_tags();
                results.insert(
                    tag.to_string(),
                    serde_json::to_value(tags).unwrap_or_default(),
                );
            }
            Tag::VendorExtension => {
                if let Some(vendor_attributes) = attributes.vendor_attributes.as_ref() {
                    // Filter out tag-related vendor attributes to avoid duplication
                    // since tags are already displayed separately under the Tag field
                    let filtered_vendor_attributes: Vec<_> = vendor_attributes
                        .iter()
                        .filter(|va| {
                            !(va.vendor_identification == VENDOR_ID_COSMIAN
                                && va.attribute_name == VENDOR_ATTR_TAG)
                        })
                        .collect();

                    // Only include VendorExtension if there are non-tag vendor attributes
                    if !filtered_vendor_attributes.is_empty() {
                        results.insert(
                            tag.to_string(),
                            serde_json::to_value(filtered_vendor_attributes).unwrap_or_default(),
                        );
                    }
                }
            }
            _x => {}
        }
    }

    let link_types: Vec<LinkType> = if attribute_link_types.is_empty() {
        LinkType::iter().collect()
    } else {
        attribute_link_types
            .iter()
            .map(|link| LinkType::from(link.clone()))
            .collect()
    };

    for link_type in &link_types {
        if let Some(v) = attributes.get_link(*link_type).as_ref() {
            results.insert(
                link_type.to_string(),
                serde_json::to_value(v).unwrap_or_default(),
            );
        }
    }

    Ok(results)
}

pub fn parse_selected_attributes_flatten(
    attributes: &Attributes,
    selected_attributes: &[&str],
) -> Result<HashMap<String, Value>, UtilsError> {
    let mut results: HashMap<String, Value> = HashMap::new();
    if selected_attributes.is_empty() {
        let values = serde_json::to_value(attributes)?;

        if let Value::Object(map) = values {
            results = map
                .into_iter()
                .map(|(key, val)| (key, serde_json::to_value(val).unwrap_or(Value::Null)))
                .collect();
        }
        return Ok(results);
    }
    for &selected_attribute_name in selected_attributes {
        match selected_attribute_name {
            "activation_date" => {
                if let Some(v) = attributes.activation_date.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned().clone(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "cryptographic_algorithm" => {
                if let Some(v) = attributes.cryptographic_algorithm.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "cryptographic_length" => {
                if let Some(v) = attributes.cryptographic_length.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "key_usage" => {
                if let Some(v) = attributes.cryptographic_usage_mask.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "key_format_type" => {
                if let Some(v) = attributes.key_format_type.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "object_type" => {
                if let Some(v) = attributes.object_type.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "vendor_attributes" => {
                if let Some(vendor_attributes) = attributes.vendor_attributes.as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(vendor_attributes).unwrap_or_default(),
                    );
                }
            }
            "public_key_id" => {
                if let Some(v) = attributes.get_link(LinkType::PublicKeyLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "private_key_id" => {
                if let Some(v) = attributes.get_link(LinkType::PrivateKeyLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "certificate_id" => {
                if let Some(v) = attributes.get_link(LinkType::CertificateLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "pkcs12_certificate_id" => {
                if let Some(v) = attributes
                    .get_link(LinkType::PKCS12CertificateLink)
                    .as_ref()
                {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "pkcs12_password_certificate" => {
                if let Some(v) = attributes.get_link(LinkType::PKCS12PasswordLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "parent_id" => {
                if let Some(v) = attributes.get_link(LinkType::ParentLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            "child_id" => {
                if let Some(v) = attributes.get_link(LinkType::ChildLink).as_ref() {
                    results.insert(
                        selected_attribute_name.to_owned(),
                        serde_json::to_value(v).unwrap_or_default(),
                    );
                }
            }
            _x => {}
        }
    }
    Ok(results)
}

pub fn build_selected_attribute(
    attribute_name: &str,
    attribute_value: String,
) -> Result<Attribute, UtilsError> {
    let attribute = match attribute_name {
        "activation_date" => {
            let format = parse("[year]-[month]-[day]T[hour]:[minute]:[second]Z")
                .map_err(|e| UtilsError::Default(e.to_string()))?;
            let activation_date = OffsetDateTime::parse(&attribute_value, &format)
                .map_err(|e| UtilsError::Default(e.to_string()))?;
            Attribute::ActivationDate(activation_date)
        }
        "cryptographic_algorithm" => {
            let cryptographic_algorithm =
                CryptographicAlgorithm::from_str(attribute_value.as_str())
                    .map_err(|e| UtilsError::Default(e.to_string()))?;
            Attribute::CryptographicAlgorithm(cryptographic_algorithm)
        }
        "cryptographic_length" => {
            let cryptographic_length = attribute_value
                .parse::<i32>()
                .map_err(|e| UtilsError::Default(e.to_string()))?;
            Attribute::CryptographicLength(cryptographic_length)
        }
        "key_usage" => {
            let key_usage = attribute_value
                .parse::<KeyUsage>()
                .map_err(|e| UtilsError::Default(e.to_string()))?;
            let Some(cryptographic_usage_mask) = build_usage_mask_from_key_usage(&[key_usage])
            else {
                return Err(UtilsError::Default(
                    "Error building cryptographic usage mask".to_owned(),
                ));
            };
            Attribute::CryptographicUsageMask(cryptographic_usage_mask)
        }
        "public_key_id" => Attribute::Link(Link {
            link_type: LinkType::PublicKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "private_key_id" => Attribute::Link(Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "certificate_id" => Attribute::Link(Link {
            link_type: LinkType::CertificateLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "pkcs12_certificate_id" => Attribute::Link(Link {
            link_type: LinkType::PKCS12CertificateLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "pkcs12_password_certificate" => Attribute::Link(Link {
            link_type: LinkType::PKCS12PasswordLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "parent_id" => Attribute::Link(Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),
        "child_id" => Attribute::Link(Link {
            link_type: LinkType::ChildLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(attribute_value),
        }),

        _ => {
            return Err(UtilsError::Default(format!(
                "Unknown attribute name: {attribute_name}"
            )));
        }
    };
    Ok(attribute)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use crate::reexport::cosmian_kmip::kmip_2_1::{
        extra::{VENDOR_ID_COSMIAN, tagging::VENDOR_ATTR_TAG},
        kmip_attributes::Attributes,
        kmip_types::{CryptographicAlgorithm, VendorAttribute, VendorAttributeValue},
    };

    #[test]
    fn test_vendor_extension_tag_filtering() {
        // Create test attributes with vendor extensions including tags
        let mut attributes = Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            ..Default::default()
        };

        // Add vendor attributes including tag data and other data
        let tag_vendor_attr = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_TAG.to_owned(),
            attribute_value: VendorAttributeValue::TextString(
                "[\"_cert\",\"test_cert\"]".to_owned(),
            ),
        };

        let other_vendor_attr = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: "some_other_attr".to_owned(),
            attribute_value: VendorAttributeValue::TextString("some_value".to_owned()),
        };

        attributes.vendor_attributes = Some(vec![tag_vendor_attr, other_vendor_attr]);

        // Test the parsing with no specific tags requested (should return all)
        let result = parse_selected_attributes(&attributes, &[], &[]).unwrap();

        // Check that VendorExtension exists but doesn't contain tag data
        if let Some(vendor_extension) = result.get("VendorExtension") {
            // Parse as array of vendor attributes and check for tag filtering
            if let Ok(vendor_attrs) =
                serde_json::from_value::<Vec<VendorAttribute>>(vendor_extension.clone())
            {
                let has_tag_attr = vendor_attrs.iter().any(|va| {
                    va.vendor_identification == VENDOR_ID_COSMIAN
                        && va.attribute_name == VENDOR_ATTR_TAG
                });

                assert!(
                    !has_tag_attr,
                    "Tag vendor attribute should be filtered out from VendorExtension"
                );
                assert_eq!(
                    vendor_attrs.len(),
                    1,
                    "Should have exactly one non-tag vendor attribute"
                );
                assert_eq!(vendor_attrs[0].attribute_name, "some_other_attr");
            } else {
                panic!("Failed to parse vendor extension as array of VendorAttribute");
            }
        } else {
            panic!("VendorExtension should be present when there are non-tag vendor attributes");
        }

        // Check that CryptographicAlgorithm is present
        assert!(
            result.contains_key("CryptographicAlgorithm"),
            "CryptographicAlgorithm should be present"
        );

        // Check that Tag is present (should show parsed tags)
        assert!(result.contains_key("Tag"), "Tag field should be present");
    }

    #[test]
    fn test_vendor_extension_only_tags_filtered_out() {
        // Create test attributes with vendor extensions containing only tag data
        let mut attributes = Attributes::default();

        // Add vendor attributes with only tag data
        let tag_vendor_attr = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_TAG.to_owned(),
            attribute_value: VendorAttributeValue::TextString("[\"_cert\"]".to_owned()),
        };

        attributes.vendor_attributes = Some(vec![tag_vendor_attr]);

        // Test the parsing
        let result = parse_selected_attributes(&attributes, &[], &[]).unwrap();

        // Check that VendorExtension is not present when only tag data exists
        assert!(
            !result.contains_key("VendorExtension"),
            "VendorExtension should not be present when it would only contain tag data"
        );

        // Check that Tag is still present
        assert!(
            result.contains_key("Tag"),
            "Tag field should still be present"
        );
    }
}
