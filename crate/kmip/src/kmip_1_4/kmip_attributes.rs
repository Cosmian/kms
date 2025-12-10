use std::fmt::{self, Formatter};

use cosmian_logger::warn;
use num_bigint_dig::BigInt;
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
};
use time::OffsetDateTime;

pub use crate::{
    KmipError,
    kmip_0::kmip_types::{
        AlternativeName, ApplicationSpecificInformation, BlockCipherMode, CertificateType,
        CryptographicUsageMask, KeyValueLocationType, PaddingMethod, RevocationReason, State,
        UsageLimits, X509CertificateIdentifier,
    },
    kmip_1_4::{
        kmip_data_structures::CryptographicParameters,
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, Digest,
            DigitalSignatureAlgorithm, Link, Name, ObjectType, RandomNumberGenerator,
        },
    },
    kmip_2_1::{
        self,
        kmip_types::{VendorAttribute, VendorAttributeValue},
    },
};
use crate::{kmip_0::kmip_types::HashingAlgorithm, kmip_1_4::kmip_types::CustomAttribute};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    ActivationDate(OffsetDateTime),
    AlternativeName(AlternativeName),
    AlwaysSensitive(bool),
    ApplicationSpecificInformation(ApplicationSpecificInformation),
    ArchiveDate(OffsetDateTime),
    CertificateIdentifier(String),
    CertificateIssuer(String),
    CertificateLength(i32),
    CertificateSubject(String),
    CertificateType(CertificateType),
    Comment(String),
    CompromiseDate(OffsetDateTime),
    CompromiseOccurrenceDate(OffsetDateTime),
    ContactInformation(String),
    CryptographicAlgorithm(CryptographicAlgorithm),
    CryptographicDomainParameters(CryptographicDomainParameters),
    CryptographicLength(i32),
    CryptographicParameters(CryptographicParameters),
    CryptographicUsageMask(CryptographicUsageMask),
    CustomAttribute(CustomAttribute),
    DeactivationDate(OffsetDateTime),
    Description(String),
    DestroyDate(OffsetDateTime),
    DigitalSignatureAlgorithm(DigitalSignatureAlgorithm),
    Digest(Digest),
    Extractable(bool),
    Fresh(bool),
    InitialDate(OffsetDateTime),
    KeyValueLocation(KeyValueLocationType),
    KeyValuePresent(bool),
    LastChangeDate(OffsetDateTime),
    LeaseTime(u32),
    Link(Link),
    Name(Name),
    NeverExtractable(bool),
    ObjectGroup(String),
    ObjectType(ObjectType),
    OperationPolicyName(String),
    OriginalCreationDate(OffsetDateTime),
    Pkcs12FriendlyName(String),
    ProcessStartDate(OffsetDateTime),
    ProtectStopDate(OffsetDateTime),
    RandomNumberGenerator(RandomNumberGenerator),
    RevocationReason(RevocationReason),
    Sensitive(bool),
    State(State),
    UniqueIdentifier(String),
    UsageLimits(UsageLimits),
    X509CertificateIdentifier(X509CertificateIdentifier),
    X509CertificateIssuer(String),
    X509CertificateSubject(String),
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut st = serializer.serialize_struct("Attribute", 2)?;
        match self {
            Self::UniqueIdentifier(value) => {
                st.serialize_field("AttributeName", "Unique Identifier")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Name(value) => {
                st.serialize_field("AttributeName", "Name")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ObjectType(value) => {
                st.serialize_field("AttributeName", "Object Type")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CryptographicAlgorithm(value) => {
                st.serialize_field("AttributeName", "Cryptographic Algorithm")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CryptographicLength(value) => {
                st.serialize_field("AttributeName", "Cryptographic Length")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CryptographicParameters(value) => {
                st.serialize_field("AttributeName", "Cryptographic Parameters")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CryptographicDomainParameters(value) => {
                st.serialize_field("AttributeName", "Cryptographic Domain Parameters")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CertificateType(value) => {
                st.serialize_field("AttributeName", "Certificate Type")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CertificateLength(value) => {
                // KMIP 1.4 uses the spaced form "Certificate Length"
                st.serialize_field("AttributeName", "Certificate Length")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::X509CertificateIdentifier(value) => {
                st.serialize_field("AttributeName", "X.509 Certificate Identifier")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::X509CertificateSubject(value) => {
                st.serialize_field("AttributeName", "X.509 Certificate Subject")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::X509CertificateIssuer(value) => {
                st.serialize_field("AttributeName", "X.509 Certificate Issuer")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CertificateIdentifier(value) => {
                st.serialize_field("AttributeName", "Certificate Identifier")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CertificateSubject(value) => {
                st.serialize_field("AttributeName", "Certificate Subject")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CertificateIssuer(value) => {
                st.serialize_field("AttributeName", "Certificate Issuer")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::DigitalSignatureAlgorithm(value) => {
                st.serialize_field("AttributeName", "Digital Signature Algorithm")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Digest(value) => {
                st.serialize_field("AttributeName", "Digest")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::OperationPolicyName(value) => {
                st.serialize_field("AttributeName", "Operation Policy Name")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CryptographicUsageMask(value) => {
                st.serialize_field("AttributeName", "Cryptographic Usage Mask")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::LeaseTime(value) => {
                st.serialize_field("AttributeName", "Lease Time")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::UsageLimits(value) => {
                st.serialize_field("AttributeName", "Usage Limits")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::State(value) => {
                st.serialize_field("AttributeName", "State")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::InitialDate(value) => {
                st.serialize_field("AttributeName", "Initial Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ActivationDate(value) => {
                st.serialize_field("AttributeName", "Activation Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ProcessStartDate(value) => {
                st.serialize_field("AttributeName", "Process Start Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ProtectStopDate(value) => {
                st.serialize_field("AttributeName", "Protect Stop Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::DeactivationDate(value) => {
                st.serialize_field("AttributeName", "Deactivation Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::DestroyDate(value) => {
                st.serialize_field("AttributeName", "Destroy Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CompromiseOccurrenceDate(value) => {
                st.serialize_field("AttributeName", "Compromise Occurrence Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CompromiseDate(value) => {
                st.serialize_field("AttributeName", "Compromise Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::RevocationReason(value) => {
                st.serialize_field("AttributeName", "Revocation Reason")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ArchiveDate(value) => {
                st.serialize_field("AttributeName", "Archive Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ObjectGroup(value) => {
                st.serialize_field("AttributeName", "Object Group")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Fresh(value) => {
                st.serialize_field("AttributeName", "Fresh")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Link(value) => {
                st.serialize_field("AttributeName", "Link")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ApplicationSpecificInformation(value) => {
                st.serialize_field("AttributeName", "Application Specific Information")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::ContactInformation(value) => {
                st.serialize_field("AttributeName", "Contact Information")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::LastChangeDate(value) => {
                st.serialize_field("AttributeName", "Last Change Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::CustomAttribute(ca) => {
                if ca.name.starts_with("x-") || ca.name.starts_with("y-") {
                    st.serialize_field("AttributeName", &ca.name)?;
                    st.serialize_field("AttributeValue", &ca.value)?;
                } else {
                    return Err(serde::ser::Error::custom(format!(
                        "Custom attribute names must start with 'x-' or 'y-', found '{}'",
                        ca.name
                    )));
                }
            }
            Self::AlternativeName(value) => {
                st.serialize_field("AttributeName", "Alternative Name")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::KeyValuePresent(value) => {
                st.serialize_field("AttributeName", "Key Value Present")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::KeyValueLocation(value) => {
                st.serialize_field("AttributeName", "Key Value Location")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::OriginalCreationDate(value) => {
                st.serialize_field("AttributeName", "Original Creation Date")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::RandomNumberGenerator(value) => {
                st.serialize_field("AttributeName", "Random Number Generator")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Pkcs12FriendlyName(value) => {
                st.serialize_field("AttributeName", "PKCS#12 Friendly Name")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Description(value) => {
                st.serialize_field("AttributeName", "Description")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Comment(value) => {
                st.serialize_field("AttributeName", "Comment")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Sensitive(value) => {
                st.serialize_field("AttributeName", "Sensitive")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::AlwaysSensitive(value) => {
                st.serialize_field("AttributeName", "Always Sensitive")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::Extractable(value) => {
                st.serialize_field("AttributeName", "Extractable")?;
                st.serialize_field("AttributeValue", value)?;
            }
            Self::NeverExtractable(value) => {
                st.serialize_field("AttributeName", "Never Extractable")?;
                st.serialize_field("AttributeValue", value)?;
            }
        }
        st.end()
    }
}

impl<'de> Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AttributeVisitor;

        impl<'de> Visitor<'de> for AttributeVisitor {
            type Value = Attribute;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct Attribute")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let Some(attribute_name_key) = map.next_key::<String>()? else {
                    return Err(de::Error::custom("missing attribute name in attribute"));
                };
                if attribute_name_key != "AttributeName" {
                    return Err(de::Error::custom(format!(
                        "expected AttributeName in attribute, found {attribute_name_key}"
                    )));
                }
                let attribute_name_value = map.next_value::<String>()?;

                // TODO: Special case of Notify for which there is no attribute value
                // This server cannot handle Notify for now

                // Some clients include an optional AttributeIndex (and/or VendorIdentification)
                // between AttributeName and AttributeValue. Tolerate and skip these fields
                // before reading the actual AttributeValue.
                let mut next_key = map.next_key::<String>()?;
                // Loop until we encounter AttributeValue, consuming tolerated intermediate fields.
                while let Some(key) = next_key.as_ref() {
                    match key.as_str() {
                        "AttributeValue" => break,
                        "AttributeIndex" => {
                            // Consume the index value and move to next key
                            let _index: i32 = map.next_value()?;
                            next_key = map.next_key::<String>()?;
                        }
                        "VendorIdentification" => {
                            // Consume vendor identification and move to next key
                            let _vendor: String = map.next_value()?;
                            next_key = map.next_key::<String>()?;
                        }
                        _ => {
                            return Err(de::Error::custom(format!(
                                "expected AttributeValue in attribute, found {key}"
                            )));
                        }
                    }
                }
                // Ensure we stopped on AttributeValue
                if next_key.as_deref() != Some("AttributeValue") {
                    return Err(de::Error::custom("No attribute value in attribute"));
                }
                match attribute_name_value.as_str() {
                    "Unique Identifier" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::UniqueIdentifier(value))
                    }
                    "Name" => {
                        let value: Name = map.next_value()?;
                        Ok(Attribute::Name(value))
                    }
                    "Object Type" => {
                        let value: ObjectType = map.next_value()?;
                        Ok(Attribute::ObjectType(value))
                    }
                    "Cryptographic Algorithm" => {
                        let value: CryptographicAlgorithm = map.next_value()?;
                        Ok(Attribute::CryptographicAlgorithm(value))
                    }
                    "Cryptographic Length" => {
                        let value: i32 = map.next_value()?;
                        Ok(Attribute::CryptographicLength(value))
                    }
                    "Cryptographic Parameters" => {
                        // Some KMIP 1.4 vectors encode AttributeValue directly as a single Enumeration
                        // (e.g., HMACSHA256) instead of the full CryptographicParameters structure.
                        // Accept both forms by deserializing an untagged union and mapping into a structure.
                        #[derive(Deserialize)]
                        #[serde(untagged)]
                        enum CryptoParamsOrEnum {
                            Struct(CryptographicParameters),
                            BlockCipherMode(BlockCipherMode),
                            PaddingMethod(PaddingMethod),
                            CryptographicAlgorithm(CryptographicAlgorithm),
                            DigitalSignatureAlgorithm(DigitalSignatureAlgorithm),
                            HashingAlgorithm(HashingAlgorithm),
                        }

                        let value: CryptoParamsOrEnum = map.next_value()?;
                        let params = match value {
                            CryptoParamsOrEnum::Struct(s) => s,
                            CryptoParamsOrEnum::BlockCipherMode(m) => CryptographicParameters {
                                block_cipher_mode: Some(m),
                                ..Default::default()
                            },
                            CryptoParamsOrEnum::PaddingMethod(p) => CryptographicParameters {
                                padding_method: Some(p),
                                ..Default::default()
                            },
                            CryptoParamsOrEnum::CryptographicAlgorithm(a) => {
                                CryptographicParameters {
                                    cryptographic_algorithm: Some(a),
                                    ..Default::default()
                                }
                            }
                            CryptoParamsOrEnum::DigitalSignatureAlgorithm(d) => {
                                CryptographicParameters {
                                    digital_signature_algorithm: Some(d),
                                    ..Default::default()
                                }
                            }
                            CryptoParamsOrEnum::HashingAlgorithm(h) => CryptographicParameters {
                                hashing_algorithm: Some(h),
                                ..Default::default()
                            },
                        };
                        Ok(Attribute::CryptographicParameters(params))
                    }
                    "Cryptographic Domain Parameters" => {
                        let value: CryptographicDomainParameters = map.next_value()?;
                        Ok(Attribute::CryptographicDomainParameters(value))
                    }
                    "Certificate Type" => {
                        let value: CertificateType = map.next_value()?;
                        Ok(Attribute::CertificateType(value))
                    }
                    "Certificate Length" => {
                        let value: i32 = map.next_value()?;
                        Ok(Attribute::CertificateLength(value))
                    }
                    "X.509 Certificate Identifier" => {
                        let value: X509CertificateIdentifier = map.next_value()?;
                        Ok(Attribute::X509CertificateIdentifier(value))
                    }
                    "X.509 Certificate Subject" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::X509CertificateSubject(value))
                    }
                    "X.509 Certificate Issuer" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::X509CertificateIssuer(value))
                    }
                    "Certificate Identifier" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::CertificateIdentifier(value))
                    }
                    "Certificate Subject" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::CertificateSubject(value))
                    }
                    "Certificate Issuer" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::CertificateIssuer(value))
                    }
                    "Digital Signature Algorithm" => {
                        let value: DigitalSignatureAlgorithm = map.next_value()?;
                        Ok(Attribute::DigitalSignatureAlgorithm(value))
                    }
                    "Digest" => {
                        let value: Digest = map.next_value()?;
                        Ok(Attribute::Digest(value))
                    }
                    "Operation Policy Name" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::OperationPolicyName(value))
                    }
                    "Cryptographic Usage Mask" => {
                        let value: CryptographicUsageMask = map.next_value()?;
                        Ok(Attribute::CryptographicUsageMask(value))
                    }
                    "Lease Time" => {
                        let value: u32 = map.next_value()?;
                        Ok(Attribute::LeaseTime(value))
                    }
                    "Usage Limits" => {
                        let value: UsageLimits = map.next_value()?;
                        Ok(Attribute::UsageLimits(value))
                    }
                    "State" => {
                        let value: State = map.next_value()?;
                        Ok(Attribute::State(value))
                    }
                    "Initial Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::InitialDate(value))
                    }
                    "Activation Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::ActivationDate(value))
                    }
                    "Process Start Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::ProcessStartDate(value))
                    }
                    "Protect Stop Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::ProtectStopDate(value))
                    }
                    "Deactivation Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::DeactivationDate(value))
                    }
                    "Destroy Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::DestroyDate(value))
                    }
                    "Compromise Occurrence Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::CompromiseOccurrenceDate(value))
                    }
                    "Compromise Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::CompromiseDate(value))
                    }
                    "Revocation Reason" => {
                        let value: RevocationReason = map.next_value()?;
                        Ok(Attribute::RevocationReason(value))
                    }
                    "Archive Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::ArchiveDate(value))
                    }
                    "Object Group" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::ObjectGroup(value))
                    }
                    "Fresh" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::Fresh(value))
                    }
                    "Link" => {
                        let value: Link = map.next_value()?;
                        Ok(Attribute::Link(value))
                    }
                    "Application Specific Information" => {
                        let value: ApplicationSpecificInformation = map.next_value()?;
                        Ok(Attribute::ApplicationSpecificInformation(value))
                    }
                    "Contact Information" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::ContactInformation(value))
                    }
                    "Last Change Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::LastChangeDate(value))
                    }
                    "Alternative Name" => {
                        let value: AlternativeName = map.next_value()?;
                        Ok(Attribute::AlternativeName(value))
                    }
                    "Key Value Present" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::KeyValuePresent(value))
                    }
                    "Key Value Location" => {
                        let value: KeyValueLocationType = map.next_value()?;
                        Ok(Attribute::KeyValueLocation(value))
                    }
                    "Original Creation Date" => {
                        let value: OffsetDateTime = map.next_value()?;
                        Ok(Attribute::OriginalCreationDate(value))
                    }
                    "Random Number Generator" => {
                        let value: RandomNumberGenerator = map.next_value()?;
                        Ok(Attribute::RandomNumberGenerator(value))
                    }
                    "PKCS#12 Friendly Name" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::Pkcs12FriendlyName(value))
                    }
                    "Description" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::Description(value))
                    }
                    "Comment" => {
                        let value: String = map.next_value()?;
                        Ok(Attribute::Comment(value))
                    }
                    "Sensitive" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::Sensitive(value))
                    }
                    "Always Sensitive" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::AlwaysSensitive(value))
                    }
                    "Extractable" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::Extractable(value))
                    }
                    "Never Extractable" => {
                        let value: bool = map.next_value()?;
                        Ok(Attribute::NeverExtractable(value))
                    }
                    name if name.starts_with("x-") || name.starts_with("y-") => {
                        // Custom attributes with vendor prefix
                        let value: CustomAttributeValue = map.next_value()?;
                        Ok(Attribute::CustomAttribute(CustomAttribute {
                            name: name.to_owned(),
                            value,
                        }))
                    }
                    // This should never happen, but just in case
                    "Custom Attribute" => {
                        let value: String = map.next_value()?;
                        serde_json::from_str(&value)
                            .map_err(de::Error::custom)
                            .map(|ca: CustomAttribute| Attribute::CustomAttribute(ca))
                    }
                    name => Err(de::Error::custom(format!("invalid attribute name: {name}"))),
                }
            }
        }

        deserializer.deserialize_struct(
            "Attribute",
            &["AttributeName", "AttributeValue"],
            AttributeVisitor,
        )
    }
}

impl From<Attribute> for kmip_2_1::kmip_attributes::Attribute {
    fn from(attribute: Attribute) -> Self {
        match attribute {
            Attribute::ActivationDate(v) => Self::ActivationDate(v),
            Attribute::AlternativeName(v) => Self::AlternativeName(v),
            Attribute::AlwaysSensitive(v) => Self::AlwaysSensitive(v),
            Attribute::ApplicationSpecificInformation(v) => Self::ApplicationSpecificInformation(v),
            Attribute::ArchiveDate(v) => Self::ArchiveDate(v),
            Attribute::CertificateLength(v) => Self::CertificateLength(v),
            Attribute::CertificateType(v) => Self::CertificateType(v),
            Attribute::Comment(v) => Self::Comment(v),
            Attribute::CompromiseDate(v) => Self::CompromiseDate(v),
            Attribute::CompromiseOccurrenceDate(v) => Self::CompromiseOccurrenceDate(v),
            Attribute::ContactInformation(v) => Self::ContactInformation(v),
            Attribute::CryptographicAlgorithm(v) => Self::CryptographicAlgorithm(v.into()),
            Attribute::CryptographicDomainParameters(v) => {
                Self::CryptographicDomainParameters(v.into())
            }
            Attribute::CryptographicLength(v) => Self::CryptographicLength(v),
            Attribute::CryptographicParameters(v) => Self::CryptographicParameters(v.into()),
            Attribute::CryptographicUsageMask(v) => Self::CryptographicUsageMask(v),
            Attribute::CustomAttribute(ca) => {
                if ca.name.starts_with("x-") {
                    Self::VendorAttribute(VendorAttribute {
                        vendor_identification: "KMIP1".to_owned(),
                        attribute_name: ca.name.clone(),
                        attribute_value: ca.value.into(),
                    })
                } else if ca.name.starts_with("y-") {
                    // y- not supported by PyKMIP
                    if &ca.name == "y-unsupported-2_1-attribute" {
                        if let CustomAttributeValue::TextString(s) = &ca.value {
                            // This is a 2.1 attribute serialized to a 1.x attribute we want to deserialize back
                            let attribute: Self = serde_json::from_str(s).unwrap_or_else(|_| {
                                warn!("Failed to deserialize KMIP 2.1 attribute: {}", s);
                                Self::Comment(format!("Unknown KMIP 2.1 attribute: {s}"))
                            });
                            attribute
                        } else {
                            warn!(
                                "Unexpected value type for y-unsupported-2_1-attribute: {:?}",
                                ca.value
                            );
                            Self::Comment(format!("Unsupported KMIP 2.1 attribute: {:?}", ca.value))
                        }
                    } else if let Some((vendor_id, attribute_name)) = ca.name.split_once("::") {
                        Self::VendorAttribute(VendorAttribute {
                            vendor_identification: vendor_id.to_owned(),
                            attribute_name: attribute_name.to_owned(),
                            attribute_value: ca.value.into(),
                        })
                    } else {
                        Self::VendorAttribute(VendorAttribute {
                            vendor_identification: "UNKNOWN".to_owned(),
                            attribute_name: ca.name.clone(),
                            attribute_value: ca.value.into(),
                        })
                    }
                } else {
                    // This should never happen, but just in case
                    warn!(
                        "Custom attribute name does not start with 'x-' or 'y-': {}",
                        ca.name
                    );
                    Self::VendorAttribute(VendorAttribute {
                        vendor_identification: "INVALID".to_owned(),
                        attribute_name: ca.name,
                        attribute_value: ca.value.into(),
                    })
                }
            }
            Attribute::DeactivationDate(v) => Self::DeactivationDate(v),
            Attribute::Description(v) => Self::Description(v),
            Attribute::DestroyDate(v) => Self::DestroyDate(v),
            Attribute::Digest(v) => Self::Digest(v.into()),
            Attribute::Pkcs12FriendlyName(_)
            | Attribute::X509CertificateIdentifier(_)
            | Attribute::X509CertificateIssuer(_)
            | Attribute::X509CertificateSubject(_)
            | Attribute::CertificateIdentifier(_)
            | Attribute::CertificateIssuer(_)
            | Attribute::CertificateSubject(_) => {
                warn!("KMIP 2.1 does not support the KMIP 1 attribute {attribute:?}");
                Self::Comment("Unsupported KMIP 1.4 attribute".to_owned())
            }
            Attribute::DigitalSignatureAlgorithm(v) => Self::DigitalSignatureAlgorithm(v.into()),
            Attribute::Extractable(v) => Self::Extractable(v),
            Attribute::Fresh(v) => Self::Fresh(v),
            Attribute::InitialDate(v) => Self::InitialDate(v),
            Attribute::KeyValueLocation(v) => Self::KeyValueLocation(v),
            Attribute::KeyValuePresent(v) => Self::KeyValuePresent(v),
            Attribute::LastChangeDate(v) => Self::LastChangeDate(v),
            // KMIP 1.4 uses u32 (Interval); KMIP 2.1 uses i32.
            Attribute::LeaseTime(v) => Self::LeaseTime(i32::try_from(v).unwrap_or_else(|_| {
                warn!(
                    "KMIP 1.4 Lease Time ({v}) exceeds i32::MAX; clamping to {}",
                    i32::MAX
                );
                i32::MAX
            })),
            Attribute::Link(v) => Self::Link(v.into()),
            Attribute::Name(v) => Self::Name(v.into()),
            Attribute::NeverExtractable(v) => Self::NeverExtractable(v),
            Attribute::ObjectGroup(v) => Self::ObjectGroup(v),
            Attribute::ObjectType(v) => Self::ObjectType(v.into()),
            Attribute::OperationPolicyName(v) => Self::VendorAttribute(VendorAttribute {
                vendor_identification: "KMIP1".to_owned(),
                attribute_name: "__Operation Policy Name__".to_owned(),
                attribute_value: VendorAttributeValue::TextString(v),
            }),
            Attribute::OriginalCreationDate(v) => Self::OriginalCreationDate(v),
            Attribute::ProcessStartDate(v) => Self::ProcessStartDate(v),
            Attribute::ProtectStopDate(v) => Self::ProtectStopDate(v),
            Attribute::RandomNumberGenerator(v) => Self::RandomNumberGenerator(v.into()),
            Attribute::RevocationReason(v) => Self::RevocationReason(v),
            Attribute::Sensitive(v) => Self::Sensitive(v),
            Attribute::State(v) => Self::State(v),
            Attribute::UniqueIdentifier(v) => {
                Self::UniqueIdentifier(kmip_2_1::kmip_types::UniqueIdentifier::TextString(v))
            }
            Attribute::UsageLimits(v) => Self::UsageLimits(v.into()),
        }
    }
}

// https://libkmip.readthedocs.io/en/latest/index.html
impl TryFrom<kmip_2_1::kmip_attributes::Attribute> for Attribute {
    type Error = KmipError;

    fn try_from(attribute: kmip_2_1::kmip_attributes::Attribute) -> Result<Self, Self::Error> {
        match attribute {
            kmip_2_1::kmip_attributes::Attribute::ActivationDate(v) => Ok(Self::ActivationDate(v)),
            kmip_2_1::kmip_attributes::Attribute::CryptographicDomainParameters(v) => {
                Ok(Self::CryptographicDomainParameters(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::CryptographicLength(v) => {
                Ok(Self::CryptographicLength(v))
            }
            kmip_2_1::kmip_attributes::Attribute::CryptographicParameters(v) => {
                Ok(Self::CryptographicParameters(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::CryptographicUsageMask(v) => {
                Ok(Self::CryptographicUsageMask(v))
            }
            kmip_2_1::kmip_attributes::Attribute::DeactivationDate(v) => {
                Ok(Self::DeactivationDate(v))
            }
            kmip_2_1::kmip_attributes::Attribute::Description(v) => Ok(Self::Description(v)),
            kmip_2_1::kmip_attributes::Attribute::Name(v) => Ok(Self::Name(v.try_into()?)),
            kmip_2_1::kmip_attributes::Attribute::ObjectType(v) => {
                Ok(Self::ObjectType(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::ProcessStartDate(v) => {
                Ok(Self::ProcessStartDate(v))
            }
            kmip_2_1::kmip_attributes::Attribute::ProtectStopDate(v) => {
                Ok(Self::ProtectStopDate(v))
            }
            kmip_2_1::kmip_attributes::Attribute::UniqueIdentifier(v) => {
                Ok(Self::UniqueIdentifier(v.to_string()))
            }
            kmip_2_1::kmip_attributes::Attribute::CryptographicAlgorithm(v) => {
                Ok(Self::CryptographicAlgorithm(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::CertificateType(v) => {
                Ok(Self::CertificateType(v))
            }
            kmip_2_1::kmip_attributes::Attribute::CertificateLength(v) => {
                Ok(Self::CertificateLength(v))
            }
            kmip_2_1::kmip_attributes::Attribute::Digest(v) => Ok(Self::Digest(v.try_into()?)),
            kmip_2_1::kmip_attributes::Attribute::DigitalSignatureAlgorithm(v) => {
                Ok(Self::DigitalSignatureAlgorithm(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::LeaseTime(v) => {
                // KMIP 2.1 uses i32, KMIP 1.4 uses u32. Convert safely.
                Ok(Self::LeaseTime(u32::try_from(v).unwrap_or(0)))
            }
            kmip_2_1::kmip_attributes::Attribute::UsageLimits(v) => Ok(Self::UsageLimits(v.into())),
            kmip_2_1::kmip_attributes::Attribute::State(v) => Ok(Self::State(v)),
            kmip_2_1::kmip_attributes::Attribute::InitialDate(v) => Ok(Self::InitialDate(v)),
            kmip_2_1::kmip_attributes::Attribute::DestroyDate(v) => Ok(Self::DestroyDate(v)),
            kmip_2_1::kmip_attributes::Attribute::CompromiseOccurrenceDate(v) => {
                Ok(Self::CompromiseOccurrenceDate(v))
            }
            kmip_2_1::kmip_attributes::Attribute::CompromiseDate(v) => Ok(Self::CompromiseDate(v)),
            kmip_2_1::kmip_attributes::Attribute::RevocationReason(v) => {
                Ok(Self::RevocationReason(v))
            }
            kmip_2_1::kmip_attributes::Attribute::ArchiveDate(v) => Ok(Self::ArchiveDate(v)),
            kmip_2_1::kmip_attributes::Attribute::ObjectGroup(v) => Ok(Self::ObjectGroup(v)),
            kmip_2_1::kmip_attributes::Attribute::Fresh(v) => Ok(Self::Fresh(v)),
            kmip_2_1::kmip_attributes::Attribute::Link(v) => Ok(Self::Link(v.try_into()?)),
            kmip_2_1::kmip_attributes::Attribute::ApplicationSpecificInformation(v) => {
                Ok(Self::ApplicationSpecificInformation(v))
            }
            kmip_2_1::kmip_attributes::Attribute::ContactInformation(v) => {
                Ok(Self::ContactInformation(v))
            }
            kmip_2_1::kmip_attributes::Attribute::LastChangeDate(v) => Ok(Self::LastChangeDate(v)),
            kmip_2_1::kmip_attributes::Attribute::VendorAttribute(vendor_attribute) => {
                let vendor_id = vendor_attribute.vendor_identification;
                if vendor_id.as_str() == "KMIP1" {
                    if vendor_attribute.attribute_name.as_str() == "__Operation Policy Name__" {
                        Ok(Self::OperationPolicyName(
                            vendor_attribute.attribute_value.to_string(),
                        ))
                    } else {
                        Ok(Self::CustomAttribute(CustomAttribute {
                            name: vendor_attribute.attribute_name,
                            value: vendor_attribute.attribute_value.into(),
                        }))
                    }
                } else if vendor_id.as_str() == "x" {
                    // KMIP 1.x TL vectors expect vendor attributes with the synthetic
                    // "x-" prefix (e.g., x-ID, x-Barcode). When the server stores
                    // attributes internally as KMIP 2.1 VendorAttribute with
                    // vendor_identification="x", map back to KMIP 1.4 CustomAttribute
                    // using the expected x-* naming convention.
                    Ok(Self::CustomAttribute(CustomAttribute {
                        name: format!("x-{}", vendor_attribute.attribute_name),
                        value: vendor_attribute.attribute_value.into(),
                    }))
                } else {
                    let name = format!("y-{}::{}", vendor_id, vendor_attribute.attribute_name);
                    let value = vendor_attribute.attribute_value.into();
                    Ok(Self::CustomAttribute(CustomAttribute { name, value }))
                }
            }
            kmip_2_1::kmip_attributes::Attribute::AlternativeName(v) => {
                Ok(Self::AlternativeName(v))
            }
            kmip_2_1::kmip_attributes::Attribute::KeyValuePresent(v) => {
                Ok(Self::KeyValuePresent(v))
            }
            kmip_2_1::kmip_attributes::Attribute::KeyValueLocation(v) => {
                Ok(Self::KeyValueLocation(v))
            }
            kmip_2_1::kmip_attributes::Attribute::OriginalCreationDate(v) => {
                Ok(Self::OriginalCreationDate(v))
            }
            kmip_2_1::kmip_attributes::Attribute::RandomNumberGenerator(v) => {
                Ok(Self::RandomNumberGenerator(v.try_into()?))
            }
            kmip_2_1::kmip_attributes::Attribute::Pkcs12FriendlyName(v) => {
                Ok(Self::Pkcs12FriendlyName(v))
            }
            kmip_2_1::kmip_attributes::Attribute::Comment(v) => Ok(Self::Comment(v)),
            kmip_2_1::kmip_attributes::Attribute::Sensitive(v) => Ok(Self::Sensitive(v)),
            kmip_2_1::kmip_attributes::Attribute::AlwaysSensitive(v) => {
                Ok(Self::AlwaysSensitive(v))
            }
            kmip_2_1::kmip_attributes::Attribute::Extractable(v) => Ok(Self::Extractable(v)),
            kmip_2_1::kmip_attributes::Attribute::NeverExtractable(v) => {
                Ok(Self::NeverExtractable(v))
            }
            kmip_2_1::kmip_attributes::Attribute::AttributeIndex(_)
            | kmip_2_1::kmip_attributes::Attribute::CertificateAttributes(_)
            | kmip_2_1::kmip_attributes::Attribute::Critical(_)
            | kmip_2_1::kmip_attributes::Attribute::KeyFormatType(_)
            | kmip_2_1::kmip_attributes::Attribute::NistKeyType(_)
            | kmip_2_1::kmip_attributes::Attribute::ObjectGroupMember(_)
            | kmip_2_1::kmip_attributes::Attribute::OpaqueDataType(_)
            | kmip_2_1::kmip_attributes::Attribute::ProtectionLevel(_)
            | kmip_2_1::kmip_attributes::Attribute::ProtectionPeriod(_)
            | kmip_2_1::kmip_attributes::Attribute::ProtectionStorageMasks(_)
            | kmip_2_1::kmip_attributes::Attribute::QuantumSafe(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateDate(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateGeneration(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateInterval(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateLatest(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateName(_)
            | kmip_2_1::kmip_attributes::Attribute::RotateOffset(_)
            | kmip_2_1::kmip_attributes::Attribute::ShortUniqueIdentifier(_) => {
                Ok(Self::CustomAttribute(CustomAttribute {
                    name: "y-unsupported-2_1-attribute".to_owned(),
                    value: CustomAttributeValue::TextString(serde_json::to_string(&attribute)?),
                }))
            }
            kmip_2_1::kmip_attributes::Attribute::X509CertificateIdentifier(v) => {
                Ok(Self::X509CertificateIdentifier(v))
            }
            kmip_2_1::kmip_attributes::Attribute::X509CertificateIssuer(v) => {
                Ok(Self::X509CertificateIssuer(v))
            }
            kmip_2_1::kmip_attributes::Attribute::X509CertificateSubject(v) => {
                Ok(Self::X509CertificateSubject(v))
            }
        }
    }
}

/// The value of a Custom Attribute (section 3.39).
///
/// Any data type or structure.
/// According to the specifications, If a structure, then the structure SHALL NOT include substructures.
/// In this implementation, we use a TTLV to represent the structure.
///
/// For reasons on why we use an adjacent tagged enum, see the comment on the `VendorAttributeValue`
/// enum in the KMIP 2.1 folder.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
#[serde(untagged)]
pub enum CustomAttributeValue {
    TextString(String),
    Integer(i32),
    LongInteger(i64),
    BigInteger(BigInt),
    ByteString(Vec<u8>),
    Boolean(bool),
    DateTime(OffsetDateTime),
    Interval(u32),
    DateTimeExtended(i128),
}

impl From<CustomAttributeValue> for kmip_2_1::kmip_types::VendorAttributeValue {
    fn from(value: CustomAttributeValue) -> Self {
        match value {
            CustomAttributeValue::TextString(v) => Self::TextString(v),
            CustomAttributeValue::LongInteger(v) => Self::LongInteger(v),
            CustomAttributeValue::BigInteger(v) => Self::BigInteger(v),
            CustomAttributeValue::ByteString(v) => Self::ByteString(v),
            CustomAttributeValue::Boolean(v) => Self::Boolean(v),
            CustomAttributeValue::DateTime(v) => Self::DateTime(v),
            CustomAttributeValue::Interval(v) => Self::Interval(v),
            CustomAttributeValue::Integer(v) => Self::Integer(v),
            CustomAttributeValue::DateTimeExtended(v) => Self::DateTimeExtended(v),
        }
    }
}

impl From<VendorAttributeValue> for CustomAttributeValue {
    fn from(value: VendorAttributeValue) -> Self {
        match value {
            VendorAttributeValue::TextString(v) => Self::TextString(v),
            VendorAttributeValue::LongInteger(v) => Self::LongInteger(v),
            VendorAttributeValue::BigInteger(v) => Self::BigInteger(v),
            VendorAttributeValue::ByteString(v) => Self::ByteString(v),
            VendorAttributeValue::Boolean(v) => Self::Boolean(v),
            VendorAttributeValue::DateTime(v) => Self::DateTime(v),
            VendorAttributeValue::Interval(v) => Self::Interval(v),
            VendorAttributeValue::Integer(v) => Self::Integer(v),
            VendorAttributeValue::DateTimeExtended(v) => Self::DateTimeExtended(v),
        }
    }
}

impl From<Vec<Attribute>> for kmip_2_1::kmip_attributes::Attributes {
    fn from(kmip_1_4_attributes: Vec<Attribute>) -> Self {
        let mut attributes = Self::default();
        for attribute in kmip_1_4_attributes {
            match attribute {
                Attribute::ActivationDate(v) => {
                    attributes.activation_date = Some(v);
                }
                Attribute::CryptographicDomainParameters(v) => {
                    attributes.cryptographic_domain_parameters = Some(v.into());
                }
                Attribute::CryptographicLength(v) => {
                    attributes.cryptographic_length = Some(v);
                }
                Attribute::CryptographicParameters(v) => {
                    attributes.cryptographic_parameters = Some(v.into());
                }
                Attribute::CryptographicUsageMask(v) => {
                    attributes.cryptographic_usage_mask = Some(v);
                }
                Attribute::DeactivationDate(v) => {
                    attributes.deactivation_date = Some(v);
                }
                Attribute::Description(v) => {
                    attributes.description = Some(v);
                }
                Attribute::Name(v) => {
                    attributes.name = Some(vec![v.into()]);
                }
                Attribute::ObjectType(v) => {
                    attributes.object_type = Some(v.into());
                }
                Attribute::ProcessStartDate(v) => {
                    attributes.process_start_date = Some(v);
                }
                Attribute::ProtectStopDate(v) => {
                    attributes.protect_stop_date = Some(v);
                }
                Attribute::UniqueIdentifier(v) => {
                    attributes.unique_identifier =
                        Some(kmip_2_1::kmip_types::UniqueIdentifier::TextString(v));
                }
                Attribute::CryptographicAlgorithm(v) => {
                    attributes.cryptographic_algorithm = Some(v.into());
                }
                Attribute::CertificateType(v) => {
                    attributes.certificate_type = Some(v);
                }
                Attribute::CertificateLength(v) => {
                    attributes.certificate_length = Some(v);
                }
                Attribute::X509CertificateIdentifier(_)
                | Attribute::X509CertificateSubject(_)
                | Attribute::X509CertificateIssuer(_)
                | Attribute::CertificateIdentifier(_)
                | Attribute::CertificateSubject(_)
                | Attribute::CertificateIssuer(_)
                | Attribute::Digest(_)
                | Attribute::OperationPolicyName(_)
                | Attribute::Pkcs12FriendlyName(_) => {
                    // Not supported in KMIP 2.1
                    warn!("KMIP 2.1 does not support the KMIP 1 attribute {attribute:?}");
                }
                Attribute::DigitalSignatureAlgorithm(v) => {
                    attributes.digital_signature_algorithm = Some(v.into());
                }

                Attribute::LeaseTime(v) => {
                    attributes.lease_time = Some(i32::try_from(v).unwrap_or_else(|_| {
                        warn!(
                            "KMIP 1.4 Lease Time ({v}) exceeds i32::MAX; clamping to {}",
                            i32::MAX
                        );
                        i32::MAX
                    }));
                }
                Attribute::UsageLimits(v) => {
                    attributes.usage_limits = Some(v.into());
                }
                Attribute::State(v) => {
                    attributes.state = Some(v);
                }
                Attribute::InitialDate(v) => {
                    attributes.initial_date = Some(v);
                }
                Attribute::DestroyDate(v) => {
                    attributes.destroy_date = Some(v);
                }
                Attribute::CompromiseOccurrenceDate(v) => {
                    attributes.compromise_occurrence_date = Some(v);
                }
                Attribute::CompromiseDate(v) => {
                    attributes.compromise_date = Some(v);
                }
                Attribute::RevocationReason(v) => {
                    attributes.revocation_reason = Some(v);
                }
                Attribute::ArchiveDate(v) => {
                    attributes.archive_date = Some(v);
                }
                Attribute::ObjectGroup(v) => {
                    attributes.object_group = Some(v);
                }
                Attribute::Fresh(v) => {
                    attributes.fresh = Some(v);
                }
                Attribute::Link(v) => {
                    attributes.link = Some(vec![v.into()]);
                }
                Attribute::ApplicationSpecificInformation(v) => {
                    attributes.application_specific_information = Some(v);
                }
                Attribute::ContactInformation(v) => {
                    attributes.contact_information = Some(v);
                }
                Attribute::LastChangeDate(v) => {
                    attributes.last_change_date = Some(v);
                }
                Attribute::CustomAttribute(CustomAttribute { name, value }) => {
                    let vas = attributes.vendor_attributes.get_or_insert(vec![]);
                    vas.push(VendorAttribute {
                        vendor_identification: "KMIP1".to_owned(),
                        attribute_name: name,
                        attribute_value: value.into(),
                    });
                }
                Attribute::AlternativeName(v) => {
                    attributes.alternative_name = Some(v);
                }
                Attribute::KeyValuePresent(v) => {
                    attributes.key_value_present = Some(v);
                }
                Attribute::KeyValueLocation(v) => {
                    attributes.key_value_location = Some(v);
                }
                Attribute::OriginalCreationDate(v) => {
                    attributes.original_creation_date = Some(v);
                }
                Attribute::RandomNumberGenerator(v) => {
                    attributes.random_number_generator = Some(v.into());
                }
                Attribute::Comment(v) => {
                    attributes.comment = Some(v);
                }
                Attribute::Sensitive(v) => {
                    attributes.sensitive = Some(v);
                }
                Attribute::AlwaysSensitive(v) => {
                    attributes.always_sensitive = Some(v);
                }
                Attribute::Extractable(v) => {
                    attributes.extractable = Some(v);
                }
                Attribute::NeverExtractable(v) => {
                    attributes.never_extractable = Some(v);
                }
            }
        }
        attributes
    }
}
