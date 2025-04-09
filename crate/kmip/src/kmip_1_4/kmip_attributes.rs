use std::fmt::{self, Formatter};

use num_bigint_dig::BigInt;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::warn;

use crate::{
    kmip_1_4::{
        kmip_data_structures::CryptographicParameters,
        kmip_types::{
            AlternativeName, ApplicationSpecificInformation, CertificateType,
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicUsageMask, Digest,
            DigitalSignatureAlgorithm, KeyValueLocationType, Link, Name, ObjectType,
            RandomNumberGenerator, RevocationReason, State, UsageLimits, X509CertificateIdentifier,
        },
    },
    kmip_2_1::{self, kmip_types::VendorAttribute},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    ActivationDate(i64),
    AlternativeName(AlternativeName),
    AlwaysSensitive(bool),
    ApplicationSpecificInformation(ApplicationSpecificInformation),
    ArchiveDate(i64),
    CertificateIdentifier(String),
    CertificateIssuer(String),
    CertificateLength(i32),
    CertificateSubject(String),
    CertificateType(CertificateType),
    Comment(String),
    CompromiseDate(i64),
    CompromiseOccurrenceDate(i64),
    ContactInformation(String),
    CryptographicAlgorithm(CryptographicAlgorithm),
    CryptographicDomainParameters(CryptographicDomainParameters),
    CryptographicLength(i32),
    CryptographicParameters(CryptographicParameters),
    CryptographicUsageMask(CryptographicUsageMask),
    CustomAttribute((String, CustomAttributeValue)),
    DeactivationDate(i64),
    Description(String),
    DestroyDate(i64),
    DigitalSignatureAlgorithm(DigitalSignatureAlgorithm),
    Digest(Digest),
    Extractable(bool),
    Fresh(bool),
    InitialDate(i64),
    KeyValueLocation(KeyValueLocationType),
    KeyValuePresent(bool),
    LastChangeDate(i64),
    LeaseTime(i64),
    Link(Link),
    Name(Name),
    NeverExtractable(bool),
    ObjectGroup(String),
    ObjectType(ObjectType),
    OperationPolicyName(String),
    OriginalCreationDate(i64),
    Pkcs12FriendlyName(String),
    ProcessStartDate(i64),
    ProtectStopDate(i64),
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
                st.serialize_field("AttributeName", "CertificateLength")?;
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
            Self::CustomAttribute((name, value)) => {
                st.serialize_field("AttributeName", name)?;
                st.serialize_field("AttributeValue", value)?;
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
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            AttributeName,
            AttributeValue,
        }

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

                let Some(attribute_value_name) = map.next_key::<String>()? else {
                    return Err(de::Error::custom("No attribute value in attribute"));
                };
                if attribute_value_name != "AttributeValue" {
                    return Err(de::Error::custom(format!(
                        "expected AttributeValue in attribute, found {attribute_value_name}"
                    )));
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
                        let value: CryptographicParameters = map.next_value()?;
                        Ok(Attribute::CryptographicParameters(value))
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
                        let value: i64 = map.next_value()?;
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
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::InitialDate(value))
                    }
                    "Activation Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::ActivationDate(value))
                    }
                    "Process Start Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::ProcessStartDate(value))
                    }
                    "Protect Stop Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::ProtectStopDate(value))
                    }
                    "Deactivation Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::DeactivationDate(value))
                    }
                    "Destroy Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::DestroyDate(value))
                    }
                    "Compromise Occurrence Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::CompromiseOccurrenceDate(value))
                    }
                    "Compromise Date" => {
                        let value: i64 = map.next_value()?;
                        Ok(Attribute::CompromiseDate(value))
                    }
                    "Revocation Reason" => {
                        let value: RevocationReason = map.next_value()?;
                        Ok(Attribute::RevocationReason(value))
                    }
                    "Archive Date" => {
                        let value: i64 = map.next_value()?;
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
                        let value: i64 = map.next_value()?;
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
                        let value: i64 = map.next_value()?;
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
                    name => {
                        if name.starts_with("x-") || name.starts_with("y-") {
                            let value: CustomAttributeValue = map.next_value()?;
                            Ok(Attribute::CustomAttribute((name.to_owned(), value)))
                        } else {
                            Err(de::Error::custom(format!("invalid attribute name: {name}")))
                        }
                    }
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
            Attribute::CryptographicDomainParameters(v) => {
                Self::CryptographicDomainParameters(v.into())
            }
            Attribute::CryptographicLength(v) => Self::CryptographicLength(v),
            Attribute::CryptographicParameters(v) => Self::CryptographicParameters(v.into()),
            Attribute::CryptographicUsageMask(v) => Self::CryptographicUsageMask(v.into()),
            Attribute::DeactivationDate(v) => Self::DeactivationDate(v),
            Attribute::Description(v) => Self::Description(v),
            Attribute::Name(v) => Self::Name(v.into()),
            Attribute::ObjectType(v) => Self::ObjectType(v.into()),
            Attribute::ProcessStartDate(v) => Self::ProcessStartDate(v),
            Attribute::ProtectStopDate(v) => Self::ProtectStopDate(v),
            Attribute::UniqueIdentifier(v) => {
                Self::UniqueIdentifier(kmip_2_1::kmip_types::UniqueIdentifier::TextString(v))
            }
            Attribute::CryptographicAlgorithm(v) => Self::CryptographicAlgorithm(v.into()),
            Attribute::CertificateType(v) => Self::CertificateType(v.into()),
            Attribute::CertificateLength(v) => Self::CertificateLength(v),
            Attribute::DigitalSignatureAlgorithm(v) => Self::DigitalSignatureAlgorithm(v.into()),
            Attribute::LeaseTime(v) => Self::LeaseTime(v),
            Attribute::UsageLimits(v) => Self::UsageLimits(v.into()),
            Attribute::State(v) => Self::State(v.into()),
            Attribute::InitialDate(v) => Self::InitialDate(v),
            Attribute::DestroyDate(v) => Self::DestroyDate(v),
            Attribute::CompromiseOccurrenceDate(v) => Self::CompromiseOccurrenceDate(v),
            Attribute::CompromiseDate(v) => Self::CompromiseDate(v),
            Attribute::RevocationReason(v) => Self::RevocationReason(v.into()),
            Attribute::ArchiveDate(v) => Self::ArchiveDate(v),
            Attribute::ObjectGroup(v) => Self::ObjectGroup(v),
            Attribute::Fresh(v) => Self::Fresh(v),
            Attribute::Link(v) => Self::Link(v.into()),
            Attribute::ApplicationSpecificInformation(v) => {
                Self::ApplicationSpecificInformation(v.into())
            }
            Attribute::ContactInformation(v) => Self::ContactInformation(v),
            Attribute::LastChangeDate(v) => Self::LastChangeDate(v),
            Attribute::CustomAttribute((n, v)) => Self::VendorAttribute(VendorAttribute {
                vendor_identification: "KMIP1".to_owned(),
                attribute_name: n,
                attribute_value: v.into(),
            }),
            Attribute::AlternativeName(v) => Self::AlternativeName(v.into()),
            Attribute::KeyValuePresent(v) => Self::KeyValuePresent(v),
            Attribute::KeyValueLocation(v) => Self::KeyValueLocation(v.into()),
            Attribute::OriginalCreationDate(v) => Self::OriginalCreationDate(v),
            Attribute::RandomNumberGenerator(v) => Self::RandomNumberGenerator(v.into()),
            Attribute::Comment(v) => Self::Comment(v),
            Attribute::Sensitive(v) => Self::Sensitive(v),
            Attribute::AlwaysSensitive(v) => Self::AlwaysSensitive(v),
            Attribute::Extractable(v) => Self::Extractable(v),
            Attribute::NeverExtractable(v) => Self::NeverExtractable(v),
            Attribute::X509CertificateIdentifier(_)
            | Attribute::X509CertificateSubject(_)
            | Attribute::X509CertificateIssuer(_)
            | Attribute::CertificateIdentifier(_)
            | Attribute::CertificateSubject(_)
            | Attribute::CertificateIssuer(_)
            | Attribute::Digest(_)
            | Attribute::OperationPolicyName(_)
            | Attribute::Pkcs12FriendlyName(_) => {
                warn!("KMIP 2.1 does not support the KMIP 1 attribute {attribute:?}");
                Self::Comment("Unsupported KMIP 1.4 attribute".to_owned())
            }
        }
    }
}

/// The value of a Custom Attribute (section 3.39).
/// Any data type or structure.
/// According to the specifications, If a structure, then the structure SHALL NOT include sub structures.
/// In this implementation, we use a JSON value to represent the structure.
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
    Structure(Value),
}

impl From<CustomAttributeValue> for kmip_2_1::kmip_types::VendorAttributeValue {
    fn from(value: CustomAttributeValue) -> Self {
        match value {
            CustomAttributeValue::TextString(v) => Self::TextString(v),
            CustomAttributeValue::Integer(v) => Self::Integer(v),
            CustomAttributeValue::LongInteger(v) => Self::LongInteger(v),
            CustomAttributeValue::BigInteger(v) => Self::BigInteger(v),
            CustomAttributeValue::ByteString(v) => Self::ByteString(v),
            CustomAttributeValue::Boolean(v) => Self::Boolean(v),
            CustomAttributeValue::DateTime(v) => Self::DateTime(v),
            CustomAttributeValue::Interval(v) => Self::Interval(v),
            CustomAttributeValue::Structure(v) => Self::Structure(v),
        }
    }
}

impl From<kmip_2_1::kmip_types::VendorAttributeValue> for CustomAttributeValue {
    fn from(value: kmip_2_1::kmip_types::VendorAttributeValue) -> Self {
        match value {
            kmip_2_1::kmip_types::VendorAttributeValue::TextString(v) => Self::TextString(v),
            kmip_2_1::kmip_types::VendorAttributeValue::Integer(v) => Self::Integer(v),
            kmip_2_1::kmip_types::VendorAttributeValue::LongInteger(v) => Self::LongInteger(v),
            kmip_2_1::kmip_types::VendorAttributeValue::BigInteger(v) => Self::BigInteger(v),
            kmip_2_1::kmip_types::VendorAttributeValue::ByteString(v) => Self::ByteString(v),
            kmip_2_1::kmip_types::VendorAttributeValue::Boolean(v) => Self::Boolean(v),
            kmip_2_1::kmip_types::VendorAttributeValue::DateTime(v) => Self::DateTime(v),
            kmip_2_1::kmip_types::VendorAttributeValue::Interval(v) => Self::Interval(v),
            kmip_2_1::kmip_types::VendorAttributeValue::Structure(v) => Self::Structure(v),
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
                    attributes.cryptographic_usage_mask = Some(v.into());
                }
                Attribute::DeactivationDate(v) => {
                    attributes.deactivation_date = Some(v);
                }
                Attribute::Description(v) => {
                    attributes.description = Some(v);
                }
                Attribute::Name(v) => {
                    todo!(
                        "KMIP 2.1 does not support the KMIP 1 attribute Name: {v:?} - should be a \
                         reference"
                    )
                    // attributes.name = Some(v.into());
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
                    attributes.certificate_type = Some(v.into());
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
                    attributes.lease_time = Some(v);
                }
                Attribute::UsageLimits(v) => {
                    attributes.usage_limits = Some(v.into());
                }
                Attribute::State(v) => {
                    attributes.state = Some(v.into());
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
                    attributes.revocation_reason = Some(v.into());
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
                    todo!(
                        "KMIP 2.1 does not support the KMIP 1 attribute Link: {v:?} - should be a \
                         reference"
                    )
                    // attributes.link = Some(v.into());
                }
                Attribute::ApplicationSpecificInformation(v) => {
                    attributes.application_specific_information = Some(v.into());
                }
                Attribute::ContactInformation(v) => {
                    attributes.contact_information = Some(v);
                }
                Attribute::LastChangeDate(v) => {
                    attributes.last_change_date = Some(v);
                }
                Attribute::CustomAttribute((n, v)) => {
                    let vas = attributes.vendor_attributes.get_or_insert(vec![]);
                    vas.push(VendorAttribute {
                        vendor_identification: "KMIP1".to_owned(),
                        attribute_name: n,
                        attribute_value: v.into(),
                    });
                }
                Attribute::AlternativeName(v) => {
                    attributes.alternative_name = Some(v.into());
                }
                Attribute::KeyValuePresent(v) => {
                    attributes.key_value_present = Some(v);
                }
                Attribute::KeyValueLocation(v) => {
                    attributes.key_value_location = Some(v.into());
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

// pub const VENDOR_ATTR_TAG: &str = "tag";

// /// Constant to use to express there are no tags
// pub const EMPTY_TAGS: [&str; 0] = [];

// /// The vendor ID to use for Cosmian specific attributes
// pub const VENDOR_ID_COSMIAN: &str = "cosmian";

// /// The vendor attribute name to use for x.509 extensions
// pub const VENDOR_ATTR_X509_EXTENSION: &str = "x509-extension";

// pub const VENDOR_ATTR_AAD: &str = "aad";
