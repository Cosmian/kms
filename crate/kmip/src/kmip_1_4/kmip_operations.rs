use std::{
    fmt::{self, Display},
    str::FromStr,
};

use cosmian_logger::{debug, trace};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use super::{
    kmip_data_structures::{
        CapabilityInformation, CryptographicParameters, DerivationParameters, ExtensionInformation,
        KeyWrappingData, KeyWrappingSpecification, ProfileInformation, RNGParameters,
        ServerInformation, TemplateAttribute,
    },
    kmip_objects::{Certificate, Object},
    kmip_types::{
        CancellationResult, CertificateRequestType, ClientRegistrationMethod, DerivationMethod,
        KeyCompressionType, KeyFormatType, ObjectGroupMember, ObjectType, OperationEnumeration,
        PutFunction, QueryFunction, SplitKeyMethod, StorageStatusMask, UniqueIdentifier,
        ValidityIndicator,
    },
};
use crate::{
    KmipError, KmipResultHelper,
    kmip_0::{
        kmip_data_structures::ValidationInformation,
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
        kmip_types::{AttestationType, Direction, KeyWrapType, RevocationReason},
    },
    kmip_1_4::kmip_attributes::Attribute,
    kmip_2_1::{self, kmip_attributes::Attributes},
};

/// 4.1 Create
/// This operation requests the server to generate a new managed cryptographic object. The request
/// contains information about the type of object being created, and some of the attributes to be
/// assigned to the object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Create {
    /// Determines the type of object to be created
    pub object_type: ObjectType,
    /// Specifies template attributes to be assigned to a new object
    pub template_attribute: TemplateAttribute,
}

impl Display for Create {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Create {{ object_type: {:?} }}", self.object_type)
    }
}

impl From<Create> for kmip_2_1::kmip_operations::Create {
    fn from(create: Create) -> Self {
        Self {
            object_type: create.object_type.into(),
            attributes: create.template_attribute.into(),
            protection_storage_masks: None,
        }
    }
}

/// Response to a Create request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateResponse {
    /// Type of Object created
    pub object_type: ObjectType,
    /// The Unique Identifier of the newly created object
    pub unique_identifier: String,
    /// The template attributes that were assigned
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

impl Display for CreateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CreateResponse {{ object_type: {:?}, unique_identifier: {}, template_attribute: {:?} }}",
            self.object_type, self.unique_identifier, self.template_attribute
        )
    }
}

impl TryFrom<kmip_2_1::kmip_operations::CreateResponse> for CreateResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::CreateResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 CreateResponse to KMIP 1.4: {value}");

        Ok(Self {
            object_type: value.object_type.try_into()?,
            unique_identifier: value.unique_identifier.to_string(),
            template_attribute: None,
        })
    }
}

/// 4.2 Create Key Pair
/// This operation requests the server to generate a new public/private key pair and register
/// the two corresponding new Managed Cryptographic Objects.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeyPair {
    /// Common template attributes that apply to both public and private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_template_attribute: Option<TemplateAttribute>,
    /// Template attributes that apply only to private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Template attributes that apply only to public key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

impl From<CreateKeyPair> for kmip_2_1::kmip_operations::CreateKeyPair {
    fn from(create_key_pair: CreateKeyPair) -> Self {
        Self {
            common_attributes: create_key_pair.common_template_attribute.map(Into::into),
            private_key_attributes: create_key_pair
                .private_key_template_attribute
                .map(Into::into),
            public_key_attributes: create_key_pair
                .public_key_template_attribute
                .map(Into::into),
            common_protection_storage_masks: None,
            private_protection_storage_masks: None,
            public_protection_storage_masks: None,
        }
    }
}

/// Response to a Create Key Pair request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeyPairResponse {
    /// Unique ID of the private key
    pub private_key_unique_identifier: String,
    /// Unique ID of the public key
    pub public_key_unique_identifier: String,
    /// Private key template attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Public key template attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

impl TryFrom<kmip_2_1::kmip_operations::CreateKeyPairResponse> for CreateKeyPairResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::CreateKeyPairResponse,
    ) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 CreateKeyPairResponse to KMIP 1.4: {value}");

        Ok(Self {
            private_key_unique_identifier: value.private_key_unique_identifier.to_string(),
            public_key_unique_identifier: value.public_key_unique_identifier.to_string(),
            private_key_template_attribute: None,
            public_key_template_attribute: None,
        })
    }
}

impl Display for CreateKeyPairResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CreateKeyPairResponse {{ private_key_unique_identifier: {}, public_key_unique_identifier: {} }}",
            self.private_key_unique_identifier, self.public_key_unique_identifier
        )
    }
}

impl fmt::Debug for CreateKeyPairResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.3 Register
/// This operation requests the server to register a Managed Object that was created by the client
/// or obtained by the client through some other means.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Register {
    // Determines the type of object being registered
    pub object_type: ObjectType,
    /// The object being registered
    pub object: Object,
    /// Template attributes for the object
    pub template_attribute: TemplateAttribute,
}

impl From<Register> for kmip_2_1::kmip_operations::Register {
    fn from(register: Register) -> Self {
        Self {
            object_type: register.object_type.into(),
            object: register.object.into(),
            attributes: register.template_attribute.into(),
            protection_storage_masks: None,
        }
    }
}

/// Response to a Register request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RegisterResponse {
    /// The unique identifier of the registered object
    pub unique_identifier: String,
    /// Template attributes applied to the object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

impl TryFrom<kmip_2_1::kmip_operations::RegisterResponse> for RegisterResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::RegisterResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 RegisterResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            template_attribute: None,
        })
    }
}

impl Display for RegisterResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegisterResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

impl fmt::Debug for RegisterResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.4 Re-key
/// This operation requests the server to generate a replacement key for an existing symmetric key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReKey {
    /// Unique identifier of the symmetric key to be rekeyed
    pub unique_identifier: String,
    /// Offset from the initialization date of the new key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
    /// Template attributes for the new key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-key request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyResponse {
    /// Unique identifier of the newly created key
    pub unique_identifier: String,
    /// Template attributes applied to the new key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.5 Re-key Key Pair
/// This operation requests the server to generate a replacement key pair for an existing public/private key pair.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyKeyPair {
    /// Unique identifier of private key to be rekeyed
    pub private_key_unique_identifier: String,
    /// Offset from the initialization date of the new key pair
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,
    /// Common template attributes for both public and private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_template_attribute: Option<TemplateAttribute>,
    /// Template attributes for private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Template attributes for public key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-key Key Pair request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyKeyPairResponse {
    /// Unique identifier of new private key
    pub private_key_unique_identifier: String,
    /// Unique identifier of new public key
    pub public_key_unique_identifier: String,
    /// Private key template attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Public key template attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// 4.6 Derive Key
/// This operation requests the server to derive a symmetric key or secret data from a key or
/// secret data that is already known to the key management system.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DeriveKey {
    /// Unique identifier of the object to derive from
    pub object_unique_identifier: String,
    /// Information for the derivation process
    pub derivation_method: DerivationMethod,
    /// Parameters for derivation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_parameters: Option<DerivationParameters>,
    /// Template attributes for the new key/secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Derive Key request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DeriveKeyResponse {
    /// Unique identifier of derived object
    pub unique_identifier: String,
    /// Template attributes applied
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.7 Certify
/// This operation requests the server to generate a Certificate object for a public key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Certify {
    pub unique_identifier: String,
    pub certificate_request_type: CertificateRequestType,
    pub certificate_request_value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Certify request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CertifyResponse {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.8 Re-certify
/// This operation requests the server to generate a new Certificate object for an existing public key.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReCertify {
    pub unique_identifier: String,
    pub certificate_request_type: CertificateRequestType,
    pub certificate_request_value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-certify request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ReCertifyResponse {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.9 Locate
/// This operation requests that the server search for one or more Managed Objects.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Locate {
    /// An Integer object that indicates the maximum number of object identifiers the server MAY return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_items: Option<i32>,

    /// An Integer object (used as a bit mask) that indicates whether only on-line objects, only archived objects,
    /// or both on-line and archived objects are to be searched. If omitted, then on-line only is assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_status_mask: Option<StorageStatusMask>,

    /// An Enumeration object that indicates the object group member type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_group_member: Option<ObjectGroupMember>,

    /// Specifies an attribute and its value(s) that are REQUIRED
    /// to match those in a candidate object (according to the matching rules defined above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<Attribute>>,
}

impl From<Locate> for kmip_2_1::kmip_operations::Locate {
    fn from(locate: Locate) -> Self {
        let attributes: Attributes = locate
            .attribute
            .map(|v| {
                v.into_iter()
                    .map(Into::into)
                    .collect::<Vec<kmip_2_1::kmip_attributes::Attribute>>()
                    .into()
            })
            .unwrap_or_default();
        Self {
            maximum_items: locate.maximum_items,
            storage_status_mask: None,
            object_group_member: None,
            attributes,
            offset_items: None,
        }
    }
}

/// Response to a Locate request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct LocateResponse {
    #[serde(skip_serializing_if = "Option::is_none", rename = "UniqueIdentifier")]
    pub unique_identifier: Option<Vec<String>>,
}

impl TryFrom<kmip_2_1::kmip_operations::LocateResponse> for LocateResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::LocateResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 LocateResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value
                .unique_identifier
                .map(|ids| ids.iter().map(ToString::to_string).collect()),
        })
    }
}

impl Display for LocateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocateResponse {{")?;
        if let Some(ids) = &self.unique_identifier {
            write!(f, " unique_identifier: [{}]", ids.join(", "))?;
        } else {
            write!(f, " unique_identifier: None")?;
        }
        write!(f, " }}")
    }
}

impl fmt::Debug for LocateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.10 Check
/// This operation requests that the server check for use of a Managed Object according
/// to values specified in the request.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Check {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_usage_mask: Option<u32>,
    // KMIP 1.4 specifies Lease Time as an Interval; use i32 to match TTLV Interval
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<i32>,
}

/// Response to a Check request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CheckResponse {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits_count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_usage_mask: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<i32>,
}

impl Display for CheckResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CheckResponse {{ unique_identifier: {}",
            self.unique_identifier
        )?;
        if let Some(v) = &self.usage_limits_count {
            write!(f, ", usage_limits_count: {v}")?;
        }
        if let Some(v) = &self.cryptographic_usage_mask {
            write!(f, ", cryptographic_usage_mask: {v}")?;
        }
        if let Some(v) = &self.lease_time {
            write!(f, ", lease_time: {v}")?;
        }
        write!(f, " }}")
    }
}

impl fmt::Debug for CheckResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.11 Get
/// This operation requests that the server returns the Managed Object specified by its
/// Unique Identifier.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Get {
    /// The Unique Identifier of the Managed Object to get.
    /// If omitted, the ID Placeholder SHALL be used (per KMIP 1.4 spec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

impl From<Get> for kmip_2_1::kmip_operations::Get {
    fn from(get: Get) -> Self {
        Self {
            unique_identifier: get
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            key_format_type: get.key_format_type.map(Into::into),
            key_compression_type: get.key_compression_type.map(Into::into),
            key_wrapping_specification: get.key_wrapping_specification.map(Into::into),
            key_wrap_type: None,
        }
    }
}

/// Response to a Get request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub unique_identifier: String,
    pub object: Object,
}

impl TryFrom<kmip_2_1::kmip_operations::GetResponse> for GetResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::GetResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 GetResponse to KMIP 1.4: {value}");

        let object = Object::try_from(value.object)?;

        Ok(Self {
            object_type: value.object_type.try_into()?,
            unique_identifier: value.unique_identifier.to_string(),
            object,
        })
    }
}

impl Display for GetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GetResponse {{ object_type: {:?}, unique_identifier: {} }}",
            self.object_type, self.unique_identifier
        )
    }
}

impl fmt::Debug for GetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.12 Get Attributes
/// This operation requests one or more attributes associated with a Managed Object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_name: Option<Vec<String>>,
}

impl From<GetAttributes> for kmip_2_1::kmip_operations::GetAttributes {
    fn from(get_attributes: GetAttributes) -> Self {
        Self {
            unique_identifier: get_attributes
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            attribute_reference: get_attributes.attribute_name.map(|v| {
                v.into_iter()
                    .map(|v| {
                        if v.starts_with("x-") || v.starts_with("y-") {
                            kmip_2_1::kmip_types::AttributeReference::Vendor(
                                kmip_2_1::kmip_types::VendorAttributeReference {
                                    vendor_identification: "KMIP1".to_owned(),
                                    attribute_name: v,
                                },
                            )
                        } else {
                            kmip_2_1::kmip_types::AttributeReference::Standard(
                                kmip_2_1::kmip_types::Tag::from_str(&v.replace(' ', ""))
                                    .unwrap_or(kmip_2_1::kmip_types::Tag::Y), //some dummy tag that will never be found
                            )
                        }
                    })
                    .collect::<Vec<kmip_2_1::kmip_types::AttributeReference>>()
            }),
        }
    }
}

/// Response to a Get Attributes request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributesResponse {
    pub unique_identifier: String,
    /// The attributes associated with the Managed Object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<Attribute>>,
}

impl TryFrom<kmip_2_1::kmip_operations::GetAttributesResponse> for GetAttributesResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::GetAttributesResponse,
    ) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 GetAttributesResponse to KMIP 1.4: {value}");

        let attributes_2_1: Vec<kmip_2_1::kmip_attributes::Attribute> = value.attributes.into();
        let attributes_1_4: Vec<Attribute> = attributes_2_1
            .into_iter()
            .flat_map(TryInto::try_into)
            .collect();

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            attribute: if attributes_1_4.is_empty() {
                None
            } else {
                Some(attributes_1_4)
            },
        })
    }
}

impl Display for GetAttributesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GetAttributesResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

impl fmt::Debug for GetAttributesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.13 Get Attribute List
/// This operation requests a list of the attribute names associated with a Managed Object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributeList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
}

impl From<GetAttributeList> for kmip_2_1::kmip_operations::GetAttributeList {
    fn from(v: GetAttributeList) -> Self {
        Self {
            unique_identifier: v
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
        }
    }
}

/// Response to a Get Attribute List request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributeListResponse {
    pub unique_identifier: String,
    // XML encodes this as a repeated AttributeName element, not a pluralized container
    #[serde(rename = "AttributeName")]
    pub attribute_names: Vec<String>,
}

impl TryFrom<kmip_2_1::kmip_operations::GetAttributeListResponse> for GetAttributeListResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::GetAttributeListResponse,
    ) -> Result<Self, Self::Error> {
        // Convert 2.1 AttributeReference list into 1.4 AttributeName list
        let mut names: Vec<String> = Vec::new();
        if let Some(attr_refs) = value.attribute_references {
            for ar in attr_refs {
                match ar {
                    kmip_2_1::kmip_types::AttributeReference::Vendor(v) => {
                        // In 1.4, vendor attribute names are carried as-is (e.g., "x-ID")
                        names.push(v.attribute_name);
                    }
                    kmip_2_1::kmip_types::AttributeReference::Standard(tag) => {
                        names.push(attribute_name_from_tag(tag));
                    }
                }
            }
        }

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            attribute_names: names,
        })
    }
}

fn attribute_name_from_tag(tag: kmip_2_1::kmip_types::Tag) -> String {
    // Convert enum variant name (e.g., CryptographicAlgorithm) to spaced form ("Cryptographic Algorithm")
    // by inserting a space before uppercase letters, then trimming.
    // Also handle a few specific prettifications.
    let raw = format!("{tag:?}"); // variant name
    let mut out = String::with_capacity(raw.len() * 2);
    let chars: Vec<char> = raw.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if i > 0 && ch.is_ascii_uppercase() {
            // insert space when transitioning to an uppercase letter
            out.push(' ');
        }
        out.push(ch);
    }

    // Minor normalizations to better match KMIP 1.x attribute naming
    // ShortUniqueIdentifier -> Short Unique Identifier
    // IVCounterNonce -> IV Counter Nonce
    // X509CertificateSubject -> X509 Certificate Subject (best effort)
    out = out
        .replace("I V", "IV")
        .replace("M A C", "MAC")
        .replace("X 509", "X509")
        .replace("U R I", "URI");

    out
}

/// 4.14 Add Attribute
/// This operation requests that the server add a new attribute or append attribute values to an existing attribute.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AddAttribute {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

impl From<AddAttribute> for kmip_2_1::kmip_operations::AddAttribute {
    fn from(add_attribute: AddAttribute) -> Self {
        Self {
            unique_identifier: kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                add_attribute.unique_identifier,
            ),
            new_attribute: add_attribute.attribute.into(),
        }
    }
}

/// Response to an Add Attribute request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AddAttributeResponse {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

impl Display for AddAttributeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AddAttributeResponse {{ unique_identifier: {}, attribute: {:?} }}",
            self.unique_identifier, self.attribute
        )
    }
}

impl From<kmip_2_1::kmip_operations::AddAttributeResponse> for AddAttributeResponse {
    fn from(add_attribute_response: kmip_2_1::kmip_operations::AddAttributeResponse) -> Self {
        Self {
            unique_identifier: add_attribute_response.unique_identifier.to_string(),
            attribute: Attribute::Comment(
                "KMIP 2 does not send the attribute value on the response".to_owned(),
            ),
        }
    }
}

/// 4.15 Modify Attribute
/// This operation requests that the server modify one or more attributes associated with a Managed Object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyAttribute {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    pub attribute: Attribute,
}

impl From<ModifyAttribute> for kmip_2_1::kmip_operations::ModifyAttribute {
    fn from(v: ModifyAttribute) -> Self {
        Self {
            unique_identifier: v
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            new_attribute: v.attribute.into(),
        }
    }
}

/// Response to a Modify Attribute request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ModifyAttributeResponse {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

impl Display for ModifyAttributeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModifyAttributeResponse {{ unique_identifier: {}, attribute: {:?} }}",
            self.unique_identifier, self.attribute
        )
    }
}

impl TryFrom<kmip_2_1::kmip_operations::ModifyAttributeResponse> for ModifyAttributeResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::ModifyAttributeResponse,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: value
                .unique_identifier
                .map(|u| u.to_string())
                .unwrap_or_default(),
            // KMIP 2.1 doesn't echo the modified attribute in the response. Preserve 1.4 shape
            // by returning a placeholder Comment attribute to avoid deep comparisons.
            attribute: Attribute::Comment(
                "KMIP 2 does not send the attribute value on the response".to_owned(),
            ),
        })
    }
}

/// 4.16 Delete Attribute
/// This operation requests that the server delete an attribute associated with a Managed Object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteAttribute {
    pub unique_identifier: String,
    pub attribute_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_index: Option<i32>,
}

impl From<DeleteAttribute> for kmip_2_1::kmip_operations::DeleteAttribute {
    fn from(v: DeleteAttribute) -> Self {
        use kmip_2_1::kmip_types::{
            AttributeReference, Tag, UniqueIdentifier, VendorAttributeReference,
        };

        let name = v.attribute_name.trim();
        let cleaned = name.replace(' ', "");
        let aref = Tag::from_str(&cleaned).map_or_else(
            |_| {
                let (vendor_identification, attribute_name) = match name.split_once('-') {
                    Some((vendor, rest)) if !vendor.is_empty() && !rest.is_empty() => {
                        (vendor.to_owned(), rest.to_owned())
                    }
                    _ => (String::new(), name.to_owned()),
                };
                AttributeReference::Vendor(VendorAttributeReference {
                    vendor_identification,
                    attribute_name,
                })
            },
            AttributeReference::Standard,
        );
        Self {
            unique_identifier: Some(UniqueIdentifier::TextString(v.unique_identifier)),
            current_attribute: None,
            attribute_references: Some(vec![aref]),
        }
    }
}

/// Response to a Delete Attribute request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteAttributeResponse {
    pub unique_identifier: String,
}

impl Display for DeleteAttributeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeleteAttributeResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

impl TryFrom<kmip_2_1::kmip_operations::DeleteAttributeResponse> for DeleteAttributeResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::DeleteAttributeResponse,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
        })
    }
}

/// 4.17 Obtain Lease
/// This operation requests a new or renewed lease for a client's use of a Managed Object.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ObtainLease {
    pub unique_identifier: String,
}

/// Response to an Obtain Lease request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ObtainLeaseResponse {
    pub unique_identifier: String,
    pub lease_time: i32,
    pub last_change_date: OffsetDateTime,
}

/// 4.18 Get Usage Allocation
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetUsageAllocation {
    pub unique_identifier: String,
}

/// Response to a Get Usage Allocation request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GetUsageAllocationResponse {
    pub unique_identifier: String,
    pub allocation_percent: i32,
    pub amount_used: i32,
}

/// 4.19 Activate
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Activate {
    pub unique_identifier: String,
}

impl From<Activate> for kmip_2_1::kmip_operations::Activate {
    fn from(activate: Activate) -> Self {
        Self {
            unique_identifier: kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                activate.unique_identifier,
            ),
        }
    }
}

/// Response to an Activate request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ActivateResponse {
    pub unique_identifier: String,
}

impl TryFrom<kmip_2_1::kmip_operations::ActivateResponse> for ActivateResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::ActivateResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
        })
    }
}

impl Display for ActivateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivateResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

impl fmt::Debug for ActivateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.20 Revoke
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Revoke {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    pub revocation_reason: RevocationReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_occurrence_date: Option<OffsetDateTime>,
}

impl From<Revoke> for kmip_2_1::kmip_operations::Revoke {
    fn from(revoke: Revoke) -> Self {
        Self {
            unique_identifier: revoke
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            revocation_reason: revoke.revocation_reason,
            compromise_occurrence_date: revoke.compromise_occurrence_date,
            cascade: false,
        }
    }
}

/// Response to a Revoke request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RevokeResponse {
    pub unique_identifier: String,
}

impl TryFrom<kmip_2_1::kmip_operations::RevokeResponse> for RevokeResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::RevokeResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
        })
    }
}

/// 4.21 Destroy
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Destroy {
    pub unique_identifier: String,
}

impl From<Destroy> for kmip_2_1::kmip_operations::Destroy {
    fn from(destroy: Destroy) -> Self {
        Self {
            unique_identifier: Some(kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                destroy.unique_identifier,
            )),
            remove: false,
            cascade: false,
        }
    }
}

/// Response to a Destroy request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DestroyResponse {
    pub unique_identifier: String,
}

impl TryFrom<kmip_2_1::kmip_operations::DestroyResponse> for DestroyResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::DestroyResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 DestroyResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
        })
    }
}

impl Display for DestroyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DestroyResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

impl fmt::Debug for DestroyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.22 Archive
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Archive {
    pub unique_identifier: String,
}

/// Response to an Archive request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ArchiveResponse {
    pub unique_identifier: String,
}

/// 4.23 Recover
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Recover {
    pub unique_identifier: String,
}

/// Response to a Recover request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RecoverResponse {
    pub unique_identifier: String,
}

/// 4.24 Validate
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Validate {
    /// One or more Certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Vec<Certificate>>,
    /// One or more Unique Identifiers of Certificate Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<Vec<UniqueIdentifier>>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_time: Option<OffsetDateTime>,
}

impl From<Validate> for kmip_2_1::kmip_operations::Validate {
    fn from(validate: Validate) -> Self {
        Self {
            certificate: validate
                .certificate
                .map(|certs| certs.into_iter().map(|c| c.certificate_value).collect()),
            unique_identifier: validate
                .unique_identifier
                .map(|uids| uids.into_iter().map(Into::into).collect()),
            validity_time: validate.validity_time.map(|t| t.to_string()),
        }
    }
}

/// Response to a Validate request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ValidateResponse {
    /// An Enumeration object indicating whether the certificate chain is valid,
    /// invalid, or unknown.
    pub validity_indicator: ValidityIndicator,
}

impl From<ValidateResponse> for kmip_2_1::kmip_operations::ValidateResponse {
    fn from(response: ValidateResponse) -> Self {
        Self {
            validity_indicator: response.validity_indicator.into(),
        }
    }
}

/// 4.25 Query
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Query {
    pub query_function: Option<Vec<QueryFunction>>,
}

impl From<Query> for kmip_2_1::kmip_operations::Query {
    fn from(query: Query) -> Self {
        Self {
            query_function: query.query_function.map(|v| {
                v.into_iter()
                    .map(Into::into)
                    .collect::<Vec<kmip_2_1::kmip_types::QueryFunction>>()
            }),
        }
    }
}

/// Response to a Query request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct QueryResponse {
    /// List of operations supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<Vec<OperationEnumeration>>,

    /// List of object types that the server supports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<Vec<ObjectType>>,

    /// List of vendor extensions supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_identification: Option<String>,

    /// Detailed information about the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_information: Option<ServerInformation>,

    /// List of extensions supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension_information: Option<Vec<ExtensionInformation>>,

    /// List of attestation types supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_types: Option<Vec<AttestationType>>,

    /// The RNG Parameters base object is a structure that contains a mandatory RNG Algorithm
    /// and a set of OPTIONAL fields that describe a Random Number Generator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rng_parameters: Option<Vec<RNGParameters>>,

    /// List of profiles supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles_information: Option<Vec<ProfileInformation>>,

    /// List of supported validation authorities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_information: Option<Vec<ValidationInformation>>,

    /// List of supported capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_information: Option<Vec<CapabilityInformation>>,

    /// Specifies a Client Registration Method that is supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_registration_method: Option<Vec<ClientRegistrationMethod>>,
}

impl TryFrom<kmip_2_1::kmip_operations::QueryResponse> for QueryResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::QueryResponse) -> Result<Self, Self::Error> {
        debug!("Converting KMIP 2.1 QueryResponse to KMIP 1.4: {value}");

        let operation = value.operation.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<OperationEnumeration>>()
        });

        let object_type = value.object_type.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<ObjectType>>()
        });

        let extension_information = value.extension_information.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<ExtensionInformation>>()
        });

        let rng_parameters = value.rng_parameters.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<RNGParameters>>()
        });

        let profiles_information = value.profiles_information.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<ProfileInformation>>()
        });

        let capability_information = value.capability_information.map(|v| {
            v.into_iter()
                .flat_map(TryInto::try_into)
                .collect::<Vec<CapabilityInformation>>()
        });

        Ok(Self {
            operation,
            object_type,
            vendor_identification: value.vendor_identification,
            // TODO: what is expected as server_information in KMIP 1 is not clear
            server_information: None,
            extension_information,
            attestation_types: value.attestation_types,
            rng_parameters,
            profiles_information,
            validation_information: value.validation_information,
            capability_information,
            client_registration_method: None,
        })
    }
}

/// 4.27 Cancel
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Cancel {
    pub asynchronous_correlation_value: String,
}

/// Response to a Cancel request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CancelResponse {
    pub cancellation_result: CancellationResult,
}

/// 4.28 Poll
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Poll {
    pub asynchronous_correlation_value: String,
}

/// Response to a Poll request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PollResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Box<Option<Operation>>,
}

/// 4.29 Encrypt
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Encrypt {
    pub unique_identifier: String,

    /// The Cryptographic Parameters (Block
    /// Cipher Mode, Padding Method,
    /// `RandomIV`) corresponding to the
    /// particular encryption method
    /// requested.
    /// If there are no Cryptographic
    /// Parameters associated with the
    /// Managed Cryptographic Object and
    /// the algorithm requires parameters then
    /// the operation SHALL return with a
    /// Result Status of Operation Failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    /// The data to be encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,

    /// The initialization vector, counter or
    /// nonce to be used (where appropriate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i_v_counter_nonce: Option<Vec<u8>>,

    /// Specifies the existing stream or by-
    /// parts cryptographic operation (as
    /// returned from a previous call to this
    /// operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,

    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,

    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,

    /// Any additional data to be authenticated via the Authenticated Encryption
    /// Tag. If supplied in multi-part encryption,
    /// this data MUST be supplied on the initial Encrypt request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_additional_data: Option<Vec<u8>>,
}

impl From<Encrypt> for kmip_2_1::kmip_operations::Encrypt {
    fn from(value: Encrypt) -> Self {
        Self {
            unique_identifier: Some(kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                value.unique_identifier,
            )),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data.map(Zeroizing::new),
            i_v_counter_nonce: value.i_v_counter_nonce,
            correlation_value: value.correlation_value,
            init_indicator: value.init_indicator,
            final_indicator: value.final_indicator,
            authenticated_encryption_additional_data: value
                .authenticated_encryption_additional_data,
        }
    }
}

/// Response to an Encrypt request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptResponse {
    pub unique_identifier: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,

    /// The initialization vector, counter or
    /// nonce to be used (where appropriate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i_v_counter_nonce: Option<Vec<u8>>,

    /// Specifies the existing stream or by-
    /// parts cryptographic operation (as
    /// returned from a previous call to this
    /// operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,

    /// Specifies the tag that will be needed to authenticate the decrypted data.
    /// Only returned on completion of the encryption of the last of the plaintext
    /// by an authenticated encryption cipher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_tag: Option<Vec<u8>>,
}

impl TryFrom<kmip_2_1::kmip_operations::EncryptResponse> for EncryptResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::EncryptResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 EncryptResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            data: value.data,
            i_v_counter_nonce: value.i_v_counter_nonce,
            correlation_value: value.correlation_value,
            authenticated_encryption_tag: value.authenticated_encryption_tag,
        })
    }
}

/// 4.30 Decrypt
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Decrypt {
    pub unique_identifier: String,

    /// The Cryptographic Parameters (Block Cipher Mode, Padding Method) corresponding
    /// to the particular decryption method requested.
    /// If omitted then the Cryptographic Parameters associated
    /// with the Managed Cryptographic Object with the lowest Attribute Index SHALL be used.
    ///
    /// If there are no Cryptographic Parameters associated with the Managed Cryptographic Object
    /// and the algorithm requires parameters then the operation SHALL return
    /// with a Result Status of Operation Failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    /// The data to be decrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,

    /// The initialization vector, counter or
    /// nonce to be used (where appropriate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i_v_counter_nonce: Option<Vec<u8>>,

    /// Specifies the existing stream or by-
    /// parts cryptographic operation (as
    /// returned from a previous call to this
    /// operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,

    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,

    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,

    /// Any additional data to be authenticated via the Authenticated Encryption
    /// Tag. If supplied in multipart encryption,
    /// this data MUST be supplied on the initial Decrypt request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_additional_data: Option<Vec<u8>>,

    /// Specifies the tag that will be needed to authenticate the decrypted data.
    /// If supplied in multipart decryption, this data MUST be supplied on the initial
    /// Decrypt request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_tag: Option<Vec<u8>>,
}

impl From<Decrypt> for kmip_2_1::kmip_operations::Decrypt {
    fn from(value: Decrypt) -> Self {
        Self {
            unique_identifier: Some(kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                value.unique_identifier,
            )),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data,
            i_v_counter_nonce: value.i_v_counter_nonce,
            correlation_value: value.correlation_value,
            init_indicator: value.init_indicator,
            final_indicator: value.final_indicator,
            authenticated_encryption_additional_data: value
                .authenticated_encryption_additional_data,
            authenticated_encryption_tag: value.authenticated_encryption_tag,
        }
    }
}

/// Response to a Decrypt request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct DecryptResponse {
    pub unique_identifier: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,

    /// Specifies the existing stream or by-
    /// parts cryptographic operation (as
    /// returned from a previous call to this
    /// operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
}

impl TryFrom<kmip_2_1::kmip_operations::DecryptResponse> for DecryptResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::DecryptResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 DecryptResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            data: value.data.map(|d| d.to_vec()),
            correlation_value: value.correlation_value,
        })
    }
}

/// 4.31 Sign
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Sign {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that is the key to
    /// use for the signature operation. If
    /// omitted, then the ID Placeholder value
    /// SHALL be used by the server as the
    /// Unique Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,

    /// The Cryptographic Parameters corresponding to the
    /// particular signature method requested.
    /// If there are no Cryptographic
    /// Parameters associated with the
    /// Managed Cryptographic Object and
    /// the algorithm requires parameters then
    /// the operation SHALL return with a
    /// Result Status of Operation Failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    /// The data to be signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Zeroizing<Vec<u8>>>,

    /// The digest of the data to be signed.
    /// Provided when the data has been pre-hashed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digested_data: Option<Vec<u8>>,

    /// Specifies the existing stream or by-
    /// parts cryptographic operation (as
    /// returned from a previous call to this
    /// operation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,

    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,

    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
}

impl From<Sign> for kmip_2_1::kmip_operations::Sign {
    fn from(value: Sign) -> Self {
        Self {
            unique_identifier: value
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data.map(|d| Zeroizing::new(d.to_vec())),
            digested_data: value.digested_data,
            correlation_value: value.correlation_value,
            init_indicator: value.init_indicator,
            final_indicator: value.final_indicator,
        }
    }
}

/// Response to a Sign request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SignResponse {
    pub unique_identifier: String,
    pub signature_data: Vec<u8>,
}

impl TryFrom<kmip_2_1::kmip_operations::SignResponse> for SignResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::SignResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 SignResponse to KMIP 1.4: {value}");
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            signature_data: value.signature_data.unwrap_or_default(),
        })
    }
}

impl Display for SignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignResponse {{ unique_identifier: {}, signature_data_len: {} }}",
            self.unique_identifier,
            self.signature_data.len()
        )
    }
}

impl fmt::Debug for SignResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.32 Signature Verify
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SignatureVerify {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the signature verify operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// The Cryptographic Parameters corresponding to the particular signature verification method requested
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The data that was signed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// The digested data to be verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digested_data: Option<Vec<u8>>,
    /// The signature to be verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_data: Option<Vec<u8>>,
    /// Specifies the existing stream or by-parts cryptographic operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation indicator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,
    /// Final operation indicator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
}

impl From<SignatureVerify> for kmip_2_1::kmip_operations::SignatureVerify {
    fn from(value: SignatureVerify) -> Self {
        Self {
            unique_identifier: value
                .unique_identifier
                .map(kmip_2_1::kmip_types::UniqueIdentifier::TextString),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data,
            digested_data: value.digested_data,
            signature_data: value.signature_data,
            correlation_value: value.correlation_value,
            init_indicator: value.init_indicator,
            final_indicator: value.final_indicator,
        }
    }
}

/// Response to a Signature Verify request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct SignatureVerifyResponse {
    pub unique_identifier: String,
    pub validity_indicator: ValidityIndicator,
}

impl TryFrom<kmip_2_1::kmip_operations::SignatureVerifyResponse> for SignatureVerifyResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::SignatureVerifyResponse,
    ) -> Result<Self, Self::Error> {
        let vi_1_4 = match value.validity_indicator {
            Some(kmip_2_1::kmip_types::ValidityIndicator::Valid) => ValidityIndicator::Valid,
            Some(kmip_2_1::kmip_types::ValidityIndicator::Invalid) => ValidityIndicator::Invalid,
            Some(kmip_2_1::kmip_types::ValidityIndicator::Unknown) | None => {
                ValidityIndicator::Unknown
            }
        };
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            validity_indicator: vi_1_4,
        })
    }
}

impl Display for SignatureVerifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignatureVerifyResponse {{ unique_identifier: {}, validity_indicator: {:?} }}",
            self.unique_identifier, self.validity_indicator
        )
    }
}

impl fmt::Debug for SignatureVerifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.33 MAC
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MAC {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The data to be hashed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,
    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
}

impl From<MAC> for kmip_2_1::kmip_operations::MAC {
    fn from(value: MAC) -> Self {
        Self {
            unique_identifier: Some(kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                value.unique_identifier,
            )),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data,
            correlation_value: value.correlation_value,
            init_indicator: value.init_indicator,
            final_indicator: value.final_indicator,
        }
    }
}

/// Response to a MAC request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct MACResponse {
    #[serde(rename = "UniqueIdentifier")]
    pub unique_identifier: String,
    /// The hashed data (as a Byte String).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "MACData")]
    pub mac_data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "CorrelationValue")]
    pub correlation_value: Option<Vec<u8>>,
}

impl TryFrom<kmip_2_1::kmip_operations::MACResponse> for MACResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::MACResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            mac_data: value.mac_data,
            correlation_value: value.correlation_value,
        })
    }
}

/// 4.34 MAC Verify
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MACVerify {
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    pub data: Vec<u8>,
    #[serde(rename = "MACData")]
    pub mac_data: Vec<u8>,
}

impl From<MACVerify> for kmip_2_1::kmip_operations::MACVerify {
    fn from(value: MACVerify) -> Self {
        Self {
            unique_identifier: kmip_2_1::kmip_types::UniqueIdentifier::TextString(
                value.unique_identifier,
            ),
            cryptographic_parameters: value.cryptographic_parameters.map(Into::into),
            data: value.data,
            mac_data: value.mac_data,
        }
    }
}

/// Response to a MAC Verify request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct MACVerifyResponse {
    pub unique_identifier: String,
    pub validity_indicator: ValidityIndicator,
}

impl TryFrom<kmip_2_1::kmip_operations::MACVerifyResponse> for MACVerifyResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::MACVerifyResponse) -> Result<Self, Self::Error> {
        let vi_1_4 = match value.validity_indicator {
            kmip_2_1::kmip_types::ValidityIndicator::Valid => ValidityIndicator::Valid,
            kmip_2_1::kmip_types::ValidityIndicator::Invalid => ValidityIndicator::Invalid,
            kmip_2_1::kmip_types::ValidityIndicator::Unknown => ValidityIndicator::Unknown,
        };
        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
            validity_indicator: vi_1_4,
        })
    }
}

impl Display for MACVerifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MACVerifyResponse {{ unique_identifier: {}, validity_indicator: {:?} }}",
            self.unique_identifier, self.validity_indicator
        )
    }
}

impl fmt::Debug for MACVerifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// 4.35 RNG Retrieve
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGRetrieve {
    pub data_length: i32,
}

/// Response to an RNG Retrieve request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGRetrieveResponse {
    pub data: Vec<u8>,
}

impl From<RNGRetrieve> for kmip_2_1::kmip_operations::RNGRetrieve {
    fn from(value: RNGRetrieve) -> Self {
        Self {
            data_length: value.data_length,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_operations::RNGRetrieveResponse> for RNGRetrieveResponse {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_operations::RNGRetrieveResponse,
    ) -> Result<Self, Self::Error> {
        Ok(Self { data: value.data })
    }
}

/// 4.36 RNG Seed
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGSeed {
    pub data: Vec<u8>,
}

/// Response to an RNG Seed request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct RNGSeedResponse {
    /// Number of bytes of seed data accepted by the RNG.
    /// KMIP 1.4 optional vectors use <DataLength>; accept it as an alias.
    #[serde(alias = "DataLength")]
    pub amount_of_seed_data: i32,
}

impl From<RNGSeed> for kmip_2_1::kmip_operations::RNGSeed {
    fn from(value: RNGSeed) -> Self {
        Self { data: value.data }
    }
}

impl Display for RNGSeedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RNGSeedResponse {{ amount_of_seed_data: {} }}",
            self.amount_of_seed_data
        )
    }
}

impl fmt::Debug for RNGSeedResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl TryFrom<kmip_2_1::kmip_operations::RNGSeedResponse> for RNGSeedResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::RNGSeedResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            amount_of_seed_data: value.amount_of_seed_data,
        })
    }
}

/// 4.37 Hash
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Hash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    pub data: Vec<u8>,
}

/// Response to a Hash request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HashResponse {
    #[serde(rename = "Data", alias = "HashData")]
    pub hash_data: Vec<u8>,
}

impl From<Hash> for kmip_2_1::kmip_operations::Hash {
    fn from(value: Hash) -> Self {
        Self {
            cryptographic_parameters: value
                .cryptographic_parameters
                .map(Into::into)
                .unwrap_or_default(),
            data: Some(value.data),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_operations::HashResponse> for HashResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::HashResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            hash_data: value.data.unwrap_or_default(),
        })
    }
}

/// 4.38 Create Split Key
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateSplitKey {
    pub split_key_parts: i32,
    pub split_key_threshold: i32,
    pub split_key_method: SplitKeyMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Create Split Key request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateSplitKeyResponse {
    pub unique_identifier: String,
    pub split_key_parts: Vec<String>,
}

/// 4.39 Join Split Key
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct JoinSplitKey {
    pub split_key_parts: Vec<Vec<u8>>,
    pub split_key_method: SplitKeyMethod,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<Vec<u8>>,
}

/// Response to a Join Split Key request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct JoinSplitKeyResponse {
    pub unique_identifier: String,
}

/// 4.40 Export
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Export {
    pub object_type: ObjectType,
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrap_type: Option<KeyWrapType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

/// Response to an Export request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ExportResponse {
    pub object_type: ObjectType,
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_data: Option<KeyWrappingData>,
    pub key_material: Vec<u8>,
}

/// 4.41 Import
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Import {
    pub object_type: ObjectType,
    pub unique_identifier: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_existing: Option<bool>,
    /// If Not Wrapped, then the server SHALL unwrap the object before storing it,
    /// and return an error if the wrapping key is not available.
    /// Otherwise, the server SHALL store the object as provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrap_type: Option<KeyWrapType>,
    /// All the object's Attributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<Attribute>>,
    /// The object being imported. The object and attributes MAY be wrapped.
    pub object: Object,
}

impl From<Import> for kmip_2_1::kmip_operations::Import {
    fn from(import: Import) -> Self {
        Self {
            object_type: import.object.object_type().into(),
            unique_identifier: import.unique_identifier.into(),
            replace_existing: import.replace_existing,
            key_wrap_type: import.key_wrap_type,
            attributes: import.attribute.unwrap_or_default().into(),
            object: import.object.into(),
        }
    }
}

/// Response to an Import request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ImportResponse {
    pub unique_identifier: String,
}

impl TryFrom<kmip_2_1::kmip_operations::ImportResponse> for ImportResponse {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::ImportResponse) -> Result<Self, Self::Error> {
        trace!("Converting KMIP 2.1 ImportResponse to KMIP 1.4: {value}");

        Ok(Self {
            unique_identifier: value.unique_identifier.to_string(),
        })
    }
}

/// The operation that processes a specific request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Operation {
    Activate(Activate),
    ActivateResponse(ActivateResponse),
    AddAttribute(AddAttribute),
    AddAttributeResponse(AddAttributeResponse),
    Archive(Archive),
    ArchiveResponse(ArchiveResponse),
    Cancel(Cancel),
    CancelResponse(CancelResponse),
    Certify(Certify),
    CertifyResponse(CertifyResponse),
    Check(Check),
    CheckResponse(CheckResponse),
    Create(Create),
    CreateKeyPair(CreateKeyPair),
    CreateKeyPairResponse(CreateKeyPairResponse),
    CreateResponse(CreateResponse),
    CreateSplitKey(CreateSplitKey),
    CreateSplitKeyResponse(CreateSplitKeyResponse),
    Decrypt(Box<Decrypt>),
    DecryptResponse(DecryptResponse),
    DeleteAttribute(DeleteAttribute),
    DeleteAttributeResponse(DeleteAttributeResponse),
    DeriveKey(DeriveKey),
    DeriveKeyResponse(DeriveKeyResponse),
    Destroy(Destroy),
    DestroyResponse(DestroyResponse),
    DiscoverVersions(DiscoverVersions),
    DiscoverVersionsResponse(DiscoverVersionsResponse),
    Encrypt(Box<Encrypt>),
    EncryptResponse(EncryptResponse),
    Export(Export),
    ExportResponse(ExportResponse),
    Get(Get),
    GetAttributes(GetAttributes),
    GetAttributesResponse(GetAttributesResponse),
    GetAttributeList(GetAttributeList),
    GetAttributeListResponse(GetAttributeListResponse),
    GetResponse(GetResponse),
    GetUsageAllocation(GetUsageAllocation),
    GetUsageAllocationResponse(GetUsageAllocationResponse),
    Hash(Hash),
    HashResponse(HashResponse),
    Import(Box<Import>),
    ImportResponse(ImportResponse),
    JoinSplitKey(JoinSplitKey),
    JoinSplitKeyResponse(JoinSplitKeyResponse),
    Locate(Locate),
    LocateResponse(LocateResponse),
    MAC(MAC),
    MACResponse(MACResponse),
    MACVerify(MACVerify),
    MACVerifyResponse(MACVerifyResponse),
    ModifyAttribute(ModifyAttribute),
    ModifyAttributeResponse(ModifyAttributeResponse),
    ObtainLease(ObtainLease),
    ObtainLeaseResponse(ObtainLeaseResponse),
    Poll(Poll),
    PollResponse(Box<PollResponse>),
    Query(Query),
    QueryResponse(Box<QueryResponse>),
    ReCertify(ReCertify),
    ReCertifyResponse(ReCertifyResponse),
    Recover(Recover),
    RecoverResponse(RecoverResponse),
    Register(Register),
    RegisterResponse(RegisterResponse),
    ReKey(ReKey),
    ReKeyKeyPair(ReKeyKeyPair),
    ReKeyKeyPairResponse(ReKeyKeyPairResponse),
    ReKeyResponse(ReKeyResponse),
    RNGRetrieve(RNGRetrieve),
    RNGRetrieveResponse(RNGRetrieveResponse),
    RNGSeed(RNGSeed),
    RNGSeedResponse(RNGSeedResponse),
    Revoke(Revoke),
    RevokeResponse(RevokeResponse),
    Sign(Sign),
    SignResponse(SignResponse),
    SignatureVerify(SignatureVerify),
    SignatureVerifyResponse(SignatureVerifyResponse),
    Validate(Validate),
    ValidateResponse(ValidateResponse),
    // KMIP 1.4 additional operations (declared for completeness)
    Notify(Notify),
    NotifyResponse(NotifyResponse),
    Put(Put),
    PutResponse(PutResponse),
}

impl Operation {
    /// Returns whether this is a request or response operation
    #[must_use]
    pub const fn direction(&self) -> Direction {
        match self {
            Self::Create(_)
            | Self::CreateKeyPair(_)
            | Self::Register(_)
            | Self::ReKey(_)
            | Self::ReKeyKeyPair(_)
            | Self::DeriveKey(_)
            | Self::Certify(_)
            | Self::ReCertify(_)
            | Self::Locate(_)
            | Self::Check(_)
            | Self::Get(_)
            | Self::GetAttributes(_)
            | Self::GetAttributeList(_)
            | Self::AddAttribute(_)
            | Self::ModifyAttribute(_)
            | Self::DeleteAttribute(_)
            | Self::ObtainLease(_)
            | Self::GetUsageAllocation(_)
            | Self::Activate(_)
            | Self::Revoke(_)
            | Self::Destroy(_)
            | Self::Archive(_)
            | Self::Recover(_)
            | Self::Validate(_)
            | Self::Query(_)
            | Self::DiscoverVersions(_)
            | Self::Cancel(_)
            | Self::Poll(_)
            | Self::Encrypt(_)
            | Self::Decrypt(_)
            | Self::Sign(_)
            | Self::SignatureVerify(_)
            | Self::MAC(_)
            | Self::MACVerify(_)
            | Self::RNGRetrieve(_)
            | Self::RNGSeed(_)
            | Self::Hash(_)
            | Self::CreateSplitKey(_)
            | Self::JoinSplitKey(_)
            | Self::Export(_)
            | Self::Import(_) => Direction::Request,
            _ => Direction::Response,
        }
    }

    /// Gets the operation enumeration value
    #[must_use]
    pub const fn operation_enum(&self) -> OperationEnumeration {
        match self {
            Self::Create(_) | Self::CreateResponse(_) => OperationEnumeration::Create,
            Self::CreateKeyPair(_) | Self::CreateKeyPairResponse(_) => {
                OperationEnumeration::CreateKeyPair
            }
            Self::Register(_) | Self::RegisterResponse(_) => OperationEnumeration::Register,
            Self::ReKey(_) | Self::ReKeyResponse(_) => OperationEnumeration::ReKey,
            Self::ReKeyKeyPair(_) | Self::ReKeyKeyPairResponse(_) => {
                OperationEnumeration::ReKeyKeyPair
            }
            Self::DeriveKey(_) | Self::DeriveKeyResponse(_) => OperationEnumeration::DeriveKey,
            Self::Certify(_) | Self::CertifyResponse(_) => OperationEnumeration::Certify,
            Self::ReCertify(_) | Self::ReCertifyResponse(_) => OperationEnumeration::ReCertify,
            Self::Locate(_) | Self::LocateResponse(_) => OperationEnumeration::Locate,
            Self::Check(_) | Self::CheckResponse(_) => OperationEnumeration::Check,
            Self::Get(_) | Self::GetResponse(_) => OperationEnumeration::Get,
            Self::GetAttributes(_) | Self::GetAttributesResponse(_) => {
                OperationEnumeration::GetAttributes
            }
            Self::GetAttributeList(_) | Self::GetAttributeListResponse(_) => {
                OperationEnumeration::GetAttributeList
            }
            Self::AddAttribute(_) | Self::AddAttributeResponse(_) => {
                OperationEnumeration::AddAttribute
            }
            Self::ModifyAttribute(_) | Self::ModifyAttributeResponse(_) => {
                OperationEnumeration::ModifyAttribute
            }
            Self::DeleteAttribute(_) | Self::DeleteAttributeResponse(_) => {
                OperationEnumeration::DeleteAttribute
            }
            Self::ObtainLease(_) | Self::ObtainLeaseResponse(_) => {
                OperationEnumeration::ObtainLease
            }
            Self::GetUsageAllocation(_) | Self::GetUsageAllocationResponse(_) => {
                OperationEnumeration::GetUsageAllocation
            }
            Self::Activate(_) | Self::ActivateResponse(_) => OperationEnumeration::Activate,
            Self::Revoke(_) | Self::RevokeResponse(_) => OperationEnumeration::Revoke,
            Self::Destroy(_) | Self::DestroyResponse(_) => OperationEnumeration::Destroy,
            Self::Archive(_) | Self::ArchiveResponse(_) => OperationEnumeration::Archive,
            Self::Recover(_) | Self::RecoverResponse(_) => OperationEnumeration::Recover,
            Self::Validate(_) | Self::ValidateResponse(_) => OperationEnumeration::Validate,
            Self::Query(_) | Self::QueryResponse(_) => OperationEnumeration::Query,
            Self::DiscoverVersions(_) | Self::DiscoverVersionsResponse(_) => {
                OperationEnumeration::DiscoverVersions
            }
            Self::Cancel(_) | Self::CancelResponse(_) => OperationEnumeration::Cancel,
            Self::Poll(_) | Self::PollResponse(_) => OperationEnumeration::Poll,
            Self::Encrypt(_) | Self::EncryptResponse(_) => OperationEnumeration::Encrypt,
            Self::Decrypt(_) | Self::DecryptResponse(_) => OperationEnumeration::Decrypt,
            Self::Sign(_) | Self::SignResponse(_) => OperationEnumeration::Sign,
            Self::SignatureVerify(_) | Self::SignatureVerifyResponse(_) => {
                OperationEnumeration::SignatureVerify
            }
            Self::MAC(_) | Self::MACResponse(_) => OperationEnumeration::MAC,
            Self::MACVerify(_) | Self::MACVerifyResponse(_) => OperationEnumeration::MACVerify,
            Self::RNGRetrieve(_) | Self::RNGRetrieveResponse(_) => {
                OperationEnumeration::RNGRetrieve
            }
            Self::RNGSeed(_) | Self::RNGSeedResponse(_) => OperationEnumeration::RNGSeed,
            Self::Hash(_) | Self::HashResponse(_) => OperationEnumeration::Hash,
            Self::CreateSplitKey(_) | Self::CreateSplitKeyResponse(_) => {
                OperationEnumeration::CreateSplitKey
            }
            Self::JoinSplitKey(_) | Self::JoinSplitKeyResponse(_) => {
                OperationEnumeration::JoinSplitKey
            }
            Self::Export(_) | Self::ExportResponse(_) => OperationEnumeration::Export,
            Self::Import(_) | Self::ImportResponse(_) => OperationEnumeration::Import,
            Self::Notify(_) | Self::NotifyResponse(_) => OperationEnumeration::Notify,
            Self::Put(_) | Self::PutResponse(_) => OperationEnumeration::Put,
        }
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Operation {{")?;
        let name = match self {
            Self::Activate(_) => "Activate",
            Self::ActivateResponse(_) => "ActivateResponse",
            Self::AddAttribute(_) => "AddAttribute",
            Self::AddAttributeResponse(_) => "AddAttributeResponse",
            Self::Archive(_) => "Archive",
            Self::ArchiveResponse(_) => "ArchiveResponse",
            Self::Cancel(_) => "Cancel",
            Self::CancelResponse(_) => "CancelResponse",
            Self::Certify(_) => "Certify",
            Self::CertifyResponse(_) => "CertifyResponse",
            Self::Check(_) => "Check",
            Self::CheckResponse(_) => "CheckResponse",
            Self::Create(_) => "Create",
            Self::CreateKeyPair(_) => "CreateKeyPair",
            Self::CreateKeyPairResponse(_) => "CreateKeyPairResponse",
            Self::CreateResponse(_) => "CreateResponse",
            Self::CreateSplitKey(_) => "CreateSplitKey",
            Self::CreateSplitKeyResponse(_) => "CreateSplitKeyResponse",
            Self::Decrypt(_) => "Decrypt",
            Self::DecryptResponse(_) => "DecryptResponse",
            Self::DeleteAttribute(_) => "DeleteAttribute",
            Self::DeleteAttributeResponse(_) => "DeleteAttributeResponse",
            Self::DeriveKey(_) => "DeriveKey",
            Self::DeriveKeyResponse(_) => "DeriveKeyResponse",
            Self::Destroy(_) => "Destroy",
            Self::DestroyResponse(_) => "DestroyResponse",
            Self::DiscoverVersions(_) => "DiscoverVersions",
            Self::DiscoverVersionsResponse(_) => "DiscoverVersionsResponse",
            Self::Encrypt(_) => "Encrypt",
            Self::EncryptResponse(_) => "EncryptResponse",
            Self::Export(_) => "Export",
            Self::ExportResponse(_) => "ExportResponse",
            Self::Get(_) => "Get",
            Self::GetAttributes(_) => "GetAttributes",
            Self::GetAttributesResponse(_) => "GetAttributesResponse",
            Self::GetAttributeList(_) => "GetAttributeList",
            Self::GetAttributeListResponse(_) => "GetAttributeListResponse",
            Self::GetResponse(_) => "GetResponse",
            Self::GetUsageAllocation(_) => "GetUsageAllocation",
            Self::GetUsageAllocationResponse(_) => "GetUsageAllocationResponse",
            Self::Hash(_) => "Hash",
            Self::HashResponse(_) => "HashResponse",
            Self::Import(_) => "Import",
            Self::ImportResponse(_) => "ImportResponse",
            Self::JoinSplitKey(_) => "JoinSplitKey",
            Self::JoinSplitKeyResponse(_) => "JoinSplitKeyResponse",
            Self::Locate(_) => "Locate",
            Self::LocateResponse(_) => "LocateResponse",
            Self::MAC(_) => "MAC",
            Self::MACResponse(_) => "MACResponse",
            Self::MACVerify(_) => "MACVerify",
            Self::MACVerifyResponse(_) => "MACVerifyResponse",
            Self::ModifyAttribute(_) => "ModifyAttribute",
            Self::ModifyAttributeResponse(_) => "ModifyAttributeResponse",
            Self::ObtainLease(_) => "ObtainLease",
            Self::ObtainLeaseResponse(_) => "ObtainLeaseResponse",
            Self::Poll(_) => "Poll",
            Self::PollResponse(_) => "PollResponse",
            Self::Query(_) => "Query",
            Self::QueryResponse(_) => "QueryResponse",
            Self::ReCertify(_) => "ReCertify",
            Self::ReCertifyResponse(_) => "ReCertifyResponse",
            Self::Recover(_) => "Recover",
            Self::RecoverResponse(_) => "RecoverResponse",
            Self::Register(_) => "Register",
            Self::RegisterResponse(_) => "RegisterResponse",
            Self::ReKey(_) => "ReKey",
            Self::ReKeyKeyPair(_) => "ReKeyKeyPair",
            Self::ReKeyKeyPairResponse(_) => "ReKeyKeyPairResponse",
            Self::ReKeyResponse(_) => "ReKeyResponse",
            Self::RNGRetrieve(_) => "RNGRetrieve",
            Self::RNGRetrieveResponse(_) => "RNGRetrieveResponse",
            Self::RNGSeed(_) => "RNGSeed",
            Self::RNGSeedResponse(_) => "RNGSeedResponse",
            Self::Revoke(_) => "Revoke",
            Self::RevokeResponse(_) => "RevokeResponse",
            Self::Sign(_) => "Sign",
            Self::SignResponse(_) => "SignResponse",
            Self::SignatureVerify(_) => "SignatureVerify",
            Self::SignatureVerifyResponse(_) => "SignatureVerifyResponse",
            Self::Validate(_) => "Validate",
            Self::ValidateResponse(_) => "ValidateResponse",
            Self::Notify(_) => "Notify",
            Self::NotifyResponse(_) => "NotifyResponse",
            Self::Put(_) => "Put",
            Self::PutResponse(_) => "PutResponse",
        };
        write!(f, "{name}}}")
    }
}

// Provide Debug for assert_eq!/derives without exposing sensitive internals.
impl fmt::Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reuse Display output for Debug to minimize verbosity and exposure
        write!(f, "{self}")
    }
}

impl TryFrom<Operation> for kmip_2_1::kmip_operations::Operation {
    type Error = KmipError;

    fn try_from(value: Operation) -> Result<Self, Self::Error> {
        Ok(match value {
            Operation::Activate(activate) => Self::Activate(activate.into()),
            Operation::AddAttribute(add_attribute) => Self::AddAttribute(add_attribute.into()),
            // Operation::Archive(archive) => {
            //     Self::Archive(archive.into())
            // }
            // Operation::Cancel(cancel) => {
            //     Self::Cancel(cancel.into())
            // }
            // Operation::Certify(certify) => {
            //     Self::Certify(certify.into())
            // }
            // Operation::Check(check) => Self::Check(check.into()),
            Operation::Create(create) => Self::Create(create.into()),
            Operation::CreateKeyPair(create_key_pair) => {
                Self::CreateKeyPair(Box::new(create_key_pair.into()))
            }
            Operation::Decrypt(decrypt) => Self::Decrypt(Box::new((*decrypt).into())),
            Operation::DeleteAttribute(delete_attribute) => {
                Self::DeleteAttribute(delete_attribute.into())
            }
            // Operation::DeriveKey(derive_key) => {
            //     Self::DeriveKey(derive_key.into())
            // }
            Operation::Destroy(destroy) => Self::Destroy(destroy.into()),
            Operation::DiscoverVersions(discover_versions) => {
                Self::DiscoverVersions(discover_versions)
            }
            Operation::DiscoverVersionsResponse(discover_versions_response) => {
                Self::DiscoverVersionsResponse(discover_versions_response)
            }
            Operation::Encrypt(encrypt) => Self::Encrypt(Box::new((*encrypt).into())),
            Operation::Get(get) => Self::Get(get.into()),
            Operation::GetAttributes(get_attributes) => Self::GetAttributes(get_attributes.into()),
            Operation::GetAttributeList(get_attribute_list) => {
                Self::GetAttributeList(get_attribute_list.into())
            }
            // Operation::GetUsageAllocation(get_usage_allocation) => {
            //     Self::GetUsageAllocation(get_usage_allocation.into())
            // }
            Operation::Import(import) => Self::Import(Box::new((*import).into())),
            // Operation::JoinSplitKey(join_split_key) => {
            //     Self::JoinSplitKey(join_split_key.into())
            // }
            Operation::Locate(locate) => Self::Locate(Box::new(locate.into())),
            Operation::MAC(mac) => Self::MAC(mac.into()),
            Operation::MACVerify(mac_verify) => Self::MACVerify(mac_verify.into()),
            Operation::ModifyAttribute(modify_attribute) => {
                Self::ModifyAttribute(modify_attribute.into())
            }
            // Operation::ObtainLease(obtain_lease) => {
            //     Self::ObtainLease(obtain_lease.into())
            // }
            // Operation::Poll(poll) => Self::Poll(poll.into()),
            Operation::Query(query) => Self::Query(query.into()),
            // Operation::ReCertify(recertify) => {
            //     Self::ReCertify(recertify.into())
            // }
            // Operation::Recover(recover) => {
            //     Self::Recover(recover.into())
            // }
            Operation::Register(register) => Self::Register(Box::new(register.into())),
            // Operation::ReKey(rekey) => Self::ReKey(rekey.into()),
            // Operation::ReKeyKeyPair(rekey_key_pair) => {
            //     Self::ReKeyKeyPair(rekey_key_pair.into())
            // }
            Operation::Revoke(revoke) => Self::Revoke(revoke.into()),
            Operation::RNGRetrieve(rng_retrieve) => Self::RNGRetrieve(rng_retrieve.into()),
            Operation::RNGSeed(rng_seed) => Self::RNGSeed(rng_seed.into()),
            Operation::Sign(sign) => Self::Sign(sign.into()),
            Operation::SignatureVerify(signature_verify) => {
                Self::SignatureVerify(signature_verify.into())
            }
            Operation::Hash(hash) => Self::Hash(hash.into()),
            Operation::Validate(validate) => Self::Validate(validate.into()),
            op => {
                return Err(KmipError::NotSupported(format!(
                    "Conversion of KMIP 1.x operation to KMIP 2.1 is not supported for: {op}"
                )));
            }
        })
    }
}

impl TryFrom<kmip_2_1::kmip_operations::Operation> for Operation {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_operations::Operation) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_operations::Operation::ActivateResponse(activate_response) => {
                Self::ActivateResponse(activate_response.try_into().context("ActivateResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::AddAttributeResponse(add_attribute_response) => {
                Self::AddAttributeResponse(add_attribute_response.into())
            }
            // Operation::ArchiveResponse(archive_response) => {
            //     Self::ArchiveResponse(archive_response.into())
            // }
            // Operation::CancelResponse(cancel_response) => {
            //     Self::CancelResponse(cancel_response.into())
            // }
            // Operation::CertifyResponse(certify_response) => {
            //     Self::CertifyResponse(certify_response.into())
            // }
            // Operation::CheckResponse(check_response) => {
            //     Self::CheckResponse(check_response.into())
            // }
            kmip_2_1::kmip_operations::Operation::CreateKeyPairResponse(
                create_key_pair_response,
            ) => Self::CreateKeyPairResponse(
                create_key_pair_response
                    .try_into()
                    .context("CreateKeyPairResponse")?,
            ),
            kmip_2_1::kmip_operations::Operation::CreateResponse(create_response) => {
                Self::CreateResponse(create_response.try_into().context("CreateResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::DecryptResponse(decrypt_response) => {
                Self::DecryptResponse(decrypt_response.try_into().context("DecryptResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::DeleteAttributeResponse(
                delete_attribute_response,
            ) => Self::DeleteAttributeResponse(
                delete_attribute_response
                    .try_into()
                    .context("DeleteAttributeResponse")?,
            ),
            // Operation::DeriveKeyResponse(derive_key_response) => {
            //     Self::DeriveKeyResponse(derive_key_response.into())
            // }
            kmip_2_1::kmip_operations::Operation::DestroyResponse(destroy_response) => {
                Self::DestroyResponse(destroy_response.try_into().context("DestroyResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::ModifyAttributeResponse(
                modify_attribute_response,
            ) => Self::ModifyAttributeResponse(
                modify_attribute_response
                    .try_into()
                    .context("ModifyAttributeResponse")?,
            ),
            kmip_2_1::kmip_operations::Operation::DiscoverVersions(discover_versions) => {
                Self::DiscoverVersions(discover_versions)
            }
            kmip_2_1::kmip_operations::Operation::DiscoverVersionsResponse(
                discover_versions_response,
            ) => Self::DiscoverVersionsResponse(discover_versions_response),
            kmip_2_1::kmip_operations::Operation::EncryptResponse(encrypt_response) => {
                Self::EncryptResponse(encrypt_response.try_into().context("EncryptResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::GetAttributesResponse(
                get_attributes_response,
            ) => Self::GetAttributesResponse((*get_attributes_response).try_into()?),
            kmip_2_1::kmip_operations::Operation::GetAttributeListResponse(
                get_attribute_list_response,
            ) => Self::GetAttributeListResponse(
                get_attribute_list_response
                    .try_into()
                    .context("GetAttributeListResponse")?,
            ),
            kmip_2_1::kmip_operations::Operation::GetResponse(get_response) => {
                Self::GetResponse(get_response.try_into()?)
            }
            // Operation::GetUsageAllocationResponse(get_usage_allocation_response) => {
            //     Self::GetUsageAllocationResponse(
            //         get_usage_allocation_response.into(),
            //     )
            // }
            kmip_2_1::kmip_operations::Operation::ImportResponse(import_response) => {
                Self::ImportResponse(import_response.try_into().context("ImportResponse")?)
            }
            // Operation::JoinSplitKeyResponse(join_split_key_response) => {
            //     Self::JoinSplitKeyResponse(
            //         join_split_key_response.into(),
            //     )
            // }
            kmip_2_1::kmip_operations::Operation::LocateResponse(locate_response) => {
                Self::LocateResponse(locate_response.try_into().context("LocateResponse")?)
            }
            // Operation::MAC(mac) => Self::MAC(mac.into()),
            kmip_2_1::kmip_operations::Operation::MACResponse(mac_response) => {
                Self::MACResponse(mac_response.try_into().context("MACResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::MACVerifyResponse(mac_verify_response) => {
                Self::MACVerifyResponse(
                    mac_verify_response
                        .try_into()
                        .context("MACVerifyResponse")?,
                )
            }
            // Operation::ModifyAttributeResponse(modify_attribute_response) => {
            //     Self::ModifyAttributeResponse(
            //         modify_attribute_response.into(),
            //     )
            // }
            // Operation::ObtainLeaseResponse(obtain_lease_response) => {
            //     Self::ObtainLeaseResponse(
            //         obtain_lease_response.into(),
            //     )
            // }
            // Operation::PollResponse(poll_response) => {
            //     Self::PollResponse(poll_response.into())
            // }
            kmip_2_1::kmip_operations::Operation::QueryResponse(query_response) => {
                Self::QueryResponse(Box::new(
                    (*query_response).try_into().context("QueryResponse")?,
                ))
            }
            // Operation::ReCertifyResponse(recertify_response) => {
            //     Self::ReCertifyResponse(recertify_response.into())
            // }
            // Operation::RecoverResponse(recover_response) => {
            //     Self::RecoverResponse(recover_response.into())
            // }
            kmip_2_1::kmip_operations::Operation::RegisterResponse(register_response) => {
                Self::RegisterResponse(register_response.try_into()?)
            }
            // Operation::ReKeyKeyPairResponse(rekey_key_pair_response) => {
            //     Self::ReKeyKeyPairResponse(
            //         rekey_key_pair_response.into(),
            //     )
            // }
            // Operation::ReKeyResponse(rekey_response) => {
            //     Self::ReKeyResponse(rekey_response.into())
            // }
            kmip_2_1::kmip_operations::Operation::RevokeResponse(revoke_response) => {
                Self::RevokeResponse(revoke_response.try_into().context("RevokeResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::HashResponse(hash_response) => {
                Self::HashResponse(hash_response.try_into().context("HashResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::RNGRetrieveResponse(rng_retrieve_response) => {
                Self::RNGRetrieveResponse(
                    rng_retrieve_response
                        .try_into()
                        .context("RNGRetrieveResponse")?,
                )
            }
            kmip_2_1::kmip_operations::Operation::RNGSeedResponse(rng_seed_response) => {
                Self::RNGSeedResponse(rng_seed_response.try_into().context("RNGSeedResponse")?)
            }
            kmip_2_1::kmip_operations::Operation::SignatureVerifyResponse(
                signature_verify_response,
            ) => Self::SignatureVerifyResponse(
                signature_verify_response
                    .try_into()
                    .context("SignatureVerifyResponse")?,
            ),
            kmip_2_1::kmip_operations::Operation::SignResponse(sign_response) => {
                Self::SignResponse(sign_response.try_into().context("SignResponse")?)
            }
            // Operation::ValidateResponse(validate_response) => {
            //     Self::ValidateResponse(validate_response.into())
            // }
            op => {
                return Err(KmipError::NotSupported(format!(
                    "Conversion from KMIP 2.1 to KMIP 1.x is not supported for Response \
                     Operation: {op}"
                )));
            }
        })
    }
}

/// 4.26 Notify (server to client)
/// Minimal declaration to allow encoding/decoding when present in KMIP 1.4 vectors.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Notify {
    /// Carries the correlation value of the original asynchronous request
    pub asynchronous_correlation_value: String,
    /// Identifies the operation that completed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationEnumeration>,
    /// Unique Identifier related to the notification (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
}

/// Response to a Notify request (empty body per spec; included for completeness)
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct NotifyResponse;

/// 4.26 Put
/// This operation requests the server to store or replace a Managed Object with provided attributes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Put {
    /// Object Type of the object being put
    pub object_type: ObjectType,
    /// Unique Identifier to use or replace (depends on `PutFunction`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,
    /// `NEW` or `REPLACE` (see `PutFunction`)
    pub put_function: PutFunction,
    /// Attributes to set on the object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<Vec<Attribute>>,
    /// The object to store
    pub object: Object,
}

/// Response to a Put request
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct PutResponse {
    pub unique_identifier: String,
}
