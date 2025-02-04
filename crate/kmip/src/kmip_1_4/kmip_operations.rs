use std::fmt::{self, Display};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{
    kmip_data_structures::*,
    kmip_objects::{Object, ObjectType},
    kmip_types::*,
};

#[derive(Debug, Eq, PartialEq)]
pub enum Direction {
    Request,
    Response,
}

/// 4.1 Create
/// This operation requests the server to generate a new managed cryptographic object. The request
/// contains information about the type of object being created, and some of the attributes to be
/// assigned to the object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Create {
    /// Determines the type of object to be created
    pub object_type: ObjectType,
    /// Specifies template attributes to be assigned to new object
    pub template_attribute: TemplateAttribute,
}

/// Response to a Create request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CreateResponse {
    /// The Unique Identifier of the newly created object
    pub unique_identifier: String,
    /// The template attributes that were assigned
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.2 Create Key Pair
/// This operation requests the server to generate a new public/private key pair and register
/// the two corresponding new Managed Cryptographic Objects.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CreateKeyPair {
    /// Common template attributes that apply to both public and private key
    pub common_template_attribute: Option<TemplateAttribute>,
    /// Template attributes that apply only to private key
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Template attributes that apply only to public key
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// Response to a Create Key Pair request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CreateKeyPairResponse {
    /// Unique ID of the private key
    pub private_key_unique_identifier: String,
    /// Unique ID of the public key  
    pub public_key_unique_identifier: String,
    /// Private key template attributes
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Public key template attributes
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// 4.3 Register
/// This operation requests the server to register a Managed Object that was created by the client
/// or obtained by the client through some other means.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Register {
    /// The object being registered
    pub object: Object,
    /// Template attributes for the object
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Register request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct RegisterResponse {
    /// The unique identifier of the registered object
    pub unique_identifier: String,
    /// Template attributes applied to the object
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.4 Re-key
/// This operation requests the server to generate a replacement key for an existing symmetric key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReKey {
    /// Unique identifier of the symmetric key to be rekeyed
    pub unique_identifier: String,
    /// Offset from the initialization date of the new key
    pub offset: Option<i32>,
    /// Template attributes for the new key
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-key request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReKeyResponse {
    /// Unique identifier of the newly created key
    pub unique_identifier: String,
    /// Template attributes applied to the new key
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.5 Re-key Key Pair
/// This operation requests the server to generate a replacement key pair for an existing public/private key pair.  
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReKeyKeyPair {
    /// Unique identifier of private key to be rekeyed
    pub private_key_unique_identifier: String,
    /// Offset from the initialization date of the new key pair
    pub offset: Option<i32>,
    /// Common template attributes for both public and private key
    pub common_template_attribute: Option<TemplateAttribute>,
    /// Template attributes for private key
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Template attributes for public key
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-key Key Pair request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReKeyKeyPairResponse {
    /// Unique identifier of new private key
    pub private_key_unique_identifier: String,
    /// Unique identifier of new public key
    pub public_key_unique_identifier: String,
    /// Private key template attributes
    pub private_key_template_attribute: Option<TemplateAttribute>,
    /// Public key template attributes
    pub public_key_template_attribute: Option<TemplateAttribute>,
}

/// 4.6 Derive Key
/// This operation requests the server to derive a symmetric key or secret data from a key or
/// secret data that is already known to the key management system.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeriveKey {
    /// Unique identifier of the object to derive from
    pub object_unique_identifier: String,
    /// Information for the derivation process
    pub derivation_method: DerivationMethod,
    /// Parameters for derivation
    pub derivation_parameters: Option<DerivationParameters>,
    /// Template attributes for the new key/secret
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Derive Key request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeriveKeyResponse {
    /// Unique identifier of derived object
    pub unique_identifier: String,
    /// Template attributes applied
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.7 Certify
/// This operation requests the server to generate a Certificate object for a public key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Certify {
    pub unique_identifier: String,
    pub certificate_request_type: CertificateRequestType,
    pub certificate_request_value: Vec<u8>,
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Certify request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CertifyResponse {
    pub unique_identifier: String,
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.8 Re-certify
/// This operation requests the server to generate a new Certificate object for an existing public key.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReCertify {
    pub unique_identifier: String,
    pub certificate_request_type: CertificateRequestType,
    pub certificate_request_value: Vec<u8>,
    pub template_attribute: Option<TemplateAttribute>,
}

/// Response to a Re-certify request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ReCertifyResponse {
    pub unique_identifier: String,
    pub template_attribute: Option<TemplateAttribute>,
}

/// 4.9 Locate
/// This operation requests that the server search for one or more Managed Objects.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Locate {
    pub attributes: Vec<Attribute>,
    pub storage_status_mask: Option<StorageStatusMask>,
    pub object_group_member: Option<ObjectGroupMember>,
}

/// Response to a Locate request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LocateResponse {
    pub unique_identifiers: Vec<String>,
}

/// 4.10 Check
/// This operation requests that the server check for use of a Managed Object according
/// to values specified in the request.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Check {
    pub unique_identifier: String,
    pub usage_limits_count: Option<i64>,
    pub cryptographic_usage_mask: Option<u32>,
    pub lease_time: Option<bool>,
}

/// Response to a Check request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CheckResponse {
    pub unique_identifier: String,
    pub usage_limits_count: Option<i64>,
    pub cryptographic_usage_mask: Option<u32>,
    pub lease_time: Option<i32>,
}

/// 4.11 Get
/// This operation requests that the server returns the Managed Object specified by its
/// Unique Identifier.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Get {
    pub unique_identifier: String,
    pub key_format_type: Option<KeyFormatType>,
    pub key_compression_type: Option<KeyCompressionType>,
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

/// Response to a Get request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub unique_identifier: String,
    pub object: Object,
}

/// 4.12 Get Attributes
/// This operation requests one or more attributes associated with a Managed Object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GetAttributes {
    pub unique_identifier: String,
    pub attribute_names: Option<Vec<String>>,
}

/// Response to a Get Attributes request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GetAttributesResponse {
    pub unique_identifier: String,
    pub attributes: Vec<Attribute>,
}

/// 4.13 Get Attribute List
/// This operation requests a list of the attribute names associated with a Managed Object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GetAttributeList {
    pub unique_identifier: String,
}

/// Response to a Get Attribute List request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct GetAttributeListResponse {
    pub unique_identifier: String,
    pub attribute_names: Vec<String>,
}

/// 4.14 Add Attribute
/// This operation requests that the server add a new attribute or append attribute values to an existing attribute.  
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AddAttribute {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

/// Response to an Add Attribute request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AddAttributeResponse {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

/// 4.15 Modify Attribute
/// This operation requests that the server modify one or more attributes associated with a Managed Object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ModifyAttribute {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

/// Response to a Modify Attribute request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ModifyAttributeResponse {
    pub unique_identifier: String,
    pub attribute: Attribute,
}

/// 4.16 Delete Attribute
/// This operation requests that the server delete an attribute associated with a Managed Object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeleteAttribute {
    pub unique_identifier: String,
    pub attribute_name: String,
    pub attribute_index: Option<i32>,
}

/// Response to a Delete Attribute request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DeleteAttributeResponse {
    pub unique_identifier: String,
}

/// 4.17 Obtain Lease
/// This operation requests a new or renewed lease for a client's use of a Managed Object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ObtainLease {
    pub unique_identifier: String,
}

/// Response to an Obtain Lease request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ObtainLeaseResponse {
    pub unique_identifier: String,
    pub lease_time: i32,
    pub last_change_date: DateTime<Utc>,
}

// Continue implementing remaining operations...

/// The operation that processes a specific request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum Operation {
    Create(Create),
    CreateResponse(CreateResponse),
    CreateKeyPair(CreateKeyPair),
    CreateKeyPairResponse(CreateKeyPairResponse),
    Register(Register),
    RegisterResponse(RegisterResponse),
    ReKey(ReKey),
    ReKeyResponse(ReKeyResponse),
    ReKeyKeyPair(ReKeyKeyPair),
    ReKeyKeyPairResponse(ReKeyKeyPairResponse),
    DeriveKey(DeriveKey),
    DeriveKeyResponse(DeriveKeyResponse),
    Certify(Certify),
    CertifyResponse(CertifyResponse),
    ReCertify(ReCertify),
    ReCertifyResponse(ReCertifyResponse),
    Locate(Locate),
    LocateResponse(LocateResponse),
    Check(Check),
    CheckResponse(CheckResponse),
    Get(Get),
    GetResponse(GetResponse),
    GetAttributes(GetAttributes),
    GetAttributesResponse(GetAttributesResponse),
    GetAttributeList(GetAttributeList),
    GetAttributeListResponse(GetAttributeListResponse),
    AddAttribute(AddAttribute),
    AddAttributeResponse(AddAttributeResponse),
    ModifyAttribute(ModifyAttribute),
    ModifyAttributeResponse(ModifyAttributeResponse),
    DeleteAttribute(DeleteAttribute),
    DeleteAttributeResponse(DeleteAttributeResponse),
    ObtainLease(ObtainLease),
    ObtainLeaseResponse(ObtainLeaseResponse),
    // ... Add remaining operations ...
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
            | Self::ObtainLease(_) => Direction::Request,
            Self::CreateResponse(_)
            | Self::CreateKeyPairResponse(_)
            | Self::RegisterResponse(_)
            | Self::ReKeyResponse(_)
            | Self::ReKeyKeyPairResponse(_)
            | Self::DeriveKeyResponse(_)
            | Self::CertifyResponse(_)
            | Self::ReCertifyResponse(_)
            | Self::LocateResponse(_)
            | Self::CheckResponse(_)
            | Self::GetResponse(_)
            | Self::GetAttributesResponse(_)
            | Self::GetAttributeListResponse(_)
            | Self::AddAttributeResponse(_)
            | Self::ModifyAttributeResponse(_)
            | Self::DeleteAttributeResponse(_)
            | Self::ObtainLeaseResponse(_) => Direction::Response,
            // ... Handle remaining operations
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
                OperationEnumeration::RekeyKeyPair
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
            } // ... continue matching remaining operations
        }
    }
}

impl Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Create(create) => write!(f, "Create({create:?})"),
            Self::CreateResponse(create_response) => {
                write!(f, "CreateResponse({create_response:?})")
            }
            Self::CreateKeyPair(create_key_pair) => write!(f, "CreateKeyPair({create_key_pair:?})"),
            Self::CreateKeyPairResponse(create_key_pair_response) => {
                write!(f, "CreateKeyPairResponse({create_key_pair_response:?})")
            }
            Self::Register(register) => write!(f, "Register({register:?})"),
            Self::RegisterResponse(register_response) => {
                write!(f, "RegisterResponse({register_response:?})")
            }
            Self::ReKey(rekey) => write!(f, "ReKey({rekey:?})"),
            Self::ReKeyResponse(rekey_response) => {
                write!(f, "ReKeyResponse({rekey_response:?})")
            }
            Self::ReKeyKeyPair(rekey_key_pair) => write!(f, "ReKeyKeyPair({rekey_key_pair:?})"),
            Self::ReKeyKeyPairResponse(rekey_key_pair_response) => {
                write!(f, "ReKeyKeyPairResponse({rekey_key_pair_response:?})")
            }
            Self::DeriveKey(derive_key) => write!(f, "DeriveKey({derive_key:?})"),
            Self::DeriveKeyResponse(derive_key_response) => {
                write!(f, "DeriveKeyResponse({derive_key_response:?})")
            }
            Self::Certify(certify) => write!(f, "Certify({certify:?})"),
            Self::CertifyResponse(certify_response) => {
                write!(f, "CertifyResponse({certify_response:?})")
            }
            Self::ReCertify(recertify) => write!(f, "ReCertify({recertify:?})"),
            Self::ReCertifyResponse(recertify_response) => {
                write!(f, "ReCertifyResponse({recertify_response:?})")
            }
            Self::Locate(locate) => write!(f, "Locate({locate:?})"),
            Self::LocateResponse(locate_response) => {
                write!(f, "LocateResponse({locate_response:?})")
            }
            Self::Check(check) => write!(f, "Check({check:?})"),
            Self::CheckResponse(check_response) => {
                write!(f, "CheckResponse({check_response:?})")
            }
            Self::Get(get) => write!(f, "Get({get:?})"),
            Self::GetResponse(get_response) => {
                write!(f, "GetResponse({get_response:?})")
            }
            Self::GetAttributes(get_attrs) => write!(f, "GetAttributes({get_attrs:?})"),
            Self::GetAttributesResponse(get_attrs_resp) => {
                write!(f, "GetAttributesResponse({get_attrs_resp:?})")
            } // ... continue implementing Display for remaining operations...
            Self::GetAttributeList(get_attr_list) => {
                write!(f, "GetAttributeList({get_attr_list:?})")
            }
            Self::GetAttributeListResponse(get_attr_list_resp) => {
                write!(f, "GetAttributeListResponse({get_attr_list_resp:?})")
            }
            Self::AddAttribute(add_attr) => write!(f, "AddAttribute({add_attr:?})"),
            Self::AddAttributeResponse(add_attr_resp) => {
                write!(f, "AddAttributeResponse({add_attr_resp:?})")
            }
            Self::ModifyAttribute(modify_attr) => write!(f, "ModifyAttribute({modify_attr:?})"),
            Self::ModifyAttributeResponse(modify_attr_resp) => {
                write!(f, "ModifyAttributeResponse({modify_attr_resp:?})")
            }
            Self::DeleteAttribute(delete_attr) => write!(f, "DeleteAttribute({delete_attr:?})"),
            Self::DeleteAttributeResponse(delete_attr_resp) => {
                write!(f, "DeleteAttributeResponse({delete_attr_resp:?})")
            }
            Self::ObtainLease(obtain_lease) => write!(f, "ObtainLease({obtain_lease:?})"),
            Self::ObtainLeaseResponse(obtain_lease_resp) => {
                write!(f, "ObtainLeaseResponse({obtain_lease_resp:?})")
            }
        }
    }
}
