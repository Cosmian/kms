use std::fmt;

use serde::{
    de::{self, MapAccess, Visitor},
    Deserialize, Serialize,
};
use strum_macros::Display;

use super::{
    kmip_data_structures::KeyWrappingSpecification,
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        AttributeReference, Attributes, CertificateRequestType, CryptographicParameters,
        KeyCompressionType, KeyFormatType, KeyWrapType, ObjectGroupMember, ProtectionStorageMasks,
        RevocationReason, StorageStatusMask, UniqueIdentifier,
    },
};
use crate::error::KmipError;

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Display, Debug, Eq, PartialEq)]
pub enum ErrorReason {
    Item_Not_Found = 0x0000_0001,
    Response_Too_Large = 0x0000_0002,
    Authentication_Not_Successful = 0x0000_0003,
    Invalid_Message = 0x0000_0004,
    Operation_Not_Supported = 0x0000_0005,
    Missing_Data = 0x0000_0006,
    Invalid_Field = 0x0000_0007,
    Feature_Not_Supported = 0x0000_0008,
    Operation_Canceled_By_Requester = 0x0000_0009,
    Cryptographic_Failure = 0x0000_000A,
    Permission_Denied = 0x0000_000C,
    Object_Archived = 0x0000_000D,
    Application_Namespace_Not_Supported = 0x0000_000F,
    Key_Format_Type_Not_Supported = 0x0000_0010,
    Key_Compression_Type_Not_Supported = 0x0000_0011,
    Encoding_Option_Error = 0x0000_0012,
    Key_Value_Not_Present = 0x0000_0013,
    Attestation_Required = 0x0000_0014,
    Attestation_Failed = 0x0000_0015,
    Sensitive = 0x0000_0016,
    Not_Extractable = 0x0000_0017,
    Object_Already_Exists = 0x0000_0018,
    Invalid_Ticket = 0x0000_0019,
    Usage_Limit_Exceeded = 0x0000_001A,
    Numeric_Range = 0x0000_001B,
    Invalid_Data_Type = 0x0000_001C,
    Read_Only_Attribute = 0x0000_001D,
    Multi_Valued_Attribute = 0x0000_001E,
    Unsupported_Attribute = 0x0000_001F,
    Attribute_Instance_Not_Found = 0x0000_0020,
    Attribute_Not_Found = 0x0000_0021,
    Attribute_Read_Only = 0x0000_0022,
    Attribute_Single_Valued = 0x0000_0023,
    Bad_Cryptographic_Parameters = 0x0000_0024,
    Bad_Password = 0x0000_0025,
    Codec_Error = 0x0000_0026,
    Illegal_Object_Type = 0x0000_0028,
    Incompatible_Cryptographic_Usage_Mask = 0x0000_0029,
    Internal_Server_Error = 0x0000_002A,
    Invalid_Asynchronous_Correlation_Value = 0x0000_002B,
    Invalid_Attribute = 0x0000_002C,
    Invalid_Attribute_Value = 0x0000_002D,
    Invalid_Correlation_Value = 0x0000_002E,
    Invalid_CSR = 0x0000_002F,
    Invalid_Object_Type = 0x0000_0030,
    Key_Wrap_Type_Not_Supported = 0x0000_0032,
    Missing_Initialization_Vector = 0x0000_0034,
    Non_Unique_Name_Attribute = 0x0000_0035,
    Object_Destroyed = 0x0000_0036,
    Object_Not_Found = 0x0000_0037,
    Not_Authorised = 0x0000_0039,
    Server_Limit_Exceeded = 0x0000_003A,
    Unknown_Enumeration = 0x0000_003B,
    Unknown_Message_Extension = 0x0000_003C,
    Unknown_Tag = 0x0000_003D,
    Unsupported_Cryptographic_Parameters = 0x0000_003E,
    Unsupported_Protocol_Version = 0x0000_003F,
    Wrapping_Object_Archived = 0x0000_0040,
    Wrapping_Object_Destroyed = 0x0000_0041,
    Wrapping_Object_Not_Found = 0x0000_0042,
    Wrong_Key_Lifecycle_State = 0x0000_0043,
    Protection_Storage_Unavailable = 0x0000_0044,
    PKCS_11_Codec_Error = 0x0000_0045,
    PKCS_11_Invalid_Function = 0x0000_0046,
    PKCS_11_Invalid_Interface = 0x0000_0047,
    Private_Protection_Storage_Unavailable = 0x0000_0048,
    Public_Protection_Storage_Unavailable = 0x0000_0049,
    General_Failure = 0x0000_0100,
}

/// This operation requests the server to Import a Managed Object specified by
/// its Unique Identifier. The request specifies the object being imported and
/// all the attributes to be assigned to the object. The attribute rules for
/// each attribute for "Initially set by" and "When implicitly set" SHALL NOT be
/// enforced as all attributes MUST be set to the supplied values rather than
/// any server generated values.
///
/// The response contains the Unique Identifier provided in the request or
/// assigned by the server. The server SHALL copy the Unique Identifier returned
/// by this operations into the ID Placeholder variable.
/// `https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115657`
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Import {
    /// The Unique Identifier of the object to be imported
    pub unique_identifier: UniqueIdentifier,
    /// Determines the type of object being imported.
    pub object_type: ObjectType,
    /// A Boolean.  If specified and true then any existing object with the same
    /// Unique Identifier SHALL be replaced by this operation. If absent or
    /// false and an object exists with the same Unique Identifier then an error
    /// SHALL be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replace_existing: Option<bool>,
    /// If Not Wrapped then the server SHALL unwrap the object before storing
    /// it, and return an error if the wrapping key is not available.
    /// Otherwise the server SHALL store the object as provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrap_type: Option<KeyWrapType>,
    /// Specifies object attributes to be associated with the new object.
    pub attributes: Attributes,
    /// The object being imported. The object and attributes MAY be wrapped.
    pub object: Object,
}

/// Deserialization needs to be handwritten because the
/// included `Object` may be incorrectly deserialized to a `PrivateKey`
/// when it is a `PublicKey` (as it is "untagged" - see `postfix()`).
/// It is a lot of code for a simple post fix but well...
impl<'de> Deserialize<'de> for Import {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)] //, rename_all = "snake_case"
        enum Field {
            UniqueIdentifier,
            ObjectType,
            ReplaceExisting,
            KeyWrapType,
            Attributes,
            Object,
        }

        struct ImportVisitor;

        impl<'de> Visitor<'de> for ImportVisitor {
            type Value = Import;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Import")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut unique_identifier: Option<UniqueIdentifier> = None;
                let mut object_type: Option<ObjectType> = None;
                let mut replace_existing: Option<bool> = None;
                let mut key_wrap_type: Option<KeyWrapType> = None;
                let mut attributes: Option<Attributes> = None;
                let mut object: Option<Object> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::UniqueIdentifier => {
                            if unique_identifier.is_some() {
                                return Err(de::Error::duplicate_field("unique_identifier"))
                            }
                            unique_identifier = Some(map.next_value()?);
                        }
                        Field::ObjectType => {
                            if object_type.is_some() {
                                return Err(de::Error::duplicate_field("object_type"))
                            }
                            object_type = Some(map.next_value()?);
                        }
                        Field::ReplaceExisting => {
                            if replace_existing.is_some() {
                                return Err(de::Error::duplicate_field("replace_existing"))
                            }
                            replace_existing = Some(map.next_value()?);
                        }
                        Field::KeyWrapType => {
                            if key_wrap_type.is_some() {
                                return Err(de::Error::duplicate_field("key_wrap_type"))
                            }
                            key_wrap_type = Some(map.next_value()?);
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(de::Error::duplicate_field("attributes"))
                            }
                            attributes = Some(map.next_value()?);
                        }
                        Field::Object => {
                            if object.is_some() {
                                return Err(de::Error::duplicate_field("object"))
                            }
                            object = Some(map.next_value()?);
                        }
                    }
                }
                let unique_identifier = unique_identifier
                    .ok_or_else(|| de::Error::missing_field("unique_identifier"))?;
                let object_type =
                    object_type.ok_or_else(|| de::Error::missing_field("object_type"))?;
                let attributes =
                    attributes.ok_or_else(|| de::Error::missing_field("attributes"))?;
                let object = object.ok_or_else(|| de::Error::missing_field("object"))?;
                // all this code .... to be able to insert that line....
                let object = Object::post_fix(object_type, object);
                Ok(Import {
                    unique_identifier,
                    object_type,
                    replace_existing,
                    key_wrap_type,
                    attributes,
                    object,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "unique_identifier",
            "object_type",
            "replace_existing",
            "key_wrap_type",
            "attributes",
            "object",
            "key_wrapping_data",
        ];
        deserializer.deserialize_struct("Import", FIELDS, ImportVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ImportResponse {
    /// The Unique Identifier of the newly imported object.
    pub unique_identifier: UniqueIdentifier,
}

/// This request is used to generate a Certificate object for a public key. This
/// request supports the certification of a new public key, as well as the
/// certification of a public key that has already been certified (i.e.,
/// certificate update). Only a single certificate SHALL be requested at a time.
///
/// The Certificate Request object MAY be omitted, in which case the public key
/// for which a Certificate object is generated SHALL be specified by its Unique
/// Identifier only. If the Certificate Request Type and the Certificate Request
/// objects are omitted from the request, then the Certificate Type SHALL be
/// specified using the Attributes object.
///
/// The Certificate Request is passed as
/// a Byte String, which allows multiple certificate request types for X.509
/// certificates (e.g., PKCS#10, PEM, etc.) to be submitted to the server.
///
/// The generated Certificate object whose Unique Identifier is returned MAY be
/// obtained by the client via a Get operation in the same batch, using the ID
/// Placeholder mechanism. For the public key, the server SHALL create a Link
/// attribute of Link Type Certificate pointing to the generated certificate.
/// For the generated certificate, the server SHALL create a Link attribute of
/// Link Type Public Key pointing to the Public Key.
///
/// The server SHALL copy the
/// Unique Identifier of the generated certificate returned by this operation
/// into the ID Placeholder variable. If the information in the Certificate
/// Request conflicts with the attributes specified in the Attributes, then the
/// information in the Certificate Request takes precedence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Certify {
    // The Unique Identifier of the Public Key or the Certificate Request being certified. If
    // omitted and Certificate Request is not present, then the ID Placeholder value is used by the
    // server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// An Enumeration object specifying the type of certificate request. It is
    /// REQUIRED if the Certificate Request is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_request_type: Option<CertificateRequestType>,
    /// A Byte String object with the certificate request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_request_value: Option<Vec<u8>>,
    /// Specifies desired attributes to be associated with the new object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,
    /// Specifies all permissible Protection Storage Mask selections for the new
    /// object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_storage_masks: Option<ProtectionStorageMasks>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CertifyResponse {
    /// The Unique Identifier of the newly created object.
    pub unique_identifier: UniqueIdentifier,
}

/// This operation requests the server to generate a new symmetric key or
/// generate Secret Data as aManaged Cryptographic Object. The request contains
/// information about the type of object being created, and some of the
/// attributes to be assigned to the object (e.g., Cryptographic Algorithm,
/// Cryptographic Length, etc.). The response contains the Unique Identifier of
/// the created object. The server SHALL copy the Unique Identifier returned by
/// this operation into the ID Placeholder variable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Create {
    /// Determines the type of object to be created.
    pub object_type: ObjectType,
    /// Specifies desired attributes to be associated with the new object.
    pub attributes: Attributes,
    /// Specifies all permissible Protection Storage Mask selections for the new
    /// object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_storage_masks: Option<ProtectionStorageMasks>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateResponse {
    /// Type of object created.
    pub object_type: ObjectType,
    /// The Unique Identifier of the newly created object.
    pub unique_identifier: UniqueIdentifier,
}

/// This operation requests the server to generate a new public/private key pair
/// and register the two corresponding new Managed Cryptographic Object
/// The request contains attributes to be assigned to the objects (e.g.,
/// Cryptographic Algorithm, Cryptographic Length, etc.). Attributes MAY be
/// specified for both keys at the same time by specifying a Common Attributes
/// object in the request. Attributes not common to both keys (e.g., Name,
/// Cryptographic Usage Mask) MAY be specified using the Private Key Attributes
/// and Public Key Attributes objects in the request, which take precedence over
/// the Common Attributes object. For the Private Key, the server SHALL create a
/// Link attribute of Link Type Public Key pointing to the Public Key.
/// For the Public Key, the server SHALL create a Link attribute of Link Type
/// Private Key pointing to the Private Key. The response contains the Unique
/// Identifiers of both created objects. The ID Placeholder value SHALL be set
/// to the Unique Identifier of the Private Key
#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeyPair {
    /// Specifies desired attributes to be associated with the new object that
    /// apply to both the Private and Public Key Objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_attributes: Option<Attributes>,
    /// Specifies the attributes to be associated with the new object that apply
    /// to the Private Key Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_attributes: Option<Attributes>,
    /// Specifies the attributes to be associated with the new object that apply
    /// to the Public Key Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_attributes: Option<Attributes>,
    /// Specifies all ProtectionStorage Mask selections that are permissible for
    /// the new Private Key and Public Key objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_protection_storage_masks: Option<ProtectionStorageMasks>,
    /// Specifies all ProtectionStorage Mask selections that are permissible for
    /// the new Private Key object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_protection_storage_masks: Option<ProtectionStorageMasks>,
    /// Specifies all ProtectionStorage Mask selections that are permissible for
    /// the new PublicKey object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_protection_storage_masks: Option<ProtectionStorageMasks>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeyPairResponse {
    /// The Unique Identifier of the newly created private key object.
    pub private_key_unique_identifier: UniqueIdentifier,
    /// The Unique Identifier of the newly created public key object.
    pub public_key_unique_identifier: UniqueIdentifier,
}

/// This operation requests that the server returns a Managed Object specified by its Unique Identifier,
/// together with its attributes.
/// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification
/// SHALL have the same semantics as for the Get operation.
/// If the Managed Object has been Destroyed then the key material for the specified managed object
/// SHALL not be returned in the response.
/// The server SHALL copy the Unique Identifier returned by this operations
/// into the ID Placeholder variable.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Export {
    /// Determines the object being requested. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Determines the key format type to be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
    /// Determines the Key Wrap Type of the returned key value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrap_type: Option<KeyWrapType>,
    /// Determines the compression method for elliptic curve public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    /// Specifies keys and other information for wrapping the returned object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

impl Export {
    /// Create a `ExportRequest` for an Object
    /// # Arguments
    /// * `uid` - The Unique Identifier of the object to be retrieved
    /// * `unwrap` - If true, the object is returned unwrapped
    /// * `key_wrapping_data` - If unwrap is false, this is the key wrapping data to be used
    /// # Returns
    /// A `ExportRequest`
    /// # Example
    /// ```
    /// use cosmian_kmip::kmip::kmip_operations::Export;
    ///
    /// let export_request = Export::new("1234", false, None);
    /// ```
    #[must_use]
    pub fn new(
        uid: &str,
        unwrap: bool,
        key_wrapping_specification: Option<KeyWrappingSpecification>,
    ) -> Self {
        let key_wrap_type = if unwrap {
            // ignore key_wrapping_data if unwrap is true
            Some(KeyWrapType::NotWrapped)
        } else if key_wrapping_specification.is_none() {
            Some(KeyWrapType::AsRegistered)
        } else {
            None
        };

        Self {
            unique_identifier: Some(uid.to_string()),
            key_format_type: None,
            key_wrap_type,
            key_compression_type: None,
            key_wrapping_specification,
        }
    }
}

impl From<String> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: String) -> Self {
        Self::new(&uid, false, None)
    }
}
impl From<&String> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: &String) -> Self {
        Self::new(uid, false, None)
    }
}
impl From<&str> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: &str) -> Self {
        Self::new(uid, false, None)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExportResponse {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub attributes: Attributes,
    pub object: Object,
}

/// This operation requests that the server returns the Managed Object specified by its Unique Identifier.
///
/// Only a single object is returned. The response contains the Unique Identifier of the object, along with the
/// object itself, which MAY be wrapped using a wrapping key as specified in the request.
///
/// The following key format capabilities SHALL be assumed by the client; restrictions apply when the client
/// requests the server to return an object in a particular format:
///
/// · If a client registered a key in a given format, the server SHALL be able to return the key during the
/// Get operation in the same format that was used when the key was registered.
///
/// · Any other format conversion MAY be supported by the server.
///
/// If Key Format Type is specified to be PKCS#12, then the response payload shall be a PKCS#12 container as
/// specified by RFC7292. The Unique Identifier shall be either that of a private key or certificate to be
/// included in the response. The container shall be protected using the Secret Data object specified via the
/// private key or certificate's PKCS#12 Password Link. The current certificate chain shall also be included as
/// determined by using the private key's Public Key link to get the corresponding public key (where relevant),
/// and then using that public key's PKCS#12 Certificate Link to get the base certificate, and then using each
/// certificate's Certificate Link to build the certificate chain. It is an error if there is more than one valid
/// certificate chain.
///
/// Specifying a value of Not Wrapped ensures that the server returns the unwrapped key value.
/// A value of As Registered can be used to retrieve the key value as it was provided in the Register operation.
/// In the latter case, the wrapping key need not be known to the server.
///
/// If no Key Wrap Type is provided, then the server may choose to return the key either wrapped or unwrapped.
/// A Get operation may use both a Key Wrap Type and a Wrapping Key Specification,
/// in which case the Key Wrap Type is processed as if there was no Wrapping Key Specification,
/// and the result is then wrapped as specified.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Get {
    /// Determines the object being requested. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Determines the key format type to be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
    /// Determines the Key Wrap Type of the returned key value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrap_type: Option<KeyWrapType>,
    /// Determines the compression method for elliptic curve public keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_compression_type: Option<KeyCompressionType>,
    /// Specifies keys and other information for wrapping the returned object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_wrapping_specification: Option<KeyWrappingSpecification>,
}

impl Get {
    /// Create a `GetRequest` for an Object
    /// # Arguments
    /// * `uid` - The Unique Identifier of the object to be retrieved
    /// * `unwrap` - If true, the object is returned unwrapped
    /// * `key_wrapping_data` - If unwrap is false, this is the key wrapping data to be used
    /// # Returns
    /// A `GetRequest`
    /// # Example
    /// ```
    /// use cosmian_kmip::kmip::kmip_operations::Get;
    ///
    /// let get_request = Get::new("1234", false, None);
    /// ```
    #[must_use]
    pub fn new(
        uid: &str,
        unwrap: bool,
        key_wrapping_specification: Option<KeyWrappingSpecification>,
    ) -> Self {
        let key_wrap_type = if unwrap {
            // ignore key_wrapping_data if unwrap is true
            Some(KeyWrapType::NotWrapped)
        } else if key_wrapping_specification.is_none() {
            Some(KeyWrapType::AsRegistered)
        } else {
            None
        };

        Self {
            unique_identifier: Some(uid.to_string()),
            key_format_type: None,
            key_wrap_type,
            key_compression_type: None,
            key_wrapping_specification,
        }
    }
}

impl From<String> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: String) -> Self {
        Self::new(&uid, false, None)
    }
}
impl From<&String> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: &String) -> Self {
        Self::new(uid, false, None)
    }
}
impl From<&str> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: &str) -> Self {
        Self::new(uid, false, None)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributes {
    /// Determines the object whose attributes
    /// are being requested. If omitted, then
    /// the ID Placeholder value is used by the
    /// server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Specifies an attribute associated with
    /// the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute_references: Option<Vec<AttributeReference>>,
}
impl From<String> for GetAttributes {
    fn from(uid: String) -> Self {
        Self {
            unique_identifier: Some(uid),
            attribute_references: None,
        }
    }
}
impl From<&String> for GetAttributes {
    fn from(uid: &String) -> Self {
        Self::from(uid.clone())
    }
}
impl From<&str> for GetAttributes {
    fn from(uid: &str) -> Self {
        Self::from(uid.to_owned())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributesResponse {
    /// The Unique Identifier of the object
    pub unique_identifier: UniqueIdentifier,
    /// Attributes
    pub attributes: Attributes,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Encrypt {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that is the key to
    /// use for the encryption operation. If
    /// omitted, then the ID Placeholder value
    /// SHALL be used by the server as the
    /// Unique Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// The Cryptographic Parameters (Block
    /// Cipher Mode, Padding Method,
    /// RandomIV) corresponding to the
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
    /// The data to be encrypted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// The initialization vector, counter or
    /// nonce to be used (where appropriate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_counter_nonce: Option<Vec<u8>>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptResponse {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that was the key
    /// used for the encryption operation.
    pub unique_identifier: UniqueIdentifier,
    /// The encrypted data (as a Byte String).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// The value used if the Cryptographic
    /// Parameters specified Random IV and
    /// the IV/Counter/Nonce value was not
    /// provided in the request and the
    /// algorithm requires the provision of an
    /// IV/Counter/Nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_counter_nonce: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value
    /// to be provided in subsequent calls to
    /// this operation for performing
    /// cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
    /// Specifies the tag that will be needed to
    /// authenticate the decrypted data (and
    /// any "additional data"). Only returned on
    /// completion of the encryption of the last
    /// of the plaintext by an authenticated
    /// encryption cipher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_tag: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Decrypt {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that is the key to
    /// use for the decryption operation. If
    /// omitted, then the ID Placeholder value
    /// SHALL be used by the server as the
    /// Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// The Cryptographic Parameters (Block
    /// Cipher Mode, Padding Method)
    /// corresponding to the particular
    /// decryption method requested.
    /// If there are no Cryptographic
    /// Parameters associated with the
    /// Managed Cryptographic Object and
    /// the algorithm requires parameters then
    /// the operation SHALL return with a
    /// Result Status of Operation Failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
    /// The data to be decrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// The initialization vector, counter or
    /// nonce to be used (where appropriate)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_counter_nonce: Option<Vec<u8>>,
    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,
    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
    /// Additional data to be authenticated via
    /// the Authenticated Encryption Tag. If
    /// supplied in multi-part decryption, this
    /// data MUST be supplied on the initial
    /// Decrypt request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_additional_data: Option<Vec<u8>>,
    /// Specifies the tag that will be needed to
    /// authenticate the decrypted data and
    /// the additional authenticated data. If
    /// supplied in multi-part decryption, this
    /// data MUST be supplied on the initial
    /// Decrypt request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_encryption_tag: Option<Vec<u8>>,
}

/// When decrypting data with Cover Crypt we can have some
/// additional metadata stored inside the header and encrypted
/// with de DEM. We need to return these data to the user but
/// the KMIP protocol do not provide a way to do it. So we prepend
/// the decrypted bytes with the decrypted additional metadata.
/// This struct is not useful (and shouldn't be use) if the user
/// ask to encrypt with something else than Cover Crypt (for example an AES encrypt.)
/// See also `DataToEncrypt` struct.
/// The binary format of this struct is:
/// 1. LEB128 unsigned length of the metadata
/// 2. metadata decrypted bytes
/// 3. data decrypted
pub struct DecryptedData {
    pub metadata: Vec<u8>,
    pub plaintext: Vec<u8>,
}

impl TryInto<Vec<u8>> for DecryptedData {
    type Error = KmipError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut result = vec![];
        leb128::write::unsigned(&mut result, self.metadata.len() as u64).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                format!(
                    "Cannot put the length of the additional metadata {} into the response.",
                    self.metadata.len()
                ),
            )
        })?;
        result.extend_from_slice(&self.metadata);
        result.extend_from_slice(&self.plaintext);

        Ok(result)
    }
}

impl TryFrom<&[u8]> for DecryptedData {
    type Error = KmipError;

    fn try_from(mut bytes: &[u8]) -> Result<Self, Self::Error> {
        let size_of_metadata = leb128::read::unsigned(&mut bytes).map_err(|_| {
            KmipError::KmipError(
                ErrorReason::Invalid_Message,
                "Expect a LEB128 encoded number (size of the metadata) at the beginning of the \
                 data to encrypt."
                    .to_owned(),
            )
        })? as usize;

        let metadata = bytes
            .take(..size_of_metadata)
            .ok_or_else(|| {
                KmipError::KmipError(
                    ErrorReason::Invalid_Message,
                    format!(
                        "After the LEB128 encoded size of access policy in bytes of \
                         {size_of_metadata}, expecting to be able to read that many bytes but the \
                         data to encrypt length is {}.",
                        bytes.len()
                    ),
                )
            })?
            .to_vec();

        // Remaining is the decrypted plaintext
        let plaintext = bytes.to_vec();

        Ok(Self {
            metadata,
            plaintext,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DecryptResponse {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that was the key
    /// used for the decryption operation.
    pub unique_identifier: UniqueIdentifier,
    /// The decrypted data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value
    /// to be provided in subsequent calls to
    /// this operation for performing
    /// cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
}

/// This operation requests that the server search for one or more Managed
/// Objects, depending on the attributes specified in the request. All attributes
/// are allowed to be used. The request MAY contain a Maximum Items field, which
/// specifies the maximum number of objects to be returned. If the Maximum Items
/// field is omitted, then the server MAY return all objects matched, or MAY
/// impose an internal maximum limit due to resource limitations.
///
/// The request MAY contain an Offset Items field, which specifies the number of
/// objects to skip that satisfy the identification criteria specified in the
/// request. An Offset Items field of 0 is the same as omitting the Offset Items
/// field. If both Offset Items and Maximum Items are specified in the request,
/// the server skips Offset Items objects and returns up to Maximum Items
/// objects.
///
/// If more than one object satisfies the identification criteria specified in
/// the request, then the response MAY contain Unique Identifiers for multiple
/// Managed Objects. Responses containing Unique Identifiers for multiple objects
/// SHALL be returned in descending order of object creation (most recently
/// created object first). Returned objects SHALL match all of the attributes in
/// the request. If no objects match, then an empty response payload is returned.
/// If no attribute is specified in the request, any object SHALL be deemed to
/// match the Locate request. The response MAY include Located Items which is the
/// count of all objects that satisfy the identification criteria.
///
/// The server returns a list of Unique Identifiers of the found objects, which
/// then MAY be retrieved using the Get operation. If the objects are archived,
/// then the Recover and Get operations are REQUIRED to be used to obtain those
/// objects. If a single Unique Identifier is returned to the client, then the
/// server SHALL copy the Unique Identifier returned by this operation into the
/// ID Placeholder variable. If the Locate operation matches more than one
/// object, and the Maximum Items value is omitted in the request, or is set to a
/// value larger than one, then the server SHALL empty the ID Placeholder,
/// causing any subsequent operations that are batched with the Locate, and which
/// do not specify a Unique Identifier explicitly, to fail. This ensures that
/// these batched operations SHALL proceed only if a single object is returned by
/// Locate.
///
/// The Date attributes in the Locate request (e.g., Initial Date, Activation
/// Date, etc.) are used to specify a time or a time range for the search. If a
/// single instance of a given Date attribute is used in the request (e.g., the
/// Activation Date), then objects with the same Date attribute are considered to
/// be matching candidate objects. If two instances of the same Date attribute
/// are used (i.e., with two different values specifying a range), then objects
/// for which the Date attribute is inside or at a limit of the range are
/// considered to be matching candidate objects. If a Date attribute is set to
/// its largest possible value, then it is equivalent to an undefined attribute.
///
/// When the Cryptographic Usage Mask attribute is specified in the request,
/// candidate objects are compared against this field via an operation that
/// consists of a logical AND of the requested mask with the mask in the
/// candidate object, and then a comparison of the resulting value with the
/// requested mask. For example, if the request contains a mask value of
/// 10001100010000, and a candidate object mask contains 10000100010000, then the
/// logical AND of the two masks is 10000100010000, which is compared against the
/// mask value in the request (10001100010000) and the match fails. This means
/// that a matching candidate object has all of the bits set in its mask that are
/// set in the requested mask, but MAY have additional bits set.
///
/// When the Usage Limits attribute is specified in the request, matching
/// candidate objects SHALL have a Usage Limits Count and Usage Limits Total
/// equal to or larger than the values specified in the request.
///
/// When an attribute that is defined as a structure is specified, all of the
/// structure fields are not REQUIRED to be specified. For instance, for the Link
/// attribute, if the Linked Object Identifier value is specified without the
/// Link Type value, then matching candidate objects have the Linked Object
/// Identifier as specified, irrespective of their Link Type.
///
/// When the Object Group attribute and the Object Group Member flag are
/// specified in the request, and the value specified for Object Group Member is
/// 'Group Member Fresh', matching candidate objects SHALL be fresh objects from
/// the object group. If there are no more fresh objects in the group, the server
/// MAY choose to generate a new object on-the-fly, based on server policy. If
/// the value specified for Object Group Member is 'Group Member Default', the
/// server locates the default object as defined by server policy.
///
/// The Storage Status Mask field is used to indicate whether on-line objects
/// (not archived or destroyed), archived objects, destroyed objects or any
/// combination of the above are to be searched.The server SHALL NOT return
/// unique identifiers for objects that are destroyed unless the Storage Status
/// Mask field includes the Destroyed Storage indicator. The server SHALL NOT
/// return unique identifiers for objects that are archived unless the Storage
/// Status Mask field includes the Archived Storage indicator.
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Locate {
    /// An Integer object that indicates the maximum number of object
    /// identifiers the server MAY return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_items: Option<i32>,
    /// An Integer object that indicates the number of object identifiers to
    /// skip that satisfy the identification criteria specified in the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset_items: Option<i32>,
    /// An Integer object (used as a bit mask) that indicates whether only
    /// on-line objects, only archived objects, destroyed objects or any
    /// combination of these, are to be searched. If omitted, then only on-line
    /// objects SHALL be returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_status_mask: Option<StorageStatusMask>,
    /// An Enumeration object that indicates the object group member type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_group_member: Option<ObjectGroupMember>,
    /// Specifies an attribute and its value(s) that are REQUIRED to match those
    /// in a candidate object (according to the matching rules defined above).
    pub attributes: Attributes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocateResponse {
    /// An Integer object that indicates the number of object identifiers that
    /// satisfy the identification criteria specified in the request. A server
    /// MAY elect to omit this value from the Response if it is unable or
    /// unwilling to determine the total count of matched items.
    // A server MAY elect to return the Located Items value even if Offset Items is not present in
    // the Request.
    #[serde(skip_serializing_if = "Option::is_none", rename = "LocatedItems")]
    pub located_items: Option<i32>,
    /// The Unique Identifier of the located objects.
    #[serde(skip_serializing_if = "Option::is_none", rename = "UniqueIdentifier")]
    pub unique_identifiers: Option<Vec<UniqueIdentifier>>,
}

/// This operation requests the server to revoke a Managed Cryptographic Object
/// or an Opaque Object. The request contains a reason for the revocation (e.g.,
/// "key compromise", "cessation of operation", etc.). The operation has one of
/// two effects.
///
/// If the revocation reason is "key compromise" or "CA compromise",
/// then the object is placed into the "compromised" state; the Date is set to
/// the current date and time; and the Compromise Occurrence Date is set to the
/// value (if provided) in the Revoke request and if a value is not provided in
/// the Revoke request then Compromise Occurrence Date SHOULD be set to the
/// Initial Date for the object.
///
/// If the revocation reason is neither "key
/// compromise" nor "CA compromise", the object is placed into the "deactivated"
/// state, and the Deactivation Date is set to the current date and time.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Revoke {
    /// Determines the object being revoked. If omitted, then the ID Placeholder
    /// value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Specifies the reason for revocation.
    pub revocation_reason: RevocationReason,
    /// SHOULD be specified if the Revocation Reason is 'key compromise' or 'CA
    /// compromise' and SHALL NOT be specified for other Revocation Reason
    /// enumerations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_occurrence_date: Option<u64>, // epoch millis
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RevokeResponse {
    /// The Unique Identifier of the object.
    pub unique_identifier: UniqueIdentifier,
}

/// This request is used to generate a replacement key pair for an existing
/// public/private key pair. It is analogous to the Create Key Pair operation,
/// except that attributes of the replacement key pair are copied from the
/// existing key pair, with the exception of the attributes listed in Re-key Key
/// Pair Attribute Requirements tor.
///
/// As the replacement of the key pair takes over the name attribute for the
/// existing public/private key pair, Re-key Key Pair SHOULD only be performed
/// once on a given key pair.
///
/// For both the existing public key and private key, the server SHALL create a
/// Link attribute of Link Type Replacement Key pointing to the replacement
/// public and private key, respectively. For both the replacement public and
/// private key, the server SHALL create a Link attribute of Link Type Replaced
/// Key pointing to the existing public and private key, respectively.
///
/// The server SHALL copy the Private Key Unique Identifier of the replacement
/// private key returned by this operation into the ID Placeholder variable.
///
/// An Offset MAY be used to indicate the difference between the Initial Date and
/// the Activation Date of the replacement key pair. If no Offset is specified,
/// the Activation Date and Deactivation Date values are copied from the existing
/// key pair. If Offset is set and dates exist for the existing key pair, then
/// the dates of the replacement key pair SHALL be set based on the dates of the
/// existing key pair as follows
#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyKeyPair {
    // Determines the existing Asymmetric key pair to be re-keyed.  If omitted, then the ID
    // Placeholder is substituted by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_unique_identifier: Option<UniqueIdentifier>,

    // An Interval object indicating the difference between the Initial Date and the Activation
    // Date of the replacement key pair to be created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,

    // Specifies desired attributes that apply to both the Private and Public Key Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_attributes: Option<Attributes>,

    // Specifies attributes that apply to the Private Key Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_attributes: Option<Attributes>,

    // Specifies attributes that apply to the Public Key Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_attributes: Option<Attributes>,

    // Specifies all Protection Storage Mask selections that are permissible for the new Private
    // Key and new Public Key objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_protection_storage_masks: Option<ProtectionStorageMasks>,

    // Specifies all Protection
    // Storage Mask selections that are permissible for the new Private Key object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_protection_storage_masks: Option<ProtectionStorageMasks>,

    // Specifies all Protection
    // Storage Mask selections that are permissible for the new Public Key object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_protection_storage_masks: Option<ProtectionStorageMasks>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyKeyPairResponse {
    // The Unique Identifier of the newly created replacement Private Key object.
    pub private_key_unique_identifier: UniqueIdentifier,
    // The Unique Identifier of the newly created replacement Public Key object.}
    pub public_key_unique_identifier: UniqueIdentifier,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Destroy {
    /// Determines the object being destroyed. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DestroyResponse {
    /// The Unique Identifier of the object.
    pub unique_identifier: UniqueIdentifier,
}
