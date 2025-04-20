use std::{
    fmt::{self, Debug, Display, Formatter},
    ops::Not,
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{
    kmip_attributes::{Attribute, Attributes},
    kmip_data_structures::{
        CapabilityInformation, DefaultsInformation, DerivationParameters, ExtensionInformation,
        KeyWrappingSpecification, ServerInformation,
    },
    kmip_objects::{Object, ObjectType},
    kmip_types::{
        AttributeReference, CertificateRequestType, CryptographicParameters, DerivationMethod,
        KeyCompressionType, KeyFormatType, ObjectGroupMember, OperationEnumeration,
        ProtectionStorageMasks, QueryFunction, StorageStatusMask, UniqueIdentifier,
        ValidityIndicator,
    },
};
use crate::{
    Deserializer, Serializer,
    error::KmipError,
    kmip_0::{
        kmip_data_structures::ValidationInformation,
        kmip_operations::{DiscoverVersions, DiscoverVersionsResponse},
        kmip_types::{AttestationType, Direction, KeyWrapType, RevocationReason},
    },
    kmip_2_1::kmip_data_structures::{ProfileInformation, RNGParameters},
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Operation {
    AddAttribute(AddAttribute),
    AddAttributeResponse(AddAttributeResponse),
    Certify(Certify),
    CertifyResponse(CertifyResponse),
    Create(Create),
    CreateResponse(CreateResponse),
    CreateKeyPair(CreateKeyPair),
    CreateKeyPairResponse(CreateKeyPairResponse),
    DiscoverVersions(DiscoverVersions),
    DiscoverVersionsResponse(DiscoverVersionsResponse),
    Decrypt(Decrypt),
    DecryptResponse(DecryptResponse),
    DeleteAttribute(DeleteAttribute),
    DeleteAttributeResponse(DeleteAttributeResponse),
    Destroy(Destroy),
    DestroyResponse(DestroyResponse),
    Encrypt(Encrypt),
    EncryptResponse(EncryptResponse),
    Export(Export),
    ExportResponse(ExportResponse),
    Get(Get),
    GetResponse(GetResponse),
    GetAttributes(GetAttributes),
    GetAttributesResponse(GetAttributesResponse),
    Hash(Hash),
    HashResponse(HashResponse),
    Import(Import),
    ImportResponse(ImportResponse),
    Locate(Locate),
    LocateResponse(LocateResponse),
    Mac(Mac),
    MacResponse(MacResponse),
    Query(Query),
    QueryResponse(QueryResponse),
    Revoke(Revoke),
    RevokeResponse(RevokeResponse),
    ReKey(ReKey),
    ReKeyResponse(ReKeyResponse),
    ReKeyKeyPair(ReKeyKeyPair),
    ReKeyKeyPairResponse(ReKeyKeyPairResponse),
    SetAttribute(SetAttribute),
    SetAttributeResponse(SetAttributeResponse),
    Validate(Validate),
    ValidateResponse(ValidateResponse),
}

impl Operation {
    #[must_use]
    pub const fn direction(&self) -> Direction {
        match self {
            Self::AddAttribute(_)
            | Self::Certify(_)
            | Self::Create(_)
            | Self::CreateKeyPair(_)
            | Self::Decrypt(_)
            | Self::DeleteAttribute(_)
            | Self::Destroy(_)
            | Self::Encrypt(_)
            | Self::Export(_)
            | Self::Get(_)
            | Self::Import(_)
            | Self::GetAttributes(_)
            | Self::Hash(_)
            | Self::Locate(_)
            | Self::Mac(_)
            | Self::Query(_)
            | Self::Revoke(_)
            | Self::ReKey(_)
            | Self::ReKeyKeyPair(_)
            | Self::Validate(_)
            | Self::DiscoverVersions(_)
            | Self::SetAttribute(_) => Direction::Request,

            Self::AddAttributeResponse(_)
            | Self::CertifyResponse(_)
            | Self::CreateResponse(_)
            | Self::CreateKeyPairResponse(_)
            | Self::DecryptResponse(_)
            | Self::DeleteAttributeResponse(_)
            | Self::DestroyResponse(_)
            | Self::EncryptResponse(_)
            | Self::ExportResponse(_)
            | Self::GetResponse(_)
            | Self::GetAttributesResponse(_)
            | Self::SetAttributeResponse(_)
            | Self::ImportResponse(_)
            | Self::HashResponse(_)
            | Self::LocateResponse(_)
            | Self::MacResponse(_)
            | Self::RevokeResponse(_)
            | Self::ReKeyResponse(_)
            | Self::ReKeyKeyPairResponse(_)
            | Self::QueryResponse(_)
            | Self::ValidateResponse(_)
            | Self::DiscoverVersionsResponse(_) => Direction::Response,
        }
    }

    #[must_use]
    pub const fn operation_enum(&self) -> OperationEnumeration {
        match self {
            Self::AddAttribute(_) | Self::AddAttributeResponse(_) => {
                OperationEnumeration::AddAttribute
            }
            Self::Certify(_) | Self::CertifyResponse(_) => OperationEnumeration::Certify,
            Self::Create(_) | Self::CreateResponse(_) => OperationEnumeration::Create,
            Self::CreateKeyPair(_) | Self::CreateKeyPairResponse(_) => {
                OperationEnumeration::CreateKeyPair
            }
            Self::Decrypt(_) | Self::DecryptResponse(_) => OperationEnumeration::Decrypt,
            Self::DeleteAttribute(_) | Self::DeleteAttributeResponse(_) => {
                OperationEnumeration::DeleteAttribute
            }
            Self::Destroy(_) | Self::DestroyResponse(_) => OperationEnumeration::Destroy,
            Self::DiscoverVersions(_) | Self::DiscoverVersionsResponse(_) => {
                OperationEnumeration::DiscoverVersions
            }
            Self::Encrypt(_) | Self::EncryptResponse(_) => OperationEnumeration::Encrypt,
            Self::Export(_) | Self::ExportResponse(_) => OperationEnumeration::Export,
            Self::Get(_) | Self::GetResponse(_) => OperationEnumeration::Get,
            Self::GetAttributes(_) | Self::GetAttributesResponse(_) => {
                OperationEnumeration::GetAttributes
            }
            Self::Import(_) | Self::ImportResponse(_) => OperationEnumeration::Import,
            Self::Hash(_) | Self::HashResponse(_) => OperationEnumeration::Hash,
            Self::Locate(_) | Self::LocateResponse(_) => OperationEnumeration::Locate,
            Self::Mac(_) | Self::MacResponse(_) => OperationEnumeration::MAC,
            Self::Query(_) | Self::QueryResponse(_) => OperationEnumeration::Query,
            Self::ReKey(_) | Self::ReKeyResponse(_) => OperationEnumeration::ReKey,
            Self::ReKeyKeyPair(_) | Self::ReKeyKeyPairResponse(_) => {
                OperationEnumeration::ReKeyKeyPair
            }
            Self::Revoke(_) | Self::RevokeResponse(_) => OperationEnumeration::Revoke,
            Self::SetAttribute(_) | Self::SetAttributeResponse(_) => {
                OperationEnumeration::SetAttribute
            }
            Self::Validate(_) | Self::ValidateResponse(_) => OperationEnumeration::Validate,
        }
    }
}

/// This operation requests the server to add a new attribute instance to be associated with
/// a Managed Object and set its value. The request contains the Unique Identifier of the
/// Managed Object to which the attribute pertains, along with the attribute name and value.
/// For single-instance attributes, this creates the attribute value. For multi-instance
/// attributes, this is how the first and subsequent values are created. Existing attribute
/// values SHALL NOT be changed by this operation. Read-Only attributes SHALL NOT be added
/// using the Add Attribute operation.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct AddAttribute {
    pub unique_identifier: UniqueIdentifier,
    pub new_attribute: Attribute,
}

/// Response to an Add Attribute request
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AddAttributeResponse {
    pub unique_identifier: UniqueIdentifier,
}

/// Certify
///
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
#[derive(Clone, Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
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

impl Display for Certify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Certify {{ unique_identifier: {:?}, certificate_request_type: {:?}, \
             certificate_request_value: {:?}, attributes: {:?}, protection_storage_masks: {:?} }}",
            self.unique_identifier,
            self.certificate_request_type,
            self.certificate_request_value,
            self.attributes,
            self.protection_storage_masks
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct CertifyResponse {
    /// The Unique Identifier of the newly created object.
    pub unique_identifier: UniqueIdentifier,
}

impl Display for CertifyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertifyResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

/// Create
///
/// This operation requests the server to generate a new symmetric key or
/// generate Secret Data as aManaged Cryptographic Object. The request contains
/// information about the type of object being created, and some of the
/// attributes to be assigned to the object (e.g., Cryptographic Algorithm,
/// Cryptographic Length, etc.). The response contains the Unique Identifier of
/// the created object. The server SHALL copy the Unique Identifier returned by
/// this operation into the ID Placeholder variable.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

impl Display for Create {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Create {{ object_type: {}, attributes: {:?}, protection_storage_masks: {:?} }}",
            self.object_type, self.attributes, self.protection_storage_masks
        )
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateResponse {
    /// Type of object created.
    pub object_type: ObjectType,
    /// The Unique Identifier of the newly created object.
    pub unique_identifier: UniqueIdentifier,
}

impl Display for CreateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CreateResponse {{ object_type: {}, unique_identifier: {} }}",
            self.object_type, self.unique_identifier
        )
    }
}

/// `CreateKeyPair`
///
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
#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug)]
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
    /// Specifies all `ProtectionStorage` Mask selections that are permissible for
    /// the new Private Key and Public Key objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_protection_storage_masks: Option<ProtectionStorageMasks>,
    /// Specifies all `ProtectionStorage` Mask selections that are permissible for
    /// the new Private Key object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_protection_storage_masks: Option<ProtectionStorageMasks>,
    /// Specifies all `ProtectionStorage` Mask selections that are permissible for
    /// the new `PublicKey` object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_protection_storage_masks: Option<ProtectionStorageMasks>,
}

impl Display for CreateKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CreateKeyPair {{ common_attributes: {:?}, private_key_attributes: {:?}, \
             public_key_attributes: {:?}, common_protection_storage_masks: {:?}, \
             private_protection_storage_masks: {:?}, public_protection_storage_masks: {:?} }}",
            self.common_attributes,
            self.private_key_attributes,
            self.public_key_attributes,
            self.common_protection_storage_masks,
            self.private_protection_storage_masks,
            self.public_protection_storage_masks
        )
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeyPairResponse {
    /// The Unique Identifier of the newly created private key object.
    pub private_key_unique_identifier: UniqueIdentifier,
    /// The Unique Identifier of the newly created public key object.
    pub public_key_unique_identifier: UniqueIdentifier,
}

impl Display for CreateKeyPairResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CreateKeyPairResponse {{ private_key_unique_identifier: {}, \
             public_key_unique_identifier: {} }}",
            self.private_key_unique_identifier, self.public_key_unique_identifier
        )
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug)]
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

impl Display for Decrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Decrypt {{ unique_identifier: {:?}, cryptographic_parameters: {:?}, data: {:?}, \
             iv_counter_nonce: {:?}, correlation_value: {:?}, init_indicator: {:?}, \
             final_indicator: {:?}, authenticated_encryption_additional_data: {:?}, \
             authenticated_encryption_tag: {:?} }}",
            self.unique_identifier,
            self.cryptographic_parameters,
            self.data,
            self.i_v_counter_nonce,
            self.correlation_value,
            self.init_indicator,
            self.final_indicator,
            self.authenticated_encryption_additional_data,
            self.authenticated_encryption_tag
        )
    }
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
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl TryInto<Vec<u8>> for DecryptedData {
    type Error = KmipError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut ser = Serializer::new();
        ser.write_vec(&self.metadata)?;

        let mut result = ser.finalize().to_vec();
        result.extend_from_slice(&self.plaintext);
        Ok(result)
    }
}

impl TryFrom<&[u8]> for DecryptedData {
    type Error = KmipError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut de = Deserializer::new(bytes);

        // Read the metadata
        let metadata = de.read_vec()?;

        // Remaining is the decrypted plaintext
        let plaintext = Zeroizing::from(de.finalize());

        Ok(Self {
            metadata,
            plaintext,
        })
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DecryptResponse {
    /// The Unique Identifier of the Managed
    /// Cryptographic Object that was the key
    /// used for the decryption operation.
    pub unique_identifier: UniqueIdentifier,
    /// The decrypted data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Zeroizing<Vec<u8>>>,
    /// Specifies the stream or by-parts value
    /// to be provided in subsequent calls to
    /// this operation for performing
    /// cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
}

impl Display for DecryptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecryptResponse {{ unique_identifier: {}, data: {:?}, correlation_value: {:?} }}",
            self.unique_identifier, self.data, self.correlation_value
        )
    }
}

#[derive(Default, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteAttribute {
    /// Determines the object whose attributes are being deleted. If omitted, then the ID Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Specifies the attribute associated with the object to be deleted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_attribute: Option<Attribute>,
    /// Specifies the reference for the attribute associated with the object to be deleted.
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "AttributeReferences"
    )]
    pub attribute_references: Option<Vec<AttributeReference>>,
}

impl Display for DeleteAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeleteAttribute {{ unique_identifier: {:?}, current_attribute: {:?}, \
             attribute_references: {:?} }}",
            self.unique_identifier, self.current_attribute, self.attribute_references
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteAttributeResponse {
    /// The Unique Identifier of the object
    pub unique_identifier: UniqueIdentifier,
}

impl Display for DeleteAttributeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeleteAttributeResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Destroy {
    /// Determines the object being destroyed. If omitted, then the ID
    /// Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Remove the object from the server's database.
    /// This is a Cosmian extension; the KMIP specification mandates that objects
    /// metadata should be kept even if the object is destroyed. This extension allows
    /// for the removal of the object metadata, typically for GDPR compliance and fixing
    /// creation errors.
    #[serde(skip_serializing_if = "<&bool>::not", default)]
    pub remove: bool,
}

impl Display for Destroy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Destroy {{ unique_identifier: {:?} }}",
            self.unique_identifier
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DestroyResponse {
    /// The Unique Identifier of the object.
    pub unique_identifier: UniqueIdentifier,
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

/// `DeriveKey`
///
/// This request is used to derive a Symmetric Key or Secret Data object from
/// keys or Secret Data objects that are already known to the key management
/// system. The request SHALL only apply to Managed Objects that have the Derive
/// Key bit set in the Cryptographic Usage Mask attribute of the specified
/// Managed Object (i.e., are able to be used for key derivation). If the
/// operation is issued for an object that does not have this bit set, then the
/// server SHALL return an error. For all derivation methods, the client SHALL
/// specify the desired length of the derived key or Secret Data object using
/// the Cryptographic Length attribute.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DeriveKey {
    /// Determines the type of object to be created.
    pub object_type: ObjectType,
    /// Determines the object or objects to be used to derive a new key. Note
    /// that the current value of the ID Placeholder SHALL NOT be used in place
    /// of a Unique Identifier in this operation.
    pub object_unique_identifier: UniqueIdentifier,
    /// An Enumeration object specifying the method to be used to derive the new
    /// key.
    pub derivation_method: DerivationMethod,
    /// A Structure object containing the parameters needed by the specified
    /// derivation method.
    pub derivation_parameters: DerivationParameters,
    /// Specifies desired attributes to be associated with the new object; the
    /// length and algorithm SHALL always be specified for the creation of a
    /// symmetric key.
    pub attributes: Attributes,
}

#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug)]
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

    /// The data to be encrypted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Zeroizing<Vec<u8>>>,

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

impl Display for Encrypt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Encrypt {{ unique_identifier: {:?}, cryptographic_parameters: {:?}, data: {:?}, \
             iv_counter_nonce: {:?}, correlation_value: {:?}, init_indicator: {:?}, \
             final_indicator: {:?}, authenticated_encryption_additional_data: {:?} }}",
            self.unique_identifier,
            self.cryptographic_parameters,
            self.data,
            self.i_v_counter_nonce,
            self.correlation_value,
            self.init_indicator,
            self.final_indicator,
            self.authenticated_encryption_additional_data,
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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
    pub i_v_counter_nonce: Option<Vec<u8>>,
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

impl Display for EncryptResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptResponse {{ unique_identifier: {}, data: {:?}, iv_counter_nonce: {:?}, \
             correlation_value: {:?}, authenticated_encryption_tag: {:?} }}",
            self.unique_identifier,
            self.data,
            self.i_v_counter_nonce,
            self.correlation_value,
            self.authenticated_encryption_tag
        )
    }
}

/// Export
///
/// This operation requests that the server returns a Managed Object specified by its Unique Identifier,
/// together with its attributes.
/// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification
/// SHALL have the same semantics as for the Get operation.
/// If the Managed Object has been Destroyed then the key material for the specified managed object
/// SHALL not be returned in the response.
/// The server SHALL copy the Unique Identifier returned by this operations
/// into the ID Placeholder variable.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug)]
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

impl Display for Export {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Export {{ unique_identifier: {:?}, key_format_type: {:?}, key_wrap_type: {:?}, \
             key_compression_type: {:?}, key_wrapping_specification: {:?} }}",
            self.unique_identifier,
            self.key_format_type,
            self.key_wrap_type,
            self.key_compression_type,
            self.key_wrapping_specification
        )
    }
}

impl Export {
    /// Create a `ExportRequest` for an Object
    /// # Arguments
    /// * `uid` - The Unique Identifier of the object to be retrieved
    /// * `unwrap` - If true, the object is returned unwrapped
    /// * `key_wrapping_data` - If unwrap is false, this is the key wrapping data to be used
    /// * `key_format_type` - The key format type to be returned
    /// # Returns
    /// A `ExportRequest`
    /// # Example
    /// ```
    /// use cosmian_kmip::kmip_2_1::kmip_operations::Export;
    ///
    /// let export_request = Export::new("1234", false, None, None);
    /// ```
    #[must_use]
    pub const fn new(
        uid: UniqueIdentifier,
        unwrap: bool,
        key_wrapping_specification: Option<KeyWrappingSpecification>,
        key_format_type: Option<KeyFormatType>,
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
            unique_identifier: Some(uid),
            key_format_type,
            key_wrap_type,
            key_compression_type: None,
            key_wrapping_specification,
        }
    }
}

impl From<String> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: String) -> Self {
        Self::new(UniqueIdentifier::TextString(uid), false, None, None)
    }
}
impl From<&String> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: &String) -> Self {
        Self::from(uid.to_string())
    }
}
impl From<&str> for Export {
    // Create a ExportRequest for an object to be returned "as registered"
    fn from(uid: &str) -> Self {
        Self::from(uid.to_owned())
    }
}

impl From<Get> for Export {
    // This is used to convert a GetRequest to an ExportRequest
    // to use the common code of export-utils
    fn from(get: Get) -> Self {
        Self {
            unique_identifier: get.unique_identifier,
            key_format_type: get.key_format_type,
            key_wrap_type: get.key_wrap_type,
            key_compression_type: get.key_compression_type,
            key_wrapping_specification: get.key_wrapping_specification,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ExportResponse {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub attributes: Attributes,
    pub object: Object,
}

impl Display for ExportResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportResponse {{ object_type: {}, unique_identifier: {}, attributes: {:?}, object: \
             {} }}",
            self.object_type, self.unique_identifier, self.attributes, self.object
        )
    }
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
#[derive(Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
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

impl Display for Get {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Get {{ unique_identifier: {:?}, key_format_type: {:?}, key_wrap_type: {:?}, \
             key_compression_type: {:?}, key_wrapping_specification: {:?} }}",
            self.unique_identifier,
            self.key_format_type,
            self.key_wrap_type,
            self.key_compression_type,
            self.key_wrapping_specification
        )
    }
}

impl Get {
    /// Create a `GetRequest` for an Object
    /// # Arguments
    /// * `unique_identifier` - The Unique Identifier of the object to be retrieved
    /// * `unwrap` - If true, the object is returned unwrapped
    /// * `key_wrapping_specification` - If unwrap is false, this is the key wrapping data to be used
    /// * `key_format_type` - The key format type to be returned
    /// # Returns
    /// A `GetRequest`
    /// # Example
    /// ```
    /// use cosmian_kmip::kmip_2_1::kmip_operations::Get;
    /// use cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
    ///
    /// let get_request = Get::new(UniqueIdentifier::TextString("1234".to_owned()), false, None, None);
    /// ```
    #[must_use]
    pub const fn new(
        unique_identifier: UniqueIdentifier,
        unwrap: bool,
        key_wrapping_specification: Option<KeyWrappingSpecification>,
        key_format_type: Option<KeyFormatType>,
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
            unique_identifier: Some(unique_identifier),
            key_format_type,
            key_wrap_type,
            key_compression_type: None,
            key_wrapping_specification,
        }
    }
}

impl From<UniqueIdentifier> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: UniqueIdentifier) -> Self {
        Self::new(uid, false, None, None)
    }
}
impl From<&UniqueIdentifier> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: &UniqueIdentifier) -> Self {
        Self::new(uid.clone(), false, None, None)
    }
}
impl From<String> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: String) -> Self {
        Self::new(UniqueIdentifier::TextString(uid), false, None, None)
    }
}
impl From<&String> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: &String) -> Self {
        Self::new(UniqueIdentifier::TextString(uid.clone()), false, None, None)
    }
}
impl From<&str> for Get {
    // Create a GetRequest for an object to be returned "as registered"
    fn from(uid: &str) -> Self {
        Self::new(
            UniqueIdentifier::TextString(uid.to_owned()),
            false,
            None,
            None,
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GetResponse {
    pub object_type: ObjectType,
    pub unique_identifier: UniqueIdentifier,
    pub object: Object,
}

impl Display for GetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GetResponse {{ object_type: {}, unique_identifier: {}, object: {} }}",
            self.object_type, self.unique_identifier, self.object
        )
    }
}

impl From<ExportResponse> for GetResponse {
    fn from(export_response: ExportResponse) -> Self {
        Self {
            object_type: export_response.object_type,
            unique_identifier: export_response.unique_identifier,
            object: export_response.object,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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
    pub attribute_reference: Option<Vec<AttributeReference>>,
}

impl Display for GetAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GetAttributes {{ unique_identifier: {:?}, attribute_references: {:?} }}",
            self.unique_identifier, self.attribute_reference
        )
    }
}

impl From<String> for GetAttributes {
    fn from(uid: String) -> Self {
        Self {
            unique_identifier: Some(UniqueIdentifier::TextString(uid)),
            attribute_reference: None,
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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct GetAttributesResponse {
    /// The Unique Identifier of the object
    pub unique_identifier: UniqueIdentifier,
    /// Attributes
    pub attributes: Attributes,
}

impl Display for GetAttributesResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GetAttributesResponse {{ unique_identifier: {}, attributes: {:?} }}",
            self.unique_identifier, self.attributes
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Hash {
    /// The Cryptographic Parameters (Hashing Algorithm) corresponding to the particular hash method requested.
    pub cryptographic_parameters: CryptographicParameters,
    /// The data to be hashed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,
    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
}

impl Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hash {{ cryptographic_parameters: {:?}, data: {:?}, correlation_value: {:?}, \
             init_indicator: {:?}, final_indicator: {:?} }}",
            self.cryptographic_parameters,
            self.data,
            self.correlation_value,
            self.init_indicator,
            self.final_indicator
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct HashResponse {
    /// The hashed data (as a Byte String).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
}

impl Display for HashResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HashResponse {{ data: {:?}, correlation_value: {:?} }}",
            self.data, self.correlation_value
        )
    }
}

/// Import
///
/// This operation requests the server to Import a Managed Object specified by
/// its Unique Identifier. The request specifies the object being imported and
/// all the attributes to be assigned to the object. The attribute rules for
/// each attribute for "Initially set by" and "When implicitly set" SHALL NOT be
/// enforced as all attributes MUST be set to the supplied values rather than
/// any server generated values.
///
/// The response contains the Unique Identifier provided in the request or
/// assigned by the server. The server SHALL copy the Unique Identifier returned
/// by this operation into the ID Placeholder variable.
/// `https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html#_Toc57115657`
///
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

impl Display for Import {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Import {{ unique_identifier: {}, object_type: {}, replace_existing: {:?}, \
             key_wrap_type: {:?}, attributes: {:?}, object: {} }}",
            self.unique_identifier,
            self.object_type,
            self.replace_existing,
            self.key_wrap_type,
            self.attributes,
            self.object
        )
    }
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ImportResponse {
    /// The Unique Identifier of the newly imported object.
    pub unique_identifier: UniqueIdentifier,
}

impl Display for ImportResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ImportResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

/// Locate
///
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
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug)]
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

impl Display for Locate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Locate {{ maximum_items: {:?}, offset_items: {:?}, storage_status_mask: {:?}, \
             object_group_member: {:?}, attributes: {:?} }}",
            self.maximum_items,
            self.offset_items,
            self.storage_status_mask,
            self.object_group_member,
            self.attributes
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

impl Display for LocateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LocateResponse {{ located_items: {:?}, unique_identifiers: {:?} }}",
            self.located_items, self.unique_identifiers
        )
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Default, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Mac {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key to use for the MAC operation. If omitted, then the ID Placeholder value SHALL be used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// The Cryptographic Parameters (Hashing Algorithm) corresponding to the particular hash method requested.
    pub cryptographic_parameters: CryptographicParameters,
    /// The data to be hashed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Specifies the existing stream or by-parts cryptographic operation (as returned from a previous call to this operation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
    /// Initial operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_indicator: Option<bool>,
    /// Final operation as Boolean
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_indicator: Option<bool>,
}

impl Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Mac {{ unique_identifier: {:?}, cryptographic_parameters: {:?}, data: {:?}, \
             correlation_value: {:?}, init_indicator: {:?}, final_indicator: {:?} }}",
            self.unique_identifier,
            self.cryptographic_parameters,
            self.data,
            self.correlation_value,
            self.init_indicator,
            self.final_indicator
        )
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MacResponse {
    /// The Unique Identifier of the Managed Cryptographic Object that is the key used for the MAC operation.
    pub unique_identifier: UniqueIdentifier,
    /// The hashed data (as a Byte String).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Specifies the stream or by-parts value to be provided in subsequent calls to this operation for performing cryptographic operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_value: Option<Vec<u8>>,
}

impl Display for MacResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MacResponse {{ data: {:?}, correlation_value: {:?} }}",
            self.data, self.correlation_value
        )
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Query {
    /// Determines what information about the server is being queried.
    /// If omitted, then the server SHALL return all information that the
    /// client is allowed to see.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_function: Option<Vec<QueryFunction>>,
}

impl Display for Query {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Query {{ query_functions: {:?} }}", self.query_function)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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

    /// List of namespaces supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_namespaces: Option<Vec<String>>,

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

    /// List of default profiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub defaults_information: Option<DefaultsInformation>,

    /// Protection Storage Masks supported by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_storage_masks: Option<ProtectionStorageMasks>,
}

/// Revoke
///
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
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
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
    pub compromise_occurrence_date: Option<i64>, // epoch millis
}

impl Display for Revoke {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Revoke {{ unique_identifier: {:?}, revocation_reason: {:?}, \
             compromise_occurrence_date: {:?} }}",
            self.unique_identifier, self.revocation_reason, self.compromise_occurrence_date
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct RevokeResponse {
    /// The Unique Identifier of the object.
    pub unique_identifier: UniqueIdentifier,
}

impl Display for RevokeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RevokeResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

/// This request is used to generate a replacement key for an existing symmetric key.
///
/// It is analogous to the Create operation, except that attributes of
/// the replacement key are copied from the existing key, with the exception of
/// the attributes listed in Re-key Attribute Requirements.
/// As the replacement key takes over the name attribute of the existing key, Re-key SHOULD only be performed once on a given key.
///
/// The server SHALL copy the Unique Identifier of the replacement key returned by this operation into the ID Placeholder variable.
/// For the existing key, the server SHALL create a Link attribute of Link Type Replacement Object pointing to the replacement key. For the replacement key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing key.
/// An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key. If no Offset is specified, the Activation Date, Process Start Date, Protect Stop Date and Deactivation Date values are copied from the existing key.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReKey {
    // Determines the existing Symmetric Key being re-keyed. If omitted, then the ID Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,

    // An Interval object indicating the difference between the Initial Date and the Activation Date of the replacement key to be created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i32>,

    /// Specifies desired attributes to be associated with the new object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Attributes>,

    /// Specifies all permissible Protection Storage Mask selections for the new
    /// object
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protection_storage_masks: Option<ProtectionStorageMasks>,
}

impl Display for ReKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReKey {{ unique_identifier: {:?}, offset: {:?}, attributes: {:?}, \
             protection_storage_masks: {:?} }}",
            self.unique_identifier, self.offset, self.attributes, self.protection_storage_masks
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyResponse {
    // The Unique Identifier of the newly created replacement Private Key object.
    pub unique_identifier: UniqueIdentifier,
}

impl Display for ReKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReKeyResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

/// `RekeyKeyPair`
///
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
#[derive(Serialize, Deserialize, Default, PartialEq, Eq, Debug)]
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

impl Display for ReKeyKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReKeyKeyPair {{ private_key_unique_identifier: {:?}, offset: {:?}, \
             common_attributes: {:?}, private_key_attributes: {:?}, public_key_attributes: {:?}, \
             common_protection_storage_masks: {:?}, private_protection_storage_masks: {:?}, \
             public_protection_storage_masks: {:?} }}",
            self.private_key_unique_identifier,
            self.offset,
            self.common_attributes,
            self.private_key_attributes,
            self.public_key_attributes,
            self.common_protection_storage_masks,
            self.private_protection_storage_masks,
            self.public_protection_storage_masks
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ReKeyKeyPairResponse {
    pub private_key_unique_identifier: UniqueIdentifier,
    pub public_key_unique_identifier: UniqueIdentifier,
}

impl Display for ReKeyKeyPairResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReKeyKeyPairResponse {{ private_key_unique_identifier: {}, \
             public_key_unique_identifier: {} }}",
            self.private_key_unique_identifier, self.public_key_unique_identifier
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SetAttribute {
    /// The Unique Identifier of the object. If omitted, then the ID Placeholder value is used by the server as the Unique Identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,
    /// Specifies the new value for the attribute associated with the object.
    pub new_attribute: Attribute,
}

impl Display for SetAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SetAttribute {{ unique_identifier: {:?}, new_attribute: {:?} }}",
            self.unique_identifier, self.new_attribute
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SetAttributeResponse {
    /// The Unique Identifier of the object
    pub unique_identifier: UniqueIdentifier,
}

impl Display for SetAttributeResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SetAttributeResponse {{ unique_identifier: {} }}",
            self.unique_identifier
        )
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusResponse {
    pub kacls_url: String,
}

/// Validate
///
/// This operation requests the server to validate a certificate chain and return
/// information on its validity. Only a single certificate chain SHALL be
/// included in each request.
/// The request MAY contain a list of certificate objects, and/or a list of
/// Unique Identifiers that identify Managed Certificate objects.
/// Together, the two lists compose a certificate chain to be validated.
/// The request MAY also contain a date for which all certificates in the
/// certificate chain are REQUIRED to be valid.
/// The method or policy by which validation is conducted is a decision of the
/// server and is outside of the scope of this protocol.
/// Likewise, the order in which the supplied certificate chain is validated and
/// the specification of trust anchors used to terminate validation are also
/// controlled by the server.
#[derive(Serialize, Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Validate {
    /// One or more Certificates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<Vec<Vec<u8>>>,
    /// One or more Unique Identifiers of Certificate Objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<Vec<UniqueIdentifier>>,
    /// A Date-Time object indicating when the certificate chain needs to be
    /// valid. If omitted, the current date and time SHALL be assumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity_time: Option<String>,
}

impl Display for Validate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Validate {{ certificate: {:?}, unique_identifier: {:?}, validity_time: {:?} }}",
            self.certificate, self.unique_identifier, self.validity_time
        )
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct ValidateResponse {
    /// An Enumeration object indicating whether the certificate chain is valid,
    /// invalid, or unknown.
    pub validity_indicator: ValidityIndicator,
}

impl Display for ValidateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ValidateResponse {{ validity_indicator: {:?} }}",
            self.validity_indicator
        )
    }
}
