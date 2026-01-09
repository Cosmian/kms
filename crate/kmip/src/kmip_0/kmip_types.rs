use std::fmt;

use kmip_derive::{KmipEnumDeserialize, KmipEnumSerialize, kmip_enum};
use serde::{
    Deserialize, Serialize, de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
};
use strum::Display;

#[kmip_enum]
pub enum TicketType {
    Login = 0x0000_0001,
}

/// This field contains the version number of the protocol, ensuring that
/// the protocol is fully understood by both communicating parties.
///
/// The version number SHALL be specified in two parts, major and minor.
///
/// Servers and clients SHALL support backward compatibility with versions
/// of the protocol with the same major version.
///
/// Support for backward compatibility with different major versions is OPTIONAL.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
#[serde(rename_all = "PascalCase")]
pub struct ProtocolVersion {
    pub protocol_version_major: i32,
    pub protocol_version_minor: i32,
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}",
            self.protocol_version_major, self.protocol_version_minor
        )
    }
}

/// This Enumeration indicates whether the client is able to accept
/// an asynchronous response.
///
/// If not present in a request, then Prohibited is assumed.
///
/// If the value is Prohibited, the server SHALL process the request synchronously.
#[kmip_enum]
pub enum AsynchronousIndicator {
    /// The server SHALL process all batch items in the request asynchronously
    /// (returning an Asynchronous Correlation Value for each batch item).
    Mandatory = 0x0000_0001,
    /// The server MAY process each batch item in the request either asynchronously
    /// (returning an Asynchronous Correlation Value for a batch item) or synchronously.
    /// The method or policy by which the server determines whether or not to process
    /// an individual batch item asynchronously is a decision of the server and
    /// is outside the scope of this protocol.
    Optional = 0x0000_0002,
    /// The server SHALL NOT process any batch item asynchronously.
    /// All batch items SHALL be processed synchronously.
    Prohibited = 0x0000_0003,
}

/// Types of attestation supported by the server
#[kmip_enum]
pub enum AttestationType {
    TPM_Quote = 0x0000_0001,
    TCG_Integrity_Report = 0x0000_0002,
    SAML_Assertion = 0x0000_0003,
}

#[kmip_enum]
pub enum HashingAlgorithm {
    MD2 = 0x0000_0001,
    MD4 = 0x0000_0002,
    MD5 = 0x0000_0003,
    // #[serde(rename = "SHA-1")]
    SHA1 = 0x0000_0004,
    // #[serde(rename = "SHA-224")]
    SHA224 = 0x0000_0005,
    // #[serde(rename = "SHA-256")]
    SHA256 = 0x0000_0006,
    // #[serde(rename = "SHA-384")]
    SHA384 = 0x0000_0007,
    // #[serde(rename = "SHA-512")]
    SHA512 = 0x0000_0008,
    // #[serde(rename = "RIPEMD-160")]
    RIPEMD160 = 0x0000_0009,
    Tiger = 0x0000_000A,
    Whirlpool = 0x0000_000B,
    // #[serde(rename = "SHA-512/224")]
    SHA512224 = 0x0000_000C,
    // #[serde(rename = "SHA-512/256")]
    SHA512256 = 0x0000_000D,
    // #[serde(rename = "SHA-3-224")]
    SHA3224 = 0x0000_000E,
    // #[serde(rename = "SHA-3-256")]
    SHA3256 = 0x0000_000F,
    // #[serde(rename = "SHA-3-384")]
    SHA3384 = 0x0000_0010,
    // #[serde(rename = "SHA-3-512")]
    SHA3512 = 0x0000_0011,
}

/// The ticket structure used to specify a Ticket
/// KMIP 2.1 Only. Used in Authentication
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Ticket {
    pub ticket_type: TicketType,
    pub ticket_value: Vec<u8>,
}

/// A Credential is a structure used to convey information used to authenticate a client
/// or server to the other party in a KMIP message. It contains a credential type and
/// credential value fields.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Credential {
    pub credential_type: CredentialType,
    pub credential_value: CredentialValue,
}

/// Credential Type Enumeration
/// Only `UsernameAndPassword`, `Device`, and `Attestation` are supported in KMIP 1.x
/// (this library does not enforce this)
#[kmip_enum]
pub enum CredentialType {
    UsernameAndPassword = 0x1,
    Device = 0x2,
    Attestation = 0x3,
    OneTimePassword = 0x4,
    HashedPassword = 0x5,
    Ticket = 0x6,
}

/// A Credential is a structure used for client identification purposes
/// and is not managed by the key management system
/// (e.g., user id/password pairs, Kerberos tokens, etc.).
/// Only `UsernameAndPassword`, `Device`, and `Attestation` are supported in KMIP 1.x
/// (this library does not enforce this)
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialValue {
    UsernameAndPassword {
        username: String,
        password: Option<String>,
    },
    Device {
        device_serial_number: Option<String>,
        password: Option<String>,
        device_identifier: Option<String>,
        network_identifier: Option<String>,
        machine_identifier: Option<String>,
        media_identifier: Option<String>,
    },
    Attestation {
        nonce: Nonce,
        attestation_type: AttestationType,
        attestation_measurement: Option<Vec<u8>>,
        attestation_assertion: Option<Vec<u8>>,
    },
    OneTimePassword {
        username: String,
        password: Option<String>,
        one_time_password: String,
    },
    HashedPassword {
        username: String,
        timestamp: u64, // epoch millis
        hashing_algorithm: Option<HashingAlgorithm>,
        hashed_password: Vec<u8>,
    },
    Ticket {
        ticket: Ticket,
    },
}

impl CredentialValue {
    #[expect(dead_code)]
    const fn value(&self) -> u32 {
        match *self {
            Self::UsernameAndPassword { .. } => 0x0000_0001,
            Self::Device { .. } => 0x0000_0002,
            Self::Attestation { .. } => 0x0000_0003,
            Self::OneTimePassword { .. } => 0x0000_0004,
            Self::HashedPassword { .. } => 0x0000_0005,
            Self::Ticket { .. } => 0x0000_0006,
        }
    }
}

impl Serialize for CredentialValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::UsernameAndPassword { username, password } => {
                let mut st = serializer.serialize_struct("UsernameAndPassword", 2)?;
                st.serialize_field("Username", username)?;
                if let Some(password) = password {
                    st.serialize_field("Password", password)?;
                }
                st.end()
            }
            Self::Device {
                device_serial_number,
                password,
                device_identifier,
                network_identifier,
                machine_identifier,
                media_identifier,
            } => {
                let mut st = serializer.serialize_struct("Device", 6)?;
                if let Some(device_serial_number) = device_serial_number {
                    st.serialize_field("DeviceSerialNumber", device_serial_number)?;
                }
                if let Some(password) = password {
                    st.serialize_field("Password", password)?;
                }
                if let Some(device_identifier) = device_identifier {
                    st.serialize_field("DeviceIdentifier", device_identifier)?;
                }
                if let Some(network_identifier) = network_identifier {
                    st.serialize_field("NetworkIdentifier", network_identifier)?;
                }
                if let Some(machine_identifier) = machine_identifier {
                    st.serialize_field("MachineIdentifier", machine_identifier)?;
                }
                if let Some(media_identifier) = media_identifier {
                    st.serialize_field("MediaIdentifier", media_identifier)?;
                }
                st.end()
            }
            Self::Attestation {
                nonce,
                attestation_type,
                attestation_measurement,
                attestation_assertion,
            } => {
                let mut st = serializer.serialize_struct("Attestation", 4)?;
                st.serialize_field("Nonce", nonce)?;
                st.serialize_field("AttestationType", attestation_type)?;
                if let Some(attestation_measurement) = attestation_measurement {
                    st.serialize_field("AttestationMeasurement", attestation_measurement)?;
                }
                if let Some(attestation_assertion) = attestation_assertion {
                    st.serialize_field("AttestationAssertion", attestation_assertion)?;
                }
                st.end()
            }
            Self::OneTimePassword {
                username,
                password,
                one_time_password,
            } => {
                let mut st = serializer.serialize_struct("OneTimePassword", 3)?;
                st.serialize_field("Username", username)?;
                if let Some(password) = password {
                    st.serialize_field("Password", password)?;
                }
                st.serialize_field("OneTimePassword", one_time_password)?;
                st.end()
            }
            Self::HashedPassword {
                username,
                timestamp,
                hashing_algorithm,
                hashed_password,
            } => {
                let mut st = serializer.serialize_struct("HashedPassword", 4)?;
                st.serialize_field("Username", username)?;
                st.serialize_field("Timestamp", timestamp)?;
                if let Some(hashing_algorithm) = hashing_algorithm {
                    st.serialize_field("HashingAlgorithm", hashing_algorithm)?;
                }
                st.serialize_field("HashedPassword", hashed_password)?;
                st.end()
            }
            Self::Ticket { ticket } => {
                let mut st = serializer.serialize_struct("Ticket", 1)?;
                st.serialize_field("Ticket", ticket)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for CredentialValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier)]
        enum Field {
            Username,
            Password,
            DeviceSerialNumber,
            DeviceIdentifier,
            NetworkIdentifier,
            MachineIdentifier,
            MediaIdentifier,
            Nonce,
            AttestationType,
            AttestationMeasurement,
            AttestationAssertion,
            OneTimePassword,
            Timestamp,
            HashingAlgorithm,
            HashedPassword,
            Ticket,
        }

        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = CredentialValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Credential")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut username: Option<String> = None;
                let mut password: Option<String> = None;
                let mut device_serial_number: Option<String> = None;
                let mut device_identifier: Option<String> = None;
                let mut network_identifier: Option<String> = None;
                let mut machine_identifier: Option<String> = None;
                let mut media_identifier: Option<String> = None;
                let mut nonce: Option<Nonce> = None;
                let mut attestation_type: Option<AttestationType> = None;
                let mut attestation_measurement: Option<Vec<u8>> = None;
                let mut attestation_assertion: Option<Vec<u8>> = None;
                let mut one_time_password: Option<String> = None;
                let mut timestamp: Option<u64> = None;
                let mut hashing_algorithm: Option<HashingAlgorithm> = None;
                let mut hashed_password: Option<Vec<u8>> = None;
                let mut ticket: Option<Ticket> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Username => {
                            if username.is_some() {
                                return Err(de::Error::duplicate_field("username"));
                            }
                            username = Some(map.next_value()?);
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"));
                            }
                            password = Some(map.next_value()?);
                        }
                        Field::DeviceSerialNumber => {
                            if device_serial_number.is_some() {
                                return Err(de::Error::duplicate_field("device_serial_number"));
                            }
                            device_serial_number = Some(map.next_value()?);
                        }
                        Field::DeviceIdentifier => {
                            if device_identifier.is_some() {
                                return Err(de::Error::duplicate_field("device_identifier"));
                            }
                            device_identifier = Some(map.next_value()?);
                        }
                        Field::NetworkIdentifier => {
                            if network_identifier.is_some() {
                                return Err(de::Error::duplicate_field("network_identifier"));
                            }
                            network_identifier = Some(map.next_value()?);
                        }
                        Field::MachineIdentifier => {
                            if machine_identifier.is_some() {
                                return Err(de::Error::duplicate_field("machine_identifier"));
                            }
                            machine_identifier = Some(map.next_value()?);
                        }
                        Field::MediaIdentifier => {
                            if media_identifier.is_some() {
                                return Err(de::Error::duplicate_field("media_identifier"));
                            }
                            media_identifier = Some(map.next_value()?);
                        }
                        Field::Nonce => {
                            if nonce.is_some() {
                                return Err(de::Error::duplicate_field("nonce"));
                            }
                            nonce = Some(map.next_value()?);
                        }
                        Field::AttestationType => {
                            if attestation_type.is_some() {
                                return Err(de::Error::duplicate_field("attestation_type"));
                            }
                            attestation_type = Some(map.next_value()?);
                        }
                        Field::AttestationMeasurement => {
                            if attestation_measurement.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "attestation_measurement_type",
                                ));
                            }
                            attestation_measurement = Some(map.next_value()?);
                        }
                        Field::AttestationAssertion => {
                            if attestation_assertion.is_some() {
                                return Err(de::Error::duplicate_field("attestation_assertion"));
                            }
                            attestation_assertion = Some(map.next_value()?);
                        }
                        Field::OneTimePassword => {
                            if one_time_password.is_some() {
                                return Err(de::Error::duplicate_field("one_time_password"));
                            }
                            one_time_password = Some(map.next_value()?);
                        }
                        Field::Timestamp => {
                            if timestamp.is_some() {
                                return Err(de::Error::duplicate_field("timestamp"));
                            }
                            timestamp = Some(map.next_value()?);
                        }
                        Field::HashingAlgorithm => {
                            if hashing_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("hashing_algorithm"));
                            }
                            hashing_algorithm = Some(map.next_value()?);
                        }
                        Field::HashedPassword => {
                            if hashed_password.is_some() {
                                return Err(de::Error::duplicate_field("hashed_password"));
                            }
                            hashed_password = Some(map.next_value()?);
                        }
                        Field::Ticket => {
                            if ticket.is_some() {
                                return Err(de::Error::duplicate_field("ticket"));
                            }
                            ticket = Some(map.next_value()?);
                        }
                    }
                }

                if let (Some(nonce), Some(attestation_type)) = (nonce, attestation_type) {
                    return Ok(CredentialValue::Attestation {
                        nonce,
                        attestation_type,
                        attestation_measurement,
                        attestation_assertion,
                    });
                } else if let Some(ticket) = ticket {
                    return Ok(CredentialValue::Ticket { ticket });
                } else if let Some(username) = username {
                    if let (Some(timestamp), Some(hashed_password)) = (timestamp, hashed_password) {
                        return Ok(CredentialValue::HashedPassword {
                            username,
                            timestamp,
                            hashing_algorithm,
                            hashed_password,
                        });
                    } else if let Some(one_time_password) = one_time_password {
                        return Ok(CredentialValue::OneTimePassword {
                            username,
                            password,
                            one_time_password,
                        });
                    }

                    return Ok(CredentialValue::UsernameAndPassword { username, password });
                }

                Ok(CredentialValue::Device {
                    device_serial_number,
                    password,
                    device_identifier,
                    network_identifier,
                    machine_identifier,
                    media_identifier,
                })
            }
        }

        const FIELDS: &[&str] = &[
            "username",
            "password",
            "device_serial_number",
            "device_identifier",
            "network_identifier",
            "machine_identifier",
            "media_identifier",
            "nonce",
            "attestation_type",
            "attestation_measurement",
            "attestation_assertion",
            "one_time_password",
            "timestamp",
            "hashing_algorithm",
            "hashed_password",
            "ticket",
        ];
        deserializer.deserialize_struct("Credential", FIELDS, CredentialVisitor)
    }
}

/// A Nonce object is a structure used by the server to send a random value to the client.
///
/// The Nonce Identifier is assigned by the server and used to identify the Nonce object.
/// The Nonce Value consists of the random data created by the server.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Nonce {
    pub nonce_id: Vec<u8>,
    pub nonce_value: Vec<u8>,
}

#[kmip_enum]
#[derive(Default)]
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
    Unknown_Object_Group = 0x0000_004A,
    Constraint_Violation = 0x0000_004B,
    Duplicate_Process_Request = 0x0000_004C,
    #[default]
    General_Failure = 0x0000_0100,
}

/// The Message Extension is an OPTIONAL structure that MAY be appended to any Batch Item.
///
/// It is used to extend protocol messages for the purpose of adding vendor-specified extensions.
/// The Message Extension is a structure that SHALL contain the Vendor Identification,
/// Criticality Indicator, and Vendor Extension fields.
///
/// The Vendor Identification SHALL be a text string that uniquely identifies the vendor,
/// allowing a client to determine if it is able to parse and understand the extension.
///
/// If a client or server receives a protocol message containing a message extension
/// that it does not understand, then its actions depend on the Criticality Indicator.
///
/// If the indicator is True (i.e., Critical), and the receiver does not understand the extension,
/// then the receiver SHALL reject the entire message.
/// If the indicator is False (i.e., Non-Critical), and the receiver does not
/// understand the extension, then the receiver MAY process the rest of the message as
/// if the extension were not present.
///
/// The Vendor Extension structure SHALL contain vendor-specific extensions.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct MessageExtension {
    /// Text String (with usage limited to alphanumeric, underscore and period –
    /// i.e. [A-Za-z0-9_.])
    pub vendor_identification: String,
    pub criticality_indicator: bool,
    // Vendor extension structure is not precisely defined by KMIP reference
    pub vendor_extension: Vec<u8>,
}

impl std::fmt::Display for MessageExtension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "MessageExtension {{ vendor_identification: {}, criticality_indicator: {}, vendor_extension: <{} bytes> }}",
            self.vendor_identification,
            self.criticality_indicator,
            self.vendor_extension.len()
        )
    }
}

/// This option SHALL only be present if the Batch Count is greater than 1.
/// This option SHALL have one of three values (Undo, Stop or Continue).
/// If not specified, then Stop is assumed.
#[kmip_enum]
pub enum BatchErrorContinuationOption {
    /// If any operation in the request fails, then the server SHALL undo all the previous operations.
    ///
    /// Batch item fails and the Result Status is set to Operation Failed.
    /// Responses to batch items that have already been processed are returned normally.
    /// Responses to batch items that have not been processed are not returned.
    Continue = 0x01,
    Stop = 0x02,
    Undo = 0x03,
}

#[kmip_enum]
pub enum ResultStatusEnumeration {
    Success = 0x0000_0000,
    OperationFailed = 0x0000_0001,
    OperationPending = 0x0000_0002,
    OperationUndone = 0x0000_0003,
}

#[derive(Debug, Eq, PartialEq)]
pub enum Direction {
    Request,
    Response,
}

#[kmip_enum]
pub enum KeyWrapType {
    NotWrapped = 0x0000_0001,
    AsRegistered = 0x0000_0002,
}

/// KMIP 1.4 FIPS186 Variation Enumeration
#[kmip_enum]
pub enum FIPS186Variation {
    Unspecified = 0x1,
    // #[serde(rename = "GP x-Original")]
    GPXOriginal = 0x2,
    // #[serde(rename = "GP x-Change Notice")]
    GPXChangeNotice = 0x3,
    // #[serde(rename = "x-Original")]
    XOriginal = 0x4,
    // #[serde(rename = "x-Change Notice")]
    XChangeNotice = 0x5,
    // #[serde(rename = "k-Original")]
    KOriginal = 0x6,
    // #[serde(rename = "k-Change Notice")]
    KChangeNotice = 0x7,
}

/// DRBG Algorithm Enumeration
#[kmip_enum]
pub enum DRBGAlgorithm {
    Unspecified = 0x1,
    // #[serde(rename = "Dual-EC")]
    DualEC = 0x2,
    Hash = 0x3,
    HMAC = 0x4,
    CTR = 0x5,
}

/// RNG Algorithm Enumeration
#[kmip_enum]
pub enum RNGAlgorithm {
    Unspecified = 0x1,
    FIPS186_2 = 0x2,
    DRBG = 0x3,
    NRBG = 0x4,
    ANSI_X931 = 0x5,
    ANSI_X962 = 0x6,
}

/// Types of validation authorities that can validate cryptographic objects.
#[kmip_enum]
pub enum ValidationAuthorityType {
    /// Common Criteria Testing Laboratory authority.
    CommonCriteriaTestingLaboratory = 0x0000_0001,
    /// National Voluntary Laboratory Accreditation Program.
    Nvlap = 0x0000_0002,
    /// National Information Assurance Partnership.
    Niap = 0x0000_0003,
    /// Authority not matching any other defined type.
    Unspecified = 0x0000_0004,
    /// Federal Information Processing Standards authority.
    FipsApprovedSecurityFunction = 0x0000_0005,
    /// ISO/IEC 19790 compliant validation.
    Iso19790Compliant = 0x0000_0006,
    /// Federal Information Security Management Act authority.
    Fisma = 0x0000_0007,
}

#[kmip_enum]
pub enum ValidationType {
    Unspecified = 0x1,
    Hardware = 0x2,
    Software = 0x3,
    Firmware = 0x4,
    Hybrid = 0x5,
}

#[kmip_enum]
pub enum UnwrapMode {
    Unspecified = 0x1,
    UsingWrappingKey = 0x2,
    UsingTransportKey = 0x3,
}

/// KMIP 1.4 Destroy Action Enumeration
#[kmip_enum]
pub enum DestroyAction {
    Unspecified = 0x1,
    KeyMaterialDeleted = 0x2,
    KeyMaterialShredded = 0x3,
    MetaDataDeleted = 0x4,
    MetaDataShredded = 0x5,
    Deleted = 0x6,
    Shredded = 0x7,
}

#[kmip_enum]
pub enum ShreddingAlgorithm {
    Unspecified = 0x1,
    Cryptographic = 0x2,
    Unsupervised = 0x3,
}

#[kmip_enum]
pub enum BlockCipherMode {
    CBC = 0x0000_0001,
    ECB = 0x0000_0002,
    PCBC = 0x0000_0003,
    CFB = 0x0000_0004,
    OFB = 0x0000_0005,
    CTR = 0x0000_0006,
    CMAC = 0x0000_0007,
    CCM = 0x0000_0008,
    GCM = 0x0000_0009,
    CBCMAC = 0x0000_000A,
    XTS = 0x0000_000B,
    AESKeyWrapPadding = 0x0000_000C, // RFC 5649
    NISTKeyWrap = 0x0000_000D,       // RFC 3394
    X9102AESKW = 0x0000_000E,
    X9102TDKW = 0x0000_000F,
    X9102AKW1 = 0x0000_0010,
    X9102AKW2 = 0x0000_0011,
    AEAD = 0x0000_0012,
    // Extensions - 8XXXXXXX
    // AES GCM SIV
    GCMSIV = 0x8000_0002,
    // This variant was introduced to support backward compatibility with versions prior to 5.15
    // In the database layer, right after deserialization, objects that have a saved BlockCipherMode (via their `KeyWrappingData`) are tested for this mode and
    // converted to AESKeyWrapPadding if found.
    LegacyNISTKeyWrap = 0x8000_000D,
}

/// Padding Method Enumeration
#[kmip_enum]
pub enum PaddingMethod {
    None = 0x1,
    OAEP = 0x2,
    PKCS5 = 0x3,
    SSL3 = 0x4,
    Zeros = 0x5,
    // #[serde(rename = "ANSI X9.23")]
    ANSI_X923 = 0x6,
    // #[serde(rename = "ISO 10126")]
    ISO10126 = 0x7,
    // #[serde(rename = "PKCS1 v1.5")]
    PKCS1v15 = 0x8,
    // #[serde(rename = "X9.31")]
    X931 = 0x9,
    PSS = 0xA,
}

/// Key Role Type Enumeration
#[kmip_enum]
pub enum KeyRoleType {
    BDK = 0x1,
    CVK = 0x2,
    DEK = 0x3,
    MKAC = 0x4,
    MKSMC = 0x5,
    MKSMI = 0x6,
    MKDAC = 0x7,
    MKDN = 0x8,
    MKCP = 0x9,
    MKOTH = 0xA,
    KEK = 0xB,
    MAC16609 = 0xC,
    MAC97971 = 0xD,
    MAC97972 = 0xE,
    MAC97973 = 0xF,
    MAC97974 = 0x10,
    MAC97975 = 0x11,
    ZPK = 0x12,
    PVKIBM = 0x13,
    PVKPVV = 0x14,
    PVKOTH = 0x15,
    DUKPT = 0x16,
    IV = 0x17,
    TRKBK = 0x18,
}

#[kmip_enum]
pub enum MaskGenerator {
    MFG1 = 0x0000_0001,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CryptographicUsageMask(pub(crate) u32);

bitflags::bitflags! {
    impl CryptographicUsageMask: u32 {
        /// Allow for signing. Applies to Sign operation. Valid for PGP Key, Private Key
        const Sign=0x0000_0001;
        /// Allow for signature verification. Applies to Signature Verify and Validate
        /// operations. Valid for PGP Key, Certificate and Public Key.
        const Verify=0x0000_0002;
        /// Allow for encryption. Applies to Encrypt operation. Valid for PGP Key,
        /// Private Key, Public Key and Symmetric Key. Encryption for the purpose of
        /// wrapping is separate Wrap Key value.
        const Encrypt=0x0000_0004;
        /// Allow for decryption. Applies to Decrypt operation. Valid for PGP Key,
        /// Private Key, Public Key and Symmetric Key. Decryption for the purpose of
        /// unwrapping is separate Unwrap Key value.
        const Decrypt=0x0000_0008;
        /// Allow for key wrapping. Applies to Get operation when wrapping is
        /// required by Wrapping Specification is provided on the object used to
        /// Wrap. Valid for PGP Key, Private Key and Symmetric Key. Note: even if
        /// the underlying wrapping mechanism is encryption, this value is logically
        /// separate.
        const WrapKey=0x0000_0010;
        /// Allow for key unwrapping. Applies to Get operation when unwrapping is
        /// required on the object used to Unwrap. Valid for PGP Key, Private Key,
        /// Public Key and Symmetric Key. Not interchangeable with Decrypt. Note:
        /// even if the underlying unwrapping mechanism is decryption, this value is
        /// logically separate.
        const UnwrapKey=0x0000_0020;
        /// Allow for MAC generation. Applies to MAC operation. Valid for Symmetric
        /// Keys
        const MACGenerate=0x0000_0080;
        /// Allow for MAC verification. Applies to MAC Verify operation. Valid for
        /// Symmetric Keys
        const MACVerify=0x0000_0100;
        /// Allow for key derivation. Applied to Derive Key operation. Valid for PGP
        /// Keys, Private Keys, Public Keys, Secret Data and Symmetric Keys.
        const DeriveKey=0x0000_0200;
        /// Allow for Key Agreement. Valid for PGP Keys, Private Keys, Public Keys,
        /// Secret Data and Symmetric Keys
        const KeyAgreement=0x0000_0800;
        /// Allow for Certificate Signing. Applies to Certify operation on a private key.
        /// Valid for Private Keys.
        const CertificateSign=0x0000_1000;
        /// Allow for CRL Sign. Valid for Private Keys
        const CRLSign=0x0000_2000;
        /// Allow for Authentication. Valid for Secret Data.
        const Authenticate=0x0010_0000;
        /// Cryptographic Usage Mask contains no Usage Restrictions.
        const Unrestricted=0x0020_0000;
        // Extensions XXX00000
    }
}

impl std::fmt::Display for CryptographicUsageMask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (name, flag) in [
            ("Sign", Self::Sign),
            ("Verify", Self::Verify),
            ("Encrypt", Self::Encrypt),
            ("Decrypt", Self::Decrypt),
            ("WrapKey", Self::WrapKey),
            ("UnwrapKey", Self::UnwrapKey),
            ("MACGenerate", Self::MACGenerate),
            ("MACVerify", Self::MACVerify),
            ("DeriveKey", Self::DeriveKey),
            ("KeyAgreement", Self::KeyAgreement),
            ("CertificateSign", Self::CertificateSign),
            ("CRLSign", Self::CRLSign),
            ("Authenticate", Self::Authenticate),
            ("Unrestricted", Self::Unrestricted),
        ] {
            if self.contains(flag) {
                if !first {
                    write!(f, " | ")?;
                }
                write!(f, "{name}")?;
                first = false;
            }
        }
        Ok(())
    }
}

impl Serialize for CryptographicUsageMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(i32::try_from(self.bits()).map_err(serde::ser::Error::custom)?)
    }
}
impl<'de> Deserialize<'de> for CryptographicUsageMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CryptographicUsageMaskVisitor;

        impl Visitor<'_> for CryptographicUsageMaskVisitor {
            type Value = CryptographicUsageMask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CryptographicUsageMask")
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(v))
            }

            // used by the TTLV representation
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }
        }
        deserializer.deserialize_any(CryptographicUsageMaskVisitor)
    }
}

/// The Certificate Type attribute is a type of certificate (e.g., X.509).
/// The Certificate Type value SHALL be set by the server when the certificate
/// is created or registered and then SHALL NOT be changed or deleted before the
/// object is destroyed.
/// The PKCS7 format is a Cosmian extension from KMIP.
#[kmip_enum]
pub enum CertificateType {
    X509 = 0x01,
    PGP = 0x02,
    // Cosmian extension used to export a X509 certificate in PKCS#7 format
    PKCS7 = 0x8000_0001,
}

/// Secret Data Type Enumeration
#[kmip_enum]
pub enum SecretDataType {
    Password = 0x1,
    Seed = 0x2,
}

/// `UsageLimits` structure for limiting the usage of a managed cryptographic object
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageLimits {
    /// The usage limits unit
    pub usage_limits_unit: UsageLimitsUnit,
    /// The usage limits count
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits_count: Option<i64>,
    /// The usage limits total
    pub usage_limits_total: i64,
}

/// `UsageLimitsUnit` enumeration defines the unit for usage limits
#[kmip_enum]
pub enum UsageLimitsUnit {
    Byte = 0x1,
    Object = 0x2,
}

#[kmip_enum]
pub enum RevocationReasonCode {
    Unspecified = 0x0000_0001,
    KeyCompromise = 0x0000_0002,
    CACompromise = 0x0000_0003,
    AffiliationChanged = 0x0000_0004,
    Superseded = 0x0000_0005,
    CessationOfOperation = 0x0000_0006,
    PrivilegeWithdrawn = 0x0000_0007,
    // Extensions 8XXXXXXX
}

/// The Revocation Reason attribute is a structure used to indicate why the
/// Managed Cryptographic Object was revoked (e.g., "compromised", "expired",
/// "no longer used", etc.). This attribute is only set by the server as a part
/// of the Revoke Operation.
/// The Revocation Message is an OPTIONAL field that is used exclusively for
/// audit trail/logging purposes and MAY contain additional information about
/// why the object was revoked (e.g., "Laptop stolen", or "Machine
/// decommissioned").
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RevocationReason {
    pub revocation_reason_code: RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_message: Option<String>,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(message) = &self.revocation_message {
            write!(f, "{}: {}", self.revocation_reason_code, message)
        } else {
            write!(f, "{}", self.revocation_reason_code)
        }
    }
}

/// `ApplicationSpecificInformation` structure for storing application-specific data
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ApplicationSpecificInformation {
    /// The application namespace
    pub application_namespace: String,
    /// The application data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_data: Option<String>,
}

impl std::fmt::Display for ApplicationSpecificInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(data) = &self.application_data {
            write!(f, "{}: {}", self.application_namespace, data)
        } else {
            write!(f, "{}", self.application_namespace)
        }
    }
}

/// `AlternativeName` structure for compact identification of objects using various name types
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct AlternativeName {
    /// Type of the alternative name
    pub alternative_name_type: AlternativeNameType,
    /// Value of the alternative name
    pub alternative_name_value: String,
}

impl std::fmt::Display for AlternativeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            self.alternative_name_type, self.alternative_name_value
        )
    }
}

/// `AlternativeNameType` enumeration
#[kmip_enum]
pub enum AlternativeNameType {
    UninterpretedTextString = 0x1,
    URI = 0x2,
    ObjectSerialNumber = 0x3,
    EmailAddress = 0x4,
    DNSName = 0x5,
    X500DirectoryName = 0x6,
    IPAddress = 0x7,
}

/// `KeyValueLocationType` enumeration indicates where a key value is stored
#[kmip_enum]
pub enum KeyValueLocationType {
    Unspecified = 0x1,
    OnPremise = 0x2,
    OffPremise = 0x3,
    OnPremiseOffPremise = 0x4,
}

/// `X509CertificateIdentifier` structure for identifying X.509 certificates
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct X509CertificateIdentifier {
    /// The Certificate Issuer
    pub issuer_distinguished_name: Vec<u8>,
    /// The Certificate Serial Number
    pub certificate_serial_number: Vec<u8>,
}

impl std::fmt::Display for X509CertificateIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Issuer: {}, Serial Number: {}",
            String::from_utf8_lossy(&self.issuer_distinguished_name),
            hex::encode(&self.certificate_serial_number)
        )
    }
}

/// This attribute is an indication of the State of an object as known to the
/// key management server. The State SHALL NOT be changed by using the Modify
/// Attribute operation on this attribute. The State SHALL only be changed by
/// the server as a part of other operations or other server processes. An
/// object SHALL be in one of the following states at any given time.
///
/// Note: The states correspond to those described in [SP800-57-1].
#[kmip_enum]
pub enum State {
    /// Pre-Active: The object exists and SHALL NOT be used for any cryptographic purpose.
    PreActive = 0x0000_0001,
    /// Active: The object SHALL be transitioned to the Active state prior to being used for any
    /// cryptographic purpose. The object SHALL only be used for all cryptographic purposes that
    /// are allowed by its Cryptographic Usage Mask attribute. If a Process Start Date attribute is
    /// set, then the object SHALL NOT be used for cryptographic purposes prior to the Process
    /// Start Date. If a Protect Stop attribute is set, then the object SHALL NOT be used for
    /// cryptographic purposes after the Process Stop Date.
    Active = 0x0000_0002,
    /// Deactivated: The object SHALL NOT be used for applying cryptographic protection (e.g.,
    /// encryption, signing, wrapping, `MACing`, deriving) . The object SHALL only be used for
    /// cryptographic purposes permitted by the Cryptographic Usage Mask attribute. The object
    /// SHOULD only be used to process cryptographically-protected information (e.g., decryption,
    /// signature verification, unwrapping, MAC verification under extraordinary circumstances and
    /// when special permission is granted.
    Deactivated = 0x0000_0003,
    /// Compromised: The object SHALL NOT be used for applying cryptographic protection (e.g.,
    /// encryption, signing, wrapping, `MACing`, deriving). The object SHOULD only be used to process
    /// cryptographically-protected information (e.g., decryption, signature verification,
    /// unwrapping, MAC verification in a client that is trusted to use managed objects that have
    /// been compromised. The object SHALL only be used for cryptographic purposes permitted by the
    /// Cryptographic Usage Mask attribute.
    Compromised = 0x0000_0004,
    /// Destroyed: The object SHALL NOT be used for any cryptographic purpose.
    Destroyed = 0x0000_0005,
    /// Destroyed Compromised: The object SHALL NOT be used for any cryptographic purpose; however
    /// its compromised status SHOULD be retained for audit or security purposes.
    Destroyed_Compromised = 0x0000_0006,
}
