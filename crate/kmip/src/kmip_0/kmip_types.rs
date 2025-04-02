use std::fmt;

use kmip_derive::{kmip_enum, KmipEnumDeserialize, KmipEnumSerialize};
use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
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
    /// is outside of the scope of this protocol.
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

/// A Credential is a structure used for client identification purposes
/// and is not managed by the key management system
/// (e.g., user id/password pairs, Kerberos tokens, etc.).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Credential {
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
        ticket_type: TicketType,
        ticket_value: Vec<u8>,
    },
}

impl Credential {
    #[allow(dead_code)]
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

impl Serialize for Credential {
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
            Self::Ticket {
                ticket_type,
                ticket_value,
            } => {
                let mut st = serializer.serialize_struct("Ticket", 2)?;
                st.serialize_field("TicketType", ticket_type)?;
                st.serialize_field("TicketValue", ticket_value)?;
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Credential {
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
            TicketType,
            TicketValue,
        }

        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = Credential;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
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
                let mut ticket_type: Option<TicketType> = None;
                let mut ticket_value: Option<Vec<u8>> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Username => {
                            if username.is_some() {
                                return Err(de::Error::duplicate_field("username"))
                            }
                            username = Some(map.next_value()?);
                        }
                        Field::Password => {
                            if password.is_some() {
                                return Err(de::Error::duplicate_field("password"))
                            }
                            password = Some(map.next_value()?);
                        }
                        Field::DeviceSerialNumber => {
                            if device_serial_number.is_some() {
                                return Err(de::Error::duplicate_field("device_serial_number"))
                            }
                            device_serial_number = Some(map.next_value()?);
                        }
                        Field::DeviceIdentifier => {
                            if device_identifier.is_some() {
                                return Err(de::Error::duplicate_field("device_identifier"))
                            }
                            device_identifier = Some(map.next_value()?);
                        }
                        Field::NetworkIdentifier => {
                            if network_identifier.is_some() {
                                return Err(de::Error::duplicate_field("network_identifier"))
                            }
                            network_identifier = Some(map.next_value()?);
                        }
                        Field::MachineIdentifier => {
                            if machine_identifier.is_some() {
                                return Err(de::Error::duplicate_field("machine_identifier"))
                            }
                            machine_identifier = Some(map.next_value()?);
                        }
                        Field::MediaIdentifier => {
                            if media_identifier.is_some() {
                                return Err(de::Error::duplicate_field("media_identifier"))
                            }
                            media_identifier = Some(map.next_value()?);
                        }
                        Field::Nonce => {
                            if nonce.is_some() {
                                return Err(de::Error::duplicate_field("nonce"))
                            }
                            nonce = Some(map.next_value()?);
                        }
                        Field::AttestationType => {
                            if attestation_type.is_some() {
                                return Err(de::Error::duplicate_field("attestation_type"))
                            }
                            attestation_type = Some(map.next_value()?);
                        }
                        Field::AttestationMeasurement => {
                            if attestation_measurement.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "attestation_measurement_type",
                                ))
                            }
                            attestation_measurement = Some(map.next_value()?);
                        }
                        Field::AttestationAssertion => {
                            if attestation_assertion.is_some() {
                                return Err(de::Error::duplicate_field("attestation_assertion"))
                            }
                            attestation_assertion = Some(map.next_value()?);
                        }
                        Field::OneTimePassword => {
                            if one_time_password.is_some() {
                                return Err(de::Error::duplicate_field("one_time_password"))
                            }
                            one_time_password = Some(map.next_value()?);
                        }
                        Field::Timestamp => {
                            if timestamp.is_some() {
                                return Err(de::Error::duplicate_field("timestamp"))
                            }
                            timestamp = Some(map.next_value()?);
                        }
                        Field::HashingAlgorithm => {
                            if hashing_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("hashing_algorithm"))
                            }
                            hashing_algorithm = Some(map.next_value()?);
                        }
                        Field::HashedPassword => {
                            if hashed_password.is_some() {
                                return Err(de::Error::duplicate_field("hashed_password"))
                            }
                            hashed_password = Some(map.next_value()?);
                        }
                        Field::TicketType => {
                            if ticket_type.is_some() {
                                return Err(de::Error::duplicate_field("ticket_type"))
                            }
                            ticket_type = Some(map.next_value()?);
                        }
                        Field::TicketValue => {
                            if ticket_value.is_some() {
                                return Err(de::Error::duplicate_field("ticket_value"))
                            }
                            ticket_value = Some(map.next_value()?);
                        }
                    }
                }

                if let (Some(nonce), Some(attestation_type)) = (nonce, attestation_type) {
                    return Ok(Credential::Attestation {
                        nonce,
                        attestation_type,
                        attestation_measurement,
                        attestation_assertion,
                    })
                } else if let (Some(ticket_type), Some(ticket_value)) = (ticket_type, ticket_value)
                {
                    return Ok(Credential::Ticket {
                        ticket_type,
                        ticket_value,
                    })
                } else if let Some(username) = username {
                    if let (Some(timestamp), Some(hashed_password)) = (timestamp, hashed_password) {
                        return Ok(Credential::HashedPassword {
                            username,
                            timestamp,
                            hashing_algorithm,
                            hashed_password,
                        })
                    } else if let Some(one_time_password) = one_time_password {
                        return Ok(Credential::OneTimePassword {
                            username,
                            password,
                            one_time_password,
                        })
                    }

                    return Ok(Credential::UsernameAndPassword { username, password })
                }

                Ok(Credential::Device {
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
            "ticket_type",
            "ticket_value",
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
    General_Failure = 0x0000_0100,
}

impl Default for ErrorReason {
    fn default() -> Self {
        Self::General_Failure
    }
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
