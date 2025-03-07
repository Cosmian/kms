#![allow(non_camel_case_types)]

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::{kmip_1_4::kmip_data_structures::CryptographicParameters, kmip_2_1};

/// KMIP 1.4 Credential Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum CredentialType {
    UsernameAndPassword = 0x1,
    Device = 0x2,
    Attestation = 0x3,
}

/// KMIP 1.4 Key Compression Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x1,
    ECPublicKeyTypeX962Compressed = 0x2,
    ECPublicKeyTypeX962CompressedPrime = 0x3,
    ECPublicKeyTypeX962CompressedChar2 = 0x4,
}

impl KeyCompressionType {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_types::KeyCompressionType {
        match self {
            Self::ECPublicKeyTypeUncompressed => {
                kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeUncompressed
            }
            Self::ECPublicKeyTypeX962Compressed => {
                kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962CompressedPrime
            }
            Self::ECPublicKeyTypeX962CompressedPrime => {
                kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962CompressedPrime
            }
            Self::ECPublicKeyTypeX962CompressedChar2 => {
                kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962CompressedChar2
            }
        }
    }
}

/// KMIP 1.4 Key Format Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum KeyFormatType {
    Raw = 0x1,
    Opaque = 0x2,
    PKCS1 = 0x3,
    PKCS8 = 0x4,
    X509 = 0x5,
    ECPrivateKey = 0x6,
    TransparentSymmetricKey = 0x7,
    TransparentDSAPrivateKey = 0x8,
    TransparentDSAPublicKey = 0x9,
    TransparentRSAPrivateKey = 0xA,
    TransparentRSAPublicKey = 0xB,
    TransparentDHPrivateKey = 0xC,
    TransparentDHPublicKey = 0xD,
    TransparentECDSAPrivateKey = 0xE,
    TransparentECDSAPublicKey = 0xF,
    TransparentECDHPrivateKey = 0x10,
    TransparentECDHPublicKey = 0x11,
    TransparentECMQVPrivateKey = 0x12,
    TransparentECMQVPublicKey = 0x13,
}

impl KeyFormatType {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_types::KeyFormatType {
        match self {
            Self::Raw => kmip_2_1::kmip_types::KeyFormatType::Raw,
            Self::Opaque => kmip_2_1::kmip_types::KeyFormatType::Opaque,
            Self::PKCS1 => kmip_2_1::kmip_types::KeyFormatType::PKCS1,
            Self::PKCS8 => kmip_2_1::kmip_types::KeyFormatType::PKCS8,
            Self::X509 => kmip_2_1::kmip_types::KeyFormatType::X509,
            Self::ECPrivateKey => kmip_2_1::kmip_types::KeyFormatType::ECPrivateKey,
            Self::TransparentSymmetricKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentSymmetricKey
            }
            Self::TransparentDSAPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentDSAPrivateKey
            }
            Self::TransparentDSAPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentDSAPublicKey
            }
            Self::TransparentRSAPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentRSAPrivateKey
            }
            Self::TransparentRSAPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentRSAPublicKey
            }
            Self::TransparentDHPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentDHPrivateKey
            }
            Self::TransparentDHPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentDHPublicKey
            }
            Self::TransparentECDSAPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPrivateKey
            }
            Self::TransparentECDSAPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPublicKey
            }
            Self::TransparentECDHPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPrivateKey
            }
            Self::TransparentECDHPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPublicKey
            }
            Self::TransparentECMQVPrivateKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPrivateKey
            }
            Self::TransparentECMQVPublicKey => {
                kmip_2_1::kmip_types::KeyFormatType::TransparentECPublicKey
            }
        }
    }
}

/// KMIP 1.4 Wrapping Method Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum WrappingMethod {
    Encrypt = 0x1,
    MACSign = 0x2,
    EncryptThenMACSign = 0x3,
    MACSignThenEncrypt = 0x4,
    TR31 = 0x5,
}

/// KMIP 1.4 Certificate Type Enumeration  
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum CertificateType {
    X509 = 0x1,
    PGP = 0x2,
}

impl CertificateType {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_types::CertificateType {
        match self {
            Self::X509 => kmip_2_1::kmip_types::CertificateType::X509,
            Self::PGP => kmip_2_1::kmip_types::CertificateType::PGP,
        }
    }
}

/// KMIP 1.4 Split Key Method Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum SplitKeyMethod {
    XOR = 0x1,
    PolynomialSharingGF2_16 = 0x2,
    PolynomialSharingPrimeField = 0x3,
    PolynomialSharingGF2_8 = 0x4,
}

/// KMIP 1.4 Secret Data Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum SecretDataType {
    Password = 0x1,
    Seed = 0x2,
}

impl SecretDataType {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_types::SecretDataType {
        match self {
            Self::Password => kmip_2_1::kmip_types::SecretDataType::Password,
            Self::Seed => kmip_2_1::kmip_types::SecretDataType::Seed,
        }
    }
}

/// KMIP 1.4 Name Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum NameType {
    UninterpretedTextString = 0x1,
    URI = 0x2,
}

/// KMIP 1.4 Object Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Certificate = 0x1,
    SymmetricKey = 0x2,
    PublicKey = 0x3,
    PrivateKey = 0x4,
    SplitKey = 0x5,
    Template = 0x6,
    SecretData = 0x7,
    OpaqueObject = 0x8,
    PGPKey = 0x9,
}

/// KMIP 1.4 Cryptographic Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum CryptographicAlgorithm {
    DES = 0x1,
    ThreeES = 0x2,
    AES = 0x3,
    RSA = 0x4,
    DSA = 0x5,
    ECDSA = 0x6,
    HMACSHA1 = 0x7,
    HMACSHA224 = 0x8,
    HMACSHA256 = 0x9,
    HMACSHA384 = 0xA,
    HMACSHA512 = 0xB,
    HMACMD5 = 0xC,
    DH = 0xD,
    ECDH = 0xE,
    ECMQV = 0xF,
    Blowfish = 0x10,
    Camellia = 0x11,
    CAST5 = 0x12,
    IDEA = 0x13,
    MARS = 0x14,
    RC2 = 0x15,
    RC4 = 0x16,
    RC5 = 0x17,
    SKIPJACK = 0x18,
    Twofish = 0x19,
    EC = 0x1A,
    OneTimePad = 0x1B,
    ChaCha20 = 0x1C,
    Poly1305 = 0x1D,
    ChaCha20Poly1305 = 0x1E,
    SHA3224 = 0x1F,
    SHA3256 = 0x20,
    SHA3384 = 0x21,
    SHA3512 = 0x22,
    HMACSHA3224 = 0x23,
    HMACSHA3256 = 0x24,
    HMACSHA3384 = 0x25,
    HMACSHA3512 = 0x26,
    SHAKE128 = 0x27,
    SHAKE256 = 0x28,
}

impl CryptographicAlgorithm {
    pub fn to_kmip_2_1(&self) -> kmip_2_1::kmip_types::CryptographicAlgorithm {
        match self {
            Self::DES => kmip_2_1::kmip_types::CryptographicAlgorithm::DES,
            Self::ThreeES => kmip_2_1::kmip_types::CryptographicAlgorithm::DES,
            Self::AES => kmip_2_1::kmip_types::CryptographicAlgorithm::AES,
            Self::RSA => kmip_2_1::kmip_types::CryptographicAlgorithm::RSA,
            Self::DSA => kmip_2_1::kmip_types::CryptographicAlgorithm::DSA,
            Self::ECDSA => kmip_2_1::kmip_types::CryptographicAlgorithm::ECDSA,
            Self::HMACSHA1 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA1,
            Self::HMACSHA224 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA224,
            Self::HMACSHA256 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA256,
            Self::HMACSHA384 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA384,
            Self::HMACSHA512 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA512,
            Self::HMACMD5 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACMD5,
            Self::DH => kmip_2_1::kmip_types::CryptographicAlgorithm::DH,
            Self::ECDH => kmip_2_1::kmip_types::CryptographicAlgorithm::ECDH,
            Self::ECMQV => kmip_2_1::kmip_types::CryptographicAlgorithm::ECMQV,
            Self::Blowfish => kmip_2_1::kmip_types::CryptographicAlgorithm::Blowfish,
            Self::Camellia => kmip_2_1::kmip_types::CryptographicAlgorithm::Camellia,
            Self::CAST5 => kmip_2_1::kmip_types::CryptographicAlgorithm::CAST5,
            Self::IDEA => kmip_2_1::kmip_types::CryptographicAlgorithm::IDEA,
            Self::MARS => kmip_2_1::kmip_types::CryptographicAlgorithm::MARS,
            Self::RC2 => kmip_2_1::kmip_types::CryptographicAlgorithm::RC2,
            Self::RC4 => kmip_2_1::kmip_types::CryptographicAlgorithm::RC4,
            Self::RC5 => kmip_2_1::kmip_types::CryptographicAlgorithm::RC5,
            Self::SKIPJACK => kmip_2_1::kmip_types::CryptographicAlgorithm::SKIPJACK,
            Self::Twofish => kmip_2_1::kmip_types::CryptographicAlgorithm::Twofish,
            Self::EC => kmip_2_1::kmip_types::CryptographicAlgorithm::EC,
            Self::OneTimePad => kmip_2_1::kmip_types::CryptographicAlgorithm::OneTimePad,
            Self::ChaCha20 => kmip_2_1::kmip_types::CryptographicAlgorithm::ChaCha20,
            Self::Poly1305 => kmip_2_1::kmip_types::CryptographicAlgorithm::Poly1305,
            Self::ChaCha20Poly1305 => {
                kmip_2_1::kmip_types::CryptographicAlgorithm::ChaCha20Poly1305
            }
            Self::SHA3224 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3224,
            Self::SHA3256 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3256,
            Self::SHA3384 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3384,
            Self::SHA3512 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3512,
            Self::HMACSHA3224 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3224,
            Self::HMACSHA3256 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3256,
            Self::HMACSHA3384 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3384,
            Self::HMACSHA3512 => kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3512,
            Self::SHAKE128 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHAKE128,
            Self::SHAKE256 => kmip_2_1::kmip_types::CryptographicAlgorithm::SHAKE256,
        }
    }
}

/// KMIP 1.4 Block Cipher Mode Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum BlockCipherMode {
    CBC = 0x1,
    ECB = 0x2,
    PCBC = 0x3,
    CFB = 0x4,
    OFB = 0x5,
    CTR = 0x6,
    CMAC = 0x7,
    CCM = 0x8,
    GCM = 0x9,
    CBC_MAC = 0xA,
    XTS = 0xB,
    AESKeyWrapPadding = 0xC,
    NISTKeyWrap = 0xD,
    X9102AESKW = 0xE,
    X9102TDKW = 0xF,
    X9102AKW1 = 0x10,
    X9102AKW2 = 0x11,
    AEAD = 0x12,
}

/// KMIP 1.4 Padding Method Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum PaddingMethod {
    None = 0x1,
    OAEP = 0x2,
    PKCS5 = 0x3,
    SSL3 = 0x4,
    Zeros = 0x5,
    #[allow(non_camel_case_types)]
    ANSI_X923 = 0x6,
    #[allow(non_camel_case_types)]
    ISO_10126 = 0x7,
    PKCS1v15 = 0x8,
    X931 = 0x9,
    PSS = 0xA,
}

/// KMIP 1.4 Hashing Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum HashingAlgorithm {
    MD2 = 0x1,
    MD4 = 0x2,
    MD5 = 0x3,
    SHA1 = 0x4,
    SHA224 = 0x5,
    SHA256 = 0x6,
    SHA384 = 0x7,
    SHA512 = 0x8,
    RIPEMD160 = 0x9,
    Tiger = 0xA,
    Whirlpool = 0xB,
    SHA512_224 = 0xC,
    SHA512_256 = 0xD,
    SHA3_224 = 0xE,
    SHA3_256 = 0xF,
    SHA3_384 = 0x10,
    SHA3_512 = 0x11,
}

/// KMIP 1.4 Key Role Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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

/// KMIP 1.4 State Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum State {
    PreActive = 0x1,
    Active = 0x2,
    Deactivated = 0x3,
    Compromised = 0x4,
    Destroyed = 0x5,
    #[allow(non_camel_case_types)]
    Destroyed_Compromised = 0x6,
}

/// KMIP 1.4 Revocation Reason Code Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum RevocationReasonCode {
    Unspecified = 0x1,
    KeyCompromise = 0x2,
    CACompromise = 0x3,
    AffiliationChanged = 0x4,
    Superseded = 0x5,
    CessationOfOperation = 0x6,
    PrivilegeWithdrawn = 0x7,
}

/// KMIP 1.4 Link Type Enumeration
#[allow(non_camel_case_types)]
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum LinkType {
    Certificate_Link = 0x101,
    Public_Key_Link = 0x102,
    Private_Key_Link = 0x103,
    Derivation_Base_Object_Link = 0x104,
    Derived_Key_Link = 0x105,
    Replacement_Object_Link = 0x106,
    Replaced_Object_Link = 0x107,
    Parent_Link = 0x108,
    Child_Link = 0x109,
    Previous_Link = 0x10A,
    Next_Link = 0x10B,
}

/// KMIP 1.4 Derivation Method Enumeration
#[allow(non_camel_case_types)]
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum DerivationMethod {
    PBKDF2 = 0x1,
    HASH = 0x2,
    HMAC = 0x3,
    ENCRYPT = 0x4,
    NIST800_108_C = 0x5,
    NIST800_108_F = 0x6,
    NIST800_108_DPI = 0x7,
    ASYMMETRIC_KEY = 0x8,
}

/// KMIP 1.4 Certificate Request Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum CertificateRequestType {
    CRMF = 0x1,
    PKCS10 = 0x2,
    PEM = 0x3,
}

/// KMIP 1.4 Validity Indicator Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ValidityIndicator {
    Valid = 0x1,
    Invalid = 0x2,
    Unknown = 0x3,
}

/// KMIP 1.4 Query Function Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum QueryFunction {
    QueryOperations = 0x1,
    QueryObjects = 0x2,
    QueryServerInformation = 0x3,
    QueryApplicationNamespaces = 0x4,
    QueryExtensionList = 0x5,
    QueryExtensionMap = 0x6,
    QueryAttestationTypes = 0x7,
    QueryRNGParameters = 0x8,
    QueryValidationParameters = 0x9,
    QueryValidationCapabilities = 0xA,
    QueryProfiles = 0xB,
}

/// KMIP 1.4 Cancellation Result Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum CancellationResult {
    Canceled = 0x1,
    UnableToCancel = 0x2,
    Completed = 0x3,
    Failed = 0x4,
    Unavailable = 0x5,
}

/// KMIP 1.4 Put Function Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum PutFunction {
    New = 0x1,
    Replace = 0x2,
}

/// KMIP 1.4 Operation Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum OperationEnumeration {
    Create = 0x1,
    CreateKeyPair = 0x2,
    Register = 0x3,
    ReKey = 0x4,
    DeriveKey = 0x5,
    Certify = 0x6,
    ReCertify = 0x7,
    Locate = 0x8,
    Check = 0x9,
    Get = 0xA,
    GetAttributes = 0xB,
    GetAttributeList = 0xC,
    AddAttribute = 0xD,
    ModifyAttribute = 0xE,
    DeleteAttribute = 0xF,
    ObtainLease = 0x10,
    GetUsageAllocation = 0x11,
    Activate = 0x12,
    Revoke = 0x13,
    Destroy = 0x14,
    Archive = 0x15,
    Recover = 0x16,
    Validate = 0x17,
    Query = 0x18,
    Cancel = 0x19,
    Poll = 0x1A,
    Notify = 0x1B,
    Put = 0x1C,
    RekeyKeyPair = 0x1D,
    DiscoverVersions = 0x1E,
    Encrypt = 0x1F,
    Decrypt = 0x20,
    Sign = 0x21,
    SignatureVerify = 0x22,
    MAC = 0x23,
    MACVerify = 0x24,
    RNGRetrieve = 0x25,
    RNGSeed = 0x26,
    Hash = 0x27,
    CreateSplitKey = 0x28,
    JoinSplitKey = 0x29,
    Import = 0x2A,
    Export = 0x2B,
}

/// KMIP 1.4 Result Status Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ResultStatus {
    Success = 0x1,
    OperationFailed = 0x2,
    OperationPending = 0x3,
    OperationUndone = 0x4,
}

/// KMIP 1.4 Result Reason Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ResultReason {
    ItemNotFound = 0x1,
    ResponseTooLarge = 0x2,
    AuthenticationNotSuccessful = 0x3,
    InvalidMessage = 0x4,
    OperationNotSupported = 0x5,
    MissingData = 0x6,
    InvalidField = 0x7,
    FeatureNotSupported = 0x8,
    OperationCanceled = 0x9,
    CryptographicFailure = 0xA,
    IllegalOperation = 0xB,
    PermissionDenied = 0xC,
    ObjectArchived = 0xD,
    IndexOutOfBounds = 0xE,
    ApplicationNamespaceNotSupported = 0xF,
    KeyFormatTypeNotSupported = 0x10,
    KeyCompressionTypeNotSupported = 0x11,
    EncodingOptionError = 0x12,
    KeyValueNotPresent = 0x13,
    AttestationRequired = 0x14,
    AttestationFailed = 0x15,
    Sensitive = 0x16,
    NotExtractable = 0x17,
    ObjectAlreadyExists = 0x18,
    GeneralFailure = 0x100,
}

/// KMIP 1.4 Batch Error Continuation Option Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum BatchErrorContinuationOption {
    Continue = 0x1,
    Stop = 0x2,
    Undo = 0x3,
}

/// KMIP 1.4 Usage Limits Unit Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum UsageLimitsUnit {
    Byte = 0x1,
    Object = 0x2,
}

/// KMIP 1.4 Encoding Option Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum EncodingOption {
    NoEncoding = 0x1,
    TTLVEncoding = 0x2,
}

/// KMIP 1.4 Object Group Member Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ObjectGroupMember {
    GroupMemberFresh = 0x1,
    GroupMemberDefault = 0x2,
}

/// KMIP 1.4 Alternative Name Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum AlternativeNameType {
    UninterpretedTextString = 0x1,
    URI = 0x2,
    ObjectSerialNumber = 0x3,
    EmailAddress = 0x4,
    DNSName = 0x5,
    X500DirectoryName = 0x6,
    IPAddress = 0x7,
}

/// KMIP 1.4 Key Value Location Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum KeyValueLocationType {
    Unspecified = 0x1,
    OnPremise = 0x2,
    OffPremise = 0x3,
    OnPremiseOffPremise = 0x4,
}

/// KMIP 1.4 Attestation Type Enumeration
#[allow(non_camel_case_types)]
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum AttestationType {
    TPM_Quote = 0x1,
    TCG_Integrity_Report = 0x2,
    SAML_Assertion = 0x3,
}

/// KMIP 1.4 RNG Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum RNGAlgorithm {
    Unspecified = 0x1,
    FIPS186_2 = 0x2,
    DRBG = 0x3,
    NRBG = 0x4,
    ANSI_X931 = 0x5,
    ANSI_X962 = 0x6,
}

/// KMIP 1.4 DRBG Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum DRBGAlgorithm {
    Unspecified = 0x1,
    HashDRBG = 0x2,
    HMACDRBG = 0x3,
    CTRDRBG = 0x4,
}

/// KMIP 1.4 FIPS186 Variation Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum FIPS186Variation {
    KeyGeneration_FIPS186_2 = 0x1,
    KeyGeneration_FIPS186_3 = 0x2,
    KeyGeneration_FIPS186_4 = 0x3,
    SigGen_FIPS186_3 = 0x4,
    SigGen_FIPS186_4 = 0x5,
}

/// KMIP 1.4 Validation Authority Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum ValidationAuthorityType {
    Unspecified = 0x1,
    NIST_CMVP = 0x2,
    Common_Criteria = 0x3,
}

/// KMIP 1.4 Validation Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ValidationType {
    Unspecified = 0x1,
    Hardware = 0x2,
    Software = 0x3,
    Firmware = 0x4,
    Hybrid = 0x5,
}

/// KMIP 1.4 Profile Name Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ProfileName {
    BEK = 0x1,
    TKLC = 0x2,
    TKTLS = 0x3,
    TKSL = 0x4,
    TKApps = 0x5,
    TKBEK = 0x6,
    TKCS = 0x7,
    TKSW = 0x8,
}

/// KMIP 1.4 Unwrap Mode Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum UnwrapMode {
    Unspecified = 0x1,
    UsingWrappingKey = 0x2,
    UsingTransportKey = 0x3,
}

/// KMIP 1.4 Destroy Action Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum DestroyAction {
    Unspecified = 0x1,
    Zeroize = 0x2,
}

/// KMIP 1.4 Shredding Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ShreddingAlgorithm {
    Unspecified = 0x1,
    CryptoShred = 0x2,
}

/// KMIP 1.4 RNG Mode Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum RNGMode {
    SharedInstantiation = 0x1,
    NonSharedInstantiation = 0x2,
}

/// KMIP 1.4 Client Registration Method Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum ClientRegistrationMethod {
    Unspecified = 0x1,
    ServerPreProvided = 0x2,
    ServerOnDemand = 0x3,
    ClientGenerated = 0x4,
    ClientRegistered = 0x5,
}

/// KMIP 1.4 Key Wrap Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum KeyWrapType {
    NotWrapped = 0x1,
    AsRegistered = 0x2,
}

/// KMIP 1.4 Mask Generator Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum MaskGenerator {
    MGF1 = 0x1,
}

/// KMIP 1.4 Storage Status Mask Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum StorageStatusMask {
    Online = 0x1,
    Archival = 0x2,
    Destroyed = 0x4,
}

/// KMIP 1.4 Cryptographic Usage Mask Flags
pub const CRYPTOGRAPHIC_USAGE_MASK_SIGN: u32 = 0x1;
pub const CRYPTOGRAPHIC_USAGE_MASK_VERIFY: u32 = 0x2;
pub const CRYPTOGRAPHIC_USAGE_MASK_ENCRYPT: u32 = 0x4;
pub const CRYPTOGRAPHIC_USAGE_MASK_DECRYPT: u32 = 0x8;
pub const CRYPTOGRAPHIC_USAGE_MASK_WRAP_KEY: u32 = 0x10;
pub const CRYPTOGRAPHIC_USAGE_MASK_UNWRAP_KEY: u32 = 0x20;
pub const CRYPTOGRAPHIC_USAGE_MASK_EXPORT: u32 = 0x40;
pub const CRYPTOGRAPHIC_USAGE_MASK_MAC_GENERATE: u32 = 0x80;
pub const CRYPTOGRAPHIC_USAGE_MASK_MAC_VERIFY: u32 = 0x100;
pub const CRYPTOGRAPHIC_USAGE_MASK_DERIVE_KEY: u32 = 0x200;
pub const CRYPTOGRAPHIC_USAGE_MASK_CONTENT_COMMITMENT: u32 = 0x400;
pub const CRYPTOGRAPHIC_USAGE_MASK_KEY_AGREEMENT: u32 = 0x800;
pub const CRYPTOGRAPHIC_USAGE_MASK_CERTIFICATE_SIGN: u32 = 0x1000;
pub const CRYPTOGRAPHIC_USAGE_MASK_CRL_SIGN: u32 = 0x2000;
pub const CRYPTOGRAPHIC_USAGE_MASK_GENERATE_CRYPTOGRAM: u32 = 0x4000;
pub const CRYPTOGRAPHIC_USAGE_MASK_VALIDATE_CRYPTOGRAM: u32 = 0x8000;
pub const CRYPTOGRAPHIC_USAGE_MASK_TRANSLATE_ENCRYPT: u32 = 0x10000;
pub const CRYPTOGRAPHIC_USAGE_MASK_TRANSLATE_DECRYPT: u32 = 0x20000;
pub const CRYPTOGRAPHIC_USAGE_MASK_TRANSLATE_WRAP: u32 = 0x40000;
pub const CRYPTOGRAPHIC_USAGE_MASK_TRANSLATE_UNWRAP: u32 = 0x80000;

/// KMIP 1.4 Recommended Curve Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum RecommendedCurve {
    P192 = 0x1,
    K163 = 0x2,
    B163 = 0x3,
    P224 = 0x4,
    K233 = 0x5,
    B233 = 0x6,
    P256 = 0x7,
    K283 = 0x8,
    B283 = 0x9,
    P384 = 0xA,
    K409 = 0xB,
    B409 = 0xC,
    P521 = 0xD,
    K571 = 0xE,
    B571 = 0xF,
    Secp112r1 = 0x10,
    Secp112r2 = 0x11,
    Secp128r1 = 0x12,
    Secp128r2 = 0x13,
    Secp160r1 = 0x14,
    Secp160k1 = 0x15,
    Secp256k1 = 0x16,
    BrainpoolP160r1 = 0x17,
    BrainpoolP160t1 = 0x18,
    BrainpoolP192r1 = 0x19,
    BrainpoolP192t1 = 0x1A,
    BrainpoolP224r1 = 0x1B,
    BrainpoolP224t1 = 0x1C,
    BrainpoolP256r1 = 0x1D,
    BrainpoolP256t1 = 0x1E,
    BrainpoolP320r1 = 0x1F,
    BrainpoolP320t1 = 0x20,
    BrainpoolP384r1 = 0x21,
    BrainpoolP384t1 = 0x22,
    BrainpoolP512r1 = 0x23,
    BrainpoolP512t1 = 0x24,
}

/// KMIP 1.4 Digital Signature Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum DigitalSignatureAlgorithm {
    MD2WithRSAEncryption = 0x1,
    MD5WithRSAEncryption = 0x2,
    SHA1WithRSAEncryption = 0x3,
    SHA224WithRSAEncryption = 0x4,
    SHA256WithRSAEncryption = 0x5,
    SHA384WithRSAEncryption = 0x6,
    SHA512WithRSAEncryption = 0x7,
    RSASSAPSS = 0x8,
    DSAWithSHA1 = 0x9,
    DSAWithSHA224 = 0xA,
    DSAWithSHA256 = 0xB,
    ECDSAWithSHA1 = 0xC,
    ECDSAWithSHA224 = 0xD,
    ECDSAWithSHA256 = 0xE,
    ECDSAWithSHA384 = 0xF,
    ECDSAWithSHA512 = 0x10,
}

/// KMIP 1.4 Opaque Data Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum OpaqueDataType {
    Unknown = 0x1,
    PKCS12 = 0x2,
}

/// Attributes structure containing all KMIP 1.4 attributes (51 total)
/// as specified in Chapter 3, paragraphs 3.1 to 3.51
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Attributes {
    /// The Unique Identifier is generated by the server to uniquely identify a
    /// Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<String>,

    /// The Name attribute is a text string used to identify a Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<Vec<Name>>,

    /// The Object Type attribute describes the type of Managed Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<ObjectType>,

    /// The Cryptographic Algorithm attribute specifies the algorithm to be used
    /// with the Cryptographic Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// The Cryptographic Length attribute specifies the length in bits of the
    /// Cryptographic Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,

    /// The Cryptographic Parameters attribute is a structure that contains
    /// various cryptographic parameters to be used with the Cryptographic Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,

    /// The Cryptographic Domain Parameters attribute is a structure that contains
    /// various cryptographic domain parameters to be used with the Cryptographic Object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_domain_parameters: Option<CryptographicDomainParameters>,

    /// The Certificate Type attribute is a type of certificate (e.g., X.509).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<CertificateType>,

    /// The Certificate Length attribute specifies the length in bits of the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_length: Option<i32>,

    /// The X.509 Certificate Identifier attribute specifies the X.509 certificate identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_identifier: Option<X509CertificateIdentifier>,

    /// The X.509 Certificate Subject attribute specifies the subject of the X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_subject: Option<String>,

    /// The X.509 Certificate Issuer attribute specifies the issuer of the X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_509_certificate_issuer: Option<String>,

    /// The Certificate Identifier attribute specifies the identifier of the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_identifier: Option<String>,

    /// The Certificate Subject attribute specifies the subject of the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,

    /// The Certificate Issuer attribute specifies the issuer of the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_issuer: Option<String>,

    /// The Digital Signature Algorithm attribute specifies the algorithm used
    /// to generate the digital signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,

    /// The Digest attribute specifies the digest value computed for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,

    /// The Operation Policy Name attribute specifies the operation policy for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_policy_name: Option<String>,

    /// The Cryptographic Usage Mask attribute specifies the cryptographic operations
    /// that may be performed using the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_usage_mask: Option<CryptographicUsageMask>,

    /// The Lease Time attribute specifies the time period during which the client
    /// expects to maintain its interest in the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<i64>,

    /// The Usage Limits attribute specifies limitations on usage of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits: Option<UsageLimits>,

    /// The State attribute specifies the state of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,

    /// The Initial Date attribute specifies when the object was initially created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_date: Option<i64>,

    /// The Activation Date attribute specifies when the object becomes active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_date: Option<i64>,

    /// The Process Start Date attribute specifies the start date for a cryptographic process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_start_date: Option<i64>,

    /// The Protect Stop Date attribute specifies the stop date for a cryptographic process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protect_stop_date: Option<i64>,

    /// The Deactivation Date attribute specifies when the object becomes inactive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivation_date: Option<i64>,

    /// The Destroy Date attribute specifies when the object was destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destroy_date: Option<i64>,

    /// The Compromise Occurrence Date attribute specifies when a compromise of
    /// the object was detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_occurrence_date: Option<i64>,

    /// The Compromise Date attribute specifies when a compromise of the object
    /// might have occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromise_date: Option<i64>,

    /// The Revocation Reason attribute specifies the reason for revocation of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,

    /// The Archive Date attribute specifies when the object was archived.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_date: Option<i64>,

    /// The Object Group attribute specifies the object group to which the object belongs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_group: Option<String>,

    /// The Fresh attribute specifies whether the object is fresh or not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,

    /// The Link attribute specifies links to related objects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<Vec<Link>>,

    /// The Application Specific Information attribute specifies information
    /// specific to the application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_specific_information: Option<ApplicationSpecificInformation>,

    /// The Contact Information attribute specifies contact information for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_information: Option<String>,

    /// The Last Change Date attribute specifies the date and time of the last change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_change_date: Option<i64>,

    /// The Alternative Name attribute specifies alternative names for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternative_name: Option<AlternativeName>,

    /// The Key Value Present attribute indicates whether the key value is present
    /// in the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_value_present: Option<bool>,

    /// The Key Value Location attribute indicates the location of the key value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_value_location: Option<KeyValueLocationType>,

    /// The Original Creation Date attribute specifies the date and time of the
    /// original creation of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_creation_date: Option<i64>,

    /// The Random Number Generator attribute specifies the random number generator
    /// used to create the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_number_generator: Option<RandomNumberGenerator>,

    /// The PKCS#12 Friendly Name attribute specifies the friendly name of the object.
    #[serde(skip_serializing_if = "Option::is_none", rename = "PKCS12FriendlyName")]
    pub pkcs12_friendly_name: Option<String>,

    /// The Description attribute specifies a description of the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The Comment attribute specifies a comment for the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// The Sensitive attribute indicates whether the object is sensitive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<bool>,

    /// The Always Sensitive attribute indicates whether the object has always
    /// been sensitive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_sensitive: Option<bool>,

    /// The Extractable attribute indicates whether the object is extractable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extractable: Option<bool>,

    /// The Never Extractable attribute indicates whether the object has ever
    /// been extractable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub never_extractable: Option<bool>,
}

/// KMIP 1.4 Name structure containing a name type and value
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Name {
    pub name_value: String,
    pub name_type: NameType,
}

/// KMIP 1.4 Cryptographic Domain Parameters
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct CryptographicDomainParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qlength: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
}

/// KMIP 1.4 X509 Certificate Identifier
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct X509CertificateIdentifier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_alternative_name: Option<Vec<AlternativeName>>,
}

/// KMIP 1.4 Digest
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Digest {
    pub hashing_algorithm: HashingAlgorithm,
    pub digest_value: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
}

/// KMIP 1.4 Cryptographic Usage Mask (bitmask)
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct CryptographicUsageMask(pub u32);

/// KMIP 1.4 Usage Limits
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageLimits {
    pub usage_limits_unit: UsageLimitsUnit,
    pub usage_limits_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits_total: Option<u64>,
}

/// KMIP 1.4 Revocation Reason
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RevocationReason {
    pub revocation_reason_code: RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_message: Option<String>,
}

/// KMIP 1.4 Application Specific Information
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ApplicationSpecificInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_data: Option<String>,
}

/// KMIP 1.4 Alternative Name
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct AlternativeName {
    pub alternative_name_value: String,
    pub alternative_name_type: AlternativeNameType,
}

/// KMIP 1.4 Random Number Generator
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RandomNumberGenerator {
    pub rng_algorithm: RNGAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rng_mode: Option<RNGMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips186_variation: Option<FIPS186Variation>,
}

/// Link Structure represents the relationship between a Managed Object and another object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    pub link_type: LinkType,
    pub linked_object_identifier: LinkedObjectIdentifier,
}

/// LinkedObjectIdentifier defines the format of the object reference in a link.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum LinkedObjectIdentifier {
    TextString(String),
    Enumeration(i32),
    Index(i32),
}
