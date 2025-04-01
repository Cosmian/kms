#![allow(non_camel_case_types)]

use kmip_derive::{kmip_enum, KmipEnumDeserialize, KmipEnumSerialize};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{
    kmip_0::kmip_types::HashingAlgorithm,
    kmip_2_1::{self},
    KmipError,
};

/// KMIP 1.4 Credential Type Enumeration
#[kmip_enum]
pub enum CredentialType {
    UsernameAndPassword = 0x1,
    Device = 0x2,
    Attestation = 0x3,
}

/// KMIP 1.4 Key Compression Type Enumeration
#[kmip_enum]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x1,
    ECPublicKeyTypeX962Compressed = 0x2,
    ECPublicKeyTypeX962CompressedPrime = 0x3,
    ECPublicKeyTypeX962CompressedChar2 = 0x4,
}

impl From<KeyCompressionType> for kmip_2_1::kmip_types::KeyCompressionType {
    fn from(val: KeyCompressionType) -> Self {
        match val {
            KeyCompressionType::ECPublicKeyTypeUncompressed => Self::ECPublicKeyTypeUncompressed,
            KeyCompressionType::ECPublicKeyTypeX962Compressed
            | KeyCompressionType::ECPublicKeyTypeX962CompressedPrime => {
                Self::ECPublicKeyTypeX962CompressedPrime
            }
            KeyCompressionType::ECPublicKeyTypeX962CompressedChar2 => {
                Self::ECPublicKeyTypeX962CompressedChar2
            }
        }
    }
}

/// KMIP 1.4 Key Format Type Enumeration
#[kmip_enum]
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

impl From<KeyFormatType> for kmip_2_1::kmip_types::KeyFormatType {
    fn from(val: KeyFormatType) -> Self {
        match val {
            KeyFormatType::Raw => Self::Raw,
            KeyFormatType::Opaque => Self::Opaque,
            KeyFormatType::PKCS1 => Self::PKCS1,
            KeyFormatType::PKCS8 => Self::PKCS8,
            KeyFormatType::X509 => Self::X509,
            KeyFormatType::ECPrivateKey => Self::ECPrivateKey,
            KeyFormatType::TransparentSymmetricKey => Self::TransparentSymmetricKey,
            KeyFormatType::TransparentDSAPrivateKey => Self::TransparentDSAPrivateKey,
            KeyFormatType::TransparentDSAPublicKey => Self::TransparentDSAPublicKey,
            KeyFormatType::TransparentRSAPrivateKey => Self::TransparentRSAPrivateKey,
            KeyFormatType::TransparentRSAPublicKey => Self::TransparentRSAPublicKey,
            KeyFormatType::TransparentDHPrivateKey => Self::TransparentDHPrivateKey,
            KeyFormatType::TransparentDHPublicKey => Self::TransparentDHPublicKey,
            KeyFormatType::TransparentECDSAPublicKey
            | KeyFormatType::TransparentECMQVPublicKey
            | KeyFormatType::TransparentECDHPublicKey => Self::TransparentECPublicKey,
            KeyFormatType::TransparentECDHPrivateKey
            | KeyFormatType::TransparentECMQVPrivateKey
            | KeyFormatType::TransparentECDSAPrivateKey => Self::TransparentECPrivateKey,
        }
    }
}

/// KMIP 1.4 Wrapping Method Enumeration
#[kmip_enum]
pub enum WrappingMethod {
    Encrypt = 0x1,
    MACSign = 0x2,
    EncryptThenMACSign = 0x3,
    MACSignThenEncrypt = 0x4,
    TR31 = 0x5,
}

impl From<WrappingMethod> for kmip_2_1::kmip_types::WrappingMethod {
    fn from(val: WrappingMethod) -> Self {
        match val {
            WrappingMethod::Encrypt => Self::Encrypt,
            WrappingMethod::MACSign => Self::MACSign,
            WrappingMethod::EncryptThenMACSign => Self::EncryptThenMACSign,
            WrappingMethod::MACSignThenEncrypt => Self::MACSignThenEncrypt,
            WrappingMethod::TR31 => Self::TR31,
        }
    }
}

/// KMIP 1.4 Certificate Type Enumeration
#[kmip_enum]
pub enum CertificateType {
    X509 = 0x1,
    PGP = 0x2,
}

impl From<CertificateType> for kmip_2_1::kmip_types::CertificateType {
    fn from(val: CertificateType) -> Self {
        match val {
            CertificateType::X509 => Self::X509,
            CertificateType::PGP => Self::PGP,
        }
    }
}

/// KMIP 1.4 Split Key Method Enumeration
#[kmip_enum]
pub enum SplitKeyMethod {
    XOR = 0x0000_0001,
    // #[serde(rename = "Polynomial Sharing GF (2^16)")]
    PolynomialSharingGf216 = 0x0000_0002,
    // #[serde(rename = "Polynomial Sharing Prime Field")]
    PolynomialSharingPrimeField = 0x0000_0003,
    // #[serde(rename = "Polynomial Sharing GF (2^8)")]
    PolynomialSharingGf28 = 0x0000_0004,
}

impl From<SplitKeyMethod> for kmip_2_1::kmip_types::SplitKeyMethod {
    fn from(val: SplitKeyMethod) -> Self {
        match val {
            SplitKeyMethod::XOR => Self::XOR,
            SplitKeyMethod::PolynomialSharingGf216 => Self::PolynomialSharingGf216,
            SplitKeyMethod::PolynomialSharingPrimeField => Self::PolynomialSharingPrimeField,
            SplitKeyMethod::PolynomialSharingGf28 => Self::PolynomialSharingGf28,
        }
    }
}

/// KMIP 1.4 Secret Data Type Enumeration
#[kmip_enum]
pub enum SecretDataType {
    Password = 0x1,
    Seed = 0x2,
}

impl From<SecretDataType> for kmip_2_1::kmip_types::SecretDataType {
    fn from(val: SecretDataType) -> Self {
        match val {
            SecretDataType::Password => Self::Password,
            SecretDataType::Seed => Self::Seed,
        }
    }
}

/// KMIP 1.4 Name Type Enumeration
#[kmip_enum]
pub enum NameType {
    UninterpretedTextString = 0x1,
    URI = 0x2,
}

impl From<NameType> for kmip_2_1::kmip_types::NameType {
    fn from(val: NameType) -> Self {
        match val {
            NameType::UninterpretedTextString => Self::UninterpretedTextString,
            NameType::URI => Self::URI,
        }
    }
}

/// KMIP 1.4 Object Type Enumeration
#[kmip_enum]
pub enum ObjectType {
    Certificate = 0x1,
    SymmetricKey = 0x2,
    PublicKey = 0x3,
    PrivateKey = 0x4,
    SplitKey = 0x5,
    // Not supported in KMIP 2.1 and deprecated in KMIP 1.4
    // Template = 0x6,
    SecretData = 0x7,
    OpaqueObject = 0x8,
    PGPKey = 0x9,
}

impl From<ObjectType> for u32 {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::Certificate => 0x01,
            ObjectType::SymmetricKey => 0x02,
            ObjectType::PublicKey => 0x03,
            ObjectType::PrivateKey => 0x04,
            ObjectType::SplitKey => 0x05,
            // ObjectType::Template => 0x06,
            ObjectType::SecretData => 0x07,
            ObjectType::OpaqueObject => 0x08,
            ObjectType::PGPKey => 0x09,
        }
    }
}

impl TryFrom<u32> for ObjectType {
    type Error = KmipError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Certificate),
            0x02 => Ok(Self::SymmetricKey),
            0x03 => Ok(Self::PublicKey),
            0x04 => Ok(Self::PrivateKey),
            0x05 => Ok(Self::SplitKey),
            0x06 => Err(KmipError::InvalidKmip14Value(
                ResultReason::InvalidField,
                "Template is not supported in this version of KMIP 1.4".to_owned(),
            )),
            0x07 => Ok(Self::SecretData),
            0x08 => Ok(Self::OpaqueObject),
            0x09 => Ok(Self::PGPKey),
            _ => Err(KmipError::InvalidKmip14Value(
                ResultReason::InvalidField,
                format!("Invalid Object Type value: {value}"),
            )),
        }
    }
}

impl From<ObjectType> for kmip_2_1::kmip_objects::ObjectType {
    fn from(val: ObjectType) -> Self {
        match val {
            ObjectType::Certificate => Self::Certificate,
            ObjectType::SymmetricKey => Self::SymmetricKey,
            ObjectType::PublicKey => Self::PublicKey,
            ObjectType::PrivateKey => Self::PrivateKey,
            ObjectType::SplitKey => Self::SplitKey,
            ObjectType::SecretData => Self::SecretData,
            ObjectType::OpaqueObject => Self::OpaqueObject,
            ObjectType::PGPKey => Self::PGPKey,
        }
    }
}

/// KMIP 1.4 Cryptographic Algorithm Enumeration
#[kmip_enum]
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

impl From<CryptographicAlgorithm> for kmip_2_1::kmip_types::CryptographicAlgorithm {
    fn from(val: CryptographicAlgorithm) -> Self {
        match val {
            CryptographicAlgorithm::DES | CryptographicAlgorithm::ThreeES => Self::DES,
            CryptographicAlgorithm::AES => Self::AES,
            CryptographicAlgorithm::RSA => Self::RSA,
            CryptographicAlgorithm::DSA => Self::DSA,
            CryptographicAlgorithm::ECDSA => Self::ECDSA,
            CryptographicAlgorithm::HMACSHA1 => Self::HMACSHA1,
            CryptographicAlgorithm::HMACSHA224 => Self::HMACSHA224,
            CryptographicAlgorithm::HMACSHA256 => Self::HMACSHA256,
            CryptographicAlgorithm::HMACSHA384 => Self::HMACSHA384,
            CryptographicAlgorithm::HMACSHA512 => Self::HMACSHA512,
            CryptographicAlgorithm::HMACMD5 => Self::HMACMD5,
            CryptographicAlgorithm::DH => Self::DH,
            CryptographicAlgorithm::ECDH => Self::ECDH,
            CryptographicAlgorithm::ECMQV => Self::ECMQV,
            CryptographicAlgorithm::Blowfish => Self::Blowfish,
            CryptographicAlgorithm::Camellia => Self::Camellia,
            CryptographicAlgorithm::CAST5 => Self::CAST5,
            CryptographicAlgorithm::IDEA => Self::IDEA,
            CryptographicAlgorithm::MARS => Self::MARS,
            CryptographicAlgorithm::RC2 => Self::RC2,
            CryptographicAlgorithm::RC4 => Self::RC4,
            CryptographicAlgorithm::RC5 => Self::RC5,
            CryptographicAlgorithm::SKIPJACK => Self::SKIPJACK,
            CryptographicAlgorithm::Twofish => Self::Twofish,
            CryptographicAlgorithm::EC => Self::EC,
            CryptographicAlgorithm::OneTimePad => Self::OneTimePad,
            CryptographicAlgorithm::ChaCha20 => Self::ChaCha20,
            CryptographicAlgorithm::Poly1305 => Self::Poly1305,
            CryptographicAlgorithm::ChaCha20Poly1305 => Self::ChaCha20Poly1305,
            CryptographicAlgorithm::SHA3224 => Self::SHA3224,
            CryptographicAlgorithm::SHA3256 => Self::SHA3256,
            CryptographicAlgorithm::SHA3384 => Self::SHA3384,
            CryptographicAlgorithm::SHA3512 => Self::SHA3512,
            CryptographicAlgorithm::HMACSHA3224 => Self::HMACSHA3224,
            CryptographicAlgorithm::HMACSHA3256 => Self::HMACSHA3256,
            CryptographicAlgorithm::HMACSHA3384 => Self::HMACSHA3384,
            CryptographicAlgorithm::HMACSHA3512 => Self::HMACSHA3512,
            CryptographicAlgorithm::SHAKE128 => Self::SHAKE128,
            CryptographicAlgorithm::SHAKE256 => Self::SHAKE256,
        }
    }
}

/// KMIP 1.4 Block Cipher Mode Enumeration
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
    // #[serde(rename = "CBC-MAC")]
    CBCMAC = 0x0000_000A,
    XTS = 0x0000_000B,
    AESKeyWrapPadding = 0x0000_000C,
    // NISTKeyWrap refers to rfc5649
    NISTKeyWrap = 0x8000_000D,
    // #[serde(rename = "X9.102 AESKW")]
    X9102AESKW = 0x0000_000E,
    // #[serde(rename = "X9.102 TDKW")]
    X9102TDKW = 0x0000_000F,
    // #[serde(rename = "X9.102 AKW1")]
    X9102AKW1 = 0x0000_0010,
    // #[serde(rename = "X9.102 AKW2")]
    X9102AKW2 = 0x0000_0011,
    AEAD = 0x0000_0012,
    // Extensions - 8XXXXXXX
    // AES GCM SIV
    GCMSIV = 0x8000_0002,
}

impl From<BlockCipherMode> for kmip_2_1::kmip_types::BlockCipherMode {
    fn from(val: BlockCipherMode) -> Self {
        match val {
            BlockCipherMode::CBC => Self::CBC,
            BlockCipherMode::ECB => Self::ECB,
            BlockCipherMode::PCBC => Self::PCBC,
            BlockCipherMode::CFB => Self::CFB,
            BlockCipherMode::OFB => Self::OFB,
            BlockCipherMode::CTR => Self::CTR,
            BlockCipherMode::CMAC => Self::CMAC,
            BlockCipherMode::CCM => Self::CCM,
            BlockCipherMode::GCM => Self::GCM,
            BlockCipherMode::CBCMAC => Self::CBCMAC,
            BlockCipherMode::XTS => Self::XTS,
            BlockCipherMode::AESKeyWrapPadding => Self::AESKeyWrapPadding,
            BlockCipherMode::NISTKeyWrap => Self::NISTKeyWrap,
            BlockCipherMode::X9102AESKW => Self::X9102AESKW,
            BlockCipherMode::X9102TDKW => Self::X9102TDKW,
            BlockCipherMode::X9102AKW1 => Self::X9102AKW1,
            BlockCipherMode::X9102AKW2 => Self::X9102AKW2,
            BlockCipherMode::AEAD => Self::AEAD,
            BlockCipherMode::GCMSIV => Self::GCMSIV,
        }
    }
}

/// KMIP 1.4 Padding Method Enumeration
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
impl From<PaddingMethod> for kmip_2_1::kmip_types::PaddingMethod {
    fn from(val: PaddingMethod) -> Self {
        match val {
            PaddingMethod::None => Self::None,
            PaddingMethod::OAEP => Self::OAEP,
            PaddingMethod::PKCS5 => Self::PKCS5,
            PaddingMethod::SSL3 => Self::SSL3,
            PaddingMethod::Zeros => Self::Zeros,
            PaddingMethod::ANSI_X923 => Self::ANSI_X923,
            PaddingMethod::ISO10126 => Self::ISO10126,
            PaddingMethod::PKCS1v15 => Self::PKCS1v15,
            PaddingMethod::X931 => Self::X931,
            PaddingMethod::PSS => Self::PSS,
        }
    }
}

/// KMIP 1.4 Key Role Type Enumeration
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

impl From<KeyRoleType> for kmip_2_1::kmip_types::KeyRoleType {
    fn from(val: KeyRoleType) -> Self {
        match val {
            KeyRoleType::BDK => Self::BDK,
            KeyRoleType::CVK => Self::CVK,
            KeyRoleType::DEK => Self::DEK,
            KeyRoleType::MKAC => Self::MKAC,
            KeyRoleType::MKSMC => Self::MKSMC,
            KeyRoleType::MKSMI => Self::MKSMI,
            KeyRoleType::MKDAC => Self::MKDAC,
            KeyRoleType::MKDN => Self::MKDN,
            KeyRoleType::MKCP => Self::MKCP,
            KeyRoleType::MKOTH => Self::MKOTH,
            KeyRoleType::KEK => Self::KEK,
            KeyRoleType::MAC16609 => Self::MAC16609,
            KeyRoleType::MAC97971 => Self::MAC97971,
            KeyRoleType::MAC97972 => Self::MAC97972,
            KeyRoleType::MAC97973 => Self::MAC97973,
            KeyRoleType::MAC97974 => Self::MAC97974,
            KeyRoleType::MAC97975 => Self::MAC97975,
            KeyRoleType::ZPK => Self::ZPK,
            KeyRoleType::PVKIBM => Self::PVKIBM,
            KeyRoleType::PVKPVV => Self::PVKPVV,
            KeyRoleType::PVKOTH => Self::PVKOTH,
            KeyRoleType::DUKPT => Self::DUKPT,
            KeyRoleType::IV => Self::IV,
            KeyRoleType::TRKBK => Self::TRKBK,
        }
    }
}

/// KMIP 1.4 State Enumeration
#[kmip_enum]
pub enum State {
    PreActive = 0x1,
    Active = 0x2,
    Deactivated = 0x3,
    Compromised = 0x4,
    Destroyed = 0x5,
    #[allow(non_camel_case_types)]
    Destroyed_Compromised = 0x6,
}

impl From<State> for kmip_2_1::kmip_types::State {
    fn from(val: State) -> Self {
        match val {
            State::PreActive => Self::PreActive,
            State::Active => Self::Active,
            State::Deactivated => Self::Deactivated,
            State::Compromised => Self::Compromised,
            State::Destroyed | State::Destroyed_Compromised => Self::Destroyed,
        }
    }
}

/// KMIP 1.4 Revocation Reason Code Enumeration
#[kmip_enum]
pub enum RevocationReasonCode {
    Unspecified = 0x1,
    KeyCompromise = 0x2,
    CACompromise = 0x3,
    AffiliationChanged = 0x4,
    Superseded = 0x5,
    CessationOfOperation = 0x6,
    PrivilegeWithdrawn = 0x7,
}

impl From<RevocationReasonCode> for kmip_2_1::kmip_types::RevocationReasonCode {
    fn from(val: RevocationReasonCode) -> Self {
        match val {
            RevocationReasonCode::Unspecified => Self::Unspecified,
            RevocationReasonCode::KeyCompromise => Self::KeyCompromise,
            RevocationReasonCode::CACompromise => Self::CACompromise,
            RevocationReasonCode::AffiliationChanged => Self::AffiliationChanged,
            RevocationReasonCode::Superseded => Self::Superseded,
            RevocationReasonCode::CessationOfOperation => Self::CessationOfOperation,
            RevocationReasonCode::PrivilegeWithdrawn => Self::PrivilegeWithdrawn,
        }
    }
}

/// KMIP 1.4 Link Type Enumeration
#[kmip_enum]
pub enum LinkType {
    CertificateLink = 0x101,
    PublicKeyLink = 0x102,
    PrivateKeyLink = 0x103,
    DerivationBaseObjectLink = 0x104,
    DerivedKeyLink = 0x105,
    ReplacementObjectLink = 0x106,
    ReplacedObjectLink = 0x107,
    ParentLink = 0x108,
    ChildLink = 0x109,
    PreviousLink = 0x10A,
    NextLink = 0x10B,
}

impl From<LinkType> for kmip_2_1::kmip_types::LinkType {
    fn from(val: LinkType) -> Self {
        match val {
            LinkType::CertificateLink => Self::CertificateLink,
            LinkType::PublicKeyLink => Self::PublicKeyLink,
            LinkType::PrivateKeyLink => Self::PrivateKeyLink,
            LinkType::DerivationBaseObjectLink => Self::DerivationBaseObjectLink,
            LinkType::DerivedKeyLink => Self::DerivedKeyLink,
            LinkType::ReplacementObjectLink => Self::ReplacementObjectLink,
            LinkType::ReplacedObjectLink => Self::ReplacedObjectLink,
            LinkType::ParentLink => Self::ParentLink,
            LinkType::ChildLink => Self::ChildLink,
            LinkType::PreviousLink => Self::PreviousLink,
            LinkType::NextLink => Self::NextLink,
        }
    }
}

/// KMIP 1.4 Derivation Method Enumeration
#[kmip_enum]
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
#[kmip_enum]
pub enum CertificateRequestType {
    CRMF = 0x1,
    PKCS10 = 0x2,
    PEM = 0x3,
}

/// KMIP 1.4 Validity Indicator Enumeration
#[kmip_enum]
pub enum ValidityIndicator {
    Valid = 0x1,
    Invalid = 0x2,
    Unknown = 0x3,
}

/// KMIP 1.4 Query Function Enumeration
#[kmip_enum]
pub enum QueryFunction {
    QueryOperations = 0x1,
    QueryObjects = 0x2,
    QueryServerInformation = 0x3,
    QueryApplicationNamespaces = 0x4,
    QueryExtensionList = 0x5,
    QueryExtensionMap = 0x6,
    QueryAttestationTypes = 0x7,
    QueryRNGs = 0x8,
    QueryValidations = 0x9,
    QueryProfiles = 0xA,
    QueryCapabilities = 0xB,
    QueryClientRegistrationMethods = 0xC,
}

/// KMIP 1.4 Cancellation Result Enumeration
#[kmip_enum]
pub enum CancellationResult {
    Canceled = 0x1,
    UnableToCancel = 0x2,
    Completed = 0x3,
    Failed = 0x4,
    Unavailable = 0x5,
}

/// KMIP 1.4 Put Function Enumeration
#[kmip_enum]
pub enum PutFunction {
    New = 0x1,
    Replace = 0x2,
}

/// KMIP 1.4 Operation Enumeration
#[kmip_enum]
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
    ReKeyKeyPair = 0x1D,
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

impl From<OperationEnumeration> for kmip_2_1::kmip_types::OperationEnumeration {
    fn from(value: OperationEnumeration) -> Self {
        match value {
            OperationEnumeration::Create => Self::Create,
            OperationEnumeration::CreateKeyPair => Self::CreateKeyPair,
            OperationEnumeration::Register => Self::Register,
            OperationEnumeration::ReKey => Self::ReKey,
            OperationEnumeration::DeriveKey => Self::DeriveKey,
            OperationEnumeration::Certify => Self::Certify,
            OperationEnumeration::ReCertify => Self::ReCertify,
            OperationEnumeration::Locate => Self::Locate,
            OperationEnumeration::Check => Self::Check,
            OperationEnumeration::Get => Self::Get,
            OperationEnumeration::GetAttributes => Self::GetAttributes,
            OperationEnumeration::GetAttributeList => Self::GetAttributeList,
            OperationEnumeration::AddAttribute => Self::AddAttribute,
            OperationEnumeration::ModifyAttribute => Self::ModifyAttribute,
            OperationEnumeration::DeleteAttribute => Self::DeleteAttribute,
            OperationEnumeration::ObtainLease => Self::ObtainLease,
            OperationEnumeration::GetUsageAllocation => Self::GetUsageAllocation,
            OperationEnumeration::Activate => Self::Activate,
            OperationEnumeration::Revoke => Self::Revoke,
            OperationEnumeration::Destroy => Self::Destroy,
            OperationEnumeration::Archive => Self::Archive,
            OperationEnumeration::Recover => Self::Recover,
            OperationEnumeration::Validate => Self::Validate,
            OperationEnumeration::Query => Self::Query,
            OperationEnumeration::Cancel => Self::Cancel,
            OperationEnumeration::Poll => Self::Poll,
            OperationEnumeration::Notify => Self::Notify,
            OperationEnumeration::Put => Self::Put,
            OperationEnumeration::ReKeyKeyPair => Self::ReKeyKeyPair,
            OperationEnumeration::DiscoverVersions => Self::DiscoverVersions,
            OperationEnumeration::Encrypt => Self::Encrypt,
            OperationEnumeration::Decrypt => Self::Decrypt,
            OperationEnumeration::Sign => Self::Sign,
            OperationEnumeration::SignatureVerify => Self::SignatureVerify,
            OperationEnumeration::MAC => Self::MAC,
            OperationEnumeration::MACVerify => Self::MACVerify,
            OperationEnumeration::RNGRetrieve => Self::RNGRetrieve,
            OperationEnumeration::RNGSeed => Self::RNGSeed,
            OperationEnumeration::Hash => Self::Hash,
            OperationEnumeration::CreateSplitKey => Self::CreateSplitKey,
            OperationEnumeration::JoinSplitKey => Self::JoinSplitKey,
            OperationEnumeration::Import => Self::Import,
            OperationEnumeration::Export => Self::Export,
        }
    }
}

/// KMIP 1.4 Result Status Enumeration
#[kmip_enum]
pub enum ResultStatus {
    Success = 0x1,
    OperationFailed = 0x2,
    OperationPending = 0x3,
    OperationUndone = 0x4,
}

/// KMIP 1.4 Result Reason Enumeration
#[kmip_enum]
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

/// KMIP 1.4 Usage Limits Unit Enumeration
#[kmip_enum]
pub enum UsageLimitsUnit {
    Byte = 0x1,
    Object = 0x2,
}

impl From<UsageLimitsUnit> for kmip_2_1::kmip_types::UsageLimitsUnit {
    fn from(val: UsageLimitsUnit) -> Self {
        match val {
            UsageLimitsUnit::Byte => Self::Byte,
            UsageLimitsUnit::Object => Self::Object,
        }
    }
}

/// KMIP 1.4 Encoding Option Enumeration
#[kmip_enum]
pub enum EncodingOption {
    NoEncoding = 0x1,
    TTLVEncoding = 0x2,
}

impl From<EncodingOption> for kmip_2_1::kmip_types::EncodingOption {
    fn from(val: EncodingOption) -> Self {
        match val {
            EncodingOption::NoEncoding => Self::NoEncoding,
            EncodingOption::TTLVEncoding => Self::TTLVEncoding,
        }
    }
}

/// KMIP 1.4 Object Group Member Enumeration
#[kmip_enum]
pub enum ObjectGroupMember {
    GroupMemberFresh = 0x1,
    GroupMemberDefault = 0x2,
}

/// KMIP 1.4 Alternative Name Type Enumeration
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

impl From<AlternativeNameType> for kmip_2_1::kmip_types::AlternativeNameType {
    fn from(val: AlternativeNameType) -> Self {
        match val {
            AlternativeNameType::UninterpretedTextString => Self::UninterpretedTextString,
            AlternativeNameType::URI => Self::URI,
            AlternativeNameType::ObjectSerialNumber => Self::ObjectSerialNumber,
            AlternativeNameType::EmailAddress => Self::EmailAddress,
            AlternativeNameType::DNSName => Self::DNSName,
            AlternativeNameType::X500DirectoryName => Self::X500DirectoryName,
            AlternativeNameType::IPAddress => Self::IPAddress,
        }
    }
}

/// KMIP 1.4 Key Value Location Type Enumeration
#[kmip_enum]
pub enum KeyValueLocationType {
    Unspecified = 0x1,
    OnPremise = 0x2,
    OffPremise = 0x3,
    OnPremiseOffPremise = 0x4,
}

impl From<KeyValueLocationType> for kmip_2_1::kmip_types::KeyValueLocationType {
    fn from(val: KeyValueLocationType) -> Self {
        match val {
            KeyValueLocationType::Unspecified => Self::Unspecified,
            KeyValueLocationType::OnPremise => Self::OnPremise,
            KeyValueLocationType::OffPremise => Self::OffPremise,
            KeyValueLocationType::OnPremiseOffPremise => Self::OnPremiseOffPremise,
        }
    }
}

/// KMIP 1.4 RNG Algorithm Enumeration
#[kmip_enum]
pub enum RNGAlgorithm {
    Unspecified = 0x1,
    FIPS186_2 = 0x2,
    DRBG = 0x3,
    NRBG = 0x4,
    ANSI_X931 = 0x5,
    ANSI_X962 = 0x6,
}

impl From<RNGAlgorithm> for kmip_2_1::kmip_types::RNGAlgorithm {
    fn from(val: RNGAlgorithm) -> Self {
        match val {
            RNGAlgorithm::Unspecified => Self::Unspecified,
            RNGAlgorithm::FIPS186_2 => Self::FIPS186_2,
            RNGAlgorithm::DRBG => Self::DRBG,
            RNGAlgorithm::NRBG => Self::NRBG,
            RNGAlgorithm::ANSI_X931 => Self::ANSI_X931,
            RNGAlgorithm::ANSI_X962 => Self::ANSI_X962,
        }
    }
}

/// KMIP 1.4 DRBG Algorithm Enumeration
#[kmip_enum]
pub enum DRBGAlgorithm {
    Unspecified = 0x1,
    // #[serde(rename = "Dual-EC")]
    DualEC = 0x2,
    Hash = 0x3,
    HMAC = 0x4,
    CTR = 0x5,
}

impl From<DRBGAlgorithm> for kmip_2_1::kmip_types::DRBGAlgorithm {
    fn from(val: DRBGAlgorithm) -> Self {
        match val {
            DRBGAlgorithm::Unspecified => Self::Unspecified,
            DRBGAlgorithm::DualEC => Self::DualEC,
            DRBGAlgorithm::Hash => Self::Hash,
            DRBGAlgorithm::HMAC => Self::HMAC,
            DRBGAlgorithm::CTR => Self::CTR,
        }
    }
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

impl From<FIPS186Variation> for kmip_2_1::kmip_types::FIPS186Variation {
    fn from(val: FIPS186Variation) -> Self {
        match val {
            FIPS186Variation::Unspecified => Self::Unspecified,
            FIPS186Variation::GPXOriginal => Self::GPXOriginal,
            FIPS186Variation::GPXChangeNotice => Self::GPXChangeNotice,
            FIPS186Variation::XOriginal => Self::XOriginal,
            FIPS186Variation::XChangeNotice => Self::XChangeNotice,
            FIPS186Variation::KOriginal => Self::KOriginal,
            FIPS186Variation::KChangeNotice => Self::KChangeNotice,
        }
    }
}

/// KMIP 1.4 Validation Authority Type Enumeration
#[kmip_enum]
pub enum ValidationAuthorityType {
    Unspecified = 0x1,
    NIST_CMVP = 0x2,
    Common_Criteria = 0x3,
}

/// KMIP 1.4 Validation Type Enumeration
#[kmip_enum]
pub enum ValidationType {
    Unspecified = 0x1,
    Hardware = 0x2,
    Software = 0x3,
    Firmware = 0x4,
    Hybrid = 0x5,
}

/// KMIP 1.4 Profile Name Enumeration
#[kmip_enum]
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
    Zeroize = 0x2,
}

/// KMIP 1.4 Shredding Algorithm Enumeration
#[kmip_enum]
pub enum ShreddingAlgorithm {
    Unspecified = 0x1,
    CryptoShred = 0x2,
}

/// KMIP 1.4 RNG Mode Enumeration
#[kmip_enum]
pub enum RNGMode {
    SharedInstantiation = 0x1,
    NonSharedInstantiation = 0x2,
}

/// KMIP 1.4 Client Registration Method Enumeration
#[kmip_enum]
pub enum ClientRegistrationMethod {
    Unspecified = 0x1,
    ServerPreProvided = 0x2,
    ServerOnDemand = 0x3,
    ClientGenerated = 0x4,
    ClientRegistered = 0x5,
}

/// KMIP 1.4 Mask Generator Enumeration
#[kmip_enum]
pub enum MaskGenerator {
    MGF1 = 0x1,
}

impl From<MaskGenerator> for kmip_2_1::kmip_types::MaskGenerator {
    fn from(val: MaskGenerator) -> Self {
        match val {
            MaskGenerator::MGF1 => Self::MFG1,
        }
    }
}

/// KMIP 1.4 Storage Status Mask Enumeration
#[kmip_enum]
pub enum StorageStatusMask {
    Online = 0x1,
    Archival = 0x2,
    Destroyed = 0x4,
}

/// KMIP 1.4 Cryptographic Usage Mask Flags

/// KMIP 1.4 Recommended Curve Enumeration
#[kmip_enum]
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
    SECP112R1 = 0x10,
    SECP112R2 = 0x11,
    SECP128R1 = 0x12,
    SECP128R2 = 0x13,
    SECP160R1 = 0x14,
    SECP160K1 = 0x15,
    SECP256K1 = 0x16,
    BRAINPOOLP160R1 = 0x17,
    BRAINPOOLP160T1 = 0x18,
    BRAINPOOLP192R1 = 0x19,
    BRAINPOOLP192T1 = 0x1A,
    BRAINPOOLP224R1 = 0x1B,
    BRAINPOOLP224T1 = 0x1C,
    BRAINPOOLP256R1 = 0x1D,
    BRAINPOOLP256T1 = 0x1E,
    BRAINPOOLP320R1 = 0x1F,
    BRAINPOOLP320T1 = 0x20,
    BRAINPOOLP384R1 = 0x21,
    BRAINPOOLP384T1 = 0x22,
    BRAINPOOLP512R1 = 0x23,
    BRAINPOOLP512T1 = 0x24,
}

impl From<RecommendedCurve> for kmip_2_1::kmip_types::RecommendedCurve {
    fn from(val: RecommendedCurve) -> Self {
        match val {
            RecommendedCurve::P192 => Self::P192,
            RecommendedCurve::K163 => Self::K163,
            RecommendedCurve::B163 => Self::B163,
            RecommendedCurve::P224 => Self::P224,
            RecommendedCurve::K233 => Self::K233,
            RecommendedCurve::B233 => Self::B233,
            RecommendedCurve::P256 => Self::P256,
            RecommendedCurve::K283 => Self::K283,
            RecommendedCurve::B283 => Self::B283,
            RecommendedCurve::P384 => Self::P384,
            RecommendedCurve::K409 => Self::K409,
            RecommendedCurve::B409 => Self::B409,
            RecommendedCurve::P521 => Self::P521,
            RecommendedCurve::K571 => Self::K571,
            RecommendedCurve::B571 => Self::B571,
            RecommendedCurve::SECP112R1 => Self::SECP112R1,
            RecommendedCurve::SECP112R2 => Self::SECP112R2,
            RecommendedCurve::SECP128R1 => Self::SECP128R1,
            RecommendedCurve::SECP128R2 => Self::SECP128R2,
            RecommendedCurve::SECP160R1 => Self::SECP160R1,
            RecommendedCurve::SECP160K1 => Self::SECP160K1,
            RecommendedCurve::SECP256K1 => Self::SECP256K1,
            RecommendedCurve::BRAINPOOLP160R1 => Self::BRAINPOOLP160R1,
            RecommendedCurve::BRAINPOOLP160T1 => Self::BRAINPOOLP160T1,
            RecommendedCurve::BRAINPOOLP192R1 => Self::BRAINPOOLP192R1,
            RecommendedCurve::BRAINPOOLP192T1 => Self::BRAINPOOLP192T1,
            RecommendedCurve::BRAINPOOLP224R1 => Self::BRAINPOOLP224R1,
            RecommendedCurve::BRAINPOOLP224T1 => Self::BRAINPOOLP224T1,
            RecommendedCurve::BRAINPOOLP256R1 => Self::BRAINPOOLP256R1,
            RecommendedCurve::BRAINPOOLP256T1 => Self::BRAINPOOLP256T1,
            RecommendedCurve::BRAINPOOLP320R1 => Self::BRAINPOOLP320R1,
            RecommendedCurve::BRAINPOOLP320T1 => Self::BRAINPOOLP320T1,
            RecommendedCurve::BRAINPOOLP384R1 => Self::BRAINPOOLP384R1,
            RecommendedCurve::BRAINPOOLP384T1 => Self::BRAINPOOLP384T1,
            RecommendedCurve::BRAINPOOLP512R1 => Self::BRAINPOOLP512R1,
            RecommendedCurve::BRAINPOOLP512T1 => Self::BRAINPOOLP512T1,
        }
    }
}

/// KMIP 1.4 Digital Signature Algorithm Enumeration
#[kmip_enum]
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

impl From<DigitalSignatureAlgorithm> for kmip_2_1::kmip_types::DigitalSignatureAlgorithm {
    fn from(val: DigitalSignatureAlgorithm) -> Self {
        match val {
            DigitalSignatureAlgorithm::MD2WithRSAEncryption => Self::MD2WithRSAEncryption,
            DigitalSignatureAlgorithm::MD5WithRSAEncryption => Self::MD5WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA1WithRSAEncryption => Self::SHA1WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA224WithRSAEncryption => Self::SHA224WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA256WithRSAEncryption => Self::SHA256WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA384WithRSAEncryption => Self::SHA384WithRSAEncryption,
            DigitalSignatureAlgorithm::SHA512WithRSAEncryption => Self::SHA512WithRSAEncryption,
            DigitalSignatureAlgorithm::RSASSAPSS => Self::RSASSAPSS,
            DigitalSignatureAlgorithm::DSAWithSHA1 => Self::DSAWithSHA1,
            DigitalSignatureAlgorithm::DSAWithSHA224 => Self::DSAWithSHA224,
            DigitalSignatureAlgorithm::DSAWithSHA256 => Self::DSAWithSHA256,
            DigitalSignatureAlgorithm::ECDSAWithSHA1 => Self::ECDSAWithSHA1,
            DigitalSignatureAlgorithm::ECDSAWithSHA224 => Self::ECDSAWithSHA224,
            DigitalSignatureAlgorithm::ECDSAWithSHA256 => Self::ECDSAWithSHA256,
            DigitalSignatureAlgorithm::ECDSAWithSHA384 => Self::ECDSAWithSHA384,
            DigitalSignatureAlgorithm::ECDSAWithSHA512 => Self::ECDSAWithSHA512,
        }
    }
}

/// KMIP 1.4 Opaque Data Type Enumeration
#[kmip_enum]
pub enum OpaqueDataType {
    Unknown = 0x1,
}

impl From<OpaqueDataType> for kmip_2_1::kmip_types::OpaqueDataType {
    fn from(val: OpaqueDataType) -> Self {
        match val {
            OpaqueDataType::Unknown => Self::Unknown,
        }
    }
}

/// KMIP 1.4 Name structure containing a name type and value
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Name {
    pub name_value: String,
    pub name_type: NameType,
}

impl From<Name> for kmip_2_1::kmip_types::Name {
    fn from(val: Name) -> Self {
        Self {
            name_value: val.name_value,
            name_type: val.name_type.into(),
        }
    }
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

impl From<CryptographicDomainParameters> for kmip_2_1::kmip_types::CryptographicDomainParameters {
    fn from(val: CryptographicDomainParameters) -> Self {
        Self {
            qlength: val.qlength,
            recommended_curve: val.recommended_curve.map(Into::into),
        }
    }
}

/// KMIP 1.4 X509 Certificate Identifier
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct X509CertificateIdentifier {
    pub issuer_distinguished_name: Vec<u8>,
    pub cxertificate_serial_number: Vec<u8>,
}

impl From<X509CertificateIdentifier> for kmip_2_1::kmip_types::X509CertificateIdentifier {
    fn from(val: X509CertificateIdentifier) -> Self {
        Self {
            issuer_distinguished_name: val.issuer_distinguished_name,
            cxertificate_serial_number: val.cxertificate_serial_number,
        }
    }
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
#[derive(Serialize, Deserialize, Clone, Debug, Copy, Eq, PartialEq)]
pub struct CryptographicUsageMask(pub u32);

bitflags::bitflags! {
#[allow(clippy::indexing_slicing)]
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

impl From<CryptographicUsageMask> for kmip_2_1::kmip_types::CryptographicUsageMask {
    fn from(val: CryptographicUsageMask) -> Self {
        Self(val.0)
    }
}

/// KMIP 1.4 Usage Limits
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageLimits {
    pub usage_limits_total: i64,
    pub usage_limits_count: i64,
    pub usage_limits_unit: UsageLimitsUnit,
}

impl From<UsageLimits> for kmip_2_1::kmip_types::UsageLimits {
    fn from(val: UsageLimits) -> Self {
        Self {
            usage_limits_unit: val.usage_limits_unit.into(),
            usage_limits_count: val.usage_limits_count,
            usage_limits_total: val.usage_limits_total,
        }
    }
}

/// KMIP 1.4 Revocation Reason
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RevocationReason {
    pub revocation_reason_code: RevocationReasonCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_message: Option<String>,
}

impl From<RevocationReason> for kmip_2_1::kmip_types::RevocationReason {
    fn from(val: RevocationReason) -> Self {
        Self {
            revocation_reason_code: val.revocation_reason_code.into(),
            revocation_message: val.revocation_message,
        }
    }
}

/// KMIP 1.4 Application Specific Information
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct ApplicationSpecificInformation {
    pub application_namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_data: Option<String>,
}

impl From<ApplicationSpecificInformation> for kmip_2_1::kmip_types::ApplicationSpecificInformation {
    fn from(val: ApplicationSpecificInformation) -> Self {
        Self {
            application_namespace: val.application_namespace,
            application_data: val.application_data,
        }
    }
}

/// KMIP 1.4 Alternative Name
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct AlternativeName {
    pub alternative_name_value: String,
    pub alternative_name_type: AlternativeNameType,
}

impl From<AlternativeName> for kmip_2_1::kmip_types::AlternativeName {
    fn from(val: AlternativeName) -> Self {
        Self {
            alternative_name_value: val.alternative_name_value,
            alternative_name_type: val.alternative_name_type.into(),
        }
    }
}

/// KMIP 1.4 Random Number Generator
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RandomNumberGenerator {
    pub rng_algorithm: RNGAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drbg_algorithm: Option<DRBGAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips186_variation: Option<FIPS186Variation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_resistance: Option<bool>,
}

impl From<RandomNumberGenerator> for kmip_2_1::kmip_types::RandomNumberGenerator {
    fn from(val: RandomNumberGenerator) -> Self {
        Self {
            rng_algorithm: val.rng_algorithm.into(),
            cryptographic_algorithm: val.cryptographic_algorithm.map(Into::into),
            cryptographic_length: val.cryptographic_length,
            hashing_algorithm: val.hashing_algorithm.map(Into::into),
            drbg_algorithm: val.drbg_algorithm.map(Into::into),
            recommended_curve: val.recommended_curve.map(Into::into),
            fips186_variation: val.fips186_variation.map(Into::into),
            prediction_resistance: val.prediction_resistance,
        }
    }
}

/// The Unique Identifier is generated by the key management system
/// to uniquely identify a Managed Object.
///
/// It is only REQUIRED to be unique within the identifier space managed
/// by a single key management system, however this identifier SHOULD be globally unique
/// in order to allow for a key management server export of such objects.
///
/// This attribute SHALL be assigned by the key management system at creation or registration time,
/// and then SHALL NOT be changed or deleted before the object is destroyed.
pub type UniqueIdentifier = String;

impl From<UniqueIdentifier> for kmip_2_1::kmip_types::UniqueIdentifier {
    fn from(val: UniqueIdentifier) -> Self {
        Self::TextString(val)
    }
}

impl From<kmip_2_1::kmip_types::UniqueIdentifier> for UniqueIdentifier {
    fn from(val: kmip_2_1::kmip_types::UniqueIdentifier) -> Self {
        val.to_string()
    }
}

impl From<LinkedObjectIdentifier> for UniqueIdentifier {
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::as_conversions
    )]
    fn from(value: LinkedObjectIdentifier) -> Self {
        match value {
            LinkedObjectIdentifier::TextString(s) => s,
        }
    }
}

/// Link Structure represents the relationship between a Managed Object and another object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    pub link_type: LinkType,
    pub linked_object_identifier: LinkedObjectIdentifier,
}

impl From<Link> for kmip_2_1::kmip_types::Link {
    fn from(val: Link) -> Self {
        Self {
            link_type: val.link_type.into(),
            linked_object_identifier: val.linked_object_identifier.into(),
        }
    }
}

/// `LinkedObjectIdentifier` defines the format of the object reference in a link.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
pub enum LinkedObjectIdentifier {
    TextString(String),
}

impl From<LinkedObjectIdentifier> for kmip_2_1::kmip_types::LinkedObjectIdentifier {
    fn from(val: LinkedObjectIdentifier) -> Self {
        match val {
            LinkedObjectIdentifier::TextString(s) => Self::TextString(s),
        }
    }
}

/// KMIP Tag values as defined in the KMIP 1.4 specification.
#[kmip_enum]
pub enum Tag {
    ActivationDate = 0x42_0001,
    ApplicationData = 0x42_0002,
    ApplicationNamespace = 0x42_0003,
    ApplicationSpecificInformation = 0x42_0004,
    ArchiveDate = 0x42_0005,
    AsynchronousCorrelationValue = 0x42_0006,
    AsynchronousIndicator = 0x42_0007,
    Attribute = 0x42_0008,
    AttributeIndex = 0x42_0009,
    AttributeName = 0x42_000A,
    AttributeValue = 0x42_000B,
    Authentication = 0x42_000C,
    BatchCount = 0x42_000D,
    BatchErrorContinuationOption = 0x42_000E,
    BatchItem = 0x42_000F,
    BatchOrderOption = 0x42_0010,
    BlockCipherMode = 0x42_0011,
    CancellationResult = 0x42_0012,
    Certificate = 0x42_0013,
    CertificateIdentifier = 0x42_0014,
    CertificateIssuer = 0x42_0015,
    CertificateIssuerAlternativeName = 0x42_0016,
    CertificateIssuerDistinguishedName = 0x42_0017,
    CertificateRequest = 0x42_0018,
    CertificateRequestType = 0x42_0019,
    CertificateSubject = 0x42_001A,
    CertificateSubjectAlternativeName = 0x42_001B,
    CertificateSubjectDistinguishedName = 0x42_001C,
    CertificateType = 0x42_001D,
    CertificateValue = 0x42_001E,
    CommonTemplateAttribute = 0x42_001F,
    CompromiseDate = 0x42_0020,
    CompromiseOccurrenceDate = 0x42_0021,
    ContactInformation = 0x42_0022,
    Credential = 0x42_0023,
    CredentialType = 0x42_0024,
    CredentialValue = 0x42_0025,
    CriticalityIndicator = 0x42_0026,
    CRTCoefficient = 0x42_0027,
    CryptographicAlgorithm = 0x42_0028,
    CryptographicDomainParameters = 0x42_0029,
    CryptographicLength = 0x42_002A,
    CryptographicParameters = 0x42_002B,
    CryptographicUsageMask = 0x42_002C,
    CustomAttribute = 0x42_002D,
    D = 0x42_002E,
    DeactivationDate = 0x42_002F,
    DerivationData = 0x42_0030,
    DerivationMethod = 0x42_0031,
    DerivationParameters = 0x42_0032,
    DestroyDate = 0x42_0033,
    Digest = 0x42_0034,
    DigestValue = 0x42_0035,
    EncryptionKeyInformation = 0x42_0036,
    G = 0x42_0037,
    HashingAlgorithm = 0x42_0038,
    InitialDate = 0x42_0039,
    InitializationVector = 0x42_003A,
    Issuer = 0x42_003B,
    IterationCount = 0x42_003C,
    IVCounterNonce = 0x42_003D,
    J = 0x42_003E,
    Key = 0x42_003F,
    KeyBlock = 0x42_0040,
    KeyCompressionType = 0x42_0041,
    KeyFormatType = 0x42_0042,
    KeyMaterial = 0x42_0043,
    KeyPartIdentifier = 0x42_0044,
    KeyValue = 0x42_0045,
    KeyWrappingData = 0x42_0046,
    KeyWrappingSpecification = 0x42_0047,
    LastChangeDate = 0x42_0048,
    LeaseTime = 0x42_0049,
    Link = 0x42_004A,
    LinkType = 0x42_004B,
    LinkedObjectIdentifier = 0x42_004C,
    MACSignature = 0x42_004D,
    MACSignatureKeyInformation = 0x42_004E,
    MaximumItems = 0x42_004F,
    MaximumResponseSize = 0x42_0050,
    MessageExtension = 0x42_0051,
    Modulus = 0x42_0052,
    Name = 0x42_0053,
    NameType = 0x42_0054,
    NameValue = 0x42_0055,
    ObjectGroup = 0x42_0056,
    ObjectType = 0x42_0057,
    Offset = 0x42_0058,
    OpaqueDataType = 0x42_0059,
    OpaqueDataValue = 0x42_005A,
    OpaqueObject = 0x42_005B,
    Operation = 0x42_005C,
    OperationPolicyName = 0x42_005D,
    P = 0x42_005E,
    PaddingMethod = 0x42_005F,
    PrimeExponentP = 0x42_0060,
    PrimeExponentQ = 0x42_0061,
    PrimeFieldSize = 0x42_0062,
    PrivateExponent = 0x42_0063,
    PrivateKey = 0x42_0064,
    PrivateKeyTemplateAttribute = 0x42_0065,
    PrivateKeyUniqueIdentifier = 0x42_0066,
    ProcessStartDate = 0x42_0067,
    ProtectStopDate = 0x42_0068,
    ProtocolVersion = 0x42_0069,
    ProtocolVersionMajor = 0x42_006A,
    ProtocolVersionMinor = 0x42_006B,
    PublicExponent = 0x42_006C,
    PublicKey = 0x42_006D,
    PublicKeyTemplateAttribute = 0x42_006E,
    PublicKeyUniqueIdentifier = 0x42_006F,
    PutFunction = 0x42_0070,
    Q = 0x42_0071,
    QString = 0x42_0072,
    Qlength = 0x42_0073,
    QueryFunction = 0x42_0074,
    RecommendedCurve = 0x42_0075,
    ReplacedUniqueIdentifier = 0x42_0076,
    RequestHeader = 0x42_0077,
    RequestMessage = 0x42_0078,
    RequestPayload = 0x42_0079,
    ResponseHeader = 0x42_007A,
    ResponseMessage = 0x42_007B,
    ResponsePayload = 0x42_007C,
    ResultMessage = 0x42_007D,
    ResultReason = 0x42_007E,
    ResultStatus = 0x42_007F,
    RevocationMessage = 0x42_0080,
    RevocationReason = 0x42_0081,
    RevocationReasonCode = 0x42_0082,
    KeyRoleType = 0x42_0083,
    Salt = 0x42_0084,
    SecretData = 0x42_0085,
    SecretDataType = 0x42_0086,
    SerialNumber = 0x42_0087,
    ServerInformation = 0x42_0088,
    SplitKey = 0x42_0089,
    SplitKeyMethod = 0x42_008A,
    SplitKeyParts = 0x42_008B,
    SplitKeyThreshold = 0x42_008C,
    State = 0x42_008D,
    StorageStatusMask = 0x42_008E,
    SymmetricKey = 0x42_008F,
    Template = 0x42_0090,
    TemplateAttribute = 0x42_0091,
    TimeStamp = 0x42_0092,
    UniqueBatchItemID = 0x42_0093,
    UniqueIdentifier = 0x42_0094,
    UsageLimits = 0x42_0095,
    UsageLimitsCount = 0x42_0096,
    UsageLimitsTotal = 0x42_0097,
    UsageLimitsUnit = 0x42_0098,
    Username = 0x42_0099,
    ValidityDate = 0x42_009A,
    ValidityIndicator = 0x42_009B,
    VendorExtension = 0x42_009C,
    VendorIdentification = 0x42_009D,
    WrappingMethod = 0x42_009E,
    X = 0x42_009F,
    Y = 0x42_00A0,
    Password = 0x42_00A1,
    DeviceIdentifier = 0x42_00A2,
    EncodingOption = 0x42_00A3,
    ExtensionInformation = 0x42_00A4,
    ExtensionName = 0x42_00A5,
    ExtensionTag = 0x42_00A6,
    ExtensionType = 0x42_00A7,
    Fresh = 0x42_00A8,
    MachineIdentifier = 0x42_00A9,
    MediaIdentifier = 0x42_00AA,
    NetworkIdentifier = 0x42_00AB,
    ObjectGroupMember = 0x42_00AC,
    CertificateLength = 0x42_00AD,
    DigitalSignatureAlgorithm = 0x42_00AE,
    CertificateSerialNumber = 0x42_00AF,
    DeviceSerialNumber = 0x42_00B0,
    IssuerAlternativeName = 0x42_00B1,
    IssuerDistinguishedName = 0x42_00B2,
    SubjectAlternativeName = 0x42_00B3,
    SubjectDistinguishedName = 0x42_00B4,
    X509CertificateIdentifier = 0x42_00B5,
    X509CertificateIssuer = 0x42_00B6,
    X509CertificateSubject = 0x42_00B7,
    KeyValueLocation = 0x42_00B8,
    KeyValueLocationValue = 0x42_00B9,
    KeyValueLocationType = 0x42_00BA,
    KeyValuePresent = 0x42_00BB,
    OriginalCreationDate = 0x42_00BC,
    PGPKey = 0x42_00BD,
    PGPKeyVersion = 0x42_00BE,
    AlternativeName = 0x42_00BF,
    AlternativeNameValue = 0x42_00C0,
    AlternativeNameType = 0x42_00C1,
    Data = 0x42_00C2,
    SignatureData = 0x42_00C3,
    DataLength = 0x42_00C4,
    RandomIV = 0x42_00C5,
    MACData = 0x42_00C6,
    AttestationType = 0x42_00C7,
    Nonce = 0x42_00C8,
    NonceID = 0x42_00C9,
    NonceValue = 0x42_00CA,
    AttestationMeasurement = 0x42_00CB,
    AttestationAssertion = 0x42_00CC,
    IVLength = 0x42_00CD,
    TagLength = 0x42_00CE,
    FixedFieldLength = 0x42_00CF,
    CounterLength = 0x42_00D0,
    InitialCounterValue = 0x42_00D1,
    InvocationFieldLength = 0x42_00D2,
    AttestationCapableIndicator = 0x42_00D3,
    OffsetItems = 0x42_00D4,
    LocatedItems = 0x42_00D5,
    CorrelationValue = 0x42_00D6,
    InitIndicator = 0x42_00D7,
    FinalIndicator = 0x42_00D8,
    RNGParameters = 0x42_00D9,
    RNGAlgorithm = 0x42_00DA,
    DRBGAlgorithm = 0x42_00DB,
    FIPS186Variation = 0x42_00DC,
    PredictionResistance = 0x42_00DD,
    RandomNumberGenerator = 0x42_00DE,
    ValidationInformation = 0x42_00DF,
    ValidationAuthorityType = 0x42_00E0,
    ValidationAuthorityCountry = 0x42_00E1,
    ValidationAuthorityURI = 0x42_00E2,
    ValidationVersionMajor = 0x42_00E3,
    ValidationVersionMinor = 0x42_00E4,
    ValidationType = 0x42_00E5,
    ValidationLevel = 0x42_00E6,
    ValidationCertificateIdentifier = 0x42_00E7,
    ValidationCertificateURI = 0x42_00E8,
    ValidationVendorURI = 0x42_00E9,
    ValidationProfile = 0x42_00EA,
    ProfileInformation = 0x42_00EB,
    ProfileName = 0x42_00EC,
    ServerURI = 0x42_00ED,
    ServerPort = 0x42_00EE,
    StreamingCapability = 0x42_00EF,
    AsynchronousCapability = 0x42_00F0,
    AttestationCapability = 0x42_00F1,
    UnwrapMode = 0x42_00F2,
    DestroyAction = 0x42_00F3,
    ShreddingAlgorithm = 0x42_00F4,
    RNGMode = 0x42_00F5,
    ClientRegistrationMethod = 0x42_00F6,
    CapabilityInformation = 0x42_00F7,
    KeyWrapType = 0x42_00F8,
    BatchUndoCapability = 0x42_00F9,
    BatchContinueCapability = 0x42_00FA,
    PKCS12FriendlyName = 0x42_00FB,
    Description = 0x42_00FC,
    Comment = 0x42_00FD,
    AuthenticatedEncryptionAdditionalData = 0x42_00FE,
    AuthenticatedEncryptionTag = 0x42_00FF,
    SaltLength = 0x42_0100,
    MaskGenerator = 0x42_0101,
    MaskGeneratorHashingAlgorithm = 0x42_0102,
    PSource = 0x42_0103,
    TrailerField = 0x42_0104,
    ClientCorrelationValue = 0x42_0105,
    ServerCorrelationValue = 0x42_0106,
    DigestedData = 0x42_0107,
    CertificateSubjectCN = 0x42_0108,
    CertificateSubjectO = 0x42_0109,
    CertificateSubjectOU = 0x42_010A,
    CertificateSubjectEmail = 0x42_010B,
    CertificateSubjectC = 0x42_010C,
    CertificateSubjectST = 0x42_010D,
    CertificateSubjectL = 0x42_010E,
    CertificateSubjectUID = 0x42_010F,
    CertificateSubjectSerialNumber = 0x42_0110,
    CertificateSubjectTitle = 0x42_0111,
    CertificateSubjectDC = 0x42_0112,
    CertificateSubjectDNQualifier = 0x42_0113,
    CertificateIssuerCN = 0x42_0114,
    CertificateIssuerO = 0x42_0115,
    CertificateIssuerOU = 0x42_0116,
    CertificateIssuerEmail = 0x42_0117,
    CertificateIssuerC = 0x42_0118,
    CertificateIssuerST = 0x42_0119,
    CertificateIssuerL = 0x42_011A,
    CertificateIssuerUID = 0x42_011B,
    CertificateIssuerSerialNumber = 0x42_011C,
    CertificateIssuerTitle = 0x42_011D,
    CertificateIssuerDC = 0x42_011E,
    CertificateIssuerDNQualifier = 0x42_011F,
    Sensitive = 0x42_0120,
    AlwaysSensitive = 0x42_0121,
    Extractable = 0x42_0122,
    NeverExtractable = 0x42_0123,
    ReplaceExisting = 0x42_0124,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_display() {
        assert_eq!(ObjectType::Certificate.to_string(), "Certificate");
        assert_eq!(ObjectType::SymmetricKey.to_string(), "SymmetricKey");
        assert_eq!(ObjectType::PublicKey.to_string(), "PublicKey");
        assert_eq!(ObjectType::PrivateKey.to_string(), "PrivateKey");
        assert_eq!(ObjectType::SplitKey.to_string(), "SplitKey");
        assert_eq!(ObjectType::SecretData.to_string(), "SecretData");
        assert_eq!(ObjectType::OpaqueObject.to_string(), "OpaqueObject");
        assert_eq!(ObjectType::PGPKey.to_string(), "PGPKey");
    }

    #[test]
    fn test_object_type_try_from() {
        assert_eq!(ObjectType::try_from(0x01).unwrap(), ObjectType::Certificate);
        assert_eq!(
            ObjectType::try_from(0x02).unwrap(),
            ObjectType::SymmetricKey
        );
        assert_eq!(ObjectType::try_from(0x03).unwrap(), ObjectType::PublicKey);
        assert_eq!(ObjectType::try_from(0x04).unwrap(), ObjectType::PrivateKey);
        assert_eq!(ObjectType::try_from(0x05).unwrap(), ObjectType::SplitKey);
        assert_eq!(ObjectType::try_from(0x07).unwrap(), ObjectType::SecretData);
        assert_eq!(
            ObjectType::try_from(0x08).unwrap(),
            ObjectType::OpaqueObject
        );
        assert_eq!(ObjectType::try_from(0x09).unwrap(), ObjectType::PGPKey);
        ObjectType::try_from(0x0A).unwrap_err();
    }

    #[test]
    fn test_object_type_from() {
        assert_eq!(u32::from(ObjectType::Certificate), 0x01);
        assert_eq!(u32::from(ObjectType::SymmetricKey), 0x02);
        assert_eq!(u32::from(ObjectType::PublicKey), 0x03);
        assert_eq!(u32::from(ObjectType::PrivateKey), 0x04);
        assert_eq!(u32::from(ObjectType::SplitKey), 0x05);
        assert_eq!(u32::from(ObjectType::SecretData), 0x07);
        assert_eq!(u32::from(ObjectType::OpaqueObject), 0x08);
        assert_eq!(u32::from(ObjectType::PGPKey), 0x09);
    }
}
