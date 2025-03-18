#![allow(non_camel_case_types)]

use std::{
    fmt,
    fmt::{Display, Formatter},
};

use kmip_derive::KmipEnumSerialize;
use serde::{
    de,
    de::{MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use strum::{Display, EnumString};
use uuid::Uuid;

use crate::kmip_2_1::{self};

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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum SplitKeyMethod {
    XOR = 0x0000_0001,
    #[serde(rename = "Polynomial Sharing GF (2^16)")]
    PolynomialSharingGf216 = 0x0000_0002,
    #[serde(rename = "Polynomial Sharing Prime Field")]
    PolynomialSharingPrimeField = 0x0000_0003,
    #[serde(rename = "Polynomial Sharing GF (2^8)")]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
#[repr(u32)]
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
    #[serde(rename = "CBC-MAC")]
    CBCMAC = 0x0000_000A,
    XTS = 0x0000_000B,
    AESKeyWrapPadding = 0x0000_000C,
    #[serde(rename = "X9.102 AESKW")]
    X9102AESKW = 0x0000_000E,
    #[serde(rename = "X9.102 TDKW")]
    X9102TDKW = 0x0000_000F,
    #[serde(rename = "X9.102 AKW1")]
    X9102AKW1 = 0x0000_0010,
    #[serde(rename = "X9.102 AKW2")]
    X9102AKW2 = 0x0000_0011,
    AEAD = 0x0000_0012,
    // Extensions - 8XXXXXXX
    // NISTKeyWrap refers to rfc5649
    NISTKeyWrap = 0x8000_0001,
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum PaddingMethod {
    None = 0x1,
    OAEP = 0x2,
    PKCS5 = 0x3,
    SSL3 = 0x4,
    Zeros = 0x5,
    #[serde(rename = "ANSI X9.23")]
    ANSI_X923 = 0x6,
    #[serde(rename = "ISO 10126")]
    ISO10126 = 0x7,
    #[serde(rename = "PKCS1 v1.5")]
    PKCS1v15 = 0x8,
    #[serde(rename = "X9.31")]
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

/// KMIP 1.4 Hashing Algorithm Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum HashingAlgorithm {
    MD2 = 0x0000_0001,
    MD4 = 0x0000_0002,
    MD5 = 0x0000_0003,
    #[serde(rename = "SHA-1")]
    SHA1 = 0x0000_0004,
    #[serde(rename = "SHA-224")]
    SHA224 = 0x0000_0005,
    #[serde(rename = "SHA-256")]
    SHA256 = 0x0000_0006,
    #[serde(rename = "SHA-384")]
    SHA384 = 0x0000_0007,
    #[serde(rename = "SHA-512")]
    SHA512 = 0x0000_0008,
    #[serde(rename = "RIPEMD-160")]
    RIPEMD160 = 0x0000_0009,
    Tiger = 0x0000_000A,
    Whirlpool = 0x0000_000B,
    #[serde(rename = "SHA-512/224")]
    SHA512224 = 0x0000_000C,
    #[serde(rename = "SHA-512/256")]
    SHA512256 = 0x0000_000D,
    #[serde(rename = "SHA-3-224")]
    SHA3224 = 0x0000_000E,
    #[serde(rename = "SHA-3-256")]
    SHA3256 = 0x0000_000F,
    #[serde(rename = "SHA-3-384")]
    SHA3384 = 0x0000_0010,
    #[serde(rename = "SHA-3-512")]
    SHA3512 = 0x0000_0011,
}

impl From<HashingAlgorithm> for kmip_2_1::kmip_types::HashingAlgorithm {
    fn from(val: HashingAlgorithm) -> Self {
        match val {
            HashingAlgorithm::MD2 => Self::MD2,
            HashingAlgorithm::MD4 => Self::MD4,
            HashingAlgorithm::MD5 => Self::MD5,
            HashingAlgorithm::SHA1 => Self::SHA1,
            HashingAlgorithm::SHA224 => Self::SHA224,
            HashingAlgorithm::SHA256 => Self::SHA256,
            HashingAlgorithm::SHA384 => Self::SHA384,
            HashingAlgorithm::SHA512 => Self::SHA512,
            HashingAlgorithm::RIPEMD160 => Self::RIPEMD160,
            HashingAlgorithm::Tiger => Self::Tiger,
            HashingAlgorithm::Whirlpool => Self::Whirlpool,
            HashingAlgorithm::SHA512224 => Self::SHA512224,
            HashingAlgorithm::SHA512256 => Self::SHA512256,
            HashingAlgorithm::SHA3224 => Self::SHA3224,
            HashingAlgorithm::SHA3256 => Self::SHA3256,
            HashingAlgorithm::SHA3384 => Self::SHA3384,
            HashingAlgorithm::SHA3512 => Self::SHA3512,
        }
    }
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
#[allow(non_camel_case_types)]
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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

impl From<UsageLimitsUnit> for kmip_2_1::kmip_types::UsageLimitsUnit {
    fn from(val: UsageLimitsUnit) -> Self {
        match val {
            UsageLimitsUnit::Byte => Self::Byte,
            UsageLimitsUnit::Object => Self::Object,
        }
    }
}

/// KMIP 1.4 Encoding Option Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum DRBGAlgorithm {
    Unspecified = 0x1,
    #[serde(rename = "Dual-EC")]
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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum FIPS186Variation {
    Unspecified = 0x1,
    #[serde(rename = "GP x-Original")]
    GPXOriginal = 0x2,
    #[serde(rename = "GP x-Change Notice")]
    GPXChangeNotice = 0x3,
    #[serde(rename = "x-Original")]
    XOriginal = 0x4,
    #[serde(rename = "x-Change Notice")]
    XChangeNotice = 0x5,
    #[serde(rename = "k-Original")]
    KOriginal = 0x6,
    #[serde(rename = "k-Change Notice")]
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

impl From<MaskGenerator> for kmip_2_1::kmip_types::MaskGenerator {
    fn from(val: MaskGenerator) -> Self {
        match val {
            MaskGenerator::MGF1 => Self::MFG1,
        }
    }
}

/// KMIP 1.4 Storage Status Mask Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum StorageStatusMask {
    Online = 0x1,
    Archival = 0x2,
    Destroyed = 0x4,
}

/// KMIP 1.4 Cryptographic Usage Mask Flags

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
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
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
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
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
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum UniqueIdentifier {
    TextString(String),
}

impl Display for UniqueIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextString(s) => write!(f, "{s}"),
        }
    }
}

impl Default for UniqueIdentifier {
    fn default() -> Self {
        Self::TextString(Uuid::new_v4().to_string())
    }
}

impl From<&UniqueIdentifier> for String {
    fn from(value: &UniqueIdentifier) -> Self {
        value.to_string()
    }
}
impl From<UniqueIdentifier> for String {
    fn from(value: UniqueIdentifier) -> Self {
        value.to_string()
    }
}
impl UniqueIdentifier {
    /// Returns the value as a string if it is a `TextString`
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::TextString(s) => Some(s),
        }
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
            LinkedObjectIdentifier::TextString(s) => Self::TextString(s),
        }
    }
}

impl From<UniqueIdentifier> for kmip_2_1::kmip_types::UniqueIdentifier {
    fn from(val: UniqueIdentifier) -> Self {
        match val {
            UniqueIdentifier::TextString(s) => Self::TextString(s),
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
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
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

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Display, Debug, Eq, PartialEq, Default)]
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

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum TicketType {
    Login = 0x0000_0001,
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

/// The KMIP version 2.1 is used as the reference
/// for the implementation here
impl Default for ProtocolVersion {
    fn default() -> Self {
        Self {
            protocol_version_major: 1,
            protocol_version_minor: 4,
        }
    }
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
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
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
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum AttestationType {
    TPM_Quote = 0x0000_0001,
    TCG_Integrity_Report = 0x0000_0002,
    SAML_Assertion = 0x0000_0003,
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

impl From<MessageExtension> for kmip_2_1::kmip_types::MessageExtension {
    fn from(val: MessageExtension) -> Self {
        Self {
            vendor_identification: val.vendor_identification,
            criticality_indicator: val.criticality_indicator,
            vendor_extension: val.vendor_extension,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(
    KmipEnumSerialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display, strum::IntoStaticStr,
)]
pub enum ResultStatusEnumeration {
    Success = 0x0000_0000,
    OperationFailed = 0x0000_0001,
    OperationPending = 0x0000_0002,
    OperationUndone = 0x0000_0003,
}

impl From<ResultStatusEnumeration> for kmip_2_1::kmip_types::ResultStatusEnumeration {
    fn from(val: ResultStatusEnumeration) -> Self {
        match val {
            ResultStatusEnumeration::Success => Self::Success,
            ResultStatusEnumeration::OperationFailed => Self::OperationFailed,
            ResultStatusEnumeration::OperationPending => Self::OperationPending,
            ResultStatusEnumeration::OperationUndone => Self::OperationUndone,
        }
    }
}
