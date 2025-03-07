#![allow(non_camel_case_types)]

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::kmip_2_1;

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

impl Into<kmip_2_1::kmip_types::CertificateType> for CertificateType {
    fn into(self) -> kmip_2_1::kmip_types::CertificateType {
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

impl Into<kmip_2_1::kmip_types::SecretDataType> for SecretDataType {
    fn into(self) -> kmip_2_1::kmip_types::SecretDataType {
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

impl Into<kmip_2_1::kmip_types::NameType> for NameType {
    fn into(self) -> kmip_2_1::kmip_types::NameType {
        match self {
            Self::UninterpretedTextString => {
                kmip_2_1::kmip_types::NameType::UninterpretedTextString
            }
            Self::URI => kmip_2_1::kmip_types::NameType::URI,
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

impl Into<kmip_2_1::kmip_objects::ObjectType> for ObjectType {
    fn into(self) -> kmip_2_1::kmip_objects::ObjectType {
        match self {
            Self::Certificate => kmip_2_1::kmip_objects::ObjectType::Certificate,
            Self::SymmetricKey => kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
            Self::PublicKey => kmip_2_1::kmip_objects::ObjectType::PublicKey,
            Self::PrivateKey => kmip_2_1::kmip_objects::ObjectType::PrivateKey,
            Self::SplitKey => kmip_2_1::kmip_objects::ObjectType::SplitKey,
            Self::SecretData => kmip_2_1::kmip_objects::ObjectType::SecretData,
            Self::OpaqueObject => kmip_2_1::kmip_objects::ObjectType::OpaqueObject,
            Self::PGPKey => kmip_2_1::kmip_objects::ObjectType::PGPKey,
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

impl Into<kmip_2_1::kmip_types::CryptographicAlgorithm> for CryptographicAlgorithm {
    fn into(self) -> kmip_2_1::kmip_types::CryptographicAlgorithm {
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

impl Into<kmip_2_1::kmip_types::HashingAlgorithm> for HashingAlgorithm {
    fn into(self) -> kmip_2_1::kmip_types::HashingAlgorithm {
        match self {
            Self::MD2 => kmip_2_1::kmip_types::HashingAlgorithm::MD2,
            Self::MD4 => kmip_2_1::kmip_types::HashingAlgorithm::MD4,
            Self::MD5 => kmip_2_1::kmip_types::HashingAlgorithm::MD5,
            Self::SHA1 => kmip_2_1::kmip_types::HashingAlgorithm::SHA1,
            Self::SHA224 => kmip_2_1::kmip_types::HashingAlgorithm::SHA224,
            Self::SHA256 => kmip_2_1::kmip_types::HashingAlgorithm::SHA256,
            Self::SHA384 => kmip_2_1::kmip_types::HashingAlgorithm::SHA384,
            Self::SHA512 => kmip_2_1::kmip_types::HashingAlgorithm::SHA512,
            Self::RIPEMD160 => kmip_2_1::kmip_types::HashingAlgorithm::RIPEMD160,
            Self::Tiger => kmip_2_1::kmip_types::HashingAlgorithm::Tiger,
            Self::Whirlpool => kmip_2_1::kmip_types::HashingAlgorithm::Whirlpool,
            Self::SHA512224 => kmip_2_1::kmip_types::HashingAlgorithm::SHA512224,
            Self::SHA512256 => kmip_2_1::kmip_types::HashingAlgorithm::SHA512256,
            Self::SHA3224 => kmip_2_1::kmip_types::HashingAlgorithm::SHA3224,
            Self::SHA3256 => kmip_2_1::kmip_types::HashingAlgorithm::SHA3256,
            Self::SHA3384 => kmip_2_1::kmip_types::HashingAlgorithm::SHA3384,
            Self::SHA3512 => kmip_2_1::kmip_types::HashingAlgorithm::SHA3512,
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

impl Into<kmip_2_1::kmip_types::State> for State {
    fn into(self) -> kmip_2_1::kmip_types::State {
        match self {
            Self::PreActive => kmip_2_1::kmip_types::State::PreActive,
            Self::Active => kmip_2_1::kmip_types::State::Active,
            Self::Deactivated => kmip_2_1::kmip_types::State::Deactivated,
            Self::Compromised => kmip_2_1::kmip_types::State::Compromised,
            Self::Destroyed => kmip_2_1::kmip_types::State::Destroyed,
            Self::Destroyed_Compromised => kmip_2_1::kmip_types::State::Destroyed,
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

impl Into<kmip_2_1::kmip_types::RevocationReasonCode> for RevocationReasonCode {
    fn into(self) -> kmip_2_1::kmip_types::RevocationReasonCode {
        match self {
            Self::Unspecified => kmip_2_1::kmip_types::RevocationReasonCode::Unspecified,
            Self::KeyCompromise => kmip_2_1::kmip_types::RevocationReasonCode::KeyCompromise,
            Self::CACompromise => kmip_2_1::kmip_types::RevocationReasonCode::CACompromise,
            Self::AffiliationChanged => {
                kmip_2_1::kmip_types::RevocationReasonCode::AffiliationChanged
            }
            Self::Superseded => kmip_2_1::kmip_types::RevocationReasonCode::Superseded,
            Self::CessationOfOperation => {
                kmip_2_1::kmip_types::RevocationReasonCode::CessationOfOperation
            }
            Self::PrivilegeWithdrawn => {
                kmip_2_1::kmip_types::RevocationReasonCode::PrivilegeWithdrawn
            }
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

impl Into<kmip_2_1::kmip_types::LinkType> for LinkType {
    fn into(self) -> kmip_2_1::kmip_types::LinkType {
        match self {
            Self::CertificateLink => kmip_2_1::kmip_types::LinkType::CertificateLink,
            Self::PublicKeyLink => kmip_2_1::kmip_types::LinkType::PublicKeyLink,
            Self::PrivateKeyLink => kmip_2_1::kmip_types::LinkType::PrivateKeyLink,
            Self::DerivationBaseObjectLink => {
                kmip_2_1::kmip_types::LinkType::DerivationBaseObjectLink
            }
            Self::DerivedKeyLink => kmip_2_1::kmip_types::LinkType::DerivedKeyLink,
            Self::ReplacementObjectLink => kmip_2_1::kmip_types::LinkType::ReplacementObjectLink,
            Self::ReplacedObjectLink => kmip_2_1::kmip_types::LinkType::ReplacedObjectLink,
            Self::ParentLink => kmip_2_1::kmip_types::LinkType::ParentLink,
            Self::ChildLink => kmip_2_1::kmip_types::LinkType::ChildLink,
            Self::PreviousLink => kmip_2_1::kmip_types::LinkType::PreviousLink,
            Self::NextLink => kmip_2_1::kmip_types::LinkType::NextLink,
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

impl Into<kmip_2_1::kmip_types::UsageLimitsUnit> for UsageLimitsUnit {
    fn into(self) -> kmip_2_1::kmip_types::UsageLimitsUnit {
        match self {
            Self::Byte => kmip_2_1::kmip_types::UsageLimitsUnit::Byte,
            Self::Object => kmip_2_1::kmip_types::UsageLimitsUnit::Object,
        }
    }
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

impl Into<kmip_2_1::kmip_types::AlternativeNameType> for AlternativeNameType {
    fn into(self) -> kmip_2_1::kmip_types::AlternativeNameType {
        match self {
            Self::UninterpretedTextString => {
                kmip_2_1::kmip_types::AlternativeNameType::UninterpretedTextString
            }
            Self::URI => kmip_2_1::kmip_types::AlternativeNameType::URI,
            Self::ObjectSerialNumber => {
                kmip_2_1::kmip_types::AlternativeNameType::ObjectSerialNumber
            }
            Self::EmailAddress => kmip_2_1::kmip_types::AlternativeNameType::EmailAddress,
            Self::DNSName => kmip_2_1::kmip_types::AlternativeNameType::DNSName,
            Self::X500DirectoryName => kmip_2_1::kmip_types::AlternativeNameType::X500DirectoryName,
            Self::IPAddress => kmip_2_1::kmip_types::AlternativeNameType::IPAddress,
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

impl Into<kmip_2_1::kmip_types::KeyValueLocationType> for KeyValueLocationType {
    fn into(self) -> kmip_2_1::kmip_types::KeyValueLocationType {
        match self {
            Self::Unspecified => kmip_2_1::kmip_types::KeyValueLocationType::Unspecified,
            Self::OnPremise => kmip_2_1::kmip_types::KeyValueLocationType::OnPremise,
            Self::OffPremise => kmip_2_1::kmip_types::KeyValueLocationType::OffPremise,
            Self::OnPremiseOffPremise => {
                kmip_2_1::kmip_types::KeyValueLocationType::OnPremiseOffPremise
            }
        }
    }
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

impl Into<kmip_2_1::kmip_types::RNGAlgorithm> for RNGAlgorithm {
    fn into(self) -> kmip_2_1::kmip_types::RNGAlgorithm {
        match self {
            Self::Unspecified => kmip_2_1::kmip_types::RNGAlgorithm::Unspecified,
            Self::FIPS186_2 => kmip_2_1::kmip_types::RNGAlgorithm::FIPS186_2,
            Self::DRBG => kmip_2_1::kmip_types::RNGAlgorithm::DRBG,
            Self::NRBG => kmip_2_1::kmip_types::RNGAlgorithm::NRBG,
            Self::ANSI_X931 => kmip_2_1::kmip_types::RNGAlgorithm::ANSI_X931,
            Self::ANSI_X962 => kmip_2_1::kmip_types::RNGAlgorithm::ANSI_X962,
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

impl Into<kmip_2_1::kmip_types::DRBGAlgorithm> for DRBGAlgorithm {
    fn into(self) -> kmip_2_1::kmip_types::DRBGAlgorithm {
        match self {
            Self::Unspecified => kmip_2_1::kmip_types::DRBGAlgorithm::Unspecified,
            Self::DualEC => kmip_2_1::kmip_types::DRBGAlgorithm::DualEC,
            Self::Hash => kmip_2_1::kmip_types::DRBGAlgorithm::Hash,
            Self::HMAC => kmip_2_1::kmip_types::DRBGAlgorithm::HMAC,
            Self::CTR => kmip_2_1::kmip_types::DRBGAlgorithm::CTR,
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

impl Into<kmip_2_1::kmip_types::FIPS186Variation> for FIPS186Variation {
    fn into(self) -> kmip_2_1::kmip_types::FIPS186Variation {
        match self {
            Self::Unspecified => kmip_2_1::kmip_types::FIPS186Variation::Unspecified,
            Self::GPXOriginal => kmip_2_1::kmip_types::FIPS186Variation::GPXOriginal,
            Self::GPXChangeNotice => kmip_2_1::kmip_types::FIPS186Variation::GPXChangeNotice,
            Self::XOriginal => kmip_2_1::kmip_types::FIPS186Variation::XOriginal,
            Self::XChangeNotice => kmip_2_1::kmip_types::FIPS186Variation::XChangeNotice,
            Self::KOriginal => kmip_2_1::kmip_types::FIPS186Variation::KOriginal,
            Self::KChangeNotice => kmip_2_1::kmip_types::FIPS186Variation::KChangeNotice,
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

impl Into<kmip_2_1::kmip_types::RecommendedCurve> for RecommendedCurve {
    fn into(self) -> kmip_2_1::kmip_types::RecommendedCurve {
        match self {
            Self::P192 => kmip_2_1::kmip_types::RecommendedCurve::P192,
            Self::K163 => kmip_2_1::kmip_types::RecommendedCurve::K163,
            Self::B163 => kmip_2_1::kmip_types::RecommendedCurve::B163,
            Self::P224 => kmip_2_1::kmip_types::RecommendedCurve::P224,
            Self::K233 => kmip_2_1::kmip_types::RecommendedCurve::K233,
            Self::B233 => kmip_2_1::kmip_types::RecommendedCurve::B233,
            Self::P256 => kmip_2_1::kmip_types::RecommendedCurve::P256,
            Self::K283 => kmip_2_1::kmip_types::RecommendedCurve::K283,
            Self::B283 => kmip_2_1::kmip_types::RecommendedCurve::B283,
            Self::P384 => kmip_2_1::kmip_types::RecommendedCurve::P384,
            Self::K409 => kmip_2_1::kmip_types::RecommendedCurve::K409,
            Self::B409 => kmip_2_1::kmip_types::RecommendedCurve::B409,
            Self::P521 => kmip_2_1::kmip_types::RecommendedCurve::P521,
            Self::K571 => kmip_2_1::kmip_types::RecommendedCurve::K571,
            Self::B571 => kmip_2_1::kmip_types::RecommendedCurve::B571,
            Self::SECP112R1 => kmip_2_1::kmip_types::RecommendedCurve::SECP112R1,
            Self::SECP112R2 => kmip_2_1::kmip_types::RecommendedCurve::SECP112R2,
            Self::SECP128R1 => kmip_2_1::kmip_types::RecommendedCurve::SECP128R1,
            Self::SECP128R2 => kmip_2_1::kmip_types::RecommendedCurve::SECP128R2,
            Self::SECP160R1 => kmip_2_1::kmip_types::RecommendedCurve::SECP160R1,
            Self::SECP160K1 => kmip_2_1::kmip_types::RecommendedCurve::SECP160K1,
            Self::SECP256K1 => kmip_2_1::kmip_types::RecommendedCurve::SECP256K1,
            Self::BRAINPOOLP160R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP160R1,
            Self::BRAINPOOLP160T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP160T1,
            Self::BRAINPOOLP192R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP192R1,
            Self::BRAINPOOLP192T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP192T1,
            Self::BRAINPOOLP224R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP224R1,
            Self::BRAINPOOLP224T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP224T1,
            Self::BRAINPOOLP256R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP256R1,
            Self::BRAINPOOLP256T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP256T1,
            Self::BRAINPOOLP320R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP320R1,
            Self::BRAINPOOLP320T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP320T1,
            Self::BRAINPOOLP384R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP384R1,
            Self::BRAINPOOLP384T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP384T1,
            Self::BRAINPOOLP512R1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP512R1,
            Self::BRAINPOOLP512T1 => kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP512T1,
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

impl Into<kmip_2_1::kmip_types::DigitalSignatureAlgorithm> for DigitalSignatureAlgorithm {
    fn into(self) -> kmip_2_1::kmip_types::DigitalSignatureAlgorithm {
        match self {
            Self::MD2WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::MD2WithRSAEncryption
            }
            Self::MD5WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::MD5WithRSAEncryption
            }
            Self::SHA1WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA1WithRSAEncryption
            }
            Self::SHA224WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA224WithRSAEncryption
            }
            Self::SHA256WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA256WithRSAEncryption
            }
            Self::SHA384WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA384WithRSAEncryption
            }
            Self::SHA512WithRSAEncryption => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA512WithRSAEncryption
            }
            Self::RSASSAPSS => kmip_2_1::kmip_types::DigitalSignatureAlgorithm::RSASSAPSS,
            Self::DSAWithSHA1 => kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA1,
            Self::DSAWithSHA224 => kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA224,
            Self::DSAWithSHA256 => kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA256,
            Self::ECDSAWithSHA1 => kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA1,
            Self::ECDSAWithSHA224 => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA224
            }
            Self::ECDSAWithSHA256 => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA256
            }
            Self::ECDSAWithSHA384 => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA384
            }
            Self::ECDSAWithSHA512 => {
                kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA512
            }
        }
    }
}

/// KMIP 1.4 Opaque Data Type Enumeration
#[derive(Debug, Display, Serialize, Deserialize, EnumString, Clone, PartialEq, Eq, Hash)]
pub enum OpaqueDataType {
    Unknown = 0x1,
    PKCS12 = 0x2,
}

/// KMIP 1.4 Name structure containing a name type and value
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Name {
    pub name_value: String,
    pub name_type: NameType,
}

impl Into<kmip_2_1::kmip_types::Name> for Name {
    fn into(self) -> kmip_2_1::kmip_types::Name {
        kmip_2_1::kmip_types::Name {
            name_value: self.name_value,
            name_type: self.name_type.into(),
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

impl Into<kmip_2_1::kmip_types::CryptographicDomainParameters> for CryptographicDomainParameters {
    fn into(self) -> kmip_2_1::kmip_types::CryptographicDomainParameters {
        kmip_2_1::kmip_types::CryptographicDomainParameters {
            qlength: self.qlength,
            recommended_curve: self.recommended_curve.map(|c| c.into()),
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

impl Into<kmip_2_1::kmip_types::X509CertificateIdentifier> for X509CertificateIdentifier {
    fn into(self) -> kmip_2_1::kmip_types::X509CertificateIdentifier {
        kmip_2_1::kmip_types::X509CertificateIdentifier {
            issuer_distinguished_name: self.issuer_distinguished_name,
            cxertificate_serial_number: self.cxertificate_serial_number,
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

impl Into<kmip_2_1::kmip_types::CryptographicUsageMask> for CryptographicUsageMask {
    fn into(self) -> kmip_2_1::kmip_types::CryptographicUsageMask {
        kmip_2_1::kmip_types::CryptographicUsageMask(self.0)
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

impl Into<kmip_2_1::kmip_types::UsageLimits> for UsageLimits {
    fn into(self) -> kmip_2_1::kmip_types::UsageLimits {
        kmip_2_1::kmip_types::UsageLimits {
            usage_limits_unit: self.usage_limits_unit.into(),
            usage_limits_count: self.usage_limits_count,
            usage_limits_total: self.usage_limits_total,
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

impl Into<kmip_2_1::kmip_types::RevocationReason> for RevocationReason {
    fn into(self) -> kmip_2_1::kmip_types::RevocationReason {
        kmip_2_1::kmip_types::RevocationReason {
            revocation_reason_code: self.revocation_reason_code.into(),
            revocation_message: self.revocation_message,
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

impl Into<kmip_2_1::kmip_types::ApplicationSpecificInformation> for ApplicationSpecificInformation {
    fn into(self) -> kmip_2_1::kmip_types::ApplicationSpecificInformation {
        kmip_2_1::kmip_types::ApplicationSpecificInformation {
            application_namespace: self.application_namespace,
            application_data: self.application_data,
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

impl Into<kmip_2_1::kmip_types::AlternativeName> for AlternativeName {
    fn into(self) -> kmip_2_1::kmip_types::AlternativeName {
        kmip_2_1::kmip_types::AlternativeName {
            alternative_name_value: self.alternative_name_value,
            alternative_name_type: self.alternative_name_type.into(),
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

impl Into<kmip_2_1::kmip_types::RandomNumberGenerator> for RandomNumberGenerator {
    fn into(self) -> kmip_2_1::kmip_types::RandomNumberGenerator {
        kmip_2_1::kmip_types::RandomNumberGenerator {
            rng_algorithm: self.rng_algorithm.into(),
            cryptographic_algorithm: self.cryptographic_algorithm.map(|c| c.into()),
            cryptographic_length: self.cryptographic_length,
            hashing_algorithm: self.hashing_algorithm.map(|h| h.into()),
            drbg_algorithm: self.drbg_algorithm.map(|d| d.into()),
            recommended_curve: self.recommended_curve.map(|r| r.into()),
            fips186_variation: self.fips186_variation.map(|f| f.into()),
            prediction_resistance: self.prediction_resistance,
        }
    }
}

/// Link Structure represents the relationship between a Managed Object and another object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct Link {
    pub link_type: LinkType,
    pub linked_object_identifier: LinkedObjectIdentifier,
}

impl Into<kmip_2_1::kmip_types::Link> for Link {
    fn into(self) -> kmip_2_1::kmip_types::Link {
        kmip_2_1::kmip_types::Link {
            link_type: self.link_type.into(),
            linked_object_identifier: self.linked_object_identifier,
        }
    }
}

/// LinkedObjectIdentifier defines the format of the object reference in a link.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum LinkedObjectIdentifier {
    TextString(String),
    Enumeration(i32),
    Index(i32),
}
