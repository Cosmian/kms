#![allow(non_camel_case_types)]

use kmip_derive::{KmipEnumDeserialize, KmipEnumSerialize, kmip_enum};
use serde::{Deserialize, Serialize};
use strum::Display;

use crate::{
    KmipError, kmip_0,
    kmip_0::kmip_types::{DRBGAlgorithm, FIPS186Variation, HashingAlgorithm, RNGAlgorithm},
    kmip_1_4::kmip_attributes::CustomAttributeValue,
    kmip_2_1::{self},
};

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

impl TryFrom<kmip_2_1::kmip_types::KeyCompressionType> for KeyCompressionType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::KeyCompressionType) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeUncompressed => {
                Ok(Self::ECPublicKeyTypeUncompressed)
            }
            kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962CompressedPrime => {
                Ok(Self::ECPublicKeyTypeX962CompressedPrime)
            }
            kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962CompressedChar2 => {
                Ok(Self::ECPublicKeyTypeX962CompressedChar2)
            }
            kmip_2_1::kmip_types::KeyCompressionType::ECPublicKeyTypeX962Hybrid => {
                Err(KmipError::InvalidKmip14Value(
                    ResultReason::InvalidField,
                    "ECPublicKeyTypeX962Hybrid is not supported in KMIP 1".to_owned(),
                ))
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
    TransparentECPrivateKey = 0x14,
    TransparentECPublicKey = 0x15,
    PKCS12 = 0x16,
    // Extensions
    ConfigurableKEM = 0x8880_0003,
    CoverCryptSecretKey = 0x8880_000C,
    CoverCryptPublicKey = 0x8880_000D,
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
            | KeyFormatType::TransparentECDHPublicKey
            | KeyFormatType::TransparentECPublicKey => Self::TransparentECPublicKey,
            KeyFormatType::TransparentECDHPrivateKey
            | KeyFormatType::TransparentECMQVPrivateKey
            | KeyFormatType::TransparentECDSAPrivateKey
            | KeyFormatType::TransparentECPrivateKey => Self::TransparentECPrivateKey,
            KeyFormatType::PKCS12 => Self::PKCS12,
            KeyFormatType::ConfigurableKEM => Self::ConfigurableKEM,
            KeyFormatType::CoverCryptSecretKey => Self::CoverCryptSecretKey,
            KeyFormatType::CoverCryptPublicKey => Self::CoverCryptPublicKey,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::KeyFormatType> for KeyFormatType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::KeyFormatType) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::KeyFormatType::Raw => Ok(Self::Raw),
            kmip_2_1::kmip_types::KeyFormatType::Opaque => Ok(Self::Opaque),
            kmip_2_1::kmip_types::KeyFormatType::PKCS1 => Ok(Self::PKCS1),
            kmip_2_1::kmip_types::KeyFormatType::PKCS8 => Ok(Self::PKCS8),
            kmip_2_1::kmip_types::KeyFormatType::X509 => Ok(Self::X509),
            kmip_2_1::kmip_types::KeyFormatType::ECPrivateKey => Ok(Self::ECPrivateKey),
            kmip_2_1::kmip_types::KeyFormatType::TransparentSymmetricKey => {
                Ok(Self::TransparentSymmetricKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentDSAPrivateKey => {
                Ok(Self::TransparentDSAPrivateKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentDSAPublicKey => {
                Ok(Self::TransparentDSAPublicKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentRSAPrivateKey => {
                Ok(Self::TransparentRSAPrivateKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentRSAPublicKey => {
                Ok(Self::TransparentRSAPublicKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentDHPrivateKey => {
                Ok(Self::TransparentDHPrivateKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::TransparentDHPublicKey => {
                Ok(Self::TransparentDHPublicKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::ConfigurableKEM => Ok(Self::ConfigurableKEM),
            kmip_2_1::kmip_types::KeyFormatType::CoverCryptSecretKey => {
                Ok(Self::CoverCryptSecretKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::CoverCryptPublicKey => {
                Ok(Self::CoverCryptPublicKey)
            }
            kmip_2_1::kmip_types::KeyFormatType::PKCS12 => Ok(Self::PKCS12),
            kmip_2_1::kmip_types::KeyFormatType::TransparentECPrivateKey
            | kmip_2_1::kmip_types::KeyFormatType::TransparentECPublicKey
            | kmip_2_1::kmip_types::KeyFormatType::PKCS10
            | kmip_2_1::kmip_types::KeyFormatType::PKCS7
            | kmip_2_1::kmip_types::KeyFormatType::EnclaveECKeyPair
            | kmip_2_1::kmip_types::KeyFormatType::EnclaveECSharedKey => {
                Err(KmipError::InvalidKmip14Value(
                    ResultReason::InvalidField,
                    format!("Key Format Type: {value:?}, is not supported in KMIP 1.4"),
                ))
            }
            #[cfg(feature = "non-fips")]
            kmip_2_1::kmip_types::KeyFormatType::Pkcs12Legacy => {
                Err(KmipError::InvalidKmip14Value(
                    ResultReason::InvalidField,
                    "Key Format Type: PKCS12Legacy is not supported in KMIP 1.4".to_owned(),
                ))
            }
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

impl TryFrom<kmip_2_1::kmip_types::WrappingMethod> for WrappingMethod {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::WrappingMethod) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::WrappingMethod::Encrypt => Ok(Self::Encrypt),
            kmip_2_1::kmip_types::WrappingMethod::MACSign => Ok(Self::MACSign),
            kmip_2_1::kmip_types::WrappingMethod::EncryptThenMACSign => {
                Ok(Self::EncryptThenMACSign)
            }
            kmip_2_1::kmip_types::WrappingMethod::MACSignThenEncrypt => {
                Ok(Self::MACSignThenEncrypt)
            }
            kmip_2_1::kmip_types::WrappingMethod::TR31 => Ok(Self::TR31),
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

impl TryFrom<kmip_2_1::kmip_types::SplitKeyMethod> for SplitKeyMethod {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::SplitKeyMethod) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::SplitKeyMethod::XOR => Ok(Self::XOR),
            kmip_2_1::kmip_types::SplitKeyMethod::PolynomialSharingGf216 => {
                Ok(Self::PolynomialSharingGf216)
            }
            kmip_2_1::kmip_types::SplitKeyMethod::PolynomialSharingPrimeField => {
                Ok(Self::PolynomialSharingPrimeField)
            }
            kmip_2_1::kmip_types::SplitKeyMethod::PolynomialSharingGf28 => {
                Ok(Self::PolynomialSharingGf28)
            }
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

impl TryFrom<kmip_2_1::kmip_types::NameType> for NameType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::NameType) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::NameType::UninterpretedTextString => {
                Ok(Self::UninterpretedTextString)
            }
            kmip_2_1::kmip_types::NameType::URI => Ok(Self::URI),
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
    // Deprecated in KMIP 1.4 but still appears in interoperability vectors (e.g., Query responses)
    Template = 0x6,
    SecretData = 0x7,
    OpaqueObject = 0x8,
    PGPKey = 0x9,
}

impl From<ObjectType> for kmip_2_1::kmip_objects::ObjectType {
    fn from(val: ObjectType) -> Self {
        match val {
            // KMIP 2.1 does not support Template object type. Return Certificate as a placeholder.
            ObjectType::Certificate | ObjectType::Template => Self::Certificate,
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

impl TryFrom<kmip_2_1::kmip_objects::ObjectType> for ObjectType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_objects::ObjectType) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_objects::ObjectType::Certificate => Ok(Self::Certificate),
            kmip_2_1::kmip_objects::ObjectType::SymmetricKey => Ok(Self::SymmetricKey),
            kmip_2_1::kmip_objects::ObjectType::PublicKey => Ok(Self::PublicKey),
            kmip_2_1::kmip_objects::ObjectType::PrivateKey => Ok(Self::PrivateKey),
            kmip_2_1::kmip_objects::ObjectType::SplitKey => Ok(Self::SplitKey),
            kmip_2_1::kmip_objects::ObjectType::SecretData => Ok(Self::SecretData),
            kmip_2_1::kmip_objects::ObjectType::OpaqueObject => Ok(Self::OpaqueObject),
            kmip_2_1::kmip_objects::ObjectType::PGPKey => Ok(Self::PGPKey),
            kmip_2_1::kmip_objects::ObjectType::CertificateRequest => {
                Err(KmipError::InvalidKmip14Value(
                    ResultReason::InvalidField,
                    "CertificateRequest is not supported in KMIP 1.4".to_owned(),
                ))
            }
        }
    }
}

impl From<ObjectType> for u32 {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
            ObjectType::Certificate => 0x01,
            ObjectType::SymmetricKey => 0x02,
            ObjectType::PublicKey => 0x03,
            ObjectType::PrivateKey => 0x04,
            ObjectType::SplitKey => 0x05,
            ObjectType::Template => 0x06,
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
            0x06 => Ok(Self::Template),
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

impl TryFrom<kmip_2_1::kmip_types::CryptographicAlgorithm> for CryptographicAlgorithm {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::CryptographicAlgorithm) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::CryptographicAlgorithm::DES => Ok(Self::DES),
            kmip_2_1::kmip_types::CryptographicAlgorithm::AES => Ok(Self::AES),
            kmip_2_1::kmip_types::CryptographicAlgorithm::RSA => Ok(Self::RSA),
            kmip_2_1::kmip_types::CryptographicAlgorithm::DSA => Ok(Self::DSA),
            kmip_2_1::kmip_types::CryptographicAlgorithm::ECDSA => Ok(Self::ECDSA),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA1 => Ok(Self::HMACSHA1),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA224 => Ok(Self::HMACSHA224),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA256 => Ok(Self::HMACSHA256),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA384 => Ok(Self::HMACSHA384),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA512 => Ok(Self::HMACSHA512),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACMD5 => Ok(Self::HMACMD5),
            kmip_2_1::kmip_types::CryptographicAlgorithm::DH => Ok(Self::DH),
            kmip_2_1::kmip_types::CryptographicAlgorithm::ECDH => Ok(Self::ECDH),
            kmip_2_1::kmip_types::CryptographicAlgorithm::ECMQV => Ok(Self::ECMQV),
            kmip_2_1::kmip_types::CryptographicAlgorithm::Blowfish => Ok(Self::Blowfish),
            kmip_2_1::kmip_types::CryptographicAlgorithm::Camellia => Ok(Self::Camellia),
            kmip_2_1::kmip_types::CryptographicAlgorithm::CAST5 => Ok(Self::CAST5),
            kmip_2_1::kmip_types::CryptographicAlgorithm::IDEA => Ok(Self::IDEA),
            kmip_2_1::kmip_types::CryptographicAlgorithm::MARS => Ok(Self::MARS),
            kmip_2_1::kmip_types::CryptographicAlgorithm::RC2 => Ok(Self::RC2),
            kmip_2_1::kmip_types::CryptographicAlgorithm::RC4 => Ok(Self::RC4),
            kmip_2_1::kmip_types::CryptographicAlgorithm::RC5 => Ok(Self::RC5),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SKIPJACK => Ok(Self::SKIPJACK),
            kmip_2_1::kmip_types::CryptographicAlgorithm::Twofish => Ok(Self::Twofish),
            kmip_2_1::kmip_types::CryptographicAlgorithm::EC => Ok(Self::EC),
            kmip_2_1::kmip_types::CryptographicAlgorithm::OneTimePad => Ok(Self::OneTimePad),
            kmip_2_1::kmip_types::CryptographicAlgorithm::ChaCha20 => Ok(Self::ChaCha20),
            kmip_2_1::kmip_types::CryptographicAlgorithm::Poly1305 => Ok(Self::Poly1305),
            kmip_2_1::kmip_types::CryptographicAlgorithm::ChaCha20Poly1305 => {
                Ok(Self::ChaCha20Poly1305)
            }
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3224 => Ok(Self::SHA3224),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3256 => Ok(Self::SHA3256),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3384 => Ok(Self::SHA3384),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHA3512 => Ok(Self::SHA3512),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3224 => Ok(Self::HMACSHA3224),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3256 => Ok(Self::HMACSHA3256),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3384 => Ok(Self::HMACSHA3384),
            kmip_2_1::kmip_types::CryptographicAlgorithm::HMACSHA3512 => Ok(Self::HMACSHA3512),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHAKE128 => Ok(Self::SHAKE128),
            kmip_2_1::kmip_types::CryptographicAlgorithm::SHAKE256 => Ok(Self::SHAKE256),
            x => Err(KmipError::InvalidKmip14Value(
                ResultReason::InvalidField,
                format!("Invalid Cryptographic Algorithm value: {x}. Not supported in KMIP 1.4"),
            )),
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

impl TryFrom<kmip_2_1::kmip_types::LinkType> for LinkType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::LinkType) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::LinkType::CertificateLink => Ok(Self::CertificateLink),
            kmip_2_1::kmip_types::LinkType::PublicKeyLink => Ok(Self::PublicKeyLink),
            kmip_2_1::kmip_types::LinkType::PrivateKeyLink => Ok(Self::PrivateKeyLink),
            kmip_2_1::kmip_types::LinkType::DerivationBaseObjectLink => {
                Ok(Self::DerivationBaseObjectLink)
            }
            kmip_2_1::kmip_types::LinkType::DerivedKeyLink => Ok(Self::DerivedKeyLink),
            kmip_2_1::kmip_types::LinkType::ReplacementObjectLink => {
                Ok(Self::ReplacementObjectLink)
            }
            kmip_2_1::kmip_types::LinkType::ReplacedObjectLink => Ok(Self::ReplacedObjectLink),
            kmip_2_1::kmip_types::LinkType::ParentLink => Ok(Self::ParentLink),
            kmip_2_1::kmip_types::LinkType::ChildLink => Ok(Self::ChildLink),
            kmip_2_1::kmip_types::LinkType::PreviousLink => Ok(Self::PreviousLink),
            kmip_2_1::kmip_types::LinkType::NextLink => Ok(Self::NextLink),
            kmip_2_1::kmip_types::LinkType::PKCS12CertificateLink
            | kmip_2_1::kmip_types::LinkType::PKCS12PasswordLink
            | kmip_2_1::kmip_types::LinkType::WrappingKeyLink => {
                Err(KmipError::InvalidKmip14Value(
                    ResultReason::InvalidField,
                    "{value:?} is not  supported in KMIP 1.4".to_owned(),
                ))
            }
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

impl From<ValidityIndicator> for kmip_2_1::kmip_types::ValidityIndicator {
    fn from(val: ValidityIndicator) -> Self {
        match val {
            ValidityIndicator::Valid => Self::Valid,
            ValidityIndicator::Invalid => Self::Invalid,
            ValidityIndicator::Unknown => Self::Unknown,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::ValidityIndicator> for ValidityIndicator {
    type Error = KmipError;

    fn try_from(val: kmip_2_1::kmip_types::ValidityIndicator) -> Result<Self, Self::Error> {
        Ok(match val {
            kmip_2_1::kmip_types::ValidityIndicator::Valid => Self::Valid,
            kmip_2_1::kmip_types::ValidityIndicator::Invalid => Self::Invalid,
            kmip_2_1::kmip_types::ValidityIndicator::Unknown => Self::Unknown,
        })
    }
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

impl From<QueryFunction> for kmip_2_1::kmip_types::QueryFunction {
    fn from(val: QueryFunction) -> Self {
        match val {
            QueryFunction::QueryOperations => Self::QueryOperations,
            QueryFunction::QueryObjects => Self::QueryObjects,
            QueryFunction::QueryServerInformation => Self::QueryServerInformation,
            QueryFunction::QueryApplicationNamespaces => Self::QueryApplicationNamespaces,
            QueryFunction::QueryExtensionList => Self::QueryExtensionList,
            QueryFunction::QueryExtensionMap => Self::QueryExtensionMap,
            QueryFunction::QueryAttestationTypes => Self::QueryAttestationTypes,
            QueryFunction::QueryRNGs => Self::QueryRNGs,
            QueryFunction::QueryValidations => Self::QueryValidations,
            QueryFunction::QueryProfiles => Self::QueryProfiles,
            QueryFunction::QueryCapabilities => Self::QueryCapabilities,
            QueryFunction::QueryClientRegistrationMethods => Self::QueryClientRegistrationMethods,
        }
    }
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
            OperationEnumeration::Activate => Self::Activate,
            OperationEnumeration::AddAttribute => Self::AddAttribute,
            OperationEnumeration::Archive => Self::Archive,
            OperationEnumeration::Cancel => Self::Cancel,
            OperationEnumeration::Certify => Self::Certify,
            OperationEnumeration::Check => Self::Check,
            OperationEnumeration::Create => Self::Create,
            OperationEnumeration::CreateKeyPair => Self::CreateKeyPair,
            OperationEnumeration::CreateSplitKey => Self::CreateSplitKey,
            OperationEnumeration::Decrypt => Self::Decrypt,
            OperationEnumeration::DeleteAttribute => Self::DeleteAttribute,
            OperationEnumeration::DeriveKey => Self::DeriveKey,
            OperationEnumeration::Destroy => Self::Destroy,
            OperationEnumeration::DiscoverVersions => Self::DiscoverVersions,
            OperationEnumeration::Encrypt => Self::Encrypt,
            OperationEnumeration::Export => Self::Export,
            OperationEnumeration::Get => Self::Get,
            OperationEnumeration::GetAttributes => Self::GetAttributes,
            OperationEnumeration::GetAttributeList => Self::GetAttributeList,
            OperationEnumeration::GetUsageAllocation => Self::GetUsageAllocation,
            OperationEnumeration::Hash => Self::Hash,
            OperationEnumeration::Import => Self::Import,
            OperationEnumeration::JoinSplitKey => Self::JoinSplitKey,
            OperationEnumeration::Locate => Self::Locate,
            OperationEnumeration::MAC => Self::MAC,
            OperationEnumeration::MACVerify => Self::MACVerify,
            OperationEnumeration::ModifyAttribute => Self::ModifyAttribute,
            OperationEnumeration::Notify => Self::Notify,
            OperationEnumeration::ObtainLease => Self::ObtainLease,
            OperationEnumeration::Poll => Self::Poll,
            OperationEnumeration::Put => Self::Put,
            OperationEnumeration::Query => Self::Query,
            OperationEnumeration::ReCertify => Self::ReCertify,
            OperationEnumeration::Recover => Self::Recover,
            OperationEnumeration::Register => Self::Register,
            OperationEnumeration::ReKey => Self::ReKey,
            OperationEnumeration::ReKeyKeyPair => Self::ReKeyKeyPair,
            OperationEnumeration::Revoke => Self::Revoke,
            OperationEnumeration::RNGRetrieve => Self::RNGRetrieve,
            OperationEnumeration::RNGSeed => Self::RNGSeed,
            OperationEnumeration::Sign => Self::Sign,
            OperationEnumeration::SignatureVerify => Self::SignatureVerify,
            OperationEnumeration::Validate => Self::Validate,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::OperationEnumeration> for OperationEnumeration {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::OperationEnumeration) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_types::OperationEnumeration::Activate => Self::Activate,
            kmip_2_1::kmip_types::OperationEnumeration::AddAttribute => Self::AddAttribute,
            kmip_2_1::kmip_types::OperationEnumeration::AdjustAttribute
            | kmip_2_1::kmip_types::OperationEnumeration::DelegatedLogin
            | kmip_2_1::kmip_types::OperationEnumeration::GetConstraints
            | kmip_2_1::kmip_types::OperationEnumeration::Interop
            | kmip_2_1::kmip_types::OperationEnumeration::Log
            | kmip_2_1::kmip_types::OperationEnumeration::Login
            | kmip_2_1::kmip_types::OperationEnumeration::Logout
            | kmip_2_1::kmip_types::OperationEnumeration::Ping
            | kmip_2_1::kmip_types::OperationEnumeration::PKCS11
            | kmip_2_1::kmip_types::OperationEnumeration::Process
            | kmip_2_1::kmip_types::OperationEnumeration::QueryAsynchronousRequests
            | kmip_2_1::kmip_types::OperationEnumeration::ReProvision
            | kmip_2_1::kmip_types::OperationEnumeration::SetAttribute
            | kmip_2_1::kmip_types::OperationEnumeration::SetConstraints
            | kmip_2_1::kmip_types::OperationEnumeration::SetDefaults
            | kmip_2_1::kmip_types::OperationEnumeration::SetEndpointRole => {
                return Err(KmipError::InvalidKmip14Value(
                    ResultReason::OperationNotSupported,
                    format!("Operation not supported: {value:?}"),
                ));
            }
            kmip_2_1::kmip_types::OperationEnumeration::Archive => Self::Archive,
            kmip_2_1::kmip_types::OperationEnumeration::Cancel => Self::Cancel,
            kmip_2_1::kmip_types::OperationEnumeration::Certify => Self::Certify,
            kmip_2_1::kmip_types::OperationEnumeration::Check => Self::Check,
            kmip_2_1::kmip_types::OperationEnumeration::Create => Self::Create,
            kmip_2_1::kmip_types::OperationEnumeration::CreateKeyPair => Self::CreateKeyPair,
            kmip_2_1::kmip_types::OperationEnumeration::CreateSplitKey => Self::CreateSplitKey,
            kmip_2_1::kmip_types::OperationEnumeration::Decrypt => Self::Decrypt,
            kmip_2_1::kmip_types::OperationEnumeration::DeleteAttribute => Self::DeleteAttribute,
            kmip_2_1::kmip_types::OperationEnumeration::DeriveKey => Self::DeriveKey,
            kmip_2_1::kmip_types::OperationEnumeration::Destroy => Self::Destroy,
            kmip_2_1::kmip_types::OperationEnumeration::DiscoverVersions => Self::DiscoverVersions,
            kmip_2_1::kmip_types::OperationEnumeration::Encrypt => Self::Encrypt,
            kmip_2_1::kmip_types::OperationEnumeration::Export => Self::Export,
            kmip_2_1::kmip_types::OperationEnumeration::Get => Self::Get,
            kmip_2_1::kmip_types::OperationEnumeration::GetAttributeList => Self::GetAttributeList,
            kmip_2_1::kmip_types::OperationEnumeration::GetAttributes => Self::GetAttributes,
            kmip_2_1::kmip_types::OperationEnumeration::GetUsageAllocation => {
                Self::GetUsageAllocation
            }
            kmip_2_1::kmip_types::OperationEnumeration::Hash => Self::Hash,
            kmip_2_1::kmip_types::OperationEnumeration::Import => Self::Import,
            kmip_2_1::kmip_types::OperationEnumeration::JoinSplitKey => Self::JoinSplitKey,
            kmip_2_1::kmip_types::OperationEnumeration::Locate => Self::Locate,
            kmip_2_1::kmip_types::OperationEnumeration::MAC => Self::MAC,
            kmip_2_1::kmip_types::OperationEnumeration::MACVerify => Self::MACVerify,
            kmip_2_1::kmip_types::OperationEnumeration::ModifyAttribute => Self::ModifyAttribute,
            kmip_2_1::kmip_types::OperationEnumeration::Notify => Self::Notify,
            kmip_2_1::kmip_types::OperationEnumeration::ObtainLease => Self::ObtainLease,
            kmip_2_1::kmip_types::OperationEnumeration::Poll => Self::Poll,
            kmip_2_1::kmip_types::OperationEnumeration::Put => Self::Put,
            kmip_2_1::kmip_types::OperationEnumeration::Query => Self::Query,
            kmip_2_1::kmip_types::OperationEnumeration::ReCertify => Self::ReCertify,
            kmip_2_1::kmip_types::OperationEnumeration::Recover => Self::Recover,
            kmip_2_1::kmip_types::OperationEnumeration::Register => Self::Register,
            kmip_2_1::kmip_types::OperationEnumeration::ReKey => Self::ReKey,
            kmip_2_1::kmip_types::OperationEnumeration::ReKeyKeyPair => Self::ReKeyKeyPair,
            kmip_2_1::kmip_types::OperationEnumeration::Revoke => Self::Revoke,
            kmip_2_1::kmip_types::OperationEnumeration::RNGRetrieve => Self::RNGRetrieve,
            kmip_2_1::kmip_types::OperationEnumeration::RNGSeed => Self::RNGSeed,
            kmip_2_1::kmip_types::OperationEnumeration::Sign => Self::Sign,
            kmip_2_1::kmip_types::OperationEnumeration::SignatureVerify => Self::SignatureVerify,
            kmip_2_1::kmip_types::OperationEnumeration::Validate => Self::Validate,
        })
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

impl From<ResultReason> for kmip_0::kmip_types::ErrorReason {
    fn from(val: ResultReason) -> Self {
        match val {
            ResultReason::ItemNotFound => Self::Item_Not_Found,
            ResultReason::ResponseTooLarge => Self::Response_Too_Large,
            ResultReason::AuthenticationNotSuccessful => Self::Authentication_Not_Successful,
            ResultReason::InvalidMessage => Self::Invalid_Message,
            ResultReason::IllegalOperation | ResultReason::OperationNotSupported => {
                Self::Operation_Not_Supported
            }
            ResultReason::MissingData => Self::Missing_Data,
            ResultReason::InvalidField => Self::Invalid_Field,
            ResultReason::FeatureNotSupported => Self::Feature_Not_Supported,
            ResultReason::OperationCanceled => Self::Operation_Canceled_By_Requester,
            ResultReason::CryptographicFailure => Self::Cryptographic_Failure,
            ResultReason::PermissionDenied => Self::Permission_Denied,
            ResultReason::ObjectArchived => Self::Object_Archived,
            ResultReason::IndexOutOfBounds => Self::Codec_Error,
            ResultReason::ApplicationNamespaceNotSupported => {
                Self::Application_Namespace_Not_Supported
            }
            ResultReason::KeyFormatTypeNotSupported => Self::Key_Format_Type_Not_Supported,
            ResultReason::KeyCompressionTypeNotSupported => {
                Self::Key_Compression_Type_Not_Supported
            }
            ResultReason::EncodingOptionError => Self::Encoding_Option_Error,
            ResultReason::KeyValueNotPresent => Self::Key_Value_Not_Present,
            ResultReason::AttestationRequired => Self::Attestation_Required,
            ResultReason::AttestationFailed => Self::Attestation_Failed,
            ResultReason::Sensitive => Self::Sensitive,
            ResultReason::NotExtractable => Self::Not_Extractable,
            ResultReason::ObjectAlreadyExists => Self::Object_Already_Exists,
            ResultReason::GeneralFailure => Self::General_Failure,
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

impl TryFrom<kmip_2_1::kmip_types::EncodingOption> for EncodingOption {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::EncodingOption) -> Result<Self, Self::Error> {
        match value {
            kmip_2_1::kmip_types::EncodingOption::NoEncoding => Ok(Self::NoEncoding),
            kmip_2_1::kmip_types::EncodingOption::TTLVEncoding => Ok(Self::TTLVEncoding),
        }
    }
}

/// KMIP 1.4 Object Group Member Enumeration
#[kmip_enum]
pub enum ObjectGroupMember {
    GroupMemberFresh = 0x1,
    GroupMemberDefault = 0x2,
}

#[kmip_enum]
pub enum ProfileName {
    BaselineServerBasicKMIPv12 = 0x0000_0001,
    BaselineServerTLSv12KMIPv12 = 0x0000_0002,
    BaselineClientBasicKMIPv12 = 0x0000_0003,
    BaselineClientTLSv12KMIPv12 = 0x0000_0004,
    CompleteServerBasicKMIPv12 = 0x0000_0005,
    CompleteServerTLSv12KMIPv12 = 0x0000_0006,
    TapeLibraryClientKMIPv10 = 0x0000_0007,
    TapeLibraryClientKMIPv11 = 0x0000_0008,
    TapeLibraryClientKMIPv12 = 0x0000_0009,
    TapeLibraryServerKMIPv10 = 0x0000_000A,
    TapeLibraryServerKMIPv11 = 0x0000_000B,
    TapeLibraryServerKMIPv12 = 0x0000_000C,
    SymmetricKeyLifecycleClientKMIPv10 = 0x0000_000D,
    SymmetricKeyLifecycleClientKMIPv11 = 0x0000_000E,
    SymmetricKeyLifecycleClientKMIPv12 = 0x0000_000F,
    SymmetricKeyLifecycleServerKMIPv10 = 0x0000_0010,
    SymmetricKeyLifecycleServerKMIPv11 = 0x0000_0011,
    SymmetricKeyLifecycleServerKMIPv12 = 0x0000_0012,
    AsymmetricKeyLifecycleClientKMIPv10 = 0x0000_0013,
    AsymmetricKeyLifecycleClientKMIPv11 = 0x0000_0014,
    AsymmetricKeyLifecycleClientKMIPv12 = 0x0000_0015,
    AsymmetricKeyLifecycleServerKMIPv10 = 0x0000_0016,
    AsymmetricKeyLifecycleServerKMIPv11 = 0x0000_0017,
    AsymmetricKeyLifecycleServerKMIPv12 = 0x0000_0018,
    BasicCryptographicClientKMIPv12 = 0x0000_0019,
    BasicCryptographicServerKMIPv12 = 0x0000_001A,
    AdvancedCryptographicClientKMIPv12 = 0x0000_001B,
    AdvancedCryptographicServerKMIPv12 = 0x0000_001C,
    RNGCryptographicClientKMIPv12 = 0x0000_001D,
    RNGCryptographicServerKMIPv12 = 0x0000_001E,
    BasicSymmetricKeyFoundryClientKMIPv10 = 0x0000_001F,
    IntermediateSymmetricKeyFoundryClientKMIPv10 = 0x0000_0020,
    AdvancedSymmetricKeyFoundryClientKMIPv10 = 0x0000_0021,
    BasicSymmetricKeyFoundryClientKMIPv11 = 0x0000_0022,
    IntermediateSymmetricKeyFoundryClientKMIPv11 = 0x0000_0023,
    AdvancedSymmetricKeyFoundryClientKMIPv11 = 0x0000_0024,
    BasicSymmetricKeyFoundryClientKMIPv12 = 0x0000_0025,
    IntermediateSymmetricKeyFoundryClientKMIPv12 = 0x0000_0026,
    AdvancedSymmetricKeyFoundryClientKMIPv12 = 0x0000_0027,
    SymmetricKeyFoundryServerKMIPv10 = 0x0000_0028,
    SymmetricKeyFoundryServerKMIPv11 = 0x0000_0029,
    SymmetricKeyFoundryServerKMIPv12 = 0x0000_002A,
    OpaqueManagedObjectStoreClientKMIPv10 = 0x0000_002B,
    OpaqueManagedObjectStoreClientKMIPv11 = 0x0000_002C,
    OpaqueManagedObjectStoreClientKMIPv12 = 0x0000_002D,
    OpaqueManagedObjectStoreServerKMIPv10 = 0x0000_002E,
    OpaqueManagedObjectStoreServerKMIPv11 = 0x0000_002F,
    OpaqueManagedObjectStoreServerKMIPv12 = 0x0000_0030,
    SuiteBMinLOS128ClientKMIPv10 = 0x0000_0031,
    SuiteBMinLOS128ClientKMIPv11 = 0x0000_0032,
    SuiteBMinLOS128ClientKMIPv12 = 0x0000_0033,
    SuiteBMinLOS128ServerKMIPv10 = 0x0000_0034,
    SuiteBMinLOS128ServerKMIPv11 = 0x0000_0035,
    SuiteBMinLOS128ServerKMIPv12 = 0x0000_0036,
    SuiteBMinLOS192ClientKMIPv10 = 0x0000_0037,
    SuiteBMinLOS192ClientKMIPv11 = 0x0000_0038,
    SuiteBMinLOS192ClientKMIPv12 = 0x0000_0039,
    SuiteBMinLOS192ServerKMIPv10 = 0x0000_003A,
    SuiteBMinLOS192ServerKMIPv11 = 0x0000_003B,
    SuiteBMinLOS192ServerKMIPv12 = 0x0000_003C,
    StorageArrayWithSelfEncryptingDriveClientKMIPv10 = 0x0000_003D,
    StorageArrayWithSelfEncryptingDriveClientKMIPv11 = 0x0000_003E,
    StorageArrayWithSelfEncryptingDriveClientKMIPv12 = 0x0000_003F,
    StorageArrayWithSelfEncryptingDriveServerKMIPv10 = 0x0000_0040,
    StorageArrayWithSelfEncryptingDriveServerKMIPv11 = 0x0000_0041,
    StorageArrayWithSelfEncryptingDriveServerKMIPv12 = 0x0000_0042,
    HTTPSClientKMIPv10 = 0x0000_0043,
    HTTPSClientKMIPv11 = 0x0000_0044,
    HTTPSClientKMIPv12 = 0x0000_0045,
    HTTPSServerKMIPv10 = 0x0000_0046,
    HTTPSServerKMIPv11 = 0x0000_0047,
    HTTPSServerKMIPv12 = 0x0000_0048,
    JSONClientKMIPv10 = 0x0000_0049,
    JSONClientKMIPv11 = 0x0000_004A,
    JSONClientKMIPv12 = 0x0000_004B,
    JSONServerKMIPv10 = 0x0000_004C,
    JSONServerKMIPv11 = 0x0000_004D,
    JSONServerKMIPv12 = 0x0000_004E,
    XMLClientKMIPv10 = 0x0000_004F,
    XMLClientKMIPv11 = 0x0000_0050,
    XMLClientKMIPv12 = 0x0000_0051,
    XMLServerKMIPv10 = 0x0000_0052,
    XMLServerKMIPv11 = 0x0000_0053,
    XMLServerKMIPv12 = 0x0000_0054,
    BaselineServerBasicKMIPv13 = 0x0000_0055,
    BaselineServerTLSv12KMIPv13 = 0x0000_0056,
    BaselineClientBasicKMIPv13 = 0x0000_0057,
    BaselineClientTLSv12KMIPv13 = 0x0000_0058,
    CompleteServerBasicKMIPv13 = 0x0000_0059,
    CompleteServerTLSv12KMIPv13 = 0x0000_005A,
    TapeLibraryClientKMIPv13 = 0x0000_005B,
    TapeLibraryServerKMIPv13 = 0x0000_005C,
    SymmetricKeyLifecycleClientKMIPv13 = 0x0000_005D,
    SymmetricKeyLifecycleServerKMIPv13 = 0x0000_005E,
    AsymmetricKeyLifecycleClientKMIPv13 = 0x0000_005F,
    AsymmetricKeyLifecycleServerKMIPv13 = 0x0000_0060,
    BasicCryptographicClientKMIPv13 = 0x0000_0061,
    BasicCryptographicServerKMIPv13 = 0x0000_0062,
    AdvancedCryptographicClientKMIPv13 = 0x0000_0063,
    AdvancedCryptographicServerKMIPv13 = 0x0000_0064,
    RNGCryptographicClientKMIPv13 = 0x0000_0065,
    RNGCryptographicServerKMIPv13 = 0x0000_0066,
    BasicSymmetricKeyFoundryClientKMIPv13 = 0x0000_0067,
    IntermediateSymmetricKeyFoundryClientKMIPv13 = 0x0000_0068,
    AdvancedSymmetricKeyFoundryClientKMIPv13 = 0x0000_0069,
    SymmetricKeyFoundryServerKMIPv13 = 0x0000_006A,
    OpaqueManagedObjectStoreClientKMIPv13 = 0x0000_006B,
    OpaqueManagedObjectStoreServerKMIPv13 = 0x0000_006C,
    SuiteBMinLOS128ClientKMIPv13 = 0x0000_006D,
    SuiteBMinLOS128ServerKMIPv13 = 0x0000_006E,
    SuiteBMinLOS192ClientKMIPv13 = 0x0000_006F,
    SuiteBMinLOS192ServerKMIPv13 = 0x0000_0070,
    StorageArrayWithSelfEncryptingDriveClientKMIPv13 = 0x0000_0071,
    StorageArrayWithSelfEncryptingDriveServerKMIPv13 = 0x0000_0072,
    HTTPSClientKMIPv13 = 0x0000_0073,
    HTTPSServerKMIPv13 = 0x0000_0074,
    JSONClientKMIPv13 = 0x0000_0075,
    JSONServerKMIPv13 = 0x0000_0076,
    XMLClientKMIPv13 = 0x0000_0077,
    XMLServerKMIPv13 = 0x0000_0078,
    BaselineServerBasicKMIPv14 = 0x0000_0079,
    BaselineServerTLSv12KMIPv14 = 0x0000_007A,
    BaselineClientBasicKMIPv14 = 0x0000_007B,
    BaselineClientTLSv12KMIPv14 = 0x0000_007C,
    CompleteServerBasicKMIPv14 = 0x0000_007D,
    CompleteServerTLSv12KMIPv14 = 0x0000_007E,
    TapeLibraryClientKMIPv14 = 0x0000_007F,
    TapeLibraryServerKMIPv14 = 0x0000_0080,
    SymmetricKeyLifecycleClientKMIPv14 = 0x0000_0081,
    SymmetricKeyLifecycleServerKMIPv14 = 0x0000_0082,
    AsymmetricKeyLifecycleClientKMIPv14 = 0x0000_0083,
    AsymmetricKeyLifecycleServerKMIPv14 = 0x0000_0084,
    BasicCryptographicClientKMIPv14 = 0x0000_0085,
    BasicCryptographicServerKMIPv14 = 0x0000_0086,
    AdvancedCryptographicClientKMIPv14 = 0x0000_0087,
    AdvancedCryptographicServerKMIPv14 = 0x0000_0088,
    RNGCryptographicClientKMIPv14 = 0x0000_0089,
    RNGCryptographicServerKMIPv14 = 0x0000_008A,
    BasicSymmetricKeyFoundryClientKMIPv14 = 0x0000_008B,
    IntermediateSymmetricKeyFoundryClientKMIPv14 = 0x0000_008C,
    AdvancedSymmetricKeyFoundryClientKMIPv14 = 0x0000_008D,
    SymmetricKeyFoundryServerKMIPv14 = 0x0000_008E,
    OpaqueManagedObjectStoreClientKMIPv14 = 0x0000_008F,
    OpaqueManagedObjectStoreServerKMIPv14 = 0x0000_0090,
    SuiteBMinLOS128ClientKMIPv14 = 0x0000_0091,
    SuiteBMinLOS128ServerKMIPv14 = 0x0000_0092,
    SuiteBMinLOS192ClientKMIPv14 = 0x0000_0093,
    SuiteBMinLOS192ServerKMIPv14 = 0x0000_0094,
    StorageArrayWithSelfEncryptingDriveClientKMIPv14 = 0x0000_0095,
    StorageArrayWithSelfEncryptingDriveServerKMIPv14 = 0x0000_0096,
    HTTPSClientKMIPv14 = 0x0000_0097,
    HTTPSServerKMIPv14 = 0x0000_0098,
    JSONClientKMIPv14 = 0x0000_0099,
    JSONServerKMIPv14 = 0x0000_009A,
    XMLClientKMIPv14 = 0x0000_009B,
    XMLServerKMIPv14 = 0x0000_009C,
    // Extension used to support KMIP 2.1 which has a completely different set of profiles
    // and is not compatible with KMIP 1.4
    KMIP21 = 0x8000_0001,
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

/// KMIP 1.4 Storage Status Mask Enumeration
#[kmip_enum]
pub enum StorageStatusMask {
    Online = 0x1,
    Archival = 0x2,
    Destroyed = 0x4,
}

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

impl TryFrom<kmip_2_1::kmip_types::RecommendedCurve> for RecommendedCurve {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::RecommendedCurve) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_types::RecommendedCurve::P192 => Self::P192,
            kmip_2_1::kmip_types::RecommendedCurve::K163 => Self::K163,
            kmip_2_1::kmip_types::RecommendedCurve::B163 => Self::B163,
            kmip_2_1::kmip_types::RecommendedCurve::P224 => Self::P224,
            kmip_2_1::kmip_types::RecommendedCurve::K233 => Self::K233,
            kmip_2_1::kmip_types::RecommendedCurve::B233 => Self::B233,
            kmip_2_1::kmip_types::RecommendedCurve::P256 => Self::P256,
            kmip_2_1::kmip_types::RecommendedCurve::K283 => Self::K283,
            kmip_2_1::kmip_types::RecommendedCurve::B283 => Self::B283,
            kmip_2_1::kmip_types::RecommendedCurve::P384 => Self::P384,
            kmip_2_1::kmip_types::RecommendedCurve::K409 => Self::K409,
            kmip_2_1::kmip_types::RecommendedCurve::B409 => Self::B409,
            kmip_2_1::kmip_types::RecommendedCurve::P521 => Self::P521,
            kmip_2_1::kmip_types::RecommendedCurve::K571 => Self::K571,
            kmip_2_1::kmip_types::RecommendedCurve::B571 => Self::B571,
            kmip_2_1::kmip_types::RecommendedCurve::SECP112R1 => Self::SECP112R1,
            kmip_2_1::kmip_types::RecommendedCurve::SECP112R2 => Self::SECP112R2,
            kmip_2_1::kmip_types::RecommendedCurve::SECP128R1 => Self::SECP128R1,
            kmip_2_1::kmip_types::RecommendedCurve::SECP128R2 => Self::SECP128R2,
            kmip_2_1::kmip_types::RecommendedCurve::SECP160R1 => Self::SECP160R1,
            kmip_2_1::kmip_types::RecommendedCurve::SECP160K1 => Self::SECP160K1,
            kmip_2_1::kmip_types::RecommendedCurve::SECP256K1 => Self::SECP256K1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP160R1 => Self::BRAINPOOLP160R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP160T1 => Self::BRAINPOOLP160T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP192R1 => Self::BRAINPOOLP192R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP192T1 => Self::BRAINPOOLP192T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP224R1 => Self::BRAINPOOLP224R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP224T1 => Self::BRAINPOOLP224T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP256R1 => Self::BRAINPOOLP256R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP256T1 => Self::BRAINPOOLP256T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP320R1 => Self::BRAINPOOLP320R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP320T1 => Self::BRAINPOOLP320T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP384R1 => Self::BRAINPOOLP384R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP384T1 => Self::BRAINPOOLP384T1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP512R1 => Self::BRAINPOOLP512R1,
            kmip_2_1::kmip_types::RecommendedCurve::BRAINPOOLP512T1 => Self::BRAINPOOLP512T1,
            x => {
                return Err(KmipError::InvalidKmip14Value(
                    ResultReason::OperationNotSupported,
                    format!("RecommendedCurve not supported in KMIP 1: {x:?}"),
                ));
            }
        })
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

impl TryFrom<kmip_2_1::kmip_types::DigitalSignatureAlgorithm> for DigitalSignatureAlgorithm {
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_types::DigitalSignatureAlgorithm,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::MD2WithRSAEncryption => {
                Self::MD2WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::MD5WithRSAEncryption => {
                Self::MD5WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA1WithRSAEncryption => {
                Self::SHA1WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA224WithRSAEncryption => {
                Self::SHA224WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA256WithRSAEncryption => {
                Self::SHA256WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA384WithRSAEncryption => {
                Self::SHA384WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::SHA512WithRSAEncryption => {
                Self::SHA512WithRSAEncryption
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::RSASSAPSS => Self::RSASSAPSS,
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA1 => Self::DSAWithSHA1,
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA224 => Self::DSAWithSHA224,
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::DSAWithSHA256 => Self::DSAWithSHA256,
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA1 => Self::ECDSAWithSHA1,
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA224 => {
                Self::ECDSAWithSHA224
            }
            kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA256
            | kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA384
            | kmip_2_1::kmip_types::DigitalSignatureAlgorithm::ECDSAWithSHA512 => {
                Self::ECDSAWithSHA256
            }
            x => {
                return Err(KmipError::InvalidKmip14Value(
                    ResultReason::OperationNotSupported,
                    format!("DigitalSignatureAlgorithm not supported in KMIP 1: {x:?}"),
                ));
            }
        })
    }
}

/// KMIP 1.4 Opaque Data Type Enumeration
#[kmip_enum]
pub enum OpaqueDataType {
    Unknown = 0x8000_0001,
}

impl From<OpaqueDataType> for kmip_2_1::kmip_types::OpaqueDataType {
    fn from(val: OpaqueDataType) -> Self {
        match val {
            OpaqueDataType::Unknown => Self::Unknown,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::OpaqueDataType> for OpaqueDataType {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::OpaqueDataType) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_types::OpaqueDataType::Unknown
            | kmip_2_1::kmip_types::OpaqueDataType::Vendor => Self::Unknown,
        })
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

impl TryFrom<kmip_2_1::kmip_types::Name> for Name {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::Name) -> Result<Self, Self::Error> {
        Ok(Self {
            name_value: value.name_value,
            name_type: value.name_type.try_into()?,
        })
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

impl TryFrom<kmip_2_1::kmip_types::CryptographicDomainParameters>
    for CryptographicDomainParameters
{
    type Error = KmipError;

    fn try_from(
        value: kmip_2_1::kmip_types::CryptographicDomainParameters,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            qlength: value.qlength,
            recommended_curve: value.recommended_curve.map(TryInto::try_into).transpose()?,
        })
    }
}

/// KMIP 1.4 Digest
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Digest {
    pub hashing_algorithm: HashingAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_value: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
}

impl From<Digest> for kmip_2_1::kmip_types::Digest {
    fn from(val: Digest) -> Self {
        Self {
            hashing_algorithm: val.hashing_algorithm,
            digest_value: val.digest_value,
            key_format_type: val.key_format_type.map(Into::into),
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::Digest> for Digest {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::Digest) -> Result<Self, Self::Error> {
        Ok(Self {
            hashing_algorithm: value.hashing_algorithm,
            digest_value: value.digest_value,
            key_format_type: value.key_format_type.map(TryInto::try_into).transpose()?,
        })
    }
}

/// KMIP 1.4 Random Number Generator
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RandomNumberGenerator {
    // KMIP spec tag is RNGAlgorithm (all caps RNG). Without an explicit rename Serde would
    // emit RngAlgorithm (PascalCase transformation of rng_algorithm), which does not match the
    // Tag enumeration variant RNGAlgorithm and causes an Unknown Tag error during TTLV encoding.
    // We therefore force the serialized field name to RNGAlgorithm.
    #[serde(rename = "RNGAlgorithm")]
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
            rng_algorithm: val.rng_algorithm,
            cryptographic_algorithm: val.cryptographic_algorithm.map(Into::into),
            cryptographic_length: val.cryptographic_length,
            hashing_algorithm: val.hashing_algorithm,
            drbg_algorithm: val.drbg_algorithm,
            recommended_curve: val.recommended_curve.map(Into::into),
            fips186_variation: val.fips186_variation,
            prediction_resistance: val.prediction_resistance,
        }
    }
}

impl TryFrom<kmip_2_1::kmip_types::RandomNumberGenerator> for RandomNumberGenerator {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::RandomNumberGenerator) -> Result<Self, Self::Error> {
        Ok(Self {
            rng_algorithm: value.rng_algorithm,
            cryptographic_algorithm: value
                .cryptographic_algorithm
                .map(TryInto::try_into)
                .transpose()?,
            cryptographic_length: value.cryptographic_length,
            hashing_algorithm: value.hashing_algorithm,
            drbg_algorithm: value.drbg_algorithm,
            recommended_curve: value.recommended_curve.map(TryInto::try_into).transpose()?,
            fips186_variation: value.fips186_variation,
            prediction_resistance: value.prediction_resistance,
        })
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

/// Link Structure represents the relationship between a Managed Object and another object.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "PascalCase")]
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

impl TryFrom<kmip_2_1::kmip_types::Link> for Link {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::Link) -> Result<Self, Self::Error> {
        Ok(Self {
            link_type: value.link_type.try_into()?,
            linked_object_identifier: value.linked_object_identifier.try_into()?,
        })
    }
}

/// `LinkedObjectIdentifier` defines the format of the object reference in a link.
pub type LinkedObjectIdentifier = String;

impl From<LinkedObjectIdentifier> for kmip_2_1::kmip_types::LinkedObjectIdentifier {
    fn from(val: LinkedObjectIdentifier) -> Self {
        Self::TextString(val)
    }
}

impl TryFrom<kmip_2_1::kmip_types::LinkedObjectIdentifier> for LinkedObjectIdentifier {
    type Error = KmipError;

    fn try_from(value: kmip_2_1::kmip_types::LinkedObjectIdentifier) -> Result<Self, Self::Error> {
        Ok(match value {
            kmip_2_1::kmip_types::LinkedObjectIdentifier::TextString(s) => s,
            kmip_2_1::kmip_types::LinkedObjectIdentifier::Enumeration(_)
            | kmip_2_1::kmip_types::LinkedObjectIdentifier::Index(_) => {
                return Err(KmipError::InvalidKmip14Value(
                    ResultReason::OperationNotSupported,
                    format!("{value} not supported in KMIP 1"),
                ));
            }
        })
    }
}

/// KMIP 1.4 Custom Attribute
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct CustomAttribute {
    pub name: String,
    pub value: CustomAttributeValue,
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
#[expect(clippy::unwrap_used)]
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
