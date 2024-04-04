// A still incomplete list of the KMIP types:
// see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html

// see CryptographicUsageMask
#![allow(non_upper_case_globals)]

use std::{
    fmt,
    fmt::{Display, Formatter},
};

#[cfg(feature = "openssl")]
use openssl::{
    hash::MessageDigest,
    md::{Md, MdRef},
};
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Serialize,
};
use strum::{Display, EnumIter, EnumString};

use super::kmip_objects::ObjectType;
#[cfg(feature = "openssl")]
use crate::kmip_error;
use crate::{
    error::KmipError,
    kmip::{
        extra::{tagging::VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
        kmip_operations::ErrorReason,
    },
};

/// 4.7
/// The Certificate Type attribute is a type of certificate (e.g., X.509).
/// The Certificate Type value SHALL be set by the server when the certificate
/// is created or registered and then SHALL NOT be changed or deleted before the
/// object is destroyed.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum CertificateType {
    X509 = 0x01,
    PGP = 0x02,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum CertificateRequestType {
    CRMF = 0x01,
    PKCS10 = 0x02,
    PEM = 0x03,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_clike_unportable_variant)]
pub enum OpaqueDataType {
    Unknown = 0x8000_0001,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_clike_unportable_variant)]
pub enum SecretDataType {
    Password = 0x01,
    Seed = 0x02,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum SplitKeyMethod {
    XOR = 0x0000_0001,
    PolynomialSharingGf216 = 0x0000_0002,
    PolynomialSharingPrimeField = 0x0000_0003,
    PolynomialSharingGf28 = 0x0000_0004,
}

/// Keys have a default Key Format Type that SHALL be produced by KMIP servers.
///
/// The default Key Format Type by object (and algorithm) is listed in the following table:
///
/// | Type | Default Key Format Type |
/// |------|-------------------------|
/// | Certificate | X.509 |
/// | Certificate Request | PKCS#10 |
/// | Opaque Object | Opaque |
/// | PGP Key | Raw |
/// | Secret Data | Raw |
/// | Symmetric Key | Raw |
/// | Split Key | Raw |
/// | RSA Private Key | PKCS#1 |
/// | RSA Public Key | PKCS#1 |
/// | EC Private Key | Transparent EC Private Key |
/// | EC Public Key | Transparent EC Public Key |
/// | DSA Private Key | Transparent DSA Private Key |
/// | DSA Public Key | Transparent DSA Public Key |
///
/// Cosmian Note: These default formats are outdated. So, even though default export
/// formats are enforced, storage formats are:
///  - PKCS#8 DER for RSA and EC private Keys (RFC 5208 and 5958)
///  - SPKI DER (RFC 5480) for RSA and EC public keys
///  - X509 DER for certificates (RFC 5280)
///  - PKCS#10 DER for certificate requests (RFC 2986)
///  - `TransparentSymmetricKey` for symmetric keys
///  - Raw for opaque objects and Secret Data
///
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display, EnumIter)]
pub enum KeyFormatType {
    Raw = 0x01,
    Opaque = 0x02,
    PKCS1 = 0x03,
    PKCS8 = 0x04,
    X509 = 0x05,
    ECPrivateKey = 0x06,
    TransparentSymmetricKey = 0x07,
    TransparentDSAPrivateKey = 0x08,
    TransparentDSAPublicKey = 0x09,
    TransparentRSAPrivateKey = 0x0A,
    TransparentRSAPublicKey = 0x0B,
    TransparentDHPrivateKey = 0x0C,
    TransparentDHPublicKey = 0x0D,
    TransparentECPrivateKey = 0x14,
    TransparentECPublicKey = 0x15,
    PKCS12 = 0x16,
    PKCS10 = 0x17,
    // Available slot 0x8880_0001,
    // Available slot 0x8880_0002,
    // Available slot 0x8880_0003,
    // Available slot 0x8880_0004,
    EnclaveECKeyPair = 0x8880_0005,
    EnclaveECSharedKey = 0x8880_0006,
    // Available slot 0x8880_0007,
    // Available slot 0x8880_0008,
    // Available slot 0x8880_0009,
    // Available slot 0x8880_000A,
    // Available slot 0x8880_000B,
    CoverCryptSecretKey = 0x8880_000C,
    CoverCryptPublicKey = 0x8880_000D,
}

#[allow(non_camel_case_types)]
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Display, Eq, PartialEq, EnumIter)]
pub enum CryptographicAlgorithm {
    DES = 0x0000_0001,
    THREE_DES = 0x0000_0002,
    AES = 0x0000_0003,
    /// This is `CKM_RSA_PKCS_OAEP` from PKCS#11
    /// see https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226895
    /// To use  `CKM_RSA_AES_KEY_WRAP` from PKCS#11, use and RSA key with AES as the algorithm
    /// See https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226908
    RSA = 0x0000_0004,
    DSA = 0x0000_0005,
    ECDSA = 0x0000_0006,
    HMACSHA1 = 0x0000_0007,
    HMACSHA224 = 0x0000_0008,
    HMACSHA256 = 0x0000_0009,
    HMACSHA384 = 0x0000_000A,
    HMACSHA512 = 0x0000_000B,
    HMACMD5 = 0x0000_000C,
    DH = 0x0000_000D,
    ECDH = 0x0000_000E,
    ECMQV = 0x0000_000F,
    Blowfish = 0x0000_0010,
    Camellia = 0x0000_0011,
    CAST5 = 0x0000_0012,
    IDEA = 0x0000_0013,
    MARS = 0x0000_0014,
    RC2 = 0x0000_0015,
    RC4 = 0x0000_0016,
    RC5 = 0x0000_0017,
    SKIPJACK = 0x0000_0018,
    Twofish = 0x0000_0019,
    EC = 0x0000_001A,
    OneTimePad = 0x0000_001B,
    ChaCha20 = 0x0000_001C,
    Poly1305 = 0x0000_001D,
    ChaCha20Poly1305 = 0x0000_001E,
    SHA3224 = 0x0000_001F,
    SHA3256 = 0x0000_0020,
    SHA3384 = 0x0000_0021,
    SHA3512 = 0x0000_0022,
    HMACSHA3224 = 0x0000_0023,
    HMACSHA3256 = 0x0000_0024,
    HMACSHA3384 = 0x0000_0025,
    HMACSHA3512 = 0x0000_0026,
    SHAKE128 = 0x0000_0027,
    SHAKE256 = 0x0000_0028,
    ARIA = 0x0000_0029,
    SEED = 0x0000_002A,
    SM2 = 0x0000_002B,
    SM3 = 0x0000_002C,
    SM4 = 0x0000_002D,
    GOSTR34102012 = 0x0000_002E,
    GOSTR34112012 = 0x0000_002F,
    GOSTR34132015 = 0x0000_0030,
    GOST2814789 = 0x0000_0031,
    XMSS = 0x0000_0032,
    SPHINCS_256 = 0x0000_0033,
    Page166Of230McEliece = 0x0000_0034,
    McEliece6960119 = 0x0000_0035,
    McEliece8192128 = 0x0000_0036,
    Ed25519 = 0x0000_0037,
    Ed448 = 0x0000_0038,
    // Available slot 0x8880_0001,
    // Available slot 0x8880_0002,
    // Available slot 0x8880_0003,
    CoverCrypt = 0x8880_0004,
    CoverCryptBulk = 0x8880_0005,
}

/// The Cryptographic Domain Parameters attribute (4.14) is a structure that
/// contains fields that MAY need to be specified in the Create Key Pair Request
/// Payload. Specific fields MAY only pertain to certain types of Managed
/// Cryptographic Objects. The domain parameter `q_length` corresponds to the bit
/// length of parameter Q (refer to RFC7778, SEC2 and SP800-56A).
/// - `q_length` applies to algorithms such as DSA and DH. The bit length of
/// parameter P (refer to RFC7778, SEC2 and SP800-56A) is specified
/// separately by setting the Cryptographic Length attribute.
/// - Recommended Curve is applicable to elliptic curve algorithms such as ECDSA, ECDH, and ECMQV
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct CryptographicDomainParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
}

impl Default for CryptographicDomainParameters {
    fn default() -> Self {
        Self {
            q_length: Some(256),
            recommended_curve: Some(RecommendedCurve::default()),
        }
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum RecommendedCurve {
    P192 = 0x0000_0001,
    K163 = 0x0000_0002,
    B163 = 0x0000_0003,
    P224 = 0x0000_0004,
    K233 = 0x0000_0005,
    B233 = 0x0000_0006,
    P256 = 0x0000_0007,
    K283 = 0x0000_0008,
    B283 = 0x0000_0009,
    P384 = 0x0000_000A,
    K409 = 0x0000_000B,
    B409 = 0x0000_000C,
    P521 = 0x0000_000D,
    K571 = 0x0000_000E,
    B571 = 0x0000_000F,
    SECP112R1 = 0x0000_0010,
    SECP112R2 = 0x0000_0011,
    SECP128R1 = 0x0000_0012,
    SECP128R2 = 0x0000_0013,
    SECP160K1 = 0x0000_0014,
    SECP160R1 = 0x0000_0015,
    SECP160R2 = 0x0000_0016,
    SECP192K1 = 0x0000_0017,
    SECP224K1 = 0x0000_0018,
    SECP256K1 = 0x0000_0019,
    SECT113R1 = 0x0000_001A,
    SECT131R1 = 0x0000_001C,
    SECT131R2 = 0x0000_001D,
    SECT163R1 = 0x0000_001E,
    SECT193R1 = 0x0000_001F,
    SECT193R2 = 0x0000_0020,
    SECT239K1 = 0x0000_0021,
    ANSIX9P192V2 = 0x0000_0022,
    ANSIX9P192V3 = 0x0000_0023,
    ANSIX9P239V1 = 0x0000_0024,
    ANSIX9P239V2 = 0x0000_0025,
    ANSIX9P239V3 = 0x0000_0026,
    ANSIX9C2PNB163V1 = 0x0000_0027,
    ANSIX9C2PNB163V2 = 0x0000_0028,
    ANSIX9C2PNB163V3 = 0x0000_0029,
    ANSIX9C2PNB176V1 = 0x0000_002A,
    ANSIX9C2TNB191V1 = 0x0000_002B,
    ANSIX9C2TNB191V2 = 0x0000_002C,
    ANSIX9C2TNB191V3 = 0x0000_002D,
    ANSIX9C2PNB208W1 = 0x0000_002E,
    ANSIX9C2TNB239V1 = 0x0000_002F,
    ANSIX9C2TNB239V2 = 0x0000_0030,
    ANSIX9C2TNB239V3 = 0x0000_0031,
    ANSIX9C2PNB272W1 = 0x0000_0032,
    ANSIX9C2PNB304W1 = 0x0000_0033,
    ANSIX9C2TNB359V1 = 0x0000_0034,
    ANSIX9C2PNB368W1 = 0x0000_0035,
    ANSIX9C2TNB431R1 = 0x0000_0036,
    BRAINPOOLP160R1 = 0x0000_0037,
    BRAINPOOLP160T1 = 0x0000_0038,
    BRAINPOOLP192R1 = 0x0000_0039,
    BRAINPOOLP192T1 = 0x0000_003A,
    BRAINPOOLP224R1 = 0x0000_003B,
    BRAINPOOLP224T1 = 0x0000_003C,
    BRAINPOOLP256R1 = 0x0000_003D,
    BRAINPOOLP256T1 = 0x0000_003E,
    BRAINPOOLP320R1 = 0x0000_003F,
    BRAINPOOLP320T1 = 0x0000_0040,
    BRAINPOOLP384T1 = 0x0000_0042,
    BRAINPOOLP512R1 = 0x0000_0043,
    BRAINPOOLP512T1 = 0x0000_0044,
    CURVE25519 = 0x0000_0045,
    CURVE448 = 0x0000_0046,
    CURVEED25519 = 0x8000_0001,
    CURVEED448 = 0x8000_0002,
    // Extensions 8XXXXXXX
}

impl Default for RecommendedCurve {
    #[cfg(feature = "fips")]
    /// Defaulting to highest security FIPS compliant curve.
    fn default() -> Self {
        Self::P521
    }

    #[cfg(not(feature = "fips"))]
    fn default() -> Self {
        Self::CURVE25519
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x0000_0001,
    ECPublicKeyTypeX962CompressedPrime = 0x0000_0002,
    ECPublicKeyTypeX962CompressedChar2 = 0x0000_0003,
    ECPublicKeyTypeX962Hybrid = 0x0000_0004,
    // Extensions 8XXXXXXX
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct CryptographicUsageMask(u32);

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

impl Serialize for CryptographicUsageMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(self.bits() as i32)
    }
}
impl<'de> Deserialize<'de> for CryptographicUsageMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CryptographicUsageMaskVisitor;

        impl<'de> Visitor<'de> for CryptographicUsageMaskVisitor {
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
                Ok(CryptographicUsageMask(v as u32))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(v as u32))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(CryptographicUsageMask(v as u32))
            }
        }
        deserializer.deserialize_any(CryptographicUsageMaskVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProtectionStorageMasks(u32);

bitflags::bitflags! {
    impl ProtectionStorageMasks: u32 {
        const Software=0x0000_0001;
        const Hardware=0x0000_0002;
        const OnProcessor=0x0000_0004;
        const OnSystem=0x0000_0008;
        const OffSystem=0x0000_0010;
        const Hypervisor=0x0000_0020;
        const OperatingSystem=0x0000_0040;
        const Container=0x0000_0080;
        const OnPremises=0x0000_0100;
        const OffPremises=0x0000_0200;
        const SelfManaged=0x0000_0400;
        const Outsourced=0x0000_0800;
        const Validated=0x0000_1000;
        const SameJurisdiction=0x0000_2000;
        // Extensions XXX00000
    }
}
impl Serialize for ProtectionStorageMasks {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(self.bits() as i32)
    }
}
impl<'de> Deserialize<'de> for ProtectionStorageMasks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ProtectionStorageMasksVisitor;

        impl<'de> Visitor<'de> for ProtectionStorageMasksVisitor {
            type Value = ProtectionStorageMasks;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ProtectionStorageMasks")
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(v))
            }

            // used by the TTLV representation
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(v as u32))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(v as u32))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(v as u32))
            }
        }
        deserializer.deserialize_any(ProtectionStorageMasksVisitor)
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub enum ObjectGroupMember {
    Group_Member_Fresh = 0x0000_0001,
    Group_Member_Default = 0x0000_0002,
    // Extensions 8XXXXXXX
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct StorageStatusMask(u32);

bitflags::bitflags! {
    impl StorageStatusMask: u32 {
        const OnlineStorage=0x0000_0001;
        const ArchivalStorage=0x0000_0002;
        const DestroyedStorage=0x0000_0004;
        // Extensions XXXXXXX0
    }
}
impl Serialize for StorageStatusMask {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_i32(self.bits() as i32)
    }
}
impl<'de> Deserialize<'de> for StorageStatusMask {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StorageStatusMaskVisitor;

        impl<'de> Visitor<'de> for StorageStatusMaskVisitor {
            type Value = StorageStatusMask;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct StorageStatusMask")
            }

            fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(v))
            }

            // used by the TTLV representation
            fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(v as u32))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(v as u32))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(v as u32))
            }
        }
        deserializer.deserialize_any(StorageStatusMaskVisitor)
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum LinkType {
    /// For Certificate objects: the parent certificate for a certificate in a
    /// certificate chain. For Public Key objects: the corresponding
    /// certificate(s), containing the same public key.
    CertificateLink = 0x0000_0101,
    /// For a Private Key object: the public key corresponding to the private
    /// key. For a Certificate object: the public key contained in the
    /// certificate.
    PublicKeyLink = 0x0000_0102,
    /// For a Public Key object: the private key corresponding to the public
    /// key.
    PrivateKeyLink = 0x0000_0103,
    /// For a derived Symmetric Key or Secret Data object: the object(s) from
    /// which the current symmetric key was derived.
    DerivationBaseObjectLink = 0x0000_0104,
    /// The symmetric key(s) or Secret Data object(s) that were derived from
    /// the current object.
    DerivedKeyLink = 0x0000_0105,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that resulted from the re-key of the current
    /// key. For a Certificate object: the certificate that resulted from the
    /// re- certify. Note that there SHALL be only one such replacement
    /// object per Managed Object.
    ReplacementObjectLink = 0x0000_0106,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that was re-keyed to obtain the current key.
    /// For a Certificate object: the certificate that was re-certified to
    /// obtain the current certificate.
    ReplacedObjectLink = 0x0000_0107,
    /// For all object types: the container or other parent object corresponding
    /// to the object.
    ParentLink = 0x0000_0108,
    /// For all object types: the subordinate, derived or other child object
    /// corresponding to the object.
    ChildLink = 0x0000_0109,
    /// For all object types: the previous object to this object.
    PreviousLink = 0x0000_010A,
    /// For all object types: the next object to this object.
    NextLink = 0x0000_010B,
    PKCS12CertificateLink = 0x0000_010C,
    PKCS12PasswordLink = 0x0000_010D,
    /// For wrapped objects: the object that was used to wrap this object.
    WrappingKeyLink = 0x0000_010E,
    //Extensions 8XXXXXXX
}

/// The following values may be specified in an operation request for a Unique
/// Identifier: If multiple unique identifiers would be referenced then the
/// operation is repeated for each of them. If an operation appears
/// multiple times in a request, it is the most recent that is referred to.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum UniqueIdentifierEnumeration {
    IDPlaceholder = 0x0000_0001,
    Certify = 0x0000_0002,
    Create = 0x0000_0003,
    CreateKeyPair = 0x0000_0004,
    CreateKeyPairPrivateKey = 0x0000_0005,
    CreateKeyPairPublicKey = 0x0000_0006,
    CreateSplitKey = 0x0000_0007,
    DeriveKey = 0x0000_0008,
    Import = 0x0000_0009,
    JoinSplitKey = 0x0000_000A,
    Locate = 0x0000_000B,
    Register = 0x0000_000C,
    Rekey = 0x0000_000D,
    Recertify = 0x0000_000E,
    RekeyKeyPair = 0x0000_000F,
    RekeyKeyPairPrivateKey = 0x0000_0010,
    RekeyKeyPairPublicKey = 0x0000_0011,
    //Extensions 8XXXXXXX
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum LinkedObjectIdentifier {
    /// Unique Identifier of a Managed Object.
    TextString(String),
    /// Unique Identifier Enumeration
    Enumeration(UniqueIdentifierEnumeration),
    /// Zero based nth Unique Identifier in the response. If
    /// negative the count is backwards from the beginning
    /// of the current operation's batch item.
    Index(i64),
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum RevocationReasonEnumeration {
    Unspecified = 0x0000_0001,
    KeyCompromise = 0x0000_0002,
    CACompromise = 0x0000_0003,
    AffiliationChanged = 0x0000_0004,
    Superseded = 0x0000_0005,
    CessationOfOperation = 0x0000_0006,
    PrivilegeWithdrawn = 0x0000_0007,
    //Extensions 8XXXXXXX
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
#[serde(untagged)]
pub enum RevocationReason {
    /// Unique Identifier Enumeration
    Enumeration(RevocationReasonEnumeration),
    /// Revocation Message
    TextString(String),
}

/// The Link attribute is a structure used to create a link from one Managed
/// Cryptographic Object to another, closely related target Managed
/// Cryptographic Object. The link has a type, and the allowed types differ,
/// depending on the Object Type of the Managed Cryptographic Object, as listed
/// below. The Linked Object Identifier identifies the target Managed
/// Cryptographic Object by its Unique Identifier. The link contains information
/// about the association  between the Managed Objects (e.g., the private key
/// corresponding to a public key; the parent certificate for a certificate in a
/// chain; or for a derived symmetric key, the base key from which it was
/// derived).
///
/// The Link attribute SHOULD be present for private keys and public keys
/// for which a certificate chain is stored by the server,
/// and for certificates in a certificate chain.
///
/// Note that it is possible for a Managed Object
/// to have multiple instances of the Link attribute (e.g., a Private Key has
/// links to the associated certificate, as well as the associated public key; a
/// Certificate object has links to both the public key and to the certificate
/// of the certification authority (CA) that signed the certificate).
///
/// It is also possible that a Managed Object does not have links to associated
/// cryptographic objects. This MAY occur in cases where the associated key
/// material is not available to the server or client (e.g., the registration of
/// a CA Signer certificate with a server, where the corresponding private key
/// is held in a different manner).
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    pub link_type: LinkType,
    pub linked_object_identifier: LinkedObjectIdentifier,
}

/// A vendor specific Attribute is a structure used for sending and receiving
/// a Managed Object attribute. The Vendor Identification
/// and Attribute Name are text-strings that are used to identify the attribute.
/// The Attribute Value is either a primitive data type or structured object,
/// depending on the attribute.
/// Vendor identification values "x" and "y" are reserved for KMIP v2.0 and
/// later implementations referencing KMIP v1.x Custom Attributes.
///
/// Vendor Attributes created by the client with Vendor Identification "x"
/// are not created (provided during object creation), set, added, adjusted,
/// modified or deleted by the server.
///
/// Vendor Attributes created by the server with Vendor Identification "y"
/// are not created (provided during object creation), set, added, adjusted,
/// modified or deleted by the client.
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct VendorAttribute {
    /// Text String (with usage limited to alphanumeric, underscore and period –
    /// i.e. [A-Za-z0-9_.])
    pub vendor_identification: String,
    pub attribute_name: String,
    pub attribute_value: Vec<u8>,
}

/// The following subsections describe the attributes that are associated with
/// Managed Objects. Attributes that an object MAY have multiple instances of
/// are referred to as multi-instance attributes. All instances of an attribute
/// SHOULD have a different value. Similarly, attributes which an object SHALL
/// only have at most one instance of are referred to as single-instance
/// attributes. Attributes are able to be obtained by a client from the server
/// using the Get Attribute operation. Some attributes are able to be set by the
/// Add Attribute operation or updated by the Modify Attribute operation, and
/// some are able to be deleted by the Delete Attribute operation if they no
/// longer apply to the Managed Object. Read-only attributes are attributes that
/// SHALL NOT be modified by either server or client, and that SHALL NOT be
/// deleted by a client.
/// When attributes are returned by the server (e.g., via a Get Attributes
/// operation), the attribute value returned SHALL NOT differ for different
/// clients unless specifically noted against each attribute. The first table in
/// each subsection contains the attribute name in the first row. This name is
/// the canonical name used when managing attributes using the Get Attributes,
/// Get Attribute List, Add Attribute, Modify Attribute, and Delete Attribute
/// operations. A server SHALL NOT delete attributes without receiving a request
/// from a client until the object is destroyed. After an object is destroyed,
/// the server MAY retain all, some or none of the object attributes,
/// depending on the object type and server policy.
// TODO: there are 56 attributes in the specs. Only a handful are implemented here
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Attributes {
    /// The Activation Date attribute contains the date and time when the
    /// Managed Object MAY begin to be used. This time corresponds to state
    /// transition. The object SHALL NOT be used for any cryptographic
    /// purpose before the Activation Date has been reached. Once the state
    /// transition from Pre-Active has occurred, then this attribute SHALL
    /// NOT be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_date: Option<u64>, // epoch millis

    /// The Certificate Attributes are the various items included in a certificate.
    /// The following list is based on RFC2253.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_attributes: Option<Box<CertificateAttributes>>,

    /// The Certificate Type attribute is a type of certificate (e.g., X.509).
    /// The Certificate Type value SHALL be set by the server when the certificate
    /// is created or registered and then SHALL NOT be changed or deleted
    /// before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_type: Option<CertificateType>,

    /// The Certificate Length attribute is the length in bytes of the Certificate object.
    /// The Certificate Length SHALL be set by the server when the object is created or registered,
    /// and then SHALL NOT be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_length: Option<i32>,

    /// The Cryptographic Algorithm of an object. The Cryptographic Algorithm of
    /// a Certificate object identifies the algorithm for the public key
    /// contained within the Certificate. The digital signature algorithm used
    /// to sign the Certificate is identified in the Digital Signature
    /// Algorithm attribute. This attribute SHALL be set by the server when
    /// the object is created or registered and then SHALL NOT be changed or
    /// deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,

    /// For keys, Cryptographic Length is the length in bits of the clear-text
    /// cryptographic key material of the Managed Cryptographic Object. For
    /// certificates, Cryptographic Length is the length in bits of the public
    /// key contained within the Certificate. This attribute SHALL be set by the
    /// server when the object is created or registered, and then SHALL NOT
    /// be changed or deleted before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_length: Option<i32>,

    /// The Cryptographic Domain Parameters attribute is a structure that
    /// contains fields that MAY need to be specified in the Create Key Pair
    /// Request Payload. Specific fields MAY only pertain to certain types
    /// of Managed Cryptographic Objects. The domain parameter Q-length
    /// corresponds to the bit length of parameter Q (refer to
    /// [RFC7778](https://www.rfc-editor.org/rfc/rfc7778.txt),
    /// [SEC2](https://www.secg.org/sec2-v2.pdf) and
    /// [SP800-56A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf)).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_domain_parameters: Option<CryptographicDomainParameters>,

    /// See `CryptographicParameters`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<Box<CryptographicParameters>>,

    /// The Cryptographic Usage Mask attribute defines the cryptographic usage
    /// of a key. This is a bit mask that indicates to the client which
    /// cryptographic functions MAY be performed using the key, and which ones
    /// SHALL NOT be performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_usage_mask: Option<CryptographicUsageMask>,

    /// 4.26 The Key Format Type attribute is a required attribute of a
    /// Cryptographic Object. It is set by the server, but a particular Key
    /// Format Type MAY be requested by the client if the cryptographic material
    /// is produced by the server (i.e., Create, Create Key Pair, Create
    /// Split Key, Re-key, Re-key Key Pair, Derive Key) on the
    /// client's behalf. The server SHALL comply with the client's requested
    /// format or SHALL fail the request. When the server calculates a
    /// Digest for the object, it SHALL compute the digest on the data in the
    /// assigned Key Format Type, as well as a digest in the default KMIP Key
    /// Format Type for that type of key and the algorithm requested (if a
    /// non-default value is specified).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,

    /// The Link attribute is a structure used to create a link from one Managed
    /// Cryptographic Object to another, closely related target Managed
    /// Cryptographic Object. The link has a type, and the allowed types differ,
    /// depending on the Object Type of the Managed Cryptographic Object, as
    /// listed below. The Linked Object Identifier identifies the target
    /// Managed Cryptographic Object by its Unique Identifier. The link contains
    /// information about the association between the Managed Objects (e.g., the
    /// private key corresponding to a public key; the parent certificate
    /// for a certificate in a chain; or for a derived symmetric key, the base
    /// key from which it was derived).
    /// The Link attribute SHOULD be present for private keys and public keys
    /// for which a certificate chain is stored by the server, and for
    /// certificates in a certificate chain. Note that it is possible for a
    /// Managed Object to have multiple instances of the Link attribute (e.g., a
    /// Private Key has links to the associated certificate, as well as the
    /// associated public key; a Certificate object has links to both the
    /// public key and to the certificate of the certification authority (CA)
    /// that signed the certificate).
    /// It is also possible that a Managed Object does not have links to
    /// associated cryptographic objects. This MAY occur in cases where the
    /// associated key material is not available to the server or client (e.g.,
    /// the registration of a CA Signer certificate with a server, where the
    /// corresponding private key is held in a different manner)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<Vec<Link>>,

    /// The Object Typeof a Managed Object (e.g., public key, private key,
    /// symmetric key, etc.) SHALL be set by the server when the object is
    /// created or registered and then SHALL NOT be changed or deleted before
    /// the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<ObjectType>,

    /// The Unique Identifier is generated by the key management system
    /// to uniquely identify a Managed Object. It is only REQUIRED to be unique
    /// within the identifier space managed by a single key management system,
    /// however this identifier SHOULD be globally unique in order to allow
    /// for a key management server export of such objects.
    /// This attribute SHALL be assigned by the key management system at creation
    /// or registration time, and then SHALL NOT be changed or deleted
    /// before the object is destroyed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_identifier: Option<UniqueIdentifier>,

    /// A vendor specific Attribute is a structure used for sending and
    /// receiving a Managed Object attribute. The Vendor Identification and
    /// Attribute Name are text-strings that are used to identify the attribute.
    /// The Attribute Value is either a primitive data type or structured
    /// object, depending on the attribute. Vendor identification values "x"
    /// and "y" are reserved for KMIP v2.0 and later implementations referencing
    /// KMIP v1.x Custom Attributes.
    /// Vendor Attributes created by the client with Vendor Identification "x"
    /// are not created (provided during object creation), set, added,
    /// adjusted, modified or deleted by the server. Vendor Attributes
    /// created by the server with Vendor Identification "y" are not created
    /// (provided during object creation), set, added, adjusted, modified or
    /// deleted by the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_attributes: Option<Vec<VendorAttribute>>,
}

impl Attributes {
    /// Add a vendor attribute to the list of vendor attributes.
    pub fn add_vendor_attribute(&mut self, vendor_attribute: VendorAttribute) -> &mut Self {
        if let Some(vas) = &mut self.vendor_attributes {
            vas.push(vendor_attribute);
        } else {
            self.vendor_attributes = Some(vec![vendor_attribute]);
        }
        self
    }

    /// Set a vendor attribute to the list of vendor attributes replacing one with an existing value
    /// if any
    pub fn set_vendor_attribute(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
        attribute_value: Vec<u8>,
    ) -> &mut Self {
        let va = self.get_vendor_attribute_mut(vendor_identification, attribute_name);
        va.attribute_value = attribute_value;
        self
    }

    /// Return the vendor attribute with the given vendor identification and
    /// attribute name.
    #[must_use]
    pub fn get_vendor_attribute_value(
        &self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<&[u8]> {
        self.vendor_attributes.as_ref().and_then(|vas| {
            vas.iter()
                .find(|&va| {
                    va.vendor_identification == vendor_identification
                        && va.attribute_name == attribute_name
                })
                .map(|va| va.attribute_value.as_slice())
        })
    }

    /// Return the vendor attribute with the given vendor identification and
    /// and remove it from the vendor attributes.
    #[must_use]
    pub fn extract_vendor_attribute_value(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> Option<Vec<u8>> {
        let value = self
            .get_vendor_attribute_value(vendor_identification, attribute_name)
            .map(<[u8]>::to_vec);
        if value.is_some() {
            self.remove_vendor_attribute(vendor_identification, attribute_name);
        }
        value
    }

    /// Return the vendor attribute with the given vendor identification and
    /// attribute name. If the attribute does not exist, an empty
    /// vendor attribute is created and returned.
    #[must_use]
    pub fn get_vendor_attribute_mut(
        &mut self,
        vendor_identification: &str,
        attribute_name: &str,
    ) -> &mut VendorAttribute {
        let vas = self.vendor_attributes.get_or_insert_with(Vec::new);
        let position = vas.iter().position(|va| {
            va.vendor_identification == vendor_identification && va.attribute_name == attribute_name
        });
        let len = vas.len();
        match position {
            None => {
                vas.push(VendorAttribute {
                    vendor_identification: vendor_identification.to_owned(),
                    attribute_name: attribute_name.to_owned(),
                    attribute_value: vec![],
                });
                &mut vas[len]
            }
            Some(position) => &mut vas[position],
        }
    }

    /// Remove a vendor attribute from the list of vendor attributes.
    pub fn remove_vendor_attribute(&mut self, vendor_identification: &str, attribute_name: &str) {
        if let Some(vas) = self.vendor_attributes.as_mut() {
            vas.retain(|va| {
                va.vendor_identification != vendor_identification
                    || va.attribute_name != attribute_name
            });
            if vas.is_empty() {
                self.vendor_attributes = None;
            }
        }
    }

    /// Get the link to the object.
    #[must_use]
    pub fn get_link(&self, link_type: LinkType) -> Option<String> {
        if let Some(links) = &self.link {
            links
                .iter()
                .find(|&l| l.link_type == link_type)
                .and_then(|l| match &l.linked_object_identifier {
                    LinkedObjectIdentifier::TextString(s) => Some(s.clone()),
                    LinkedObjectIdentifier::Enumeration(_e) => None,
                    LinkedObjectIdentifier::Index(i) => Some(i.to_string()),
                })
        } else {
            None
        }
    }

    /// Remove the link from the attributes
    pub fn remove_link(&mut self, link_type: LinkType) {
        if let Some(links) = self.link.as_mut() {
            links.retain(|l| l.link_type != link_type);
            if links.is_empty() {
                self.link = None;
            }
        }
    }

    /// Get the parent id of the object.
    #[must_use]
    pub fn get_parent_id(&self) -> Option<String> {
        self.get_link(LinkType::ParentLink)
    }

    /// Add a link to the object.
    pub fn add_link(
        &mut self,
        link_type: LinkType,
        linked_object_identifier: LinkedObjectIdentifier,
    ) {
        let links = self.link.get_or_insert_with(Vec::new);
        links.push(Link {
            link_type,
            linked_object_identifier,
        });
    }

    /// Set the attributes's object type.
    pub fn set_object_type(&mut self, object_type: ObjectType) {
        self.object_type = Some(object_type);
    }

    /// Set the attributes's CryptographicUsageMask.
    pub fn set_cryptographic_usage_mask(&mut self, mask: Option<CryptographicUsageMask>) {
        self.cryptographic_usage_mask = mask;
    }

    /// Set the bits in `mask` to the attributes's CryptographicUsageMask bits.
    pub fn set_cryptographic_usage_mask_bits(&mut self, mask: CryptographicUsageMask) {
        let mask = if let Some(attr_mask) = self.cryptographic_usage_mask {
            attr_mask | mask
        } else {
            mask
        };

        self.cryptographic_usage_mask = Some(mask);
    }

    /// Check that `flag` bit is set in object's CryptographicUsageMask.
    /// If FIPS mode is disabled, check if Unrestricted bit is set too.
    ///
    /// Raise error if `flag` is not set or if object's CryptographicUsageMask
    /// is None.
    pub fn is_usage_mask_flag_set(&self, flag: CryptographicUsageMask) -> Result<(), KmipError> {
        let usage_mask = self.cryptographic_usage_mask.ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                "CryptographicUsageMask is None".to_string(),
            )
        })?;

        #[cfg(not(feature = "fips"))]
        // In non-FIPS mode, Unrestricted can be allowed.
        let flag = flag | CryptographicUsageMask::Unrestricted;

        if (usage_mask & flag).bits() != 0 {
            Ok(())
        } else {
            Err(KmipError::InvalidKmipValue(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                format!(
                    "CryptographicUsageMask {} a bit is not set against flags {}",
                    usage_mask.bits(),
                    flag.bits()
                )
                .to_string(),
            ))
        }
    }
}

/// The Certificate Attributes are the various items included in a certificate. The following list is based on RFC2253.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CertificateAttributes {
    // Certificate Subject CN
    pub certificate_subject_cn: String,
    // Certificate Subject O
    pub certificate_subject_o: String,
    // Certificate Subject OU
    pub certificate_subject_ou: String,
    // Certificate Subject Email
    pub certificate_subject_email: String,
    // Certificate Subject C
    pub certificate_subject_c: String,
    // Certificate Subject ST
    pub certificate_subject_st: String,
    // Certificate Subject L
    pub certificate_subject_l: String,
    // Certificate Subject UID
    pub certificate_subject_uid: String,
    // Certificate Subject Serial Number
    pub certificate_subject_serial_number: String,
    // Certificate Subject Title
    pub certificate_subject_title: String,
    // Certificate Subject DC
    pub certificate_subject_dc: String,
    // Certificate Subject DN Qualifier
    pub certificate_subject_dn_qualifier: String,
    // Certificate Issuer CN
    pub certificate_issuer_cn: String,
    // Certificate Issuer O
    pub certificate_issuer_o: String,
    // Certificate Issuer OU
    pub certificate_issuer_ou: String,
    // Certificate Issuer Email
    pub certificate_issuer_email: String,
    // Certificate Issuer C
    pub certificate_issuer_c: String,
    // Certificate Issuer ST
    pub certificate_issuer_st: String,
    // Certificate Issuer L
    pub certificate_issuer_l: String,
    // Certificate Issuer UID
    pub certificate_issuer_uid: String,
    // Certificate Issuer Serial Number
    pub certificate_issuer_serial_number: String,
    // Certificate Issuer Title
    pub certificate_issuer_title: String,
    // Certificate Issuer DC
    pub certificate_issuer_dc: String,
    // Certificate Issuer DN Qualifier
    pub certificate_issuer_dn_qualifier: String,
}

impl CertificateAttributes {
    pub fn parse_subject_line(subject_line: &str) -> Result<Self, KmipError> {
        let mut certificate_attributes = CertificateAttributes::default();

        for component in subject_line.split(',') {
            let mut parts = component.splitn(2, '=');
            let key = parts
                .next()
                .ok_or_else(|| KmipError::Default("subject name identifier missing".to_string()))?
                .trim();
            let value = parts
                .next()
                .ok_or_else(|| {
                    KmipError::Default(format!("subject name value missing for identifier {key}"))
                })?
                .trim();
            match key {
                "CN" => value.clone_into(&mut certificate_attributes.certificate_subject_cn),
                "O" => value.clone_into(&mut certificate_attributes.certificate_subject_o),
                "OU" => value.clone_into(&mut certificate_attributes.certificate_subject_ou),
                "Email" => value.clone_into(&mut certificate_attributes.certificate_subject_email),
                "C" => value.clone_into(&mut certificate_attributes.certificate_subject_c),
                "ST" => value.clone_into(&mut certificate_attributes.certificate_subject_st),
                "L" => value.clone_into(&mut certificate_attributes.certificate_subject_l),
                "UID" => value.clone_into(&mut certificate_attributes.certificate_subject_uid),
                "Serial Number" => {
                    value.clone_into(&mut certificate_attributes.certificate_subject_serial_number);
                }
                "Title" => value.clone_into(&mut certificate_attributes.certificate_subject_title),
                "DC" => value.clone_into(&mut certificate_attributes.certificate_subject_dc),
                "DN Qualifier" => {
                    value.clone_into(&mut certificate_attributes.certificate_subject_dn_qualifier);
                }
                _ => {
                    return Err(KmipError::Default(format!(
                        "Invalid subject line identifier: {key}"
                    )))
                }
            }
        }
        Ok(certificate_attributes)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct VendorAttributeReference {
    pub vendor_identification: String,
    pub attribute_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum AttributeReference {
    Vendor(VendorAttributeReference),
    Standard(Tag),
}

impl AttributeReference {
    #[must_use]
    pub fn tags_reference() -> Self {
        AttributeReference::Vendor(VendorAttributeReference {
            vendor_identification: VENDOR_ID_COSMIAN.to_string(),
            attribute_name: VENDOR_ATTR_TAG.to_string(),
        })
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumString, Display)]
pub enum Tag {
    ActivationDate = 0x42_0001,
    ApplicationData = 0x42_0002,
    ApplicationNamespace = 0x42_0003,
    ApplicationSpecific_Information = 0x42_0004,
    ArchiveDate = 0x42_0005,
    AsynchronousCorrelation_Value = 0x42_0006,
    AsynchronousIndicator = 0x42_0007,
    Attribute = 0x42_0008,
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
    CertificateRequest = 0x42_0018,
    CertificateRequestType = 0x42_0019,
    CertificateType = 0x42_001D,
    CertificateValue = 0x42_001E,
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
    MACSignatureKey_Information = 0x42_004E,
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
    P = 0x42_005E,
    PaddingMethod = 0x42_005F,
    PrimeExponentP = 0x42_0060,
    PrimeExponentQ = 0x42_0061,
    PrimeFieldSize = 0x42_0062,
    PrivateExponent = 0x42_0063,
    PrivateKey = 0x42_0064,
    PrivateKeyUniqueIdentifier = 0x42_0066,
    ProcessStartDate = 0x42_0067,
    ProtectStopDate = 0x42_0068,
    ProtocolVersion = 0x42_0069,
    ProtocolVersionMajor = 0x42_006A,
    ProtocolVersionMinor = 0x42_006B,
    PublicExponent = 0x42_006C,
    PublicKey = 0x42_006D,
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
    ServerInformation = 0x42_0088,
    SplitKey = 0x42_0089,
    SplitKeyMethod = 0x42_008A,
    SplitKeyParts = 0x42_008B,
    SplitKeyThreshold = 0x42_008C,
    State = 0x42_008D,
    StorageStatusMask = 0x42_008E,
    SymmetricKey = 0x42_008F,
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
    Attributes = 0x42_0125,
    CommonAttributes = 0x42_0126,
    PrivateKeyAttributes = 0x42_0127,
    PublicKeyAttributes = 0x42_0128,
    ExtensionEnumeration = 0x42_0129,
    ExtensionAttribute = 0x42_012A,
    ExtensionParentStructureTag = 0x42_012B,
    ExtensionDescription = 0x42_012C,
    ServerName = 0x42_012D,
    ServerSerialNumber = 0x42_012E,
    ServerVersion = 0x42_012F,
    ServerLoad = 0x42_0130,
    ProductName = 0x42_0131,
    BuildLevel = 0x42_0132,
    BuildDate = 0x42_0133,
    ClusterInfo = 0x42_0134,
    AlternateFailoverEndpoints = 0x42_0135,
    ShortUniqueIdentifier = 0x42_0136,
    Reserved = 0x42_0137,
    Tag = 0x42_0138,
    CertificateRequestUniqueIdentifier = 0x42_0139,
    NISTKeyType = 0x42_013A,
    AttributeReference = 0x42_013B,
    CurrentAttribute = 0x42_013C,
    NewAttribute = 0x42_013D,
    CertificateRequestValue = 0x42_0140,
    LogMessage = 0x42_0141,
    ProfileVersion = 0x42_0142,
    ProfileVersionMajor = 0x42_0143,
    ProfileVersionMinor = 0x42_0144,
    ProtectionLevel = 0x42_0145,
    ProtectionPeriod = 0x42_0146,
    QuantumSafe = 0x42_0147,
    QuantumSafeCapability = 0x42_0148,
    Ticket = 0x42_0149,
    TicketType = 0x42_014A,
    TicketValue = 0x42_014B,
    RequestCount = 0x42_014C,
    Rights = 0x42_014D,
    Objects = 0x42_014E,
    Operations = 0x42_014F,
    Right = 0x42_0150,
    EndpointRole = 0x42_0151,
    DefaultsInformation = 0x42_0152,
    ObjectDefaults = 0x42_0153,
    Ephemeral = 0x42_0154,
    ServerHashedPassword = 0x42_0155,
    OneTimePassword = 0x42_0156,
    HashedPassword = 0x42_0157,
    AdjustmentType = 0x42_0158,
    PKCS11Interface = 0x42_0159,
    PKCS11Function = 0x42_015A,
    PKCS11InputParameters = 0x42_015B,
    PKCS11OutputParameters = 0x42_015C,
    PKCS11ReturnCode = 0x42_015D,
    ProtectionStorageMask = 0x42_015E,
    ProtectionStorageMasks = 0x42_015F,
    InteropFunction = 0x42_0160,
    InteropIdentifier = 0x42_0161,
    AdjustmentValue = 0x42_0162,
    CommonProtectionStorageMasks = 0x42_0163,
    PrivateProtectionStorageMasks = 0x42_0164,
    PublicProtectionStorageMasks = 0x42_0165,
    // Extensions 540000 – 54FFFF
}

/// Indicates the method used to wrap the Key Value.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum WrappingMethod {
    Encrypt = 0x0000_0001,
    MACSign = 0x0000_0002,
    EncryptThenMACSign = 0x0000_0003,
    MACSignThenEncrypt = 0x0000_0004,
    TR31 = 0x0000_0005,
}
impl Default for WrappingMethod {
    fn default() -> Self {
        Self::Encrypt
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
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
    X9102AESKW = 0x0000_000E,
    X9102TDKW = 0x0000_000F,
    X9102AKW1 = 0x0000_0010,
    X9102AKW2 = 0x0000_0011,
    AEAD = 0x0000_0012,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum PaddingMethod {
    None = 0x0000_0001,
    OAEP = 0x0000_0002,
    PKCS5 = 0x0000_0003,
    SSL3 = 0x0000_0004,
    Zeros = 0x0000_0005,
    ANSIX923 = 0x0000_0006,
    ISO10126 = 0x0000_0007,
    PKCS1v15 = 0x0000_0008,
    X931 = 0x0000_0009,
    PSS = 0x0000_000A,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum HashingAlgorithm {
    MD2 = 0x0000_0001,
    MD4 = 0x0000_0002,
    MD5 = 0x0000_0003,
    SHA1 = 0x0000_0004,
    SHA224 = 0x0000_0005,
    SHA256 = 0x0000_0006,
    SHA384 = 0x0000_0007,
    SHA512 = 0x0000_0008,
    RIPEMD_160 = 0x0000_0009,
    Tiger = 0x0000_000A,
    Whirlpool = 0x0000_000B,
    SHA512224 = 0x0000_000C,
    SHA512256 = 0x0000_000D,
    SHA3224 = 0x0000_000E,
    SHA3256 = 0x0000_000F,
    SHA3384 = 0x0000_0010,
    SHA3512 = 0x0000_0011,
}

#[cfg(feature = "openssl")]
impl TryFrom<HashingAlgorithm> for &'static MdRef {
    type Error = KmipError;

    fn try_from(hashing_algorithm: HashingAlgorithm) -> Result<Self, Self::Error> {
        match hashing_algorithm {
            HashingAlgorithm::SHA1 => Ok(Md::sha1()),
            HashingAlgorithm::SHA224 => Ok(Md::sha224()),
            HashingAlgorithm::SHA256 => Ok(Md::sha256()),
            HashingAlgorithm::SHA384 => Ok(Md::sha384()),
            HashingAlgorithm::SHA512 => Ok(Md::sha512()),
            HashingAlgorithm::SHA3224 => Ok(Md::sha3_224()),
            HashingAlgorithm::SHA3256 => Ok(Md::sha3_256()),
            HashingAlgorithm::SHA3384 => Ok(Md::sha3_384()),
            HashingAlgorithm::SHA3512 => Ok(Md::sha3_512()),
            h => Err(kmip_error!(
                "Unsupported hash function: {h:?} for the openssl provider"
            )),
        }
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<HashingAlgorithm> for MessageDigest {
    type Error = KmipError;

    fn try_from(hashing_algorithm: HashingAlgorithm) -> Result<Self, Self::Error> {
        match hashing_algorithm {
            HashingAlgorithm::SHA1 => Ok(MessageDigest::sha1()),
            HashingAlgorithm::SHA224 => Ok(MessageDigest::sha224()),
            HashingAlgorithm::SHA256 => Ok(MessageDigest::sha256()),
            HashingAlgorithm::SHA384 => Ok(MessageDigest::sha384()),
            HashingAlgorithm::SHA512 => Ok(MessageDigest::sha512()),
            HashingAlgorithm::SHA3224 => Ok(MessageDigest::sha3_224()),
            HashingAlgorithm::SHA3256 => Ok(MessageDigest::sha3_256()),
            HashingAlgorithm::SHA3384 => Ok(MessageDigest::sha3_384()),
            HashingAlgorithm::SHA3512 => Ok(MessageDigest::sha3_512()),
            h => Err(kmip_error!(
                "Unsupported hash function: {h:?} for the openssl Message Digest provider"
            )),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyRoleType {
    BDK = 0x0000_0001,
    CVK = 0x0000_0002,
    DEK = 0x0000_0003,
    MKAC = 0x0000_0004,
    MKSMC = 0x0000_0005,
    MKSMI = 0x0000_0006,
    MKDAC = 0x0000_0007,
    MKDN = 0x0000_0008,
    MKCP = 0x0000_0009,
    MKOTH = 0x0000_000A,
    KEK = 0x0000_000B,
    MAC16609 = 0x0000_000C,
    MAC97971 = 0x0000_000D,
    MAC97972 = 0x0000_000E,
    MAC97973 = 0x0000_000F,
    MAC97974 = 0x0000_0010,
    MAC97975 = 0x0000_0011,
    ZPK = 0x0000_0012,
    PVKIBM = 0x0000_0013,
    PVKPVV = 0x0000_0014,
    PVKOTH = 0x0000_0015,
    DUKPT = 0x0000_0016,
    IV = 0x0000_0017,
    TRKBK = 0x0000_0018,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum DigitalSignatureAlgorithm {
    MD2WithRSAEncryption = 0x0000_0001,
    MD5WithRSAEncryption = 0x0000_0002,
    SHA1WithRSAEncryption = 0x0000_0003,
    SHA224WithRSAEncryption = 0x0000_0004,
    SHA256WithRSAEncryption = 0x0000_0005,
    SHA384WithRSAEncryption = 0x0000_0006,
    SHA512WithRSAEncryption = 0x0000_0007,
    RSASSAPSS = 0x0000_0008,
    DSAWithSHA1 = 0x0000_0009,
    DSAWithSHA224 = 0x0000_000A,
    DSAWithSHA256 = 0x0000_000B,
    ECDSAWithSHA1 = 0x0000_000C,
    ECDSAWithSHA224 = 0x0000_000D,
    ECDSAWithSHA256 = 0x0000_000E,
    ECDSAWithSHA384 = 0x0000_000F,
    ECDSAWithSHA512 = 0x0000_0010,
    SHA3256WithRSAEncryption = 0x0000_0011,
    SHA3384WithRSAEncryption = 0x0000_0012,
    SHA3512WithRSAEncryption = 0x0000_0013,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum MaskGenerator {
    MFG1 = 0x0000_0001,
}

/// The Cryptographic Parameters attribute is a structure that contains a set of
/// OPTIONAL fields that describe certain cryptographic parameters to be used
/// when performing cryptographic operations using the object. Specific fields
/// MAY pertain only to certain types of Managed Objects. The Cryptographic
/// Parameters attribute of a Certificate object identifies the cryptographic
/// parameters of the public key contained within the Certificate.
///
/// The Cryptographic Algorithm is also used to specify the parameters for
/// cryptographic operations. For operations involving digital signatures,
/// either the Digital Signature Algorithm can be specified or the Cryptographic
/// Algorithm and Hashing Algorithm combination can be specified. Random IV can
/// be used to request that the KMIP server generate an appropriate IV for a
/// cryptographic operation that uses an IV. The generated Random IV is returned
/// in the response to the cryptographic operation.
///
/// IV Length is the length of the Initialization Vector in bits. This parameter
/// SHALL be provided when the specified Block Cipher Mode supports variable IV
/// lengths such as CTR or GCM. Tag Length is the length of the authenticator
/// tag in bytes. This parameter SHALL be provided when the Block Cipher Mode is
/// GCM.
///
/// The IV used with counter modes of operation (e.g., CTR and GCM) cannot
/// repeat for a given cryptographic key. To prevent an IV/key reuse, the IV is
/// often constructed of three parts: a fixed field, an invocation field, and a
/// counter as described in SP800-38A and SP800-38D. The Fixed Field Length
/// is the length of the fixed field portion of the IV in bits. The Invocation
/// Field Length is the length of the invocation field portion of the IV in
/// bits. The Counter Length is the length of the counter portion of the IV in
/// bits.
///
/// Initial Counter Value is the starting counter value for CTR mode (for
/// RFC3686 it is 1).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CryptographicParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_cipher_mode: Option<BlockCipherMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding_method: Option<PaddingMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_role_type: Option<KeyRoleType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_signature_algorithm: Option<DigitalSignatureAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub random_iv: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iv_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_field_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_field_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_counter_value: Option<u64>,
    /// if omitted, defaults to the block size of the Mask Generator Hashing
    /// Algorithm Cosmian extension: In AES: used as the number of
    /// additional data at the end of the submitted data that become part of
    /// the MAC calculation. These additional data are removed
    /// from the encrypted data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_length: Option<u64>,
    /// if omitted defaults to MGF1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator: Option<MaskGenerator>,
    /// if omitted defaults to SHA-1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p_source: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailer_field: Option<u64>,
}

/// Contains the Unique Identifier value of the encryption key and
/// associated cryptographic parameters.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptionKeyInformation {
    pub unique_identifier: UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<Box<CryptographicParameters>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct MacSignatureKeyInformation {
    pub unique_identifier: UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<Box<CryptographicParameters>>,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum EncodingOption {
    /// the wrapped un-encoded value of the Byte String Key Material field in
    /// the Key Value structure
    NoEncoding = 0x0000_0001,
    /// the wrapped TTLV-encoded Key Value structure
    TTLVEncoding = 0x0000_0002,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyWrapType {
    NotWrapped = 0x0000_0001,
    AsRegistered = 0x0000_0002,
}

/// This attribute is an indication of the State of an object as known to the
/// key management server. The State SHALL NOT be changed by using the Modify
/// Attribute operation on this attribute. The State SHALL only be changed by
/// the server as a part of other operations or other server processes. An
/// object SHALL be in one of the following states at any given time.
///
/// Note: The states correspond to those described in [SP800-57-1].
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum StateEnumeration {
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

/// The Unique Identifier is generated by the key management system
/// to uniquely identify a Managed Object.
///
/// It is only REQUIRED to be unique within the identifier space managed
/// by a single key management system, however this identifier SHOULD be globally unique
/// in order to allow for a key management server export of such objects.
///
/// This attribute SHALL be assigned by the key management system at creation or registration time,
/// and then SHALL NOT be changed or deleted before the object is destroyed.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(untagged)]
pub enum UniqueIdentifier {
    TextString(String),
    Enumeration(UniqueIdentifierEnumeration),
    Integer(i32),
}

impl Display for UniqueIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            UniqueIdentifier::TextString(s) => write!(f, "{s}"),
            UniqueIdentifier::Enumeration(e) => write!(f, "{e}"),
            UniqueIdentifier::Integer(i) => write!(f, "{i}"),
        }
    }
}

impl UniqueIdentifier {
    /// Returns the value as a string if it is a `TextString`
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            UniqueIdentifier::TextString(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the value as a string if it is a `TextString`
    #[must_use]
    pub fn to_string(&self) -> Option<String> {
        match self {
            UniqueIdentifier::TextString(s) => Some(s.clone()),
            _ => None,
        }
    }
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
    pub protocol_version_major: u32,
    pub protocol_version_minor: u32,
}

/// The KMIP version 2.1 is used as the reference
/// for the implementation here
impl Default for ProtocolVersion {
    fn default() -> Self {
        ProtocolVersion {
            protocol_version_major: 2,
            protocol_version_minor: 1,
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
    fn value(&self) -> u32 {
        match *self {
            Credential::UsernameAndPassword { .. } => 0x0000_0001,
            Credential::Device { .. } => 0x0000_0002,
            Credential::Attestation { .. } => 0x0000_0003,
            Credential::OneTimePassword { .. } => 0x0000_0004,
            Credential::HashedPassword { .. } => 0x0000_0005,
            Credential::Ticket { .. } => 0x0000_0006,
        }
    }
}

impl Serialize for Credential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Credential::UsernameAndPassword { username, password } => {
                let mut st = serializer.serialize_struct("UsernameAndPassword", 2)?;
                st.serialize_field("Username", username)?;
                if let Some(password) = password {
                    st.serialize_field("Password", password)?;
                }
                st.end()
            }
            Credential::Device {
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
            Credential::Attestation {
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
            Credential::OneTimePassword {
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
            Credential::HashedPassword {
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
            Credential::Ticket {
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

/// This option SHALL only be present if the Batch Count is greater than 1.
/// This option SHALL have one of three values (Undo, Stop or Continue).
/// If not specified, then Stop is assumed.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum BatchErrorContinuationOption {
    /// If any operation in the request fails, then the server SHALL undo all the previous operations.
    ///
    /// Batch item fails and Result Status is set to Operation Failed.
    /// Responses to batch items that have already been processed are returned normally.
    /// Responses to batch items that have not been processed are not returned.
    Undo,
    Stop,
    Continue,
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

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum OperationEnumeration {
    Create = 0x0000_0001,
    CreateKeyPair = 0x0000_0002,
    Register = 0x0000_0003,
    Rekey = 0x0000_0004,
    DeriveKey = 0x0000_0005,
    Certify = 0x0000_0006,
    Recertify = 0x0000_0007,
    Locate = 0x0000_0008,
    Check = 0x0000_0009,
    Get = 0x0000_000A,
    GetAttributes = 0x0000_000B,
    GetAttributeList = 0x0000_000C,
    AddAttribute = 0x0000_000D,
    ModifyAttribute = 0x0000_000E,
    DeleteAttribute = 0x0000_000F,
    ObtainLease = 0x0000_0010,
    GetUsageAllocation = 0x0000_0011,
    Activate = 0x0000_0012,
    Revoke = 0x0000_0013,
    Destroy = 0x0000_0014,
    Archive = 0x0000_0015,
    Recover = 0x0000_0016,
    Validate = 0x0000_0017,
    Query = 0x0000_0018,
    Cancel = 0x0000_0019,
    Poll = 0x0000_001A,
    Notify = 0x0000_001B,
    Put = 0x0000_001C,
    RekeyKeyPair = 0x0000_001D,
    DiscoverVersions = 0x0000_001E,
    Encrypt = 0x0000_001F,
    Decrypt = 0x0000_0020,
    Sign = 0x0000_0021,
    SignatureVerify = 0x0000_0022,
    MAC = 0x0000_0023,
    MACVerify = 0x0000_0024,
    RNGRetrieve = 0x0000_0025,
    RNGSeed = 0x0000_0026,
    Hash = 0x0000_0027,
    CreateSplitKey = 0x0000_0028,
    JoinSplitKey = 0x0000_0029,
    Import = 0x0000_002A,
    Export = 0x0000_002B,
    Log = 0x0000_002C,
    Login = 0x0000_002D,
    Logout = 0x0000_002E,
    DelegatedLogin = 0x0000_002F,
    AdjustAttribute = 0x0000_0030,
    SetAttribute = 0x0000_0031,
    SetEndpointRole = 0x0000_0032,
    PKCS11 = 0x0000_0033,
    Interop = 0x0000_0034,
    ReProvision = 0x0000_0035,
    SetDefaults = 0x0000_0036,
    SetConstraints = 0x0000_0037,
    GetConstraints = 0x0000_0038,
    QueryAsynchronousRequests = 0x0000_0039,
    Process = 0x0000_003A,
    Ping = 0x0000_003B,
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum ResultStatusEnumeration {
    Success = 0x0000_0000,
    OperationFailed = 0x0000_0001,
    OperationPending = 0x0000_0002,
    OperationUndone = 0x0000_0003,
}
