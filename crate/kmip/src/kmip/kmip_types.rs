// A still incomplete list of the KMIP types:
// see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html

// see CryptographicUsageMask
#![allow(non_upper_case_globals)]
use std::{
    fmt,
    fmt::{Display, Formatter},
};

use clap::ValueEnum;
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
use tracing::trace;
use uuid::Uuid;

use super::kmip_objects::ObjectType;
use crate::{
    error::KmipError,
    kmip::{
        extra::{tagging::VENDOR_ATTR_TAG, VENDOR_ID_COSMIAN},
        kmip_operations::ErrorReason,
    },
    kmip_error,
};
pub const VENDOR_ATTR_AAD: &str = "aad";

/// 4.7
/// The Certificate Type attribute is a type of certificate (e.g., X.509).
/// The Certificate Type value SHALL be set by the server when the certificate
/// is created or registered and then SHALL NOT be changed or deleted before the
/// object is destroyed.
/// The PKCS7 format is a Cosmian extension from KMIP.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[allow(clippy::enum_clike_unportable_variant)]
pub enum CertificateType {
    X509 = 0x01,
    PGP = 0x02,
    PKCS7 = 0x8000_0001,
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
/// | Certificate | PKCS#7 |
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
#[derive(
    ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumIter, Display,
)]
pub enum KeyFormatType {
    #[value(name = "Raw")]
    Raw = 0x01,
    #[value(name = "Opaque")]
    Opaque = 0x02,
    #[value(name = "PKCS1")]
    PKCS1 = 0x03,
    #[value(name = "PKCS8")]
    PKCS8 = 0x04,
    #[value(name = "X509")]
    X509 = 0x05,
    #[value(name = "ECPrivateKey")]
    ECPrivateKey = 0x06,
    #[value(name = "TransparentSymmetricKey")]
    TransparentSymmetricKey = 0x07,
    #[value(name = "TransparentDSAPrivateKey")]
    TransparentDSAPrivateKey = 0x08,
    #[value(name = "TransparentDSAPublicKey")]
    TransparentDSAPublicKey = 0x09,
    #[value(name = "TransparentRSAPrivateKey")]
    TransparentRSAPrivateKey = 0x0A,
    #[value(name = "TransparentRSAPublicKey")]
    TransparentRSAPublicKey = 0x0B,
    #[value(name = "TransparentDHPrivateKey")]
    TransparentDHPrivateKey = 0x0C,
    #[value(name = "TransparentDHPublicKey")]
    TransparentDHPublicKey = 0x0D,
    #[value(name = "TransparentECPrivateKey")]
    TransparentECPrivateKey = 0x14,
    #[value(name = "TransparentECPublicKey")]
    TransparentECPublicKey = 0x15,
    #[value(name = "PKCS12")]
    PKCS12 = 0x16,
    #[value(name = "PKCS10")]
    PKCS10 = 0x17,
    #[cfg(not(feature = "fips"))]
    /// This mode is to support legacy, but common, PKCS#12 formats that use
    /// `PBE_WITHSHA1AND40BITRC2_CBC` for the encryption algorithm of certificate,
    /// `PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC` for the encryption algorithm of the key
    /// and SHA-1 for the MAC.
    /// This is not a standard PKCS#12 format but is used by some software
    /// such as Java `KeyStores`, Mac OS X Keychains, and some versions of OpenSSL (1x).
    /// Use PKCS12 instead for standard (newer) PKCS#12 format.
    Pkcs12Legacy = 0x8880_0001,
    PKCS7 = 0x8880_0002,
    // Available slot 0x8880_0003,
    // Available slot 0x8880_0004,
    #[value(name = "EnclaveECKeyPair")]
    EnclaveECKeyPair = 0x8880_0005,
    #[value(name = "EnclaveECSharedKey")]
    EnclaveECSharedKey = 0x8880_0006,
    // Available slot 0x8880_0007,
    // Available slot 0x8880_0008,
    // Available slot 0x8880_0009,
    // Available slot 0x8880_000A,
    // Available slot 0x8880_000B,
    #[value(name = "CoverCryptSecretKey")]
    CoverCryptSecretKey = 0x8880_000C,
    #[value(name = "CoverCryptPublicKey")]
    CoverCryptPublicKey = 0x8880_000D,
}

#[allow(non_camel_case_types)]
#[allow(clippy::enum_clike_unportable_variant)]
#[derive(
    ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Display, Eq, PartialEq, EnumIter,
)]
pub enum CryptographicAlgorithm {
    #[value(name = "DES")]
    DES = 0x0000_0001,
    #[value(name = "THREE_DES")]
    THREE_DES = 0x0000_0002,
    #[value(name = "AES")]
    AES = 0x0000_0003,
    /// This is `CKM_RSA_PKCS_OAEP` from PKCS#11
    /// see <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
    /// To use  `CKM_RSA_AES_KEY_WRAP` from PKCS#11, use and RSA key with AES as the algorithm
    /// See <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226908
    #[value(name = "RSA")]
    RSA = 0x0000_0004,
    #[value(name = "DSA")]
    DSA = 0x0000_0005,
    #[value(name = "ECDSA")]
    ECDSA = 0x0000_0006,
    #[value(name = "HMACSHA1")]
    HMACSHA1 = 0x0000_0007,
    #[value(name = "HMACSHA224")]
    HMACSHA224 = 0x0000_0008,
    #[value(name = "HMACSHA256")]
    HMACSHA256 = 0x0000_0009,
    #[value(name = "HMACSHA384")]
    HMACSHA384 = 0x0000_000A,
    #[value(name = "HMACSHA512")]
    HMACSHA512 = 0x0000_000B,
    #[value(name = "HMACMD5")]
    HMACMD5 = 0x0000_000C,
    #[value(name = "DH")]
    DH = 0x0000_000D,
    #[value(name = "ECDH")]
    ECDH = 0x0000_000E,
    #[value(name = "ECMQV")]
    ECMQV = 0x0000_000F,
    #[value(name = "Blowfish")]
    Blowfish = 0x0000_0010,
    #[value(name = "Camellia")]
    Camellia = 0x0000_0011,
    #[value(name = "CAST5")]
    CAST5 = 0x0000_0012,
    #[value(name = "IDEA")]
    IDEA = 0x0000_0013,
    #[value(name = "MARS")]
    MARS = 0x0000_0014,
    #[value(name = "RC2")]
    RC2 = 0x0000_0015,
    #[value(name = "RC4")]
    RC4 = 0x0000_0016,
    #[value(name = "RC5")]
    RC5 = 0x0000_0017,
    #[value(name = "SKIPJACK")]
    SKIPJACK = 0x0000_0018,
    #[value(name = "Twofish")]
    Twofish = 0x0000_0019,
    #[value(name = "EC")]
    EC = 0x0000_001A,
    #[value(name = "OneTimePad")]
    OneTimePad = 0x0000_001B,
    #[value(name = "ChaCha20")]
    ChaCha20 = 0x0000_001C,
    #[value(name = "Poly1305")]
    Poly1305 = 0x0000_001D,
    #[value(name = "ChaCha20Poly1305")]
    ChaCha20Poly1305 = 0x0000_001E,
    #[value(name = "SHA3224")]
    SHA3224 = 0x0000_001F,
    #[value(name = "SHA3256")]
    SHA3256 = 0x0000_0020,
    #[value(name = "SHA3384")]
    SHA3384 = 0x0000_0021,
    #[value(name = "SHA3512")]
    SHA3512 = 0x0000_0022,
    #[value(name = "HMACSHA3224")]
    HMACSHA3224 = 0x0000_0023,
    #[value(name = "HMACSHA3256")]
    HMACSHA3256 = 0x0000_0024,
    #[value(name = "HMACSHA3384")]
    HMACSHA3384 = 0x0000_0025,
    #[value(name = "HMACSHA3512")]
    HMACSHA3512 = 0x0000_0026,
    #[value(name = "SHAKE128")]
    SHAKE128 = 0x0000_0027,
    #[value(name = "SHAKE256")]
    SHAKE256 = 0x0000_0028,
    #[value(name = "ARIA")]
    ARIA = 0x0000_0029,
    #[value(name = "SEED")]
    SEED = 0x0000_002A,
    #[value(name = "SM2")]
    SM2 = 0x0000_002B,
    #[value(name = "SM3")]
    SM3 = 0x0000_002C,
    #[value(name = "SM4")]
    SM4 = 0x0000_002D,
    #[value(name = "GOSTR34102012")]
    GOSTR34102012 = 0x0000_002E,
    #[value(name = "GOSTR34112012")]
    GOSTR34112012 = 0x0000_002F,
    #[value(name = "GOSTR34132015")]
    GOSTR34132015 = 0x0000_0030,
    #[value(name = "GOST2814789")]
    GOST2814789 = 0x0000_0031,
    #[value(name = "XMSS")]
    XMSS = 0x0000_0032,
    #[value(name = "SPHINCS_256")]
    SPHINCS_256 = 0x0000_0033,
    #[value(name = "Page166Of230McEliece")]
    Page166Of230McEliece = 0x0000_0034,
    #[value(name = "McEliece6960119")]
    McEliece6960119 = 0x0000_0035,
    #[value(name = "McEliece8192128")]
    McEliece8192128 = 0x0000_0036,
    #[value(name = "Ed25519")]
    Ed25519 = 0x0000_0037,
    #[value(name = "Ed448")]
    Ed448 = 0x0000_0038,
    // Available slot 0x8880_0001,
    // Available slot 0x8880_0002,
    // Available slot 0x8880_0003,
    #[value(name = "CoverCrypt")]
    CoverCrypt = 0x8880_0004,
    #[value(name = "CoverCryptBulk")]
    CoverCryptBulk = 0x8880_0005,
}

/// The Cryptographic Domain Parameters attribute (4.14) is a structure that
/// contains fields that MAY need to be specified in the Create Key Pair Request
/// Payload. Specific fields MAY only pertain to certain types of Managed
/// Cryptographic Objects. The domain parameter `q_length` corresponds to the bit
/// length of parameter Q (refer to RFC7778, SEC2 and SP800-56A).
/// - `q_length` applies to algorithms such as DSA and DH. The bit length of parameter P (refer to RFC7778, SEC2 and SP800-56A) is specified separately by setting the Cryptographic Length attribute.
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProtectionStorageMasks(u32);

bitflags::bitflags! {
#[allow(clippy::indexing_slicing)]
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
        serializer.serialize_i32(i32::try_from(self.bits()).map_err(serde::ser::Error::custom)?)
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
                Ok(ProtectionStorageMasks(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(ProtectionStorageMasks(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
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
#[allow(clippy::indexing_slicing)]
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
        serializer.serialize_i32(i32::try_from(self.bits()).map_err(serde::ser::Error::custom)?)
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
                Ok(StorageStatusMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }

            // used by the direct JSON representation
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StorageStatusMask(
                    u32::try_from(v).map_err(de::Error::custom)?,
                ))
            }
        }
        deserializer.deserialize_any(StorageStatusMaskVisitor)
    }
}

#[allow(non_camel_case_types)]
#[derive(
    ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Eq, Display, PartialEq, EnumIter,
)]
pub enum LinkType {
    /// For Certificate objects: the parent certificate for a certificate in a
    /// certificate chain. For Public Key objects: the corresponding
    /// certificate(s), containing the same public key.
    #[value(name = "CertificateLink")]
    CertificateLink = 0x0000_0101,
    /// For a Private Key object: the public key corresponding to the private
    /// key. For a Certificate object: the public key contained in the
    /// certificate.
    #[value(name = "PublicKeyLink")]
    PublicKeyLink = 0x0000_0102,
    /// For a Public Key object: the private key corresponding to the public
    /// key.
    #[value(name = "PrivateKeyLink")]
    PrivateKeyLink = 0x0000_0103,
    /// For a derived Symmetric Key or Secret Data object: the object(s) from
    /// which the current symmetric key was derived.
    #[value(name = "DerivationBaseObjectLink")]
    DerivationBaseObjectLink = 0x0000_0104,
    /// The symmetric key(s) or Secret Data object(s) that were derived from
    /// the current object.
    #[value(name = "DerivedKeyLink")]
    DerivedKeyLink = 0x0000_0105,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that resulted from the re-key of the current
    /// key. For a Certificate object: the certificate that resulted from the
    /// re- certify. Note that there SHALL be only one such replacement
    /// object per Managed Object.
    #[value(name = "ReplacementObjectLink")]
    ReplacementObjectLink = 0x0000_0106,
    /// For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric
    /// Public Key object: the key that was re-keyed to obtain the current key.
    /// For a Certificate object: the certificate that was re-certified to
    /// obtain the current certificate.
    #[value(name = "ReplacedObjectLink")]
    ReplacedObjectLink = 0x0000_0107,
    /// For all object types: the container or other parent object corresponding
    /// to the object.
    #[value(name = "ParentLink")]
    ParentLink = 0x0000_0108,
    /// For all object types: the subordinate, derived or other child object
    /// corresponding to the object.
    #[value(name = "ChildLink")]
    ChildLink = 0x0000_0109,
    /// For all object types: the previous object to this object.
    #[value(name = "PreviousLink")]
    PreviousLink = 0x0000_010A,
    /// For all object types: the next object to this object.
    #[value(name = "NextLink")]
    NextLink = 0x0000_010B,
    #[value(name = "PKCS12CertificateLink")]
    PKCS12CertificateLink = 0x0000_010C,
    #[value(name = "PKCS12PasswordLink")]
    PKCS12PasswordLink = 0x0000_010D,
    /// For wrapped objects: the object that was used to wrap this object.
    #[value(name = "WrappingKeyLink")]
    WrappingKeyLink = 0x0000_010E,
    //Extensions 8XXXXXXX
}

/// The following values may be specified in an operation request for a Unique
/// Identifier: If multiple unique identifiers would be referenced then the
/// operation is repeated for each of them. If an operation appears
/// multiple times in a request, it is the most recent that is referred to.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display, Hash)]
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

impl Display for LinkedObjectIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextString(s) => write!(f, "{s}"),
            Self::Enumeration(e) => write!(f, "{e}"),
            Self::Index(i) => write!(f, "{i}"),
        }
    }
}

impl From<UniqueIdentifier> for LinkedObjectIdentifier {
    fn from(value: UniqueIdentifier) -> Self {
        match value {
            UniqueIdentifier::TextString(s) => Self::TextString(s),
            UniqueIdentifier::Enumeration(e) => Self::Enumeration(e),
            UniqueIdentifier::Integer(i) => Self::Index(i64::from(i)),
        }
    }
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

impl Display for VendorAttribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VendorAttribute {{ vendor_identification: {}, attribute_name: {}, attribute_value: \
             {} }}",
            self.vendor_identification,
            self.attribute_name,
            hex::encode(&self.attribute_value)
        )
    }
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
    pub cryptographic_parameters: Option<CryptographicParameters>,

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
    #[allow(clippy::indexing_slicing)]
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
    pub fn get_link(&self, link_type: LinkType) -> Option<LinkedObjectIdentifier> {
        self.link.as_ref().and_then(|links| {
            links
                .iter()
                .find(|&l| l.link_type == link_type)
                .map(|l| l.linked_object_identifier.clone())
        })
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
    pub fn get_parent_id(&self) -> Option<LinkedObjectIdentifier> {
        self.get_link(LinkType::ParentLink)
    }

    /// Set a link to an object.
    /// If a link of the same type already exists, it is removed.
    /// There can only be one link of a given type.
    pub fn set_link(
        &mut self,
        link_type: LinkType,
        linked_object_identifier: LinkedObjectIdentifier,
    ) {
        self.remove_link(link_type);
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

    /// Set the attributes's `CryptographicUsageMask`.
    pub fn set_cryptographic_usage_mask(&mut self, mask: Option<CryptographicUsageMask>) {
        self.cryptographic_usage_mask = mask;
    }

    /// Set the bits in `mask` to the attributes's `CryptographicUsageMask` bits.
    pub fn set_cryptographic_usage_mask_bits(&mut self, mask: CryptographicUsageMask) {
        let mask = self
            .cryptographic_usage_mask
            .map_or(mask, |attr_mask| attr_mask | mask);

        self.cryptographic_usage_mask = Some(mask);
    }

    /// Check that `flag` bit is set in object's `CryptographicUsageMask`.
    /// If FIPS mode is disabled, check if Unrestricted bit is set too.
    ///
    /// Return `true` if `flag` has at least one bit set in self's attributes,
    /// return `false` otherwise.
    /// Raise error if object's `CryptographicUsageMask` is None.
    pub fn is_usage_authorized_for(&self, flag: CryptographicUsageMask) -> Result<bool, KmipError> {
        let usage_mask = self.cryptographic_usage_mask.ok_or_else(|| {
            KmipError::InvalidKmipValue(
                ErrorReason::Incompatible_Cryptographic_Usage_Mask,
                "CryptographicUsageMask is None".to_owned(),
            )
        })?;

        #[cfg(not(feature = "fips"))]
        // In non-FIPS mode, Unrestricted can be allowed.
        let flag = flag | CryptographicUsageMask::Unrestricted;

        Ok((usage_mask & flag).bits() != 0)
    }

    /// Remove the authenticated additional data from the attributes and return it - for AESGCM unwrapping
    #[must_use]
    pub fn remove_aad(&mut self) -> Option<Vec<u8>> {
        let aad = self
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_AAD)
            .map(|value: &[u8]| value.to_vec());

        if aad.is_some() {
            self.remove_vendor_attribute(VENDOR_ID_COSMIAN, VENDOR_ATTR_AAD);
        }
        aad
    }

    /// Add the authenticated additional data to the attributes - for AESGCM unwrapping
    pub fn add_aad(&mut self, value: &[u8]) {
        let va = VendorAttribute {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_AAD.to_owned(),
            attribute_value: value.to_vec(),
        };
        self.add_vendor_attribute(va);
    }
}

/// Structure used in various operations to provide the New Attribute value in the request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Attribute {
    ActivationDate(u64),
    CryptographicAlgorithm(CryptographicAlgorithm),
    CryptographicLength(i32),
    CryptographicParameters(CryptographicParameters),
    CryptographicDomainParameters(CryptographicDomainParameters),
    CryptographicUsageMask(CryptographicUsageMask),
    Links(Vec<Link>),
    VendorAttributes(Vec<VendorAttribute>),
}

impl Display for Attribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActivationDate(activation_date) => {
                write!(f, "ActivationDate: {activation_date}")
            }
            Self::CryptographicAlgorithm(crypto_algorithm) => {
                write!(f, "CryptographicAlgorithm: {crypto_algorithm}")
            }
            Self::CryptographicLength(crypto_length) => {
                write!(f, "CryptographicLength: {crypto_length}")
            }
            Self::CryptographicParameters(crypto_parameters) => {
                write!(f, "CryptographicParameters: {crypto_parameters:?}")
            }
            Self::CryptographicDomainParameters(crypto_domain_parameters) => {
                write!(
                    f,
                    "CryptographicDomainParameters: {crypto_domain_parameters:?}"
                )
            }
            Self::CryptographicUsageMask(crypto_usage_mask) => {
                write!(f, "CryptographicUsageMask: {crypto_usage_mask:?}")
            }
            Self::Links(links) => write!(f, "Links: {links:?}"),
            Self::VendorAttributes(vendor_attributes) => {
                write!(f, "VendorAttributes: {vendor_attributes:?}")
            }
        }
    }
}

impl Serialize for Attribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::ActivationDate(activation_date) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("ActivationDate", activation_date)?;
                st.end()
            }
            Self::CryptographicAlgorithm(crypto_algorithm) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicAlgorithm", crypto_algorithm)?;
                st.end()
            }
            Self::CryptographicLength(crypto_length) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicLength", crypto_length)?;
                st.end()
            }
            Self::CryptographicParameters(crypto_parameters) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicParameters", crypto_parameters)?;
                st.end()
            }
            Self::CryptographicDomainParameters(crypto_domain_parameters) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicDomainParameters", crypto_domain_parameters)?;
                st.end()
            }
            Self::CryptographicUsageMask(crypto_usage_mask) => {
                let mut st = serializer.serialize_struct("Attribute", 1)?;
                st.serialize_field("CryptographicUsageMask", crypto_usage_mask)?;
                st.end()
            }
            Self::Links(links) => {
                let mut st = serializer.serialize_struct("Attribute", links.len())?;
                for link in links {
                    st.serialize_field("Link", link)?;
                }
                st.end()
            }
            Self::VendorAttributes(vendor_attributes) => {
                let mut st = serializer.serialize_struct("Attribute", vendor_attributes.len())?;
                for vendor_attribute in vendor_attributes {
                    st.serialize_field("VendorAttribute", vendor_attribute)?;
                }
                st.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Attribute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier)]
        enum Field {
            ActivationDate,
            CryptographicAlgorithm,
            CryptographicLength,
            CryptographicParameters,
            CryptographicDomainParameters,
            CryptographicUsageMask,
            Link,
            VendorAttribute,
        }

        struct AttributeVisitor;

        impl<'de> Visitor<'de> for AttributeVisitor {
            type Value = Attribute;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct AttributeVisitor")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut activation_date: Option<u64> = None;
                let mut cryptographic_algorithm: Option<CryptographicAlgorithm> = None;
                let mut cryptographic_length: Option<i32> = None;
                let mut cryptographic_parameters: Option<CryptographicParameters> = None;
                let mut cryptographic_domain_parameters: Option<CryptographicDomainParameters> =
                    None;
                let mut cryptographic_usage_mask: Option<CryptographicUsageMask> = None;
                let mut links: Vec<Link> = Vec::new();
                let mut vendor_attributes: Vec<VendorAttribute> = Vec::new();

                while let Some(key) = map.next_key()? {
                    trace!("visit_map: Key: {key:?}");
                    match key {
                        Field::ActivationDate => {
                            if activation_date.is_some() {
                                return Err(de::Error::duplicate_field("activation_date"))
                            }
                            activation_date = Some(map.next_value()?);
                        }
                        Field::CryptographicAlgorithm => {
                            if cryptographic_algorithm.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_algorithm"))
                            }
                            cryptographic_algorithm = Some(map.next_value()?);
                        }
                        Field::CryptographicLength => {
                            if cryptographic_length.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_length"))
                            }
                            cryptographic_length = Some(map.next_value()?);
                        }
                        Field::CryptographicParameters => {
                            if cryptographic_parameters.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_parameters"))
                            }
                            cryptographic_parameters = Some(map.next_value()?);
                        }
                        Field::CryptographicDomainParameters => {
                            if cryptographic_domain_parameters.is_some() {
                                return Err(de::Error::duplicate_field(
                                    "cryptographic_domain_parameters",
                                ))
                            }
                            cryptographic_domain_parameters = Some(map.next_value()?);
                        }
                        Field::CryptographicUsageMask => {
                            if cryptographic_usage_mask.is_some() {
                                return Err(de::Error::duplicate_field("cryptographic_usage_mask"))
                            }
                            cryptographic_usage_mask = Some(map.next_value()?);
                        }
                        Field::Link => {
                            links.push(map.next_value()?);
                        }
                        Field::VendorAttribute => {
                            vendor_attributes.push(map.next_value()?);
                        }
                    }
                }

                trace!("Attribute::deserialize: Link: {:?}", links);
                if let Some(activation_date) = activation_date {
                    return Ok(Attribute::ActivationDate(activation_date))
                } else if let Some(cryptographic_algorithm) = cryptographic_algorithm {
                    return Ok(Attribute::CryptographicAlgorithm(cryptographic_algorithm))
                } else if let Some(cryptographic_length) = cryptographic_length {
                    return Ok(Attribute::CryptographicLength(cryptographic_length))
                } else if let Some(cryptographic_parameters) = cryptographic_parameters {
                    return Ok(Attribute::CryptographicParameters(cryptographic_parameters))
                } else if let Some(cryptographic_domain_parameters) =
                    cryptographic_domain_parameters
                {
                    return Ok(Attribute::CryptographicDomainParameters(
                        cryptographic_domain_parameters,
                    ))
                } else if let Some(cryptographic_usage_mask) = cryptographic_usage_mask {
                    return Ok(Attribute::CryptographicUsageMask(cryptographic_usage_mask))
                } else if !links.is_empty() {
                    return Ok(Attribute::Links(links))
                } else if !vendor_attributes.is_empty() {
                    return Ok(Attribute::VendorAttributes(vendor_attributes))
                }

                Ok(Attribute::ActivationDate(0))
            }
        }

        const FIELDS: &[&str] = &[
            "activation_date",
            "cryptographic_algorithm",
            "cryptographic_length",
            "cryptographic_parameters",
            "cryptographic_domain_parameters",
            "cryptographic_usage_mask",
            "link",
            "public_key_link",
            "vendor_attributes",
        ];
        deserializer.deserialize_struct("Attribute", FIELDS, AttributeVisitor)
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
        let mut certificate_attributes = Self::default();

        for component in subject_line.split(',') {
            let mut parts = component.splitn(2, '=');
            let key = parts
                .next()
                .ok_or_else(|| {
                    KmipError::Default(
                        "Missing x509 certificate `subject name` identifier".to_owned(),
                    )
                })?
                .trim();
            let value = parts
                .next()
                .ok_or_else(|| {
                    KmipError::Default(format!(
                        "Missing or invalid x509 certificate `subject name` value for identifier \
                         {key}"
                    ))
                })?
                .trim();
            match key {
                "CN" => value.clone_into(&mut certificate_attributes.certificate_subject_cn),
                "O" => value.clone_into(&mut certificate_attributes.certificate_subject_o),
                "OU" => value.clone_into(&mut certificate_attributes.certificate_subject_ou),
                "emailAddress" => {
                    value.clone_into(&mut certificate_attributes.certificate_subject_email);
                }
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
        Self::Vendor(VendorAttributeReference {
            vendor_identification: VENDOR_ID_COSMIAN.to_owned(),
            attribute_name: VENDOR_ATTR_TAG.to_owned(),
        })
    }
}

#[allow(non_camel_case_types)]
#[allow(clippy::enum_variant_names)]
#[derive(
    Serialize,
    Deserialize,
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Display,
    EnumString,
    EnumIter,
    Hash,
    ValueEnum,
)]
pub enum Tag {
    #[value(name = "ActivationDate")]
    ActivationDate = 0x42_0001,
    #[value(name = "ApplicationData")]
    ApplicationData = 0x42_0002,
    #[value(name = "ApplicationNamespace")]
    ApplicationNamespace = 0x42_0003,
    #[value(name = "ApplicationSpecific_Information")]
    ApplicationSpecific_Information = 0x42_0004,
    #[value(name = "ArchiveDate")]
    ArchiveDate = 0x42_0005,
    #[value(name = "AsynchronousCorrelation_Value")]
    AsynchronousCorrelation_Value = 0x42_0006,
    #[value(name = "AsynchronousIndicator")]
    AsynchronousIndicator = 0x42_0007,
    #[value(name = "Attribute")]
    Attribute = 0x42_0008,
    #[value(name = "AttributeName")]
    AttributeName = 0x42_000A,
    #[value(name = "AttributeValue")]
    AttributeValue = 0x42_000B,
    #[value(name = "Authentication")]
    Authentication = 0x42_000C,
    #[value(name = "BatchCount")]
    BatchCount = 0x42_000D,
    #[value(name = "BatchErrorContinuationOption")]
    BatchErrorContinuationOption = 0x42_000E,
    #[value(name = "BatchItem")]
    BatchItem = 0x42_000F,
    #[value(name = "BatchOrderOption")]
    BatchOrderOption = 0x42_0010,
    #[value(name = "BlockCipherMode")]
    BlockCipherMode = 0x42_0011,
    #[value(name = "CancellationResult")]
    CancellationResult = 0x42_0012,
    #[value(name = "Certificate")]
    Certificate = 0x42_0013,
    #[value(name = "CertificateRequest")]
    CertificateRequest = 0x42_0018,
    #[value(name = "CertificateRequestType")]
    CertificateRequestType = 0x42_0019,
    #[value(name = "CertificateType")]
    CertificateType = 0x42_001D,
    #[value(name = "CertificateValue")]
    CertificateValue = 0x42_001E,
    #[value(name = "CompromiseDate")]
    CompromiseDate = 0x42_0020,
    #[value(name = "CompromiseOccurrenceDate")]
    CompromiseOccurrenceDate = 0x42_0021,
    #[value(name = "ContactInformation")]
    ContactInformation = 0x42_0022,
    #[value(name = "Credential")]
    Credential = 0x42_0023,
    #[value(name = "CredentialType")]
    CredentialType = 0x42_0024,
    #[value(name = "CredentialValue")]
    CredentialValue = 0x42_0025,
    #[value(name = "CriticalityIndicator")]
    CriticalityIndicator = 0x42_0026,
    #[value(name = "CRTCoefficient")]
    CRTCoefficient = 0x42_0027,
    #[value(name = "CryptographicAlgorithm")]
    CryptographicAlgorithm = 0x42_0028,
    #[value(name = "CryptographicDomainParameters")]
    CryptographicDomainParameters = 0x42_0029,
    #[value(name = "CryptographicLength")]
    CryptographicLength = 0x42_002A,
    #[value(name = "CryptographicParameters")]
    CryptographicParameters = 0x42_002B,
    #[value(name = "CryptographicUsageMask")]
    CryptographicUsageMask = 0x42_002C,
    #[value(name = "D")]
    D = 0x42_002E,
    #[value(name = "DeactivationDate")]
    DeactivationDate = 0x42_002F,
    #[value(name = "DerivationData")]
    DerivationData = 0x42_0030,
    #[value(name = "DerivationMethod")]
    DerivationMethod = 0x42_0031,
    #[value(name = "DerivationParameters")]
    DerivationParameters = 0x42_0032,
    #[value(name = "DestroyDate")]
    DestroyDate = 0x42_0033,
    #[value(name = "Digest")]
    Digest = 0x42_0034,
    #[value(name = "DigestValue")]
    DigestValue = 0x42_0035,
    #[value(name = "EncryptionKeyInformation")]
    EncryptionKeyInformation = 0x42_0036,
    #[value(name = "G")]
    G = 0x42_0037,
    #[value(name = "HashingAlgorithm")]
    HashingAlgorithm = 0x42_0038,
    #[value(name = "InitialDate")]
    InitialDate = 0x42_0039,
    #[value(name = "InitializationVector")]
    InitializationVector = 0x42_003A,
    #[value(name = "IterationCount")]
    IterationCount = 0x42_003C,
    #[value(name = "IVCounterNonce")]
    IVCounterNonce = 0x42_003D,
    #[value(name = "J")]
    J = 0x42_003E,
    #[value(name = "Key")]
    Key = 0x42_003F,
    #[value(name = "KeyBlock")]
    KeyBlock = 0x42_0040,
    #[value(name = "KeyCompressionType")]
    KeyCompressionType = 0x42_0041,
    #[value(name = "KeyFormatType")]
    KeyFormatType = 0x42_0042,
    #[value(name = "KeyMaterial")]
    KeyMaterial = 0x42_0043,
    #[value(name = "KeyPartIdentifier")]
    KeyPartIdentifier = 0x42_0044,
    #[value(name = "KeyValue")]
    KeyValue = 0x42_0045,
    #[value(name = "KeyWrappingData")]
    KeyWrappingData = 0x42_0046,
    #[value(name = "KeyWrappingSpecification")]
    KeyWrappingSpecification = 0x42_0047,
    #[value(name = "LastChangeDate")]
    LastChangeDate = 0x42_0048,
    #[value(name = "LeaseTime")]
    LeaseTime = 0x42_0049,
    #[value(name = "Link")]
    Link = 0x42_004A,
    #[value(name = "LinkType")]
    LinkType = 0x42_004B,
    #[value(name = "LinkedObjectIdentifier")]
    LinkedObjectIdentifier = 0x42_004C,
    #[value(name = "MACSignature")]
    MACSignature = 0x42_004D,
    #[value(name = "MACSignatureKey_Information")]
    MACSignatureKey_Information = 0x42_004E,
    #[value(name = "MaximumItems")]
    MaximumItems = 0x42_004F,
    #[value(name = "MaximumResponseSize")]
    MaximumResponseSize = 0x42_0050,
    #[value(name = "MessageExtension")]
    MessageExtension = 0x42_0051,
    #[value(name = "Modulus")]
    Modulus = 0x42_0052,
    #[value(name = "Name")]
    Name = 0x42_0053,
    #[value(name = "NameType")]
    NameType = 0x42_0054,
    #[value(name = "NameValue")]
    NameValue = 0x42_0055,
    #[value(name = "ObjectGroup")]
    ObjectGroup = 0x42_0056,
    #[value(name = "ObjectType")]
    ObjectType = 0x42_0057,
    #[value(name = "Offset")]
    Offset = 0x42_0058,
    #[value(name = "OpaqueDataType")]
    OpaqueDataType = 0x42_0059,
    #[value(name = "OpaqueDataValue")]
    OpaqueDataValue = 0x42_005A,
    #[value(name = "OpaqueObject")]
    OpaqueObject = 0x42_005B,
    #[value(name = "Operation")]
    Operation = 0x42_005C,
    #[value(name = "P")]
    P = 0x42_005E,
    #[value(name = "PaddingMethod")]
    PaddingMethod = 0x42_005F,
    #[value(name = "PrimeExponentP")]
    PrimeExponentP = 0x42_0060,
    #[value(name = "PrimeExponentQ")]
    PrimeExponentQ = 0x42_0061,
    #[value(name = "PrimeFieldSize")]
    PrimeFieldSize = 0x42_0062,
    #[value(name = "PrivateExponent")]
    PrivateExponent = 0x42_0063,
    #[value(name = "PrivateKey")]
    PrivateKey = 0x42_0064,
    #[value(name = "PrivateKeyUniqueIdentifier")]
    PrivateKeyUniqueIdentifier = 0x42_0066,
    #[value(name = "ProcessStartDate")]
    ProcessStartDate = 0x42_0067,
    #[value(name = "ProtectStopDate")]
    ProtectStopDate = 0x42_0068,
    #[value(name = "ProtocolVersion")]
    ProtocolVersion = 0x42_0069,
    #[value(name = "ProtocolVersionMajor")]
    ProtocolVersionMajor = 0x42_006A,
    #[value(name = "ProtocolVersionMinor")]
    ProtocolVersionMinor = 0x42_006B,
    #[value(name = "PublicExponent")]
    PublicExponent = 0x42_006C,
    #[value(name = "PublicKey")]
    PublicKey = 0x42_006D,
    #[value(name = "PublicKeyUniqueIdentifier")]
    PublicKeyUniqueIdentifier = 0x42_006F,
    #[value(name = "PutFunction")]
    PutFunction = 0x42_0070,
    #[value(name = "Q")]
    Q = 0x42_0071,
    #[value(name = "QString")]
    QString = 0x42_0072,
    #[value(name = "Qlength")]
    Qlength = 0x42_0073,
    #[value(name = "QueryFunction")]
    QueryFunction = 0x42_0074,
    #[value(name = "RecommendedCurve")]
    RecommendedCurve = 0x42_0075,
    #[value(name = "ReplacedUniqueIdentifier")]
    ReplacedUniqueIdentifier = 0x42_0076,
    #[value(name = "RequestHeader")]
    RequestHeader = 0x42_0077,
    #[value(name = "RequestMessage")]
    RequestMessage = 0x42_0078,
    #[value(name = "RequestPayload")]
    RequestPayload = 0x42_0079,
    #[value(name = "ResponseHeader")]
    ResponseHeader = 0x42_007A,
    #[value(name = "ResponseMessage")]
    ResponseMessage = 0x42_007B,
    #[value(name = "ResponsePayload")]
    ResponsePayload = 0x42_007C,
    #[value(name = "ResultMessage")]
    ResultMessage = 0x42_007D,
    #[value(name = "ResultReason")]
    ResultReason = 0x42_007E,
    #[value(name = "ResultStatus")]
    ResultStatus = 0x42_007F,
    #[value(name = "RevocationMessage")]
    RevocationMessage = 0x42_0080,
    #[value(name = "RevocationReason")]
    RevocationReason = 0x42_0081,
    #[value(name = "RevocationReasonCode")]
    RevocationReasonCode = 0x42_0082,
    #[value(name = "KeyRoleType")]
    KeyRoleType = 0x42_0083,
    #[value(name = "Salt")]
    Salt = 0x42_0084,
    #[value(name = "SecretData")]
    SecretData = 0x42_0085,
    #[value(name = "SecretDataType")]
    SecretDataType = 0x42_0086,
    #[value(name = "ServerInformation")]
    ServerInformation = 0x42_0088,
    #[value(name = "SplitKey")]
    SplitKey = 0x42_0089,
    #[value(name = "SplitKeyMethod")]
    SplitKeyMethod = 0x42_008A,
    #[value(name = "SplitKeyParts")]
    SplitKeyParts = 0x42_008B,
    #[value(name = "SplitKeyThreshold")]
    SplitKeyThreshold = 0x42_008C,
    #[value(name = "State")]
    State = 0x42_008D,
    #[value(name = "StorageStatusMask")]
    StorageStatusMask = 0x42_008E,
    #[value(name = "SymmetricKey")]
    SymmetricKey = 0x42_008F,
    #[value(name = "TimeStamp")]
    TimeStamp = 0x42_0092,
    #[value(name = "UniqueBatchItemID")]
    UniqueBatchItemID = 0x42_0093,
    #[value(name = "UniqueIdentifier")]
    UniqueIdentifier = 0x42_0094,
    #[value(name = "UsageLimits")]
    UsageLimits = 0x42_0095,
    #[value(name = "UsageLimitsCount")]
    UsageLimitsCount = 0x42_0096,
    #[value(name = "UsageLimitsTotal")]
    UsageLimitsTotal = 0x42_0097,
    #[value(name = "UsageLimitsUnit")]
    UsageLimitsUnit = 0x42_0098,
    #[value(name = "Username")]
    Username = 0x42_0099,
    #[value(name = "ValidityDate")]
    ValidityDate = 0x42_009A,
    #[value(name = "ValidityIndicator")]
    ValidityIndicator = 0x42_009B,
    #[value(name = "VendorExtension")]
    VendorExtension = 0x42_009C,
    #[value(name = "VendorIdentification")]
    VendorIdentification = 0x42_009D,
    #[value(name = "WrappingMethod")]
    WrappingMethod = 0x42_009E,
    #[value(name = "X")]
    X = 0x42_009F,
    #[value(name = "Y")]
    Y = 0x42_00A0,
    #[value(name = "Password")]
    Password = 0x42_00A1,
    #[value(name = "DeviceIdentifier")]
    DeviceIdentifier = 0x42_00A2,
    #[value(name = "EncodingOption")]
    EncodingOption = 0x42_00A3,
    #[value(name = "ExtensionInformation")]
    ExtensionInformation = 0x42_00A4,
    #[value(name = "ExtensionName")]
    ExtensionName = 0x42_00A5,
    #[value(name = "ExtensionTag")]
    ExtensionTag = 0x42_00A6,
    #[value(name = "ExtensionType")]
    ExtensionType = 0x42_00A7,
    #[value(name = "Fresh")]
    Fresh = 0x42_00A8,
    #[value(name = "MachineIdentifier")]
    MachineIdentifier = 0x42_00A9,
    #[value(name = "MediaIdentifier")]
    MediaIdentifier = 0x42_00AA,
    #[value(name = "NetworkIdentifier")]
    NetworkIdentifier = 0x42_00AB,
    #[value(name = "ObjectGroupMember")]
    ObjectGroupMember = 0x42_00AC,
    #[value(name = "CertificateLength")]
    CertificateLength = 0x42_00AD,
    #[value(name = "DigitalSignatureAlgorithm")]
    DigitalSignatureAlgorithm = 0x42_00AE,
    #[value(name = "CertificateSerialNumber")]
    CertificateSerialNumber = 0x42_00AF,
    #[value(name = "DeviceSerialNumber")]
    DeviceSerialNumber = 0x42_00B0,
    #[value(name = "IssuerAlternativeName")]
    IssuerAlternativeName = 0x42_00B1,
    #[value(name = "IssuerDistinguishedName")]
    IssuerDistinguishedName = 0x42_00B2,
    #[value(name = "SubjectAlternativeName")]
    SubjectAlternativeName = 0x42_00B3,
    #[value(name = "SubjectDistinguishedName")]
    SubjectDistinguishedName = 0x42_00B4,
    #[value(name = "X509CertificateIdentifier")]
    X509CertificateIdentifier = 0x42_00B5,
    #[value(name = "X509CertificateIssuer")]
    X509CertificateIssuer = 0x42_00B6,
    #[value(name = "X509CertificateSubject")]
    X509CertificateSubject = 0x42_00B7,
    #[value(name = "KeyValueLocation")]
    KeyValueLocation = 0x42_00B8,
    #[value(name = "KeyValueLocationValue")]
    KeyValueLocationValue = 0x42_00B9,
    #[value(name = "KeyValueLocationType")]
    KeyValueLocationType = 0x42_00BA,
    #[value(name = "KeyValuePresent")]
    KeyValuePresent = 0x42_00BB,
    #[value(name = "OriginalCreationDate")]
    OriginalCreationDate = 0x42_00BC,
    #[value(name = "PGPKey")]
    PGPKey = 0x42_00BD,
    #[value(name = "PGPKeyVersion")]
    PGPKeyVersion = 0x42_00BE,
    #[value(name = "AlternativeName")]
    AlternativeName = 0x42_00BF,
    #[value(name = "AlternativeNameValue")]
    AlternativeNameValue = 0x42_00C0,
    #[value(name = "AlternativeNameType")]
    AlternativeNameType = 0x42_00C1,
    #[value(name = "Data")]
    Data = 0x42_00C2,
    #[value(name = "SignatureData")]
    SignatureData = 0x42_00C3,
    #[value(name = "DataLength")]
    DataLength = 0x42_00C4,
    #[value(name = "RandomIV")]
    RandomIV = 0x42_00C5,
    #[value(name = "MACData")]
    MACData = 0x42_00C6,
    #[value(name = "AttestationType")]
    AttestationType = 0x42_00C7,
    #[value(name = "Nonce")]
    Nonce = 0x42_00C8,
    #[value(name = "NonceID")]
    NonceID = 0x42_00C9,
    #[value(name = "NonceValue")]
    NonceValue = 0x42_00CA,
    #[value(name = "AttestationMeasurement")]
    AttestationMeasurement = 0x42_00CB,
    #[value(name = "AttestationAssertion")]
    AttestationAssertion = 0x42_00CC,
    #[value(name = "IVLength")]
    IVLength = 0x42_00CD,
    #[value(name = "TagLength")]
    TagLength = 0x42_00CE,
    #[value(name = "FixedFieldLength")]
    FixedFieldLength = 0x42_00CF,
    #[value(name = "CounterLength")]
    CounterLength = 0x42_00D0,
    #[value(name = "InitialCounterValue")]
    InitialCounterValue = 0x42_00D1,
    #[value(name = "InvocationFieldLength")]
    InvocationFieldLength = 0x42_00D2,
    #[value(name = "AttestationCapableIndicator")]
    AttestationCapableIndicator = 0x42_00D3,
    #[value(name = "OffsetItems")]
    OffsetItems = 0x42_00D4,
    #[value(name = "LocatedItems")]
    LocatedItems = 0x42_00D5,
    #[value(name = "CorrelationValue")]
    CorrelationValue = 0x42_00D6,
    #[value(name = "InitIndicator")]
    InitIndicator = 0x42_00D7,
    #[value(name = "FinalIndicator")]
    FinalIndicator = 0x42_00D8,
    #[value(name = "RNGParameters")]
    RNGParameters = 0x42_00D9,
    #[value(name = "RNGAlgorithm")]
    RNGAlgorithm = 0x42_00DA,
    #[value(name = "DRBGAlgorithm")]
    DRBGAlgorithm = 0x42_00DB,
    #[value(name = "FIPS186Variation")]
    FIPS186Variation = 0x42_00DC,
    #[value(name = "PredictionResistance")]
    PredictionResistance = 0x42_00DD,
    #[value(name = "RandomNumberGenerator")]
    RandomNumberGenerator = 0x42_00DE,
    #[value(name = "ValidationInformation")]
    ValidationInformation = 0x42_00DF,
    #[value(name = "ValidationAuthorityType")]
    ValidationAuthorityType = 0x42_00E0,
    #[value(name = "ValidationAuthorityCountry")]
    ValidationAuthorityCountry = 0x42_00E1,
    #[value(name = "ValidationAuthorityURI")]
    ValidationAuthorityURI = 0x42_00E2,
    #[value(name = "ValidationVersionMajor")]
    ValidationVersionMajor = 0x42_00E3,
    #[value(name = "ValidationVersionMinor")]
    ValidationVersionMinor = 0x42_00E4,
    #[value(name = "ValidationType")]
    ValidationType = 0x42_00E5,
    #[value(name = "ValidationLevel")]
    ValidationLevel = 0x42_00E6,
    #[value(name = "ValidationCertificateIdentifier")]
    ValidationCertificateIdentifier = 0x42_00E7,
    #[value(name = "ValidationCertificateURI")]
    ValidationCertificateURI = 0x42_00E8,
    #[value(name = "ValidationVendorURI")]
    ValidationVendorURI = 0x42_00E9,
    #[value(name = "ValidationProfile")]
    ValidationProfile = 0x42_00EA,
    #[value(name = "ProfileInformation")]
    ProfileInformation = 0x42_00EB,
    #[value(name = "ProfileName")]
    ProfileName = 0x42_00EC,
    #[value(name = "ServerURI")]
    ServerURI = 0x42_00ED,
    #[value(name = "ServerPort")]
    ServerPort = 0x42_00EE,
    #[value(name = "StreamingCapability")]
    StreamingCapability = 0x42_00EF,
    #[value(name = "AsynchronousCapability")]
    AsynchronousCapability = 0x42_00F0,
    #[value(name = "AttestationCapability")]
    AttestationCapability = 0x42_00F1,
    #[value(name = "UnwrapMode")]
    UnwrapMode = 0x42_00F2,
    #[value(name = "DestroyAction")]
    DestroyAction = 0x42_00F3,
    #[value(name = "ShreddingAlgorithm")]
    ShreddingAlgorithm = 0x42_00F4,
    #[value(name = "RNGMode")]
    RNGMode = 0x42_00F5,
    #[value(name = "ClientRegistrationMethod")]
    ClientRegistrationMethod = 0x42_00F6,
    #[value(name = "CapabilityInformation")]
    CapabilityInformation = 0x42_00F7,
    #[value(name = "KeyWrapType")]
    KeyWrapType = 0x42_00F8,
    #[value(name = "BatchUndoCapability")]
    BatchUndoCapability = 0x42_00F9,
    #[value(name = "BatchContinueCapability")]
    BatchContinueCapability = 0x42_00FA,
    #[value(name = "PKCS12FriendlyName")]
    PKCS12FriendlyName = 0x42_00FB,
    #[value(name = "Description")]
    Description = 0x42_00FC,
    #[value(name = "Comment")]
    Comment = 0x42_00FD,
    #[value(name = "AuthenticatedEncryptionAdditionalData")]
    AuthenticatedEncryptionAdditionalData = 0x42_00FE,
    #[value(name = "AuthenticatedEncryptionTag")]
    AuthenticatedEncryptionTag = 0x42_00FF,
    #[value(name = "SaltLength")]
    SaltLength = 0x42_0100,
    #[value(name = "MaskGenerator")]
    MaskGenerator = 0x42_0101,
    #[value(name = "MaskGeneratorHashingAlgorithm")]
    MaskGeneratorHashingAlgorithm = 0x42_0102,
    #[value(name = "PSource")]
    PSource = 0x42_0103,
    #[value(name = "TrailerField")]
    TrailerField = 0x42_0104,
    #[value(name = "ClientCorrelationValue")]
    ClientCorrelationValue = 0x42_0105,
    #[value(name = "ServerCorrelationValue")]
    ServerCorrelationValue = 0x42_0106,
    #[value(name = "DigestedData")]
    DigestedData = 0x42_0107,
    #[value(name = "CertificateSubjectCN")]
    CertificateSubjectCN = 0x42_0108,
    #[value(name = "CertificateSubjectO")]
    CertificateSubjectO = 0x42_0109,
    #[value(name = "CertificateSubjectOU")]
    CertificateSubjectOU = 0x42_010A,
    #[value(name = "CertificateSubjectEmail")]
    CertificateSubjectEmail = 0x42_010B,
    #[value(name = "CertificateSubjectC")]
    CertificateSubjectC = 0x42_010C,
    #[value(name = "CertificateSubjectST")]
    CertificateSubjectST = 0x42_010D,
    #[value(name = "CertificateSubjectL")]
    CertificateSubjectL = 0x42_010E,
    #[value(name = "CertificateSubjectUID")]
    CertificateSubjectUID = 0x42_010F,
    #[value(name = "CertificateSubjectSerialNumber")]
    CertificateSubjectSerialNumber = 0x42_0110,
    #[value(name = "CertificateSubjectTitle")]
    CertificateSubjectTitle = 0x42_0111,
    #[value(name = "CertificateSubjectDC")]
    CertificateSubjectDC = 0x42_0112,
    #[value(name = "CertificateSubjectDNQualifier")]
    CertificateSubjectDNQualifier = 0x42_0113,
    #[value(name = "CertificateIssuerCN")]
    CertificateIssuerCN = 0x42_0114,
    #[value(name = "CertificateIssuerO")]
    CertificateIssuerO = 0x42_0115,
    #[value(name = "CertificateIssuerOU")]
    CertificateIssuerOU = 0x42_0116,
    #[value(name = "CertificateIssuerEmail")]
    CertificateIssuerEmail = 0x42_0117,
    #[value(name = "CertificateIssuerC")]
    CertificateIssuerC = 0x42_0118,
    #[value(name = "CertificateIssuerST")]
    CertificateIssuerST = 0x42_0119,
    #[value(name = "CertificateIssuerL")]
    CertificateIssuerL = 0x42_011A,
    #[value(name = "CertificateIssuerUID")]
    CertificateIssuerUID = 0x42_011B,
    #[value(name = "CertificateIssuerSerialNumber")]
    CertificateIssuerSerialNumber = 0x42_011C,
    #[value(name = "CertificateIssuerTitle")]
    CertificateIssuerTitle = 0x42_011D,
    #[value(name = "CertificateIssuerDC")]
    CertificateIssuerDC = 0x42_011E,
    #[value(name = "CertificateIssuerDNQualifier")]
    CertificateIssuerDNQualifier = 0x42_011F,
    #[value(name = "Sensitive")]
    Sensitive = 0x42_0120,
    #[value(name = "AlwaysSensitive")]
    AlwaysSensitive = 0x42_0121,
    #[value(name = "Extractable")]
    Extractable = 0x42_0122,
    #[value(name = "NeverExtractable")]
    NeverExtractable = 0x42_0123,
    #[value(name = "ReplaceExisting")]
    ReplaceExisting = 0x42_0124,
    #[value(name = "Attributes")]
    Attributes = 0x42_0125,
    #[value(name = "CommonAttributes")]
    CommonAttributes = 0x42_0126,
    #[value(name = "PrivateKeyAttributes")]
    PrivateKeyAttributes = 0x42_0127,
    #[value(name = "PublicKeyAttributes")]
    PublicKeyAttributes = 0x42_0128,
    #[value(name = "ExtensionEnumeration")]
    ExtensionEnumeration = 0x42_0129,
    #[value(name = "ExtensionAttribute")]
    ExtensionAttribute = 0x42_012A,
    #[value(name = "ExtensionParentStructureTag")]
    ExtensionParentStructureTag = 0x42_012B,
    #[value(name = "ExtensionDescription")]
    ExtensionDescription = 0x42_012C,
    #[value(name = "ServerName")]
    ServerName = 0x42_012D,
    #[value(name = "ServerSerialNumber")]
    ServerSerialNumber = 0x42_012E,
    #[value(name = "ServerVersion")]
    ServerVersion = 0x42_012F,
    #[value(name = "ServerLoad")]
    ServerLoad = 0x42_0130,
    #[value(name = "ProductName")]
    ProductName = 0x42_0131,
    #[value(name = "BuildLevel")]
    BuildLevel = 0x42_0132,
    #[value(name = "BuildDate")]
    BuildDate = 0x42_0133,
    #[value(name = "ClusterInfo")]
    ClusterInfo = 0x42_0134,
    #[value(name = "AlternateFailoverEndpoints")]
    AlternateFailoverEndpoints = 0x42_0135,
    #[value(name = "ShortUniqueIdentifier")]
    ShortUniqueIdentifier = 0x42_0136,
    #[value(name = "Reserved")]
    Reserved = 0x42_0137,
    #[value(name = "Tag")]
    Tag = 0x42_0138,
    #[value(name = "CertificateRequestUniqueIdentifier")]
    CertificateRequestUniqueIdentifier = 0x42_0139,
    #[value(name = "NISTKeyType")]
    NISTKeyType = 0x42_013A,
    #[value(name = "AttributeReference")]
    AttributeReference = 0x42_013B,
    #[value(name = "CurrentAttribute")]
    CurrentAttribute = 0x42_013C,
    #[value(name = "NewAttribute")]
    NewAttribute = 0x42_013D,
    #[value(name = "CertificateRequestValue")]
    CertificateRequestValue = 0x42_0140,
    #[value(name = "LogMessage")]
    LogMessage = 0x42_0141,
    #[value(name = "ProfileVersion")]
    ProfileVersion = 0x42_0142,
    #[value(name = "ProfileVersionMajor")]
    ProfileVersionMajor = 0x42_0143,
    #[value(name = "ProfileVersionMinor")]
    ProfileVersionMinor = 0x42_0144,
    #[value(name = "ProtectionLevel")]
    ProtectionLevel = 0x42_0145,
    #[value(name = "ProtectionPeriod")]
    ProtectionPeriod = 0x42_0146,
    #[value(name = "QuantumSafe")]
    QuantumSafe = 0x42_0147,
    #[value(name = "QuantumSafeCapability")]
    QuantumSafeCapability = 0x42_0148,
    #[value(name = "Ticket")]
    Ticket = 0x42_0149,
    #[value(name = "TicketType")]
    TicketType = 0x42_014A,
    #[value(name = "TicketValue")]
    TicketValue = 0x42_014B,
    #[value(name = "RequestCount")]
    RequestCount = 0x42_014C,
    #[value(name = "Rights")]
    Rights = 0x42_014D,
    #[value(name = "Objects")]
    Objects = 0x42_014E,
    #[value(name = "Operations")]
    Operations = 0x42_014F,
    #[value(name = "Right")]
    Right = 0x42_0150,
    #[value(name = "EndpointRole")]
    EndpointRole = 0x42_0151,
    #[value(name = "DefaultsInformation")]
    DefaultsInformation = 0x42_0152,
    #[value(name = "ObjectDefaults")]
    ObjectDefaults = 0x42_0153,
    #[value(name = "Ephemeral")]
    Ephemeral = 0x42_0154,
    #[value(name = "ServerHashedPassword")]
    ServerHashedPassword = 0x42_0155,
    #[value(name = "OneTimePassword")]
    OneTimePassword = 0x42_0156,
    #[value(name = "HashedPassword")]
    HashedPassword = 0x42_0157,
    #[value(name = "AdjustmentType")]
    AdjustmentType = 0x42_0158,
    #[value(name = "PKCS11Interface")]
    PKCS11Interface = 0x42_0159,
    #[value(name = "PKCS11Function")]
    PKCS11Function = 0x42_015A,
    #[value(name = "PKCS11InputParameters")]
    PKCS11InputParameters = 0x42_015B,
    #[value(name = "PKCS11OutputParameters")]
    PKCS11OutputParameters = 0x42_015C,
    #[value(name = "PKCS11ReturnCode")]
    PKCS11ReturnCode = 0x42_015D,
    #[value(name = "ProtectionStorageMask")]
    ProtectionStorageMask = 0x42_015E,
    #[value(name = "ProtectionStorageMasks")]
    ProtectionStorageMasks = 0x42_015F,
    #[value(name = "InteropFunction")]
    InteropFunction = 0x42_0160,
    #[value(name = "InteropIdentifier")]
    InteropIdentifier = 0x42_0161,
    #[value(name = "AdjustmentValue")]
    AdjustmentValue = 0x42_0162,
    #[value(name = "CommonProtectionStorageMasks")]
    CommonProtectionStorageMasks = 0x42_0163,
    #[value(name = "PrivateProtectionStorageMasks")]
    PrivateProtectionStorageMasks = 0x42_0164,
    #[value(name = "PublicProtectionStorageMasks")]
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

#[allow(non_camel_case_types, clippy::enum_clike_unportable_variant)]
#[derive(
    ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, EnumIter, Display,
)]
pub enum BlockCipherMode {
    #[value(name = "CBC")]
    CBC = 0x0000_0001,
    #[value(name = "ECB")]
    ECB = 0x0000_0002,
    #[value(name = "PCBC")]
    PCBC = 0x0000_0003,
    #[value(name = "CFB")]
    CFB = 0x0000_0004,
    #[value(name = "OFB")]
    OFB = 0x0000_0005,
    #[value(name = "CTR")]
    CTR = 0x0000_0006,
    #[value(name = "CMAC")]
    CMAC = 0x0000_0007,
    #[value(name = "CCM")]
    CCM = 0x0000_0008,
    #[value(name = "GCM")]
    GCM = 0x0000_0009,
    #[value(name = "CBCMAC")]
    CBCMAC = 0x0000_000A,
    #[value(name = "XTS")]
    XTS = 0x0000_000B,
    #[value(name = "X9102AESKW")]
    X9102AESKW = 0x0000_000E,
    #[value(name = "X9102TDKW")]
    X9102TDKW = 0x0000_000F,
    #[value(name = "X9102AKW1")]
    X9102AKW1 = 0x0000_0010,
    #[value(name = "X9102AKW2")]
    X9102AKW2 = 0x0000_0011,
    #[value(name = "AEAD")]
    AEAD = 0x0000_0012,
    // Extensions - 8XXXXXXX
    #[value(name = "NISTKeyWrap")]
    // NISTKeyWrap refers to rfc5649
    NISTKeyWrap = 0x8000_0001,
    #[value(name = "GCMSIV")]
    // AES GCM SIV
    GCMSIV = 0x8000_0002,
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

impl TryFrom<HashingAlgorithm> for MessageDigest {
    type Error = KmipError;

    fn try_from(hashing_algorithm: HashingAlgorithm) -> Result<Self, Self::Error> {
        match hashing_algorithm {
            HashingAlgorithm::SHA1 => Ok(Self::sha1()),
            HashingAlgorithm::SHA224 => Ok(Self::sha224()),
            HashingAlgorithm::SHA256 => Ok(Self::sha256()),
            HashingAlgorithm::SHA384 => Ok(Self::sha384()),
            HashingAlgorithm::SHA512 => Ok(Self::sha512()),
            HashingAlgorithm::SHA3224 => Ok(Self::sha3_224()),
            HashingAlgorithm::SHA3256 => Ok(Self::sha3_256()),
            HashingAlgorithm::SHA3384 => Ok(Self::sha3_384()),
            HashingAlgorithm::SHA3512 => Ok(Self::sha3_512()),
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
    /// the wrapped-encoded value of the Byte String Key Material field in
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
#[derive(
    ValueEnum, Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display, EnumIter,
)]
pub enum StateEnumeration {
    /// Pre-Active: The object exists and SHALL NOT be used for any cryptographic purpose.
    #[value(name = "PreActive")]
    PreActive = 0x0000_0001,
    /// Active: The object SHALL be transitioned to the Active state prior to being used for any
    /// cryptographic purpose. The object SHALL only be used for all cryptographic purposes that
    /// are allowed by its Cryptographic Usage Mask attribute. If a Process Start Date attribute is
    /// set, then the object SHALL NOT be used for cryptographic purposes prior to the Process
    /// Start Date. If a Protect Stop attribute is set, then the object SHALL NOT be used for
    /// cryptographic purposes after the Process Stop Date.
    #[value(name = "Active")]
    Active = 0x0000_0002,
    /// Deactivated: The object SHALL NOT be used for applying cryptographic protection (e.g.,
    /// encryption, signing, wrapping, `MACing`, deriving) . The object SHALL only be used for
    /// cryptographic purposes permitted by the Cryptographic Usage Mask attribute. The object
    /// SHOULD only be used to process cryptographically-protected information (e.g., decryption,
    /// signature verification, unwrapping, MAC verification under extraordinary circumstances and
    /// when special permission is granted.
    #[value(name = "Deactivated")]
    Deactivated = 0x0000_0003,
    /// Compromised: The object SHALL NOT be used for applying cryptographic protection (e.g.,
    /// encryption, signing, wrapping, `MACing`, deriving). The object SHOULD only be used to process
    /// cryptographically-protected information (e.g., decryption, signature verification,
    /// unwrapping, MAC verification in a client that is trusted to use managed objects that have
    /// been compromised. The object SHALL only be used for cryptographic purposes permitted by the
    /// Cryptographic Usage Mask attribute.
    #[value(name = "Compromised")]
    Compromised = 0x0000_0004,
    /// Destroyed: The object SHALL NOT be used for any cryptographic purpose.
    #[value(name = "Destroyed")]
    Destroyed = 0x0000_0005,
    /// Destroyed Compromised: The object SHALL NOT be used for any cryptographic purpose; however
    /// its compromised status SHOULD be retained for audit or security purposes.
    #[value(name = "Destroyed_Compromised")]
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
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
#[serde(untagged)]
pub enum UniqueIdentifier {
    TextString(String),
    Enumeration(UniqueIdentifierEnumeration),
    Integer(i32),
}

impl Display for UniqueIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextString(s) => write!(f, "{s}"),
            Self::Enumeration(e) => write!(f, "{e}"),
            Self::Integer(i) => write!(f, "{i}"),
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
            _ => None,
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
            LinkedObjectIdentifier::Enumeration(e) => Self::Enumeration(e),
            LinkedObjectIdentifier::Index(i) => Self::Integer(i as i32),
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
        Self {
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

/// An Enumeration object indicating whether the certificate chain is valid,
/// invalid, or unknown.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq, Display)]
pub enum ValidityIndicator {
    Valid = 0x0000_0000,
    Invalid = 0x0000_0001,
    Unknown = 0x0000_0002,
}

impl ValidityIndicator {
    #[must_use]
    pub const fn and(&self, vi: Self) -> Self {
        match (self, vi) {
            (Self::Valid, Self::Valid) => Self::Valid,
            (Self::Invalid, _) | (_, Self::Invalid) => Self::Invalid,
            _ => Self::Unknown,
        }
    }

    #[must_use]
    pub const fn from_bool(b: bool) -> Self {
        if b { Self::Valid } else { Self::Invalid }
    }
}
