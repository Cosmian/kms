// A still incomplete list of the KMIP types:
// see https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html

// see CryptographicUsageMask
#![allow(non_upper_case_globals)]
use std::{
    fmt,
    fmt::{Display, Formatter},
};

use kmip_derive::{KmipEnumDeserialize, KmipEnumSerialize, kmip_enum};
use num_bigint_dig::BigInt;
use serde::{
    Deserialize, Serialize,
    de::{self, Visitor},
};
use strum::Display;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    error::KmipError,
    kmip_0::kmip_types::{
        BlockCipherMode, DRBGAlgorithm, FIPS186Variation, HashingAlgorithm, KeyRoleType,
        MaskGenerator, PaddingMethod, RNGAlgorithm,
    },
    kmip_2_1::extra::{VENDOR_ID_COSMIAN, tagging::VENDOR_ATTR_TAG},
};

pub const VENDOR_ATTR_AAD: &str = "aad";

#[kmip_enum]
pub enum CertificateRequestType {
    CRMF = 0x01,
    PKCS10 = 0x02,
    PEM = 0x03,
}

#[kmip_enum]
pub enum OpaqueDataType {
    Unknown = 0x8000_0001,
    /// Vendor-specific opaque data type used in interoperability test vectors
    Vendor = 0x8012_3456,
}

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
#[kmip_enum]
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
    /// This mode is to support legacy, but common, PKCS#12 formats that use
    /// `PBE_WITHSHA1AND40BITRC2_CBC` for the encryption algorithm of certificate,
    /// `PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC` for the encryption algorithm of the key
    /// and SHA-1 for the `MAC`.
    /// This is not a standard PKCS#12 format but is used by some software
    /// such as Java `KeyStores`, Mac OS X Keychains, and some versions of OpenSSL (1x).
    /// Use PKCS12 instead for standard (newer) PKCS#12 format.
    #[cfg(feature = "non-fips")]
    Pkcs12Legacy = 0x8880_0001,
    PKCS7 = 0x8880_0002,
    ConfigurableKEM = 0x8880_0003,
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

#[kmip_enum]
pub enum CryptographicAlgorithm {
    DES = 0x0000_0001,
    THREE_DES = 0x0000_0002,
    AES = 0x0000_0003,
    /// This is `CKM_RSA_PKCS_OAEP` from PKCS#11
    /// see <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226895
    /// To use  `CKM_RSA_AES_KEY_WRAP` from PKCS#11, use and RSA key with AES as the algorithm
    /// See <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html>#_Toc408226908
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
    MLKEM_512 = 0x0000_0039,
    MLKEM_768 = 0x0000_003A,
    MLKEM_1024 = 0x0000_003B,
    // Available slot 0x8880_0001,
    // Available slot 0x8880_0002,
    ConfigurableKEM = 0x8880_0003,
    CoverCrypt = 0x8880_0004,
    CoverCryptBulk = 0x8880_0005,
}

/// The Cryptographic Domain Parameters attribute (4.14) is a structure that
/// contains fields that MAY need to be specified in the Create Key Pair Request
/// Payload. Specific fields MAY only pertain to certain types of Managed
/// Cryptographic Objects. The domain parameter `q_length` corresponds to the bit
/// length of parameter Q (refer to RFC7778, SEC2 and SP800-56A).
///
/// - `q_length` applies to algorithms such as DSA and DH. The bit length of
///   parameter P (refer to RFC7778, SEC2 and SP800-56A) is specified separately
///   by setting the Cryptographic Length attribute.
///
/// - Recommended Curve is applicable to elliptic curve algorithms such as
///   ECDSA, ECDH, and ECMQV
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct CryptographicDomainParameters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qlength: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_curve: Option<RecommendedCurve>,
}

impl Default for CryptographicDomainParameters {
    fn default() -> Self {
        Self {
            qlength: Some(256),
            recommended_curve: Some(RecommendedCurve::default()),
        }
    }
}

impl Display for CryptographicDomainParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(qlen) = &self.qlength {
            writeln!(f, "    Q Length: {qlen}")?;
        }
        if let Some(curve) = &self.recommended_curve {
            writeln!(f, "    Recommended Curve: {curve}")?;
        }
        Ok(())
    }
}

#[kmip_enum]
pub enum DerivationMethod {
    PBKDF2 = 0x0000_0001,
    HASH = 0x0000_0002,
    HMAC = 0x0000_0003,
    ENCRYPT = 0x0000_0004,
    NIST800_108C = 0x0000_0005,
    NIST800_108F = 0x0000_0006,
    NIST800_108DPI = 0x0000_0007,
    Asymmetric_Key = 0x0000_0008,
    AWS_Signature_Version_4 = 0x0000_0009,
    HKDF = 0x0000_000A,
    // Extensions items available at values 8XXX_XXXX.
}

#[kmip_enum]
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
    BRAINPOOLP384R1 = 0x0000_0041,
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
    /// Defaulting to highest security FIPS compliant curve.
    #[cfg(not(feature = "non-fips"))]
    fn default() -> Self {
        Self::P521
    }

    #[cfg(feature = "non-fips")]
    fn default() -> Self {
        Self::CURVE25519
    }
}

#[kmip_enum]
pub enum KeyCompressionType {
    ECPublicKeyTypeUncompressed = 0x0000_0001,
    ECPublicKeyTypeX962CompressedPrime = 0x0000_0002,
    ECPublicKeyTypeX962CompressedChar2 = 0x0000_0003,
    ECPublicKeyTypeX962Hybrid = 0x0000_0004,
    // Extensions 8XXXXXXX
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

impl Display for ProtectionStorageMasks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<&str> = Vec::new();
        if self.contains(Self::Software) {
            parts.push("Software");
        }
        if self.contains(Self::Hardware) {
            parts.push("Hardware");
        }
        if self.contains(Self::OnProcessor) {
            parts.push("On Processor");
        }
        if self.contains(Self::OnSystem) {
            parts.push("On System");
        }
        if self.contains(Self::OffSystem) {
            parts.push("Off System");
        }
        if self.contains(Self::Hypervisor) {
            parts.push("Hypervisor");
        }
        if self.contains(Self::OperatingSystem) {
            parts.push("Operating System");
        }
        if self.contains(Self::Container) {
            parts.push("Container");
        }
        if self.contains(Self::OnPremises) {
            parts.push("On Premises");
        }
        if self.contains(Self::OffPremises) {
            parts.push("Off Premises");
        }
        if self.contains(Self::SelfManaged) {
            parts.push("Self Managed");
        }
        if self.contains(Self::Outsourced) {
            parts.push("Outsourced");
        }
        if self.contains(Self::Validated) {
            parts.push("Validated");
        }
        if self.contains(Self::SameJurisdiction) {
            parts.push("Same Jurisdiction");
        }
        write!(f, "{}", parts.join(" | "))
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

        impl Visitor<'_> for ProtectionStorageMasksVisitor {
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

#[kmip_enum]
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

impl Display for StorageStatusMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts: Vec<&str> = Vec::new();
        if self.contains(Self::OnlineStorage) {
            parts.push("Online Storage");
        }
        if self.contains(Self::ArchivalStorage) {
            parts.push("Archival Storage");
        }
        if self.contains(Self::DestroyedStorage) {
            parts.push("Destroyed Storage");
        }
        write!(f, "{}", parts.join(" | "))
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

        impl Visitor<'_> for StorageStatusMaskVisitor {
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

#[kmip_enum]
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
    // Extensions 8XXXXXXX
}

/// The following values may be specified in an operation request for a Unique
/// Identifier: If multiple unique identifiers would be referenced then the
/// operation is repeated for each of them. If an operation appears
/// multiple times in a request, it is the most recent that is referred to.
#[kmip_enum]
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
    // Extensions 8XXXXXXX
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Link {
    pub link_type: LinkType,
    pub linked_object_identifier: LinkedObjectIdentifier,
}

impl Display for Link {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Link {{ link_type: {}, linked_object_identifier: {} }}",
            self.link_type, self.linked_object_identifier
        )
    }
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct VendorAttribute {
    /// Text String (with usage limited to alphanumeric, underscore and period –
    /// i.e. [A-Za-z0-9_.])
    pub vendor_identification: String,
    pub attribute_name: String,
    pub attribute_value: VendorAttributeValue,
}

impl Display for VendorAttribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VendorAttribute {{ vendor_identification: {}, attribute_name: {}, attribute_value: \
             {} }}",
            self.vendor_identification, self.attribute_name, self.attribute_value
        )
    }
}

/// The value of a Vendor Attribute
/// Any data type or structure.
/// If a structure, only TTLV is supported.
///
/// The reason to use adjacently tagged enum is to allow for JSON serialization
/// without losing the type information for `ByteString`, `DateTime` and `BigInteger`
/// which all serialize to arrays in JSON, making deserialization impossible without
/// type indication.
/// The same is true for `Integer` and `LongInteger` which serialize to numbers in JSON.
///
/// The serialization and deserialization to TTLV of this adjacently tagged enum
/// involves special treatment in the KMIP serializer and deserializer.
/// In particular, the name of the variants must match the `TTLValue` variant names EXACTLY.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(tag = "_t", content = "_c")]
pub enum VendorAttributeValue {
    TextString(String),
    Integer(i32),
    LongInteger(i64),
    BigInteger(BigInt),
    ByteString(Vec<u8>),
    Boolean(bool),
    DateTime(OffsetDateTime),
    Interval(u32),
    DateTimeExtended(i128),
    // no support for structure which is complex and does not bring much
}

impl Display for VendorAttributeValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextString(s) => write!(f, "{s}"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::LongInteger(i) => write!(f, "{i}"),
            Self::BigInteger(i) => write!(f, "{i}"),
            Self::ByteString(b) => write!(f, "{}", hex::encode(b)),
            Self::Boolean(b) => write!(f, "{b}"),
            Self::DateTime(dt) => write!(f, "{dt}"),
            Self::Interval(i) => write!(f, "{i}"),
            Self::DateTimeExtended(dt) => write!(f, "{dt}"),
        }
    }
}

/// The Certificate Attributes are the various items included in a certificate. The following list is based on RFC2253.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Default, Debug)]
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

impl Display for CertificateAttributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CertificateAttributes {{ CN: {}, O: {}, OU: {}, Email: {}, C: {}, ST: {}, L: {}, \
             UID: {}, Serial Number: {}, Title: {}, DC: {}, DN Qualifier: {} }}",
            self.certificate_subject_cn,
            self.certificate_subject_o,
            self.certificate_subject_ou,
            self.certificate_subject_email,
            self.certificate_subject_c,
            self.certificate_subject_st,
            self.certificate_subject_l,
            self.certificate_subject_uid,
            self.certificate_subject_serial_number,
            self.certificate_subject_title,
            self.certificate_subject_dc,
            self.certificate_subject_dn_qualifier
        )
    }
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
                    )));
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

impl Display for AttributeReference {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vendor(v) => write!(
                f,
                "VendorAttributeReference {{ vendor_identification: {}, attribute_name: {} }}",
                v.vendor_identification, v.attribute_name
            ),
            Self::Standard(t) => write!(f, "Tag::{t}"),
        }
    }
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
#[kmip_enum]
#[derive(Default)]
pub enum WrappingMethod {
    #[default]
    Encrypt = 0x0000_0001,
    MACSign = 0x0000_0002,
    EncryptThenMACSign = 0x0000_0003,
    MACSignThenEncrypt = 0x0000_0004,
    TR31 = 0x0000_0005,
}

#[kmip_enum]
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Default, Debug)]
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
    pub iv_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_field_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_field_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counter_length: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_counter_value: Option<i32>,
    /// if omitted, defaults to the block size of the Mask Generator Hashing
    /// Algorithm Cosmian extension: In AES: used as the number of
    /// additional data at the end of the submitted data that become part of
    /// the MAC calculation. These additional data are removed
    /// from the encrypted data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt_length: Option<i32>,
    /// if omitted defaults to MGF1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator: Option<MaskGenerator>,
    /// if omitted defaults to SHA-1
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mask_generator_hashing_algorithm: Option<HashingAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p_source: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailer_field: Option<i32>,
}

impl Display for CryptographicParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        if let Some(v) = &self.block_cipher_mode {
            parts.push(format!("BlockCipherMode: {v}"));
        }
        if let Some(v) = &self.padding_method {
            parts.push(format!("PaddingMethod: {v}"));
        }
        if let Some(v) = &self.hashing_algorithm {
            parts.push(format!("HashingAlgorithm: {v}"));
        }
        if let Some(v) = &self.key_role_type {
            parts.push(format!("KeyRoleType: {v}"));
        }
        if let Some(v) = &self.digital_signature_algorithm {
            parts.push(format!("DigitalSignatureAlgorithm: {v}"));
        }
        if let Some(v) = &self.cryptographic_algorithm {
            parts.push(format!("CryptographicAlgorithm: {v}"));
        }
        if let Some(v) = &self.random_iv {
            parts.push(format!("RandomIV: {v}"));
        }
        if let Some(v) = &self.iv_length {
            parts.push(format!("IVLength: {v}"));
        }
        if let Some(v) = &self.tag_length {
            parts.push(format!("TagLength: {v}"));
        }
        if let Some(v) = &self.fixed_field_length {
            parts.push(format!("FixedFieldLength: {v}"));
        }
        if let Some(v) = &self.invocation_field_length {
            parts.push(format!("InvocationFieldLength: {v}"));
        }
        if let Some(v) = &self.counter_length {
            parts.push(format!("CounterLength: {v}"));
        }
        if let Some(v) = &self.initial_counter_value {
            parts.push(format!("InitialCounterValue: {v}"));
        }
        if let Some(v) = &self.salt_length {
            parts.push(format!("SaltLength: {v}"));
        }
        if let Some(v) = &self.mask_generator {
            parts.push(format!("MaskGenerator: {v}"));
        }
        if let Some(v) = &self.mask_generator_hashing_algorithm {
            parts.push(format!("MaskGeneratorHashingAlgorithm: {v}"));
        }
        if let Some(p_source) = &self.p_source {
            parts.push(format!("PSource: {}", hex::encode(p_source)));
        }
        if let Some(v) = &self.trailer_field {
            parts.push(format!("TrailerField: {v}"));
        }
        write!(f, "CryptographicParameters({})", parts.join(", "))
    }
}

/// Contains the Unique Identifier value of the encryption key and
/// associated cryptographic parameters.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct EncryptionKeyInformation {
    pub unique_identifier: UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

impl Display for EncryptionKeyInformation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptionKeyInformation(id: {}, params: {})",
            self.unique_identifier,
            self.cryptographic_parameters
                .as_ref()
                .map_or_else(|| "None".to_owned(), std::string::ToString::to_string)
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct MacSignatureKeyInformation {
    pub unique_identifier: UniqueIdentifier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_parameters: Option<CryptographicParameters>,
}

impl Display for MacSignatureKeyInformation {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MacSignatureKeyInformation(id: {}, params: {})",
            self.unique_identifier,
            self.cryptographic_parameters
                .as_ref()
                .map_or_else(|| "None".to_owned(), std::string::ToString::to_string)
        )
    }
}

#[kmip_enum]
pub enum EncodingOption {
    /// the wrapped-encoded value of the Byte String Key Material field in
    /// the Key Value structure
    NoEncoding = 0x0000_0001,
    /// the wrapped TTLV-encoded Key Value structure
    TTLVEncoding = 0x0000_0002,
}

/// The Digest attribute is a structure that contains the digest value of the key or secret data
/// (i.e., digest of the Key Material), certificate (i.e., digest of the Certificate Value),
/// or opaque object (i.e., digest of the Opaque Data Value).
/// If the Key Material is a Byte String, then the Digest Value SHALL be calculated
/// on this Byte String.
/// If the Key Material is a structure, then the Digest Value SHALL be calculated
/// on the TTLV-encoded Key Material structure.
/// The Key Format Type field in the Digest attribute indicates the format of the Managed Object
/// from which the Digest Value was calculated. Multiple digests MAY be calculated
/// using different algorithms and/or key format types.
/// If this attribute exists, then it SHALL have a mandatory attribute instance computed
/// with the SHA-256 hashing algorithm and the default Key Value Format for this object type and algorithm.
/// Clients may request via supplying a non-default Key Format Value attribute on operations
/// that create a Managed Object, and the server SHALL produce an additional Digest attribute
/// for that Key Value Type.
/// The digest(s) are static and SHALL be set by the server when the object is created or registered,
/// provided that the server has access to the Key Material
/// or the Digest Value (possibly obtained via out-of-band mechanisms).
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Digest {
    pub hashing_algorithm: HashingAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_value: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_format_type: Option<KeyFormatType>,
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest(algorithm: {}, value: {:?}, format: {:?})",
            self.hashing_algorithm,
            self.digest_value.as_deref().map(hex::encode),
            self.key_format_type
        )
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
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Hash, Debug)]
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

impl From<&str> for UniqueIdentifier {
    fn from(value: &str) -> Self {
        Self::TextString(value.to_owned())
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

impl TryFrom<LinkedObjectIdentifier> for UniqueIdentifier {
    type Error = KmipError;

    fn try_from(value: LinkedObjectIdentifier) -> Result<Self, Self::Error> {
        Ok(match value {
            LinkedObjectIdentifier::TextString(s) => Self::TextString(s),
            LinkedObjectIdentifier::Enumeration(e) => Self::Enumeration(e),
            LinkedObjectIdentifier::Index(i) => {
                let v = i32::try_from(i).map_err(|_e| {
                    KmipError::Default("linked object index out of i32 range".into())
                })?;
                Self::Integer(v)
            }
        })
    }
}

#[kmip_enum]
pub enum OperationEnumeration {
    Create = 0x0000_0001,
    CreateKeyPair = 0x0000_0002,
    Register = 0x0000_0003,
    ReKey = 0x0000_0004,
    DeriveKey = 0x0000_0005,
    Certify = 0x0000_0006,
    ReCertify = 0x0000_0007,
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
    ReKeyKeyPair = 0x0000_001D,
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

/// An Enumeration object indicating whether the certificate chain is valid,
/// invalid, or unknown.
#[kmip_enum]
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

/// `NistKeyType` enumeration used with NIST SP 800-56 and SP 800-108 operations
#[kmip_enum]
pub enum NistKeyType {
    AESP1 = 0x1,
    AESP2 = 0x2,
    AESP3 = 0x3,
    AESP4 = 0x4,
    AESP5 = 0x5,
    TDES2 = 0x6,
    TDES3 = 0x7,
    DESRW128 = 0x8,
    DESRW192 = 0x9,
    DESRW256 = 0xA,
    HMACSHA1 = 0xB,
    HMACSHA224 = 0xC,
    HMACSHA256 = 0xD,
    HMACSHA384 = 0xE,
    HMACSHA512 = 0xF,
}

/// `ProtectionLevel` enumeration indicates the level of protection required for an object (KMIP 2.1 Profiles test vectors use Low/High)
#[kmip_enum]
pub enum ProtectionLevel {
    High = 0x1,
    Low = 0x2,
}

/// `RandomNumberGenerator` structure contains details of the random number generation
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct RandomNumberGenerator {
    // Ensure KMIP-compliant field name RNGAlgorithm instead of the default RngAlgorithm
    // produced by rename_all = "PascalCase" so that tag mapping remains consistent and
    // avoids Unknown Tag errors when round-tripping through XML/TTLV.
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

impl Display for RandomNumberGenerator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<String> = Vec::new();
        parts.push(format!("RNGAlgorithm: {}", self.rng_algorithm));
        if let Some(v) = &self.cryptographic_algorithm {
            parts.push(format!("CryptographicAlgorithm: {v}"));
        }
        if let Some(v) = &self.cryptographic_length {
            parts.push(format!("CryptographicLength: {v}"));
        }
        if let Some(v) = &self.hashing_algorithm {
            parts.push(format!("HashingAlgorithm: {v}"));
        }
        if let Some(v) = &self.drbg_algorithm {
            parts.push(format!("DRBGAlgorithm: {v}"));
        }
        if let Some(v) = &self.recommended_curve {
            parts.push(format!("RecommendedCurve: {v}"));
        }
        if let Some(v) = &self.fips186_variation {
            parts.push(format!("FIPS186Variation: {v}"));
        }
        if let Some(v) = &self.prediction_resistance {
            parts.push(format!("PredictionResistance: {v}"));
        }
        write!(f, "RandomNumberGenerator({})", parts.join(", "))
    }
}

/// Name structure for identifying Managed Objects
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Name {
    /// The Name Value
    pub name_value: String,
    /// The Name Type
    pub name_type: NameType,
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Name(value: {}, type: {})",
            self.name_value, self.name_type
        )
    }
}

/// `NameType` enumeration defines the type of name used to identify managed objects
#[kmip_enum]
pub enum NameType {
    UninterpretedTextString = 0x1,
    URI = 0x2,
}

/// The `QueryFunction` is used to indicate what server information is being requested.
#[kmip_enum]
pub enum QueryFunction {
    QueryOperations = 0x000_0001,
    QueryObjects = 0x000_0002,
    QueryServerInformation = 0x000_0003,
    QueryApplicationNamespaces = 0x000_0004,
    QueryExtensionList = 0x000_0005,
    QueryExtensionMap = 0x000_0006,
    QueryAttestationTypes = 0x000_0007,
    QueryRNGs = 0x000_0008,
    QueryValidations = 0x000_0009,
    QueryProfiles = 0x000_000A,
    QueryCapabilities = 0x000_000B,
    QueryClientRegistrationMethods = 0x000_000C,
    QueryDefaultsInformation = 0x000_000D,
    QueryStorageProtectionMasks = 0x000_000E,
}

/// Random Number Generation Mode enumeration
#[kmip_enum]
pub enum RNGMode {
    Unspecified = 0x01,
    SharedInstantiation = 0x02,
    NonSharedInstantiation = 0x03,
}

/// Methods by which clients can register with a KMIP server.
#[kmip_enum]
pub enum ClientRegistrationMethod {
    /// The client is not required to register.
    Unspecified = 0x0000_0001,
    /// The client must register using server-defined method.
    ServerPreRegistered = 0x0000_0002,
    /// The client registers by providing a password to the server.
    ServerPreregisteredPadding = 0x0000_0003,
    /// The server accepts clients with specific platform configurations.
    ServerTrustedPlatformModule = 0x0000_0004,
    /// The server validates the client based on attestation data.
    ServerClientAttestation = 0x0000_0005,
    /// Server-specific registration method.
    ServerCustom = 0x0000_0006,
}

/// Supported profile identifiers in the KMIP specification.
#[kmip_enum]
pub enum ProfileName {
    CompleteServerBasic = 0x0000_0104,
    CompleteServerTLSv12 = 0x0000_0105,
    TapeLibraryClient = 0x0000_0106,
    TapeLibraryServer = 0x0000_0107,
    SymmetricKeyLifecycleClient = 0x0000_0108,
    SymmetricKeyLifecycleServer = 0x0000_0109,
    AsymmetricKeyLifecycleClient = 0x0000_010A,
    AsymmetricKeyLifecycleServer = 0x0000_010B,
    BasicCryptographicClient = 0x0000_010C,
    BasicCryptographicServer = 0x0000_010D,
    AdvancedCryptographicClient = 0x0000_010E,
    AdvancedCryptographicServer = 0x0000_010F,
    RNGCryptographicClient = 0x0000_0110,
    RNGCryptographicServer = 0x0000_0111,
    BasicSymmetricKeyFoundryClient = 0x0000_0112,
    IntermediateSymmetricKeyFoundryClient = 0x0000_0113,
    AdvancedSymmetricKeyFoundryClient = 0x0000_0114,
    SymmetricKeyFoundryServer = 0x0000_0115,
    OpaqueMangedObjectStoreClient = 0x0000_0116,
    OpaqueMangedObjectStoreServer = 0x0000_0117,
    Reserved118 = 0x0000_0118,
    Reserved119 = 0x0000_0119,
    Reserved11A = 0x0000_011A,
    Reserved11B = 0x0000_011B,
    StorageArrayWithSelfEncryptingDriveClient = 0x0000_011C,
    StorageArrayWithSelfEncryptingDriveServer = 0x0000_011D,
    HTTPSClient = 0x0000_011E,
    HTTPSServer = 0x0000_011F,
    JSONClient = 0x0000_0120,
    JSONServer = 0x0000_0121,
    XMLClient = 0x0000_0122,
    XMLServer = 0x0000_0123,
    AESXTSClient = 0x0000_0124,
    AESXTSServer = 0x0000_0125,
    QuantumSafeClient = 0x0000_0126,
    QuantumSafeServer = 0x0000_0127,
    PKCS11Client = 0x0000_0128,
    PKCS11Server = 0x0000_0129,
    BaselineClient = 0x0000_012A,
    BaselineServer = 0x0000_012B,
    CompleteServer = 0x0000_012C,
}

/// Types of items that can be used in TTLV encoding.
#[kmip_enum]
pub enum ItemType {
    Structure = 0x0000_0001,
    Integer = 0x0000_0002,
    LongInteger = 0x0000_0003,
    BigInteger = 0x0000_0004,
    Enumeration = 0x0000_0005,
    Boolean = 0x0000_0006,
    TextString = 0x0000_0007,
    ByteString = 0x0000_0008,
    DateTime = 0x0000_0009,
    Interval = 0x0000_000A,
    DateTimeExtended = 0x0000_000B,
}

impl TryFrom<ItemType> for i32 {
    type Error = KmipError;

    fn try_from(value: ItemType) -> Result<Self, Self::Error> {
        #[expect(clippy::as_conversions)]
        // This conversion is idiomatic for items marked with #[repr(u32)]
        Self::try_from(value as u32).map_err(|e| {
            KmipError::ConversionError(format!("Failed to convert ItemType to i32: {e}"))
        })
    }
}

/// Batch Error Continuation Option enumeration (KMIP 2.x) - aligns with KMIP 1.x values.
#[kmip_enum]
pub enum BatchErrorContinuationOption {
    Continue = 0x01,
    Stop = 0x02,
    Undo = 0x03,
}

// --------------------------
// Usage Limits (KMIP 2.1)
// --------------------------

/// `UsageLimitsUnit` for KMIP 2.x extends the 1.x set with Block and Operation.
/// Spec text (2.1) indicates units can be Byte, Block, Object, Operation.
#[kmip_enum]
pub enum UsageLimitsUnit {
    Byte = 0x1,
    Block = 0x2,
    Object = 0x3,
    Operation = 0x4,
}

/// KMIP 2.1 `UsageLimits` structure. Count MAY be omitted in requests (e.g. Locate test vectors
/// provide only Total + Unit). Total is kept mandatory to preserve semantics (adjust if future
/// vectors show it can be absent too).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct UsageLimits {
    pub usage_limits_unit: UsageLimitsUnit,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_limits_count: Option<i64>,
    pub usage_limits_total: i64,
}

impl Display for UsageLimits {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UsageLimits(unit: {}, count: {:?}, total: {})",
            self.usage_limits_unit, self.usage_limits_count, self.usage_limits_total
        )
    }
}

// Conversions with KMIP 1.x structure (which requires count & only supports Byte/Object units)
impl From<crate::kmip_0::kmip_types::UsageLimits> for UsageLimits {
    fn from(v: crate::kmip_0::kmip_types::UsageLimits) -> Self {
        // Map 1.x units (Byte=0x1, Object=0x2) to 2.x (Byte=0x1, Object=0x3)
        let unit = match v.usage_limits_unit {
            crate::kmip_0::kmip_types::UsageLimitsUnit::Byte => UsageLimitsUnit::Byte,
            crate::kmip_0::kmip_types::UsageLimitsUnit::Object => UsageLimitsUnit::Object,
        };
        Self {
            usage_limits_unit: unit,
            usage_limits_count: v.usage_limits_count,
            usage_limits_total: v.usage_limits_total,
        }
    }
}

impl From<UsageLimits> for crate::kmip_0::kmip_types::UsageLimits {
    fn from(v: UsageLimits) -> Self {
        // Collapse unsupported units for 1.x to Object when not Byte/Object
        let unit = match v.usage_limits_unit {
            UsageLimitsUnit::Byte => crate::kmip_0::kmip_types::UsageLimitsUnit::Byte,
            UsageLimitsUnit::Object => crate::kmip_0::kmip_types::UsageLimitsUnit::Object,
            UsageLimitsUnit::Block | UsageLimitsUnit::Operation => {
                crate::kmip_0::kmip_types::UsageLimitsUnit::Object
            }
        };
        Self {
            usage_limits_unit: unit,
            usage_limits_count: v.usage_limits_count,
            usage_limits_total: v.usage_limits_total,
        }
    }
}
