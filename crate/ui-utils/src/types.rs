use std::fmt::Display;

use cosmian_kmip::kmip_2_1::kmip_types::RecommendedCurve;
use strum::EnumString;

#[derive(Debug, Clone, Copy, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum Curve {
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "nist-p192")]
    NistP192,
    #[strum(to_string = "nist-p224")]
    NistP224,
    #[strum(to_string = "nist-p256")]
    NistP256,
    #[strum(to_string = "nist-p384")]
    NistP384,
    #[strum(to_string = "nist-p521")]
    NistP521,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "x25519")]
    X25519,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "ed25519")]
    Ed25519,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "x448")]
    X448,
    #[cfg(not(feature = "fips"))]
    #[strum(to_string = "ed448")]
    Ed448,
}

impl From<Curve> for RecommendedCurve {
    fn from(curve: Curve) -> Self {
        match curve {
            #[cfg(not(feature = "fips"))]
            Curve::NistP192 => Self::P192,
            Curve::NistP224 => Self::P224,
            Curve::NistP256 => Self::P256,
            Curve::NistP384 => Self::P384,
            Curve::NistP521 => Self::P521,
            #[cfg(not(feature = "fips"))]
            Curve::X25519 => Self::CURVE25519,
            #[cfg(not(feature = "fips"))]
            Curve::Ed25519 => Self::CURVEED25519,
            #[cfg(not(feature = "fips"))]
            Curve::X448 => Self::CURVE448,
            #[cfg(not(feature = "fips"))]
            Curve::Ed448 => Self::CURVEED448,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub enum ExportKeyFormat {
    JsonTtlv,
    Sec1Pem,
    Sec1Der,
    Pkcs1Pem,
    Pkcs1Der,
    Pkcs8Pem,
    Pkcs8Der,
    SpkiPem,
    SpkiDer,
    Base64,
    Raw,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "kebab-case")]
pub(crate) enum WrappingAlgorithm {
    NistKeyWrap,
    AesGCM,
    RsaPkcsV15,
    RsaOaep,
    RsaAesKeyWrap,
}

impl WrappingAlgorithm {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::NistKeyWrap => "nist-key-wrap",
            Self::AesGCM => "aes-gcm",
            Self::RsaPkcsV15 => "rsa-pkcs-v15",
            Self::RsaOaep => "rsa-oaep",
            Self::RsaAesKeyWrap => "rsa-aes-key-wrap",
        }
    }
}

impl Display for WrappingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
