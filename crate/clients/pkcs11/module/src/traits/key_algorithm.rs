use std::str::FromStr;

use pkcs1::ObjectIdentifier;
use pkcs11_sys::{CK_KEY_TYPE, CKK_AES, CKK_EC, CKK_RSA};

use crate::ModuleResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Aes256,
    Rsa,
    EccP256,
    EccP384,
    EccP521,
    Ed25519,
    X25519,
    X448,
    Ed448,
    Secp224k1,
    Secp256k1,
}

impl KeyAlgorithm {
    #[must_use]
    pub const fn to_ck_key_type(&self) -> CK_KEY_TYPE {
        match self {
            Self::Aes256 => CKK_AES,
            Self::Rsa => CKK_RSA,
            Self::EccP256
            | Self::Secp224k1
            | Self::Secp256k1
            | Self::EccP384
            | Self::EccP521
            | Self::Ed448
            | Self::Ed25519
            | Self::X448
            | Self::X25519 => CKK_EC,
        }
    }

    #[must_use]
    pub const fn is_rsa(&self) -> bool {
        matches!(self, Self::Rsa)
    }

    #[must_use]
    pub const fn is_ecc(&self) -> bool {
        matches!(
            self,
            Self::EccP256
                | Self::EccP384
                | Self::EccP521
                | Self::Ed448
                | Self::Ed25519
                | Self::X448
                | Self::X25519
                | Self::Secp224k1
                | Self::Secp256k1
        )
    }

    #[must_use]
    pub const fn to_oid_str(&self) -> &'static str {
        match self {
            Self::Aes256 => "2.16.840.1.101.3.4.1.41",
            Self::Rsa => "1.2.840.113549.1.1.1",
            Self::EccP256 => "1.2.840.10045.3.1.7",
            Self::EccP384 => "1.3.132.0.34",
            Self::EccP521 => "1.3.132.0.35",
            Self::Ed25519 => "1.3.101.112",
            Self::X25519 => "1.3.101.110",
            Self::X448 => "1.3.101.111",
            Self::Ed448 => "1.3.101.113",
            Self::Secp224k1 => "1.3.132.0.32",
            Self::Secp256k1 => "1.3.132.0.33",
        }
    }

    pub fn to_oid(&self) -> ModuleResult<ObjectIdentifier> {
        Ok(ObjectIdentifier::from_str(self.to_oid_str())?)
    }

    #[must_use]
    pub fn from_oid_str(oid: &str) -> Option<Self> {
        match oid {
            "2.16.840.1.101.3.4.1.41" => Some(Self::Aes256),
            "1.2.840.113549.1.1.1" => Some(Self::Rsa),
            "1.2.840.10045.3.1.7" => Some(Self::EccP256),
            "1.3.132.0.34" => Some(Self::EccP384),
            "1.3.132.0.35" => Some(Self::EccP521),
            "1.3.101.112" => Some(Self::Ed25519),
            "1.3.101.110" => Some(Self::X25519),
            "1.3.101.111" => Some(Self::X448),
            "1.3.101.113" => Some(Self::Ed448),
            "1.3.132.0.32" => Some(Self::Secp224k1),
            "1.3.132.0.33" => Some(Self::Secp256k1),
            _ => None,
        }
    }

    #[must_use]
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Self::from_oid_str(&oid.to_string())
    }
}
