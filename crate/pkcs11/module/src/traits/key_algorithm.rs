use std::str::FromStr;

use pkcs1::ObjectIdentifier;
use pkcs11_sys::{CKK_EC, CKK_RSA, CK_KEY_TYPE};

use crate::MResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa,
    EccP256,
    EccP384,
    EccP521,
    Ed25519,
    X25519,
    X448,
    Ed448,
}

impl KeyAlgorithm {
    pub fn to_ck_key_type(&self) -> CK_KEY_TYPE {
        match self {
            KeyAlgorithm::Rsa => CKK_RSA,
            KeyAlgorithm::EccP256
            | KeyAlgorithm::EccP384
            | KeyAlgorithm::EccP521
            | KeyAlgorithm::Ed448
            | KeyAlgorithm::Ed25519
            | KeyAlgorithm::X448
            | KeyAlgorithm::X25519 => CKK_EC,
        }
    }

    pub fn is_rsa(&self) -> bool {
        matches!(self, KeyAlgorithm::Rsa)
    }

    pub fn is_ecc(&self) -> bool {
        matches!(
            self,
            KeyAlgorithm::EccP256
                | KeyAlgorithm::EccP384
                | KeyAlgorithm::EccP521
                | KeyAlgorithm::Ed448
                | KeyAlgorithm::Ed25519
                | KeyAlgorithm::X448
                | KeyAlgorithm::X25519
        )
    }

    pub fn to_oid_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa => "1.2.840.113549.1.1.1",
            KeyAlgorithm::EccP256 => "1.2.840.10045.3.1.7",
            KeyAlgorithm::EccP384 => "1.3.132.0.34",
            KeyAlgorithm::EccP521 => "1.3.132.0.35",
            KeyAlgorithm::Ed25519 => "1.3.101.112",
            KeyAlgorithm::X25519 => "1.3.101.110",
            KeyAlgorithm::X448 => "1.3.101.111",
            KeyAlgorithm::Ed448 => "1.3.101.113",
        }
    }

    pub fn to_oid(&self) -> MResult<ObjectIdentifier> {
        ObjectIdentifier::from_str(self.to_oid_str()).map_err(Into::into)
    }

    pub fn from_oid_str(oid: &str) -> Option<Self> {
        match oid {
            "1.2.840.113549.1.1.1" => Some(KeyAlgorithm::Rsa),
            "1.2.840.10045.3.1.7" => Some(KeyAlgorithm::EccP256),
            "1.3.132.0.34" => Some(KeyAlgorithm::EccP384),
            "1.3.132.0.35" => Some(KeyAlgorithm::EccP521),
            "1.3.101.112" => Some(KeyAlgorithm::Ed25519),
            "1.3.101.110" => Some(KeyAlgorithm::X25519),
            "1.3.101.111" => Some(KeyAlgorithm::X448),
            "1.3.101.113" => Some(KeyAlgorithm::Ed448),
            _ => None,
        }
    }

    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Self::from_oid_str(&oid.to_string())
    }
}
