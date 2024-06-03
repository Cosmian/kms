use std::str::FromStr;

use pkcs1::ObjectIdentifier;
use pkcs11_sys::{CKK_EC, CKK_RSA, CK_KEY_TYPE};

use crate::MResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa1024,
    Rsa2048,
    Rsa3072,
    Rsa4096,
    EccP256,
    EccP384,
    EccP521,
    Ed25519,
    X25519,
    X448,
    Ed448,
}

impl KeyAlgorithm {
    pub fn key_len(&self) -> usize {
        match self {
            KeyAlgorithm::Rsa1024 => 1024,
            KeyAlgorithm::Rsa2048 => 2048,
            KeyAlgorithm::Rsa3072 => 3072,
            KeyAlgorithm::Rsa4096 => 4096,
            KeyAlgorithm::EccP256 => 256,
            KeyAlgorithm::EccP384 => 384,
            KeyAlgorithm::EccP521 => 521,
            KeyAlgorithm::Ed25519 => 256,
            KeyAlgorithm::X25519 => 256,
            KeyAlgorithm::X448 => 448,
            KeyAlgorithm::Ed448 => 456,
        }
    }

    pub fn to_ck_key_type(&self) -> CK_KEY_TYPE {
        match self {
            KeyAlgorithm::Rsa1024
            | KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa3072
            | KeyAlgorithm::Rsa4096 => CKK_RSA,
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
        match self {
            KeyAlgorithm::Rsa1024
            | KeyAlgorithm::Rsa2048
            | KeyAlgorithm::Rsa3072
            | KeyAlgorithm::Rsa4096 => true,
            _ => false,
        }
    }

    pub fn is_ecc(&self) -> bool {
        match self {
            KeyAlgorithm::EccP256
            | KeyAlgorithm::EccP384
            | KeyAlgorithm::EccP521
            | KeyAlgorithm::Ed448
            | KeyAlgorithm::Ed25519
            | KeyAlgorithm::X448
            | KeyAlgorithm::X25519 => true,
            _ => false,
        }
    }

    pub fn to_oid_str(&self) -> &'static str {
        match self {
            KeyAlgorithm::Rsa1024 => "1.2.840.113549.1.1.1",
            KeyAlgorithm::Rsa2048 => "1.2.840.113549.1.1.1",
            KeyAlgorithm::Rsa3072 => "1.2.840.113549.1.1.1",
            KeyAlgorithm::Rsa4096 => "1.2.840.113549.1.1.1",
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

    pub fn from_oid_str(oid: &str, key_size: Option<usize>) -> Option<Self> {
        match oid {
            "1.2.840.113549.1.1.1" => match key_size {
                Some(1024) => Some(KeyAlgorithm::Rsa1024),
                Some(2048) => Some(KeyAlgorithm::Rsa2048),
                Some(3072) => Some(KeyAlgorithm::Rsa3072),
                Some(4096) => Some(KeyAlgorithm::Rsa4096),
                _ => None,
            },
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

    pub fn from_oid(oid: &ObjectIdentifier, key_size: Option<usize>) -> Option<Self> {
        Self::from_oid_str(&oid.to_string(), key_size)
    }
}
