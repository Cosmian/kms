use cosmian_kms_crypto::openssl::oid::{asn1_object, nid_of};
use openssl::{nid::Nid, pkey::Id};
use pkcs1::ObjectIdentifier;
use pkcs11_sys::{CK_KEY_TYPE, CKK_AES, CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_RSA};

use crate::{ModuleError, ModuleResult};

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
    /// All key algorithms, to look one up by NID.
    const ALL: [Self; 11] = [
        Self::Aes256,
        Self::Rsa,
        Self::EccP256,
        Self::EccP384,
        Self::EccP521,
        Self::Ed25519,
        Self::X25519,
        Self::X448,
        Self::Ed448,
        Self::Secp224k1,
        Self::Secp256k1,
    ];

    /// Maps this key algorithm to its PKCS#11 `CKA_KEY_TYPE` value.
    ///
    /// PKCS#11 v2.40 introduced `CKK_EC_EDWARDS` and `CKK_EC_MONTGOMERY` as the
    /// dedicated key types for Edwards-curve (Ed25519/Ed448) and Montgomery-curve
    /// (X25519/X448) keys, distinct from the NIST/SECG `CKK_EC` type used by
    /// P-256/P-384/P-521/secp256k1/secp224k1. Reporting the correct, distinct type
    /// is required for PKCS#11 v3.x conformance: `CKA_KEY_TYPE`-aware clients (e.g.
    /// `OpenSC`'s `pkcs11-tool --mechanism EDDSA`) search for `CKK_EC_EDWARDS`
    /// specifically and will not find Ed25519/Ed448 keys reported as `CKK_EC`.
    #[must_use]
    pub const fn to_ck_key_type(&self) -> CK_KEY_TYPE {
        match self {
            Self::Aes256 => CKK_AES,
            Self::Rsa => CKK_RSA,
            Self::EccP256 | Self::Secp224k1 | Self::Secp256k1 | Self::EccP384 | Self::EccP521 => {
                CKK_EC
            }
            Self::Ed25519 | Self::Ed448 => CKK_EC_EDWARDS,
            Self::X25519 | Self::X448 => CKK_EC_MONTGOMERY,
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

    /// The `OpenSSL` NID of the OID that identifies this key algorithm: the algorithm OID
    /// for AES, RSA and the Edwards/Montgomery curves, the curve OID for the other EC keys.
    #[must_use]
    pub fn nid(&self) -> Nid {
        match self {
            Self::Aes256 => Nid::AES_256_ECB,
            Self::Rsa => Nid::RSAENCRYPTION,
            Self::EccP256 => Nid::X9_62_PRIME256V1,
            Self::EccP384 => Nid::SECP384R1,
            Self::EccP521 => Nid::SECP521R1,
            // rust-openssl has no `Nid` constant for these: `EVP_PKEY_<alg>` is defined as
            // `NID_<alg>` in OpenSSL's `evp.h`.
            Self::Ed25519 => Nid::from_raw(Id::ED25519.as_raw()),
            Self::X25519 => Nid::from_raw(Id::X25519.as_raw()),
            Self::X448 => Nid::from_raw(Id::X448.as_raw()),
            Self::Ed448 => Nid::from_raw(Id::ED448.as_raw()),
            Self::Secp224k1 => Nid::SECP224K1,
            Self::Secp256k1 => Nid::SECP256K1,
        }
    }

    pub fn to_oid(&self) -> ModuleResult<ObjectIdentifier> {
        let object =
            asn1_object(self.nid()).map_err(|e| ModuleError::Cryptography(e.to_string()))?;
        Ok(ObjectIdentifier::from_bytes(object.as_slice())?)
    }

    #[must_use]
    pub fn from_oid_str(oid: &str) -> Option<Self> {
        let nid = nid_of(oid);
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.nid() == nid)
    }

    #[must_use]
    pub fn from_oid(oid: &ObjectIdentifier) -> Option<Self> {
        Self::from_oid_str(&oid.to_string())
    }

    /// `true` for `id-ecPublicKey`, the SPKI algorithm of EC keys, whose curve OID is carried
    /// in the SPKI parameters.
    #[must_use]
    pub fn is_ec_public_key_oid(oid: &ObjectIdentifier) -> bool {
        nid_of(&oid.to_string()) == Nid::X9_62_ID_ECPUBLICKEY
    }
}
