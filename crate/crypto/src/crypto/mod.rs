use cosmian_kmip::kmip_2_1::{
    extra::VENDOR_ID_COSMIAN,
    kmip_attributes::Attributes,
    kmip_objects::Object,
    kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse},
    kmip_types::VendorAttributeValue,
};
pub use elliptic_curves::CURVE_25519_Q_LENGTH_BITS;
pub use password_derivation::FIPS_MIN_SALT_SIZE;

use crate::error::CryptoError;

pub mod certificates;
#[cfg(feature = "non-fips")]
pub mod cover_crypt;
pub mod dh_shared_keys;
pub mod elliptic_curves;
#[cfg(feature = "non-fips")]
pub mod kem;
pub mod password_derivation;
pub mod rsa;
pub mod secret;
pub mod symmetric;
pub mod wrap;

pub trait EncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, CryptoError>;
}

impl<T: EncryptionSystem + ?Sized> EncryptionSystem for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, CryptoError> {
        (**self).encrypt(request)
    }
}

pub trait DecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, CryptoError>;
}

/// A `KeyPair` is a tuple `(Object::PrivateKey, Object::PublicKey)`
///
/// Note: this object does not exist in the KMIP specs,
/// hence its definition here
pub struct KeyPair(pub (Object, Object));

impl KeyPair {
    /// Create a new `KeyPair` from a private and public key
    #[must_use]
    pub const fn new(private_key: Object, public_key: Object) -> Self {
        Self((private_key, public_key))
    }

    /// Get the private key
    #[must_use]
    pub const fn private_key(&self) -> &Object {
        &self.0.0
    }

    /// Get the public key
    #[must_use]
    pub const fn public_key(&self) -> &Object {
        &self.0.1
    }

    /// Get the private key
    pub const fn private_key_mut(&mut self) -> &mut Object {
        &mut self.0.0
    }

    /// Get the public key
    pub const fn public_key_mut(&mut self) -> &mut Object {
        &mut self.0.1
    }
}

pub const VENDOR_ATTR_COVER_CRYPT_ATTR: &str = "cover_crypt_attributes";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_STRUCTURE: &str = "cover_crypt_access_structure";
pub const VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY: &str = "cover_crypt_access_policy";
pub const VENDOR_ATTR_COVER_CRYPT_REKEY_ACTION: &str = "cover_crypt_rekey_action";

/// Extract an `Covercrypt` Access policy from attributes
pub fn access_policy_from_attributes(attributes: &Attributes) -> Result<String, CryptoError> {
    attributes
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, VENDOR_ATTR_COVER_CRYPT_ACCESS_POLICY)
        .map_or_else(
            || {
                Err(CryptoError::Kmip(
                    "the attributes do not contain an Access Policy".to_owned(),
                ))
            },
            |bytes| {
                let VendorAttributeValue::ByteString(bytes) = bytes else {
                    return Err(CryptoError::Kmip(
                        "the Access Policy is not a byte string".to_owned(),
                    ));
                };
                String::from_utf8(bytes.clone()).map_err(|e| {
                    CryptoError::Kmip(format!(
                        "failed to read Access Policy string from the (vendor) attributes bytes: \
                         {e}"
                    ))
                })
            },
        )
}
