pub mod cover_crypt;
pub mod dh_shared_keys;
pub mod elliptic_curves;
pub mod error;
pub mod generic;
pub mod hybrid_encryption;
pub mod password_derivation;
pub mod rsa;
pub mod symmetric;
pub mod wrap;

use cosmian_kmip::kmip::kmip_operations::{Decrypt, DecryptResponse, Encrypt, EncryptResponse};
pub use elliptic_curves::Q_LENGTH_BITS;
use error::KmsCryptoError;

pub trait EncryptionSystem {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmsCryptoError>;
}

impl<T: EncryptionSystem + ?Sized> EncryptionSystem for Box<T> {
    fn encrypt(&self, request: &Encrypt) -> Result<EncryptResponse, KmsCryptoError> {
        (**self).encrypt(request)
    }
}

pub trait DecryptionSystem {
    fn decrypt(&self, request: &Decrypt) -> Result<DecryptResponse, KmsCryptoError>;
}
