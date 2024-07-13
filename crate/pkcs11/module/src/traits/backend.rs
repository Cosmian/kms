use std::sync::{Arc, RwLock};

use once_cell::sync::Lazy;
use zeroize::Zeroizing;

use crate::{
    traits::{
        Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        RemoteObjectId, SearchOptions, Version,
    },
    MResult,
};

//  The Backend is first staged so it can be stored in a Box<dyn Backend>. This
//  allows the Backend to be reference with `&'static`.
static STAGED_BACKEND: RwLock<Option<Box<dyn Backend>>> = RwLock::new(None);
static BACKEND: Lazy<Box<dyn Backend>> =
    Lazy::new(|| STAGED_BACKEND.write().unwrap().take().unwrap());

/// Stores a backend to later be returned by all calls `crate::backend()`.
pub fn register_backend(backend: Box<dyn Backend>) {
    *STAGED_BACKEND.write().unwrap() = Some(backend);
}

pub fn backend() -> &'static dyn Backend {
    BACKEND.as_ref()
}

pub trait Backend: Send + Sync {
    /// The token label
    /// e.g.
    /// `*b"Foo software token              "`
    fn token_label(&self) -> [u8; 32];
    /// The id of the manufacturer of the token
    fn token_manufacturer_id(&self) -> [u8; 32];
    /// The model of the token
    fn token_model(&self) -> [u8; 16];
    /// The serial number of the token
    fn token_serial_number(&self) -> [u8; 16];
    /// The description of this library
    fn library_description(&self) -> [u8; 32];
    /// The version of this library
    fn library_version(&self) -> Version;

    fn find_certificate(&self, query: SearchOptions) -> MResult<Option<Arc<dyn Certificate>>>;
    fn find_all_certificates(&self) -> MResult<Vec<Arc<dyn Certificate>>>;
    fn find_private_key(&self, query: SearchOptions) -> MResult<Arc<dyn PrivateKey>>;
    fn find_public_key(&self, query: SearchOptions) -> MResult<Arc<dyn PublicKey>>;
    fn find_all_private_keys(&self) -> MResult<Vec<Arc<dyn PrivateKey>>>;
    fn find_all_public_keys(&self) -> MResult<Vec<Arc<dyn PublicKey>>>;
    fn find_data_object(&self, query: SearchOptions) -> MResult<Option<Arc<dyn DataObject>>>;
    fn find_all_data_objects(&self) -> MResult<Vec<Arc<dyn DataObject>>>;
    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        label: Option<&str>,
    ) -> MResult<Arc<dyn PrivateKey>>;

    fn decrypt(
        &self,
        remote_object: Arc<dyn RemoteObjectId>,
        algorithm: EncryptionAlgorithm,
        ciphertext: Vec<u8>,
    ) -> MResult<Zeroizing<Vec<u8>>>;
}
