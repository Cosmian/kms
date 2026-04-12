use std::sync::{Arc, LazyLock, RwLock};

use zeroize::Zeroizing;

use super::{SignatureAlgorithm, SymmetricKey};
use crate::{
    ModuleError, ModuleResult,
    core::object::Object,
    traits::{
        Certificate, DataObject, EncryptionAlgorithm, KeyAlgorithm, PrivateKey, PublicKey,
        SearchOptions, Version,
    },
};

// ── Internal: std::sync::atomic re-export ─────────────────────────────────
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
pub struct SignContext {
    pub algorithm: SignatureAlgorithm,
    pub private_key: Arc<dyn PrivateKey>,
    /// Payload stored for multipart `C_SignUpdate` operations.
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct DecryptContext {
    pub remote_object_id: String,
    pub algorithm: EncryptionAlgorithm,
    pub iv: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EncryptContext {
    pub remote_object_id: String,
    pub algorithm: EncryptionAlgorithm,
    pub iv: Option<Vec<u8>>,
}

static BACKEND: LazyLock<RwLock<Option<Arc<dyn Backend>>>> = LazyLock::new(|| RwLock::new(None));

/// Stores (or replaces) the backend used by all PKCS#11 operations.
/// Called by the provider at `C_GetFunctionList` (modes 0/1) or at
/// `C_Login` time when OIDC-pin mode is active (mode 2).
pub fn register_backend(backend: Box<dyn Backend>) {
    if let Ok(mut guard) = BACKEND.write() {
        *guard = Some(Arc::from(backend));
    }
}

/// Clears the registered backend. Called by `C_Logout` when OIDC-pin mode is active.
pub fn clear_backend() {
    if let Ok(mut guard) = BACKEND.write() {
        *guard = None;
    }
}

/// Returns the currently registered backend.
/// Returns [`ModuleError::UserNotLoggedIn`] when no backend is registered
/// (i.e. before `C_GetFunctionList` or after `C_Logout` in OIDC-pin mode).
pub fn backend() -> ModuleResult<Arc<dyn Backend>> {
    let guard = BACKEND
        .read()
        .map_err(|e| ModuleError::Default(e.to_string()))?;
    guard.clone().ok_or(ModuleError::UserNotLoggedIn)
}

// ── OIDC pin-as-access-token mode ────────────────────────────────────────

/// Whether `pkcs11_use_pin_as_access_token = true` is set in `ckms.toml`.
///
/// Uses `AtomicBool` (not `OnceLock`) so that the value can be *updated* on
/// each call to `C_GetFunctionList`.  On Windows the DLL is kept in memory by
/// the Tokio background-I/O threads that live inside the static `RUNTIME`
/// (in the provider crate).  A second `Library::new()` in a test therefore
/// returns the **same DLL instance** with its static state intact, so every
/// `register_*` helper must support repeated calls with fresh values.
static PKCS11_USE_PIN_AS_ACCESS_TOKEN: AtomicBool = AtomicBool::new(false);

/// Registers whether `pkcs11_use_pin_as_access_token = true` is set in `ckms.toml`.
/// Called at every `C_GetFunctionList` invocation (overwriting any previous value).
pub fn register_pin_mode(enabled: bool) {
    PKCS11_USE_PIN_AS_ACCESS_TOKEN.store(enabled, Ordering::SeqCst);
}

/// Returns `true` when the OIDC-pin mode is active: the `pPin` passed to
/// `C_Login` is treated as a bearer token for every subsequent KMS request.
pub fn use_pin_as_access_token() -> bool {
    PKCS11_USE_PIN_AS_ACCESS_TOKEN.load(Ordering::SeqCst)
}

// ── Login callback (provider ↔ module bridge) ─────────────────────────────

type LoginFn = Box<dyn Fn(&str) -> ModuleResult<()> + Send + Sync>;

/// Login callback, wrapped in `RwLock<Option<…>>` so that it can be
/// *replaced* on every `C_GetFunctionList` call (see the comment on
/// `PKCS11_USE_PIN_AS_ACCESS_TOKEN` above for the rationale).
static LOGIN_FN: LazyLock<RwLock<Option<LoginFn>>> = LazyLock::new(|| RwLock::new(None));

/// Registers (or replaces) the login callback at `C_GetFunctionList` time (mode 2 only).
/// The closure receives the bearer token, builds an authenticated `KmsClient`,
/// and calls `register_backend` to replace the pre-login stub.
pub fn register_login_fn(f: LoginFn) {
    if let Ok(mut guard) = LOGIN_FN.write() {
        *guard = Some(f);
    }
}

/// Invokes the registered login callback with `token`.
/// Returns [`ModuleError::UserNotLoggedIn`] if no callback was registered.
pub fn invoke_login_fn(token: &str) -> ModuleResult<()> {
    let guard = LOGIN_FN
        .read()
        .map_err(|e| ModuleError::Default(e.to_string()))?;
    let f = guard.as_ref().ok_or(ModuleError::UserNotLoggedIn)?;
    f(token)
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

    fn find_certificate(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn Certificate>>>;
    fn find_all_certificates(&self) -> ModuleResult<Vec<Arc<dyn Certificate>>>;

    fn find_private_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PrivateKey>>;
    fn find_all_private_keys(&self) -> ModuleResult<Vec<Arc<dyn PrivateKey>>>;

    fn find_public_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn PublicKey>>;
    fn find_all_public_keys(&self) -> ModuleResult<Vec<Arc<dyn PublicKey>>>;

    fn find_symmetric_key(&self, query: SearchOptions) -> ModuleResult<Arc<dyn SymmetricKey>>;
    fn find_all_symmetric_keys(&self) -> ModuleResult<Vec<Arc<dyn SymmetricKey>>>;

    fn find_data_object(&self, query: SearchOptions) -> ModuleResult<Option<Arc<dyn DataObject>>>;
    fn find_all_data_objects(&self) -> ModuleResult<Vec<Arc<dyn DataObject>>>;

    fn find_all_objects(&self) -> ModuleResult<Vec<Arc<Object>>>;

    fn generate_key(
        &self,
        algorithm: KeyAlgorithm,
        key_length: usize,
        sensitive: bool,
        label: Option<&str>,
    ) -> ModuleResult<Arc<dyn SymmetricKey>>;

    fn create_object(&self, label: &str, data: &[u8]) -> ModuleResult<Arc<dyn DataObject>>;
    fn revoke_object(&self, remote_id: &str) -> ModuleResult<()>;
    fn destroy_object(&self, remote_id: &str) -> ModuleResult<()>;

    fn encrypt(&self, ctx: &EncryptContext, cleartext: Vec<u8>) -> ModuleResult<Vec<u8>>;

    fn decrypt(
        &self,
        ctx: &DecryptContext,
        ciphertext: Vec<u8>,
    ) -> ModuleResult<Zeroizing<Vec<u8>>>;

    fn remote_sign(
        &self,
        remote_id: &str,
        algorithm: &SignatureAlgorithm,
        data: &[u8],
    ) -> ModuleResult<Vec<u8>>;
}
