mod activate;
pub(crate) mod export_key;
mod get_key_uid;
mod get_rotation_policy;
pub(crate) mod import_key;
mod locate;
mod rekey_keypair;
pub(crate) mod resolve_key;
mod revoke_reason_args;
mod rotation_policy_args;
mod set_rotation_policy;
pub(crate) mod sign;
pub(crate) mod signature_verify;
pub mod utils;

mod wrap_key;

mod unwrap_key;

pub use activate::ActivateKeyAction;
pub use export_key::ExportSecretDataOrKeyAction;
pub(crate) use get_key_uid::get_key_uid;
pub use get_rotation_policy::GetRotationPolicyAction;
pub use import_key::ImportSecretDataOrKeyAction;
pub use locate::LocateObjectsAction;
pub use rekey_keypair::ReKeyKeyPairAction;
pub use revoke_reason_args::RevokeReasonArgs;
pub use rotation_policy_args::RotationPolicyArgs;
pub use set_rotation_policy::SetRotationPolicyAction;
pub use unwrap_key::UnwrapSecretDataOrKeyAction;
pub use wrap_key::WrapSecretDataOrKeyAction;

/// The size of a symmetric wrapping key in bytes derived from a password
pub const SYMMETRIC_WRAPPING_KEY_SIZE: usize = 32;

/// Vendor attribute name for the Crypto Officer ceremony flag.
///
/// Shared by `ckms sym keys create-split-key --ceremony` (bring-your-own-key path)
/// and `ckms access-rights crypto-officer create-split-key` (guided path).
pub(crate) const VENDOR_ATTR_CO_CEREMONY: &str = "x-cosmian-crypto-officer-ceremony";
