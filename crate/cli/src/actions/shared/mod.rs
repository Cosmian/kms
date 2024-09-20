mod export_key;
mod get_attributes;
pub(crate) mod import_key;
mod locate;
pub mod utils;

#[cfg(feature = "openssl")]
mod wrap_key;

#[cfg(feature = "openssl")]
mod unwrap_key;

pub use export_key::{ExportBlockCipherMode, ExportKeyAction, ExportKeyFormat};
pub use get_attributes::{AttributeTag, GetAttributesAction};
pub use import_key::ImportKeyAction;
pub use locate::LocateObjectsAction;
#[cfg(feature = "openssl")]
pub use unwrap_key::UnwrapKeyAction;
#[cfg(feature = "openssl")]
pub use wrap_key::WrapKeyAction;

/// The size of a symmetric wrapping key in bytes derived from a password
pub const SYMMETRIC_WRAPPING_KEY_SIZE: usize = 32;
