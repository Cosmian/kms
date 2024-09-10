mod delete_attributes;
mod export_key;
mod get_attributes;
pub(crate) mod import_key;
mod locate;
mod set_attributes;
pub mod utils;

#[cfg(feature = "openssl")]
mod wrap_key;

#[cfg(feature = "openssl")]
mod unwrap_key;

pub use delete_attributes::DeleteAttributesAction;
pub use export_key::{ExportKeyAction, ExportKeyFormat};
pub use get_attributes::GetAttributesAction;
pub use import_key::ImportKeyAction;
pub use locate::LocateObjectsAction;
pub use set_attributes::{SetAttributesAction, SetOrDeleteAttributes, VendorAttributeCli};
#[cfg(feature = "openssl")]
pub use unwrap_key::UnwrapKeyAction;
#[cfg(feature = "openssl")]
pub use wrap_key::WrapKeyAction;

/// The size of a symmetric wrapping key in bytes derived from a password
pub const SYMMETRIC_WRAPPING_KEY_SIZE: usize = 32;
