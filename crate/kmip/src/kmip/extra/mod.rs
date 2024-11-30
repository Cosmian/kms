mod bulk_data;
mod certificates;
pub mod tagging;
mod wrap_on_create;
pub mod x509_extensions;

pub use bulk_data::BulkData;

/// The vendor ID to use for Cosmian specific attributes
pub const VENDOR_ID_COSMIAN: &str = "cosmian";

/// The vendor attribute name to use for x.509 extensions
pub const VENDOR_ATTR_X509_EXTENSION: &str = "x509-extension";
