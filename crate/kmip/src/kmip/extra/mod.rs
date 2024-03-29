mod certificates;
pub mod tagging;
#[cfg(feature = "openssl")]
pub mod x509_extensions;

/// The vendor ID to use for Cosmian specific attributes
pub const VENDOR_ID_COSMIAN: &str = "cosmian";

/// The vendor attribute name to use for x.509 extensions
pub const VENDOR_ATTR_X509_EXTENSION: &str = "x509-extension";
