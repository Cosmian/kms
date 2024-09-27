#[cfg(not(feature = "fips"))]
mod cover_crypt_tests;

pub(crate) mod google_cse;
mod ms_dke;
pub(crate) mod test_set_attribute;
pub(crate) mod test_utils;
pub(crate) mod test_validate;

mod bulk_encrypt_decrypt_tests;
#[cfg(not(feature = "fips"))]
mod curve_25519_tests;
#[cfg(not(feature = "fips"))]
mod kmip_messages;
#[cfg(not(feature = "fips"))]
mod kmip_server_tests;
