pub mod create_key_pair;
#[cfg(not(feature = "fips"))]
pub mod encrypt_decrypt;

pub(crate) const SUB_COMMAND: &str = "ec";
