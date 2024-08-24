pub(crate) mod create_key_pair;
#[cfg(not(feature = "fips"))]
pub(crate) mod encrypt_decrypt;

pub(crate) const SUB_COMMAND: &str = "ec";
