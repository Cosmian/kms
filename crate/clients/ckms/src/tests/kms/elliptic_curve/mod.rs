#[cfg(feature = "non-fips")]
pub(crate) mod create_key_pair;
#[cfg(feature = "non-fips")]
pub(crate) mod encrypt_decrypt;
#[cfg(feature = "non-fips")]
pub(crate) mod sign_verify;

#[cfg(feature = "non-fips")]
pub(crate) const SUB_COMMAND: &str = "ec";
