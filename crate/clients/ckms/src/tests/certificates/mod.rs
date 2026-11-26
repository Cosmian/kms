pub(crate) mod certify;
mod certify_pqc;
// FIPS: every test of this module needs ECIES or an EC/X25519 certificate encryption, or
// CKM_RSA_AES_KEY_WRAP (refused with "not meant to wrap keys" in a FIPS build).
#[cfg(feature = "non-fips")]
pub(crate) mod encrypt;
mod export;
mod generate_csr;
pub(crate) mod import;
pub(crate) mod validate;

#[cfg(feature = "non-fips")] // only used by the non-FIPS certificate encryption tests
pub(crate) const SUB_COMMAND: &str = "certificates";
