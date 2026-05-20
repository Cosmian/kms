mod build_certificate;
mod certify_op;
mod issuer;
mod resolve_issuer;
mod resolve_subject;
pub(crate) mod rfc9608;
#[cfg(feature = "non-fips")]
mod rfc9881;
#[cfg(feature = "non-fips")]
mod rfc9909;
#[cfg(feature = "non-fips")]
mod rfc9935;
mod subject;

#[cfg(test)]
mod tests;

// Re-export the public API of this module.
// Re-export helpers used by sibling RFC submodules via `super::`.
use build_certificate::extension_config_is_ca;
#[cfg(feature = "non-fips")]
use build_certificate::pqc_signing_key_usage;
pub(crate) use certify_op::certify;
