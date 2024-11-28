#![allow(clippy::print_stdout)]
//! These tests are gated behind the HSM feature flag. They require a running KMS-HSM server.
//! Configure the client file at the location indicated by `KSM_HSM_CLIENT_CONF` with the appropriate content
//! then run the tests with the following command:
//! ```bash
//!  cargo test --color=always --features hsm --lib tests::hsm::test_all_hsm_cli
//! ```

#[cfg(not(feature = "fips"))]
use crate::tests::hsm::encrypt_decrypt::test_rsa_pkcs_v15;
use crate::{
    error::result::CliResult,
    tests::hsm::encrypt_decrypt::{test_aes_gcm, test_rsa_pkcs_oaep},
};

const KMS_HSM_CLIENT_CONF: &str = "/home/bgrieder/.cosmian/kms_hsm.json";

mod encrypt_decrypt;
mod revoke_destroy;
mod wrap_with_hsm_key;

#[test]
fn test_all_hsm_cli() -> CliResult<()> {
    test_aes_gcm()?;
    test_rsa_pkcs_oaep()?;
    #[cfg(not(feature = "fips"))]
    test_rsa_pkcs_v15()?;
    Ok(())
}
