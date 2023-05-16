mod auth_tests;
mod configure;
mod cover_crypt;
mod elliptic_curve;
mod permission;
mod sgx;
mod shared;
mod symmetric;
pub mod test_utils;
pub mod utils;

const PROG_NAME: &str = "ckms";

#[cfg(feature = "staging")]
const PATTERN_CONF_PATH: &str = "test_data/kms-staging.json";

const CONF_PATH: &str = "/tmp/tmp.json";
const CONF_PATH_BAD_KEY: &str = "/tmp/kms_bad_key.bad";
