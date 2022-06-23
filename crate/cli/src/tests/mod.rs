mod abe;
mod configure;
mod cover_crypt;
mod permission;
mod sgx;

pub(crate) mod utils;

pub(crate) mod test_utils;

const PROG_NAME: &str = "cosmian_kms_cli";
#[cfg(feature = "staging")]
const PATTERN_CONF_PATH: &str = "test_data/kms-staging.json";
#[cfg(not(feature = "staging"))]
const PATTERN_CONF_PATH: &str = "test_data/kms.json";
const CONF_PATH: &str = "/tmp/tmp.json";
const CONF_PATH_BAD_KEY: &str = "/tmp/kms_bad_key.bad";
