pub use cosmian_kms_server::{
    config::{DEFAULT_SQLITE_PATH, HsmConfig, MainDBConfig},
    openssl_providers::init_openssl_providers_for_tests,
};
pub use test_jwt::AUTH0_TOKEN;
#[cfg(feature = "non-fips")]
pub use test_server::start_test_kms_server_with_pqc_tls;
pub use test_server::{
    TestClientOptions, TestsContext, hsm_config_path, start_default_test_kms_server,
    start_default_test_kms_server_with_cert_auth, start_default_test_kms_server_with_jwt_auth,
    start_default_test_kms_server_with_multi_privileged_users,
    start_default_test_kms_server_with_non_revocable_key_ids,
    start_default_test_kms_server_with_privileged_users,
    start_default_test_kms_server_with_softhsm2_and_kek,
    start_default_test_kms_server_with_three_softhsm2,
    start_default_test_kms_server_with_utimaco_and_kek,
    start_default_test_kms_server_with_utimaco_hsm, start_test_kms_server_with_config,
    start_test_server, start_test_server_from_toml, start_test_server_with_patch, test_config_path,
};
pub use vector_runner::{run_test_vector, run_test_vector_with_context};

mod test_server;

mod test_jwt;

pub mod vector_runner;

use std::sync::Once;

/// Initialize tracing/logging once for the entire test process.
/// Prevents panics like: "Tracing already initialized or crashed" when tests
/// or multiple crates call `cosmian_logger::log_init` concurrently.
static INIT_LOGGING: Once = Once::new();

pub fn init_test_logging() {
    INIT_LOGGING.call_once(|| {
        cosmian_logger::log_init(option_env!("RUST_LOG"));
        // Also initialize OpenSSL legacy provider for non-FIPS tests
        cosmian_kms_server::openssl_providers::init_openssl_providers_for_tests();
    });
}

pub mod reexport {
    pub use cosmian_kms_server;
}

#[cfg(test)]
mod certify_tests;
