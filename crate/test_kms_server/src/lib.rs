pub use cosmian_kms_server::{
    config::{HsmConfig, MainDBConfig},
    openssl_providers::init_openssl_providers_for_tests,
};
pub use test_server::{
    TestsContext, load_client_config, load_server_config, start_default_test_kms_server,
    start_default_test_kms_server_with_cert_auth,
    start_default_test_kms_server_with_non_revocable_key_ids,
    start_default_test_kms_server_with_privileged_users,
    start_default_test_kms_server_with_utimaco_and_kek,
    start_default_test_kms_server_with_utimaco_hsm, start_temp_test_kms_server,
    start_test_kms_server_with_config, with_server_port,
};

mod test_server;

mod test_jwt;

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
