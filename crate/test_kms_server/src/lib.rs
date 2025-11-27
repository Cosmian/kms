pub use cosmian_kms_server::config::{DEFAULT_SQLITE_PATH, HsmConfig, MainDBConfig};
pub use test_server::{
    ApiTokenPolicy, AuthenticationOptions, BuildServerParamsOptions, ClientAuthOptions,
    ClientCertPolicy, JwtAuth as ServerJwtAuth, JwtPolicy, TestsContext, TlsMode as ServerTlsMode,
    build_server_params, build_server_params_full, start_default_test_kms_server,
    start_default_test_kms_server_with_cert_auth,
    start_default_test_kms_server_with_non_revocable_key_ids,
    start_default_test_kms_server_with_privileged_users,
    start_default_test_kms_server_with_utimaco_and_kek,
    start_default_test_kms_server_with_utimaco_hsm, start_test_kms_server_with_config,
    start_test_server_with_options,
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
    });
}

pub mod reexport {
    pub use cosmian_kms_server;
}
