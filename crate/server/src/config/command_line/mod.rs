mod auth_verifier_config;
mod azure_ekm_config;
mod clap_config;
mod crl_config;
mod db;
mod google_cse_config;
mod hsm_config;
mod http_config;
mod idp_auth_config;
mod jwks_endpoint_config;
mod kmip_policy_config;
mod logging;
mod proxy_config;
mod roles_config;
pub mod secret_backends;
mod socket_server_config;
mod tls_config;
mod ui_config;
mod vault_config;
mod workspace;

pub use auth_verifier_config::AuthVerifierConfig;
pub use azure_ekm_config::AzureEkmConfig;
#[cfg(not(target_os = "windows"))]
pub use clap_config::DEFAULT_COSMIAN_KMS_CONF;
pub use clap_config::{ClapConfig, get_default_config_path};
pub use crl_config::CrlConfig;
pub use db::{DEFAULT_SQLITE_PATH, DatabaseType, MainDBConfig};
pub use google_cse_config::GoogleCseConfig;
pub use hsm_config::{HsmConfig, HsmModel};
pub use http_config::{HttpConfig, default_cors_origins};
pub use idp_auth_config::IdpAuthConfig;
pub use jwks_endpoint_config::JwksEndpointConfig;
pub use kmip_policy_config::{
    AesKeySize, KmipAllowlistsConfig, KmipPolicyConfig, KmipPolicyId, RsaKeySize,
};
pub use logging::{LoggingConfig, get_default_rolling_log_dir};
pub use proxy_config::ProxyConfig;
pub use roles_config::RolesConfig;
pub use secret_backends::{
    AwsSsmBackendConfig, AzureKvBackendConfig, CosmianKmsSecretConfig, SecretBackendConfig,
    SecretBackendKind, VaultBackendConfig,
};
pub use socket_server_config::SocketServerConfig;
pub use tls_config::TlsConfig;
pub use ui_config::{
    AuthVerifierRuntimeConfig, OidcConfig, OidcDiscoveredEndpoints, OidcRuntimeConfig, UiConfig,
    get_default_ui_dist_path,
};
pub use vault_config::VaultConfig;
pub use workspace::WorkspaceConfig;
