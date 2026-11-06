use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
#[derive(Default)]
pub struct GoogleCseConfig {
    /// This setting turns on endpoints handling Google CSE feature
    #[clap(
        long = "google-cse-enable",
        id = "google_cse_enable",
        value_name = "GOOGLE_CSE_ENABLE",
        env = "KMS_GOOGLE_CSE_ENABLE",
        default_value = "false"
    )]
    #[serde(rename = "google_cse_enable")]
    pub enable: bool,

    /// This setting turns off the validation of the tokens
    /// used by this server's Google Workspace CSE feature.
    #[clap(
        long = "google-cse-disable-tokens-validation",
        id = "google_cse_disable_tokens_validation",
        value_name = "GOOGLE_CSE_DISABLE_TOKENS_VALIDATION",
        env = "KMS_GOOGLE_CSE_DISABLE_TOKENS_VALIDATION",
        default_value = "false"
    )]
    #[serde(rename = "google_cse_disable_tokens_validation")]
    pub disable_tokens_validation: bool,

    /// This setting contains the list of KACLS server URLs that can access this server for Google CSE migration,
    /// through the privilegedunwrap endpoint (used to fetch exposed jwks on server start)
    #[clap(
        long = "google-cse-incoming-url-whitelist",
        id = "google_cse_incoming_url_whitelist",
        value_name = "GOOGLE_CSE_INCOMING_URL_WHITELIST",
        env = "KMS_GOOGLE_CSE_INCOMING_URL_WHITELIST"
    )]
    #[serde(rename = "google_cse_incoming_url_whitelist")]
    pub incoming_url_whitelist: Option<Vec<String>>,

    /// PEM PKCS8 RSA private key used to ensure consistency of certificate handling and privileged unwrap operations
    /// across server restarts and multiple server instances. If not provided, a random key will be generated at server startup.
    #[clap(
        long = "google-cse-migration-key",
        id = "google_cse_migration_key",
        value_name = "GOOGLE_CSE_MIGRATION_KEY",
        env = "KMS_GOOGLE_CSE_MIGRATION_KEY"
    )]
    #[serde(rename = "google_cse_migration_key")]
    pub migration_key: Option<String>,
}
