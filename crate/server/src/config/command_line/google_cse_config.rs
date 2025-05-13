use clap::Args;
use serde::{Deserialize, Serialize};

#[derive(Debug, Args, Deserialize, Serialize, Clone)]
#[serde(default)]
#[derive(Default)]
pub struct GoogleCseConfig {
    /// This setting turns on endpoints handling Google CSE feature
    #[clap(long, env = "KMS_GOOGLE_CSE_ENABLE", default_value = "false")]
    pub google_cse_enable: bool,

    /// This setting turns off the validation of the tokens
    /// used by this server's Google Workspace CSE feature.
    #[clap(
        long,
        env = "KMS_GOOGLE_CSE_DISABLE_TOKENS_VALIDATION",
        default_value = "false"
    )]
    pub google_cse_disable_tokens_validation: bool,

    /// This setting contains the list of KACLS server URLs that can access this server for Google CSE migration,
    /// through the privilegedunwrap endpoint (used to fetch exposed jwks on server start)
    #[clap(long, env = "KMS_GOOGLE_CSE_INCOMING_URL_WHITELIST")]
    pub google_cse_incoming_url_whitelist: Option<Vec<String>>,

    /// Base64-encoded RSA private key used to ensure consistency of certificate handling and privileged unwrap operations
    /// across server restarts and multiple server instances. If not provided, a random key will be generated at server startup.
    #[clap(long, env = "KMS_GOOGLE_CSE_MIGRATION_KEY")]
    pub google_cse_migration_key: Option<String>,
}
