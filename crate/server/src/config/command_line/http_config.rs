use std::fmt::Display;

use clap::Args;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 9998;
#[cfg(target_os = "windows")]
const DEFAULT_HOSTNAME: &str = "127.0.0.1";
#[cfg(not(target_os = "windows"))]
const DEFAULT_HOSTNAME: &str = "0.0.0.0";

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    /// The KMS HTTP server port
    #[clap(long, env = "KMS_PORT", default_value_t = DEFAULT_PORT, verbatim_doc_comment)]
    pub port: u16,

    /// The KMS HTTP server hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = DEFAULT_HOSTNAME, verbatim_doc_comment)]
    pub hostname: String,

    /// An optional API token to use for authentication on the HTTP server.
    #[clap(long, env = "KMS_API_TOKEN", verbatim_doc_comment)]
    pub api_token_id: Option<String>,

    /// Maximum number of requests per second per IP address allowed by the rate limiter.
    /// When set, the server enforces this limit to mitigate `DoS` and brute-force attacks.
    /// Requests exceeding the limit receive HTTP 429 Too Many Requests.
    /// Leave unset (default) to disable rate limiting.
    #[clap(long, env = "KMS_RATE_LIMIT_PER_SECOND", verbatim_doc_comment)]
    pub rate_limit_per_second: Option<u32>,
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.hostname, self.port)?;
        if let Some(ref token) = self.api_token_id {
            write!(f, " (api_token: {token})")?;
        }
        if let Some(rps) = self.rate_limit_per_second {
            write!(f, " (rate_limit: {rps}/s)")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", &self))
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            hostname: DEFAULT_HOSTNAME.to_owned(),
            api_token_id: None,
            rate_limit_per_second: None,
        }
    }
}
