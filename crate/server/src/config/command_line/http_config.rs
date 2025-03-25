use std::fmt::Display;

use clap::Args;
use serde::{Deserialize, Serialize};

const DEFAULT_PORT: u16 = 9998;
const DEFAULT_HOSTNAME: &str = "0.0.0.0";

#[derive(Args, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    /// The KMS HTTP server port
    #[clap(long, env = "KMS_PORT", default_value_t = DEFAULT_PORT)]
    pub port: u16,

    /// The KMS HTTP server hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = DEFAULT_HOSTNAME)]
    pub hostname: String,

    /// The API token to use for authentication
    #[clap(long, env = "KMS_API_TOKEN")]
    pub api_token_id: Option<String>,
}

impl Display for HttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http(s)://{}:{}, ", self.hostname, self.port)?;
        if let Some(token) = &self.api_token_id {
            write!(f, "API token id :{}", token.replace('.', "*"))?;
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
        }
    }
}
