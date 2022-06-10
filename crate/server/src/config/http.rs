use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct HTTPConfig {
    /// The server http port
    #[clap(long, env = "KMS_PORT", default_value = "9998")]
    pub port: u16,

    /// The server http hostname
    #[clap(long, env = "KMS_HOSTNAME", default_value = "localhost")]
    pub hostname: String,
}

impl Default for HTTPConfig {
    fn default() -> Self {
        HTTPConfig {
            port: 9998,
            hostname: "0.0.0.0".to_string(),
        }
    }
}

impl HTTPConfig {
    pub fn init(&self) -> eyre::Result<String> {
        Ok(format!("{}:{}", self.hostname, self.port))
    }
}
