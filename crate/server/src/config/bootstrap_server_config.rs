use clap::Args;

#[derive(Debug, Args, Clone)]
pub struct BootstrapServerConfig {
    #[clap(long, env("KMS_USE_BOOTSTRAP_SERVER"), default_value("false"))]
    pub use_bootstrap_server: bool,

    #[clap(
        long,
        env("KMS_BOOTSTRAP_SERVER_COMMON_NAME"),
        default_value("cosmian.kms")
    )]
    pub bootstrap_server_common_name: String,

    #[clap(long, env("KMS_BOOTSTRAP_SERVER_PORT"), default_value("9998"))]
    pub bootstrap_server_port: usize,
}

impl Default for BootstrapServerConfig {
    fn default() -> Self {
        Self {
            use_bootstrap_server: false,
            bootstrap_server_common_name: "cosmian.kms".to_string(),
            bootstrap_server_port: 443,
        }
    }
}
