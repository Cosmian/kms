use clap::Args;

/// The configuration used by the bootstrap server.
///
/// The hostname is the same as the one used by the KMS server,
/// only the port can be changed.
#[derive(Debug, Args, Clone)]
pub struct BootstrapServerConfig {
    /// Whether configuration should be finalized using a bootstrap server
    #[clap(long, env("KMS_USE_BOOTSTRAP_SERVER"), default_value("false"))]
    pub use_bootstrap_server: bool,

    /// The name that will be the CN
    /// in the bootstrap server self-signed certificate
    #[clap(
        long,
        env("KMS_BOOTSTRAP_SERVER_COMMON_NAME"),
        default_value("cosmian.kms")
    )]
    pub bootstrap_server_common_name: String,

    /// The bootstrap server may be started on a specific port
    #[clap(long, env("KMS_BOOTSTRAP_SERVER_PORT"), default_value("9998"))]
    pub bootstrap_server_port: usize,
}

impl Default for BootstrapServerConfig {
    fn default() -> Self {
        Self {
            use_bootstrap_server: false,
            bootstrap_server_common_name: "cosmian.kms".to_string(),
            bootstrap_server_port: 9998,
        }
    }
}
