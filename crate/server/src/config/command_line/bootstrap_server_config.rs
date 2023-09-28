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

    /// Subject as an RFC 4514 string for the RA-TLS certificate
    /// in the bootstrap server
    #[clap(
        long,
        env("KMS_BOOTSTRAP_SERVER_SUBJECT"),
        default_value("CN=cosmian.kms,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France")
    )]
    pub bootstrap_server_subject: String,

    /// Number of days before the certificate expires
    #[clap(
        long,
        env("KMS_BOOTSTRAP_SERVER_EXPIRATION_DAYS"),
        default_value("365")
    )]
    pub bootstrap_server_expiration_days: u64,

    /// The bootstrap server may be started on a specific port,
    /// The hostname will be that configured in --hostname
    #[clap(long, env("KMS_BOOTSTRAP_SERVER_PORT"), default_value("9998"))]
    pub bootstrap_server_port: u16,

    /// Ensure RA-TLS is available and used.
    /// The server will not start if this is not the case.
    #[clap(long, env("KMS_ENSURE_RA_TLS"), default_value("false"))]
    pub ensure_ra_tls: bool,
}

impl Default for BootstrapServerConfig {
    fn default() -> Self {
        Self {
            use_bootstrap_server: false,
            bootstrap_server_subject: "CN=cosmian.kms,O=Cosmian Tech,C=FR,L=Paris,ST=Ile-de-France"
                .to_string(),
            bootstrap_server_port: 9998,
            bootstrap_server_expiration_days: 365,
            ensure_ra_tls: false,
        }
    }
}
