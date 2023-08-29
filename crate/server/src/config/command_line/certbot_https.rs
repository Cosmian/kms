use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Args;
use tracing::info;

use super::WorkspaceConfig;
use crate::{core::certbot::Certbot, kms_error, result::KResult};

#[derive(Debug, Args)]
pub struct HttpsCertbotConfig {
    /// Enable TLS and use Let's Encrypt certbot to get a certificate
    #[clap(long, required(false), env("KMS_USE_CERTBOT"), default_value = "false")]
    pub use_certbot: bool,

    /// The hostname of the KMS HTTPS server
    /// that will be used as the Common Name in the Let's Encrypt certificate
    #[clap(
        long,
        env("KMS_CERTBOT_HOSTNAME"),
        required(false),
        required_if_eq("use_certbot", "true"),
        default_value = ""
    )]
    pub certbot_hostname: String,

    /// The email used during the Let's Encrypt certbot certification process
    #[clap(
        long,
        env("KMS_CERTBOT_EMAIL"),
        required(false),
        required_if_eq("use_certbot", "true"),
        default_value = ""
    )]
    pub certbot_email: String,

    /// The folder where the KMS will store the SSL material created by certbot
    ///
    /// A relative path is taken relative to the root_data_path
    #[clap(long, env = "KMS_CERTBOT_SSL_PATH", default_value = "./certbot-ssl")]
    pub certbot_ssl_path: PathBuf,
}

impl Default for HttpsCertbotConfig {
    fn default() -> Self {
        Self {
            use_certbot: false,
            certbot_email: String::new(),
            certbot_hostname: String::new(),
            certbot_ssl_path: std::env::temp_dir(),
        }
    }
}

impl HttpsCertbotConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> KResult<Certbot> {
        let certbot_ssl_path = workspace.finalize_directory(&self.certbot_ssl_path)?;

        let http_root_path = workspace.tmp_path.join("html");

        if !Path::new(&http_root_path).exists() {
            info!("Creating {:?}...", http_root_path);
            fs::create_dir_all(&http_root_path)?;
        }

        Ok(Certbot::new(
            self.certbot_email.clone(),
            self.certbot_hostname.clone(),
            std::fs::canonicalize(http_root_path).map_err(|e| kms_error!(e))?,
            std::fs::canonicalize(certbot_ssl_path).map_err(|e| kms_error!(e))?,
        ))
    }
}
