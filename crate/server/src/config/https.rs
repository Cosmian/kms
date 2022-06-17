use clap::Args;
#[cfg(feature = "https")]
use {
    super::workspace::WorkspaceConfig,
    crate::core::certbot::Certbot,
    std::{fs, path::Path},
    tracing::info,
};

#[derive(Debug, Args)]
pub struct HTTPSConfig {
    /// The domain name of the HTTPS server
    #[clap(long, env = "KMS_SSL_DOMAIN_NAME")]
    pub domain_name: String,

    /// The email used during the HTTPS certification process
    #[clap(long, env = "KMS_SSL_EMAIL")]
    pub email: String,
}

impl Default for HTTPSConfig {
    fn default() -> Self {
        HTTPSConfig {
            email: "".to_string(),
            domain_name: "".to_string(),
        }
    }
}

impl HTTPSConfig {
    #[cfg(feature = "https")]
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<Certbot> {
        let keys_path = workspace.private_path.join("ssl");

        if !Path::new(&keys_path).exists() {
            info!("Creating {:?}...", keys_path);
            fs::create_dir_all(&keys_path)?;
        }

        let http_root_path = workspace.tmp_path.join("html");

        if !Path::new(&http_root_path).exists() {
            info!("Creating {:?}...", http_root_path);
            fs::create_dir_all(&http_root_path)?;
        }

        Ok(Certbot::new(
            self.email.to_owned(),
            self.domain_name.to_owned(),
            http_root_path,
            keys_path,
        ))
    }
}
