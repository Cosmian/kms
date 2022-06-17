use std::path::{Path, PathBuf};

use clap::Args;
use libsgx::utils::is_running_inside_enclave;

use super::workspace::WorkspaceConfig;

#[derive(Debug, Args)]
pub struct EnclaveConfig {
    /// The path of the sgx manifest
    #[clap(long, env = "KMS_MANIFEST_FILENAME", parse(from_os_str))]
    pub manifest_filename: PathBuf,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        EnclaveConfig {
            manifest_filename: PathBuf::from("kms.manifest"),
        }
    }
}

impl EnclaveConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<PathBuf> {
        if !is_running_inside_enclave() {
            eyre::bail!("You are not running inside an enclave")
        }

        let manifest_path = workspace.public_path.join(&self.manifest_filename);

        if !Path::new(&manifest_path).exists() {
            eyre::bail!("Can't find '{manifest_path:?}' as manifest_path");
        }

        Ok(manifest_path)
    }
}
