use std::path::{Path, PathBuf};

use clap::Args;
use libsgx::utils::is_running_inside_enclave;

use super::{workspace::WorkspaceConfig, EnclaveParams};

#[derive(Debug, Args)]
pub struct EnclaveConfig {
    /// The path of the sgx manifest
    #[clap(long, env = "KMS_ENCLAVE_MANIFEST_FILENAME", parse(from_os_str))]
    pub manifest_filename: PathBuf,

    #[clap(long, env = "KMS_ENCLAVE_PUBLIC_KEY", parse(from_os_str))]
    pub public_key_filename: PathBuf,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        EnclaveConfig {
            manifest_filename: PathBuf::from("kms.manifest.sgx"),
            public_key_filename: PathBuf::from("cosmian-signer-key.pub"),
        }
    }
}

impl EnclaveConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<EnclaveParams> {
        if !is_running_inside_enclave() {
            eyre::bail!("You are not running inside an enclave")
        }

        let manifest_path = workspace.public_path.join(&self.manifest_filename);

        if !Path::new(&manifest_path).exists() {
            eyre::bail!("Can't find '{manifest_path:?}' as manifest_path");
        }

        let public_key_path = workspace.public_path.join(&self.public_key_filename);

        if !Path::new(&public_key_path).exists() {
            eyre::bail!("Can't find '{public_key_path:?}' as public_key_path");
        }

        Ok(EnclaveParams {
            manifest_path,
            public_key_path,
        })
    }
}
