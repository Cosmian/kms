use std::path::{Path, PathBuf};

use clap::Args;
use libsgx::utils::is_running_inside_enclave;

use super::{workspace::WorkspaceConfig, EnclaveParams};

#[derive(Debug, Args)]
pub struct EnclaveConfig {
    /// The directory where the manifest and public key files are located
    /// This path should not be encrypted by the enclave and should be directly readable from it
    ///   
    /// A relative path is taken relative to the root_data_path
    #[clap(long, env("KMS_ENCLAVE_DIR_PATH"), default_value("./enclave"))]
    pub enclave_dir_path: PathBuf,

    /// The filename of the sgx manifest
    #[clap(
        long,
        env("KMS_ENCLAVE_MANIFEST_FILENAME"),
        default_value("kms.manifest.sgx")
    )]
    pub manifest_filename: PathBuf,

    /// The filename of the public key
    #[clap(
        long,
        env("KMS_ENCLAVE_PUBLIC_KEY_FILENAME"),
        default_value("mr-signer-key.pub")
    )]
    pub public_key_filename: PathBuf,
}

impl Default for EnclaveConfig {
    fn default() -> Self {
        Self {
            enclave_dir_path: PathBuf::from("./enclave"),
            manifest_filename: PathBuf::from("kms.manifest.sgx"),
            public_key_filename: PathBuf::from("mr-signer-key.pub"),
        }
    }
}

impl EnclaveConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> eyre::Result<EnclaveParams> {
        if !is_running_inside_enclave() {
            let default = Self::default();
            // these paths are never used nor created
            return Ok(EnclaveParams {
                manifest_path: default.enclave_dir_path.join(default.manifest_filename),
                public_key_path: default.enclave_dir_path.join(default.public_key_filename),
            })
        }

        // finalize the enclave dir path
        let enclave_dir_path = workspace.finalize_directory(&self.enclave_dir_path)?;

        let manifest_path = enclave_dir_path.join(&self.manifest_filename);
        if !Path::new(&manifest_path).exists() {
            eyre::bail!("Can't find '{manifest_path:?}' as manifest_path");
        }

        let public_key_path = enclave_dir_path.join(&self.public_key_filename);
        if !Path::new(&public_key_path).exists() {
            eyre::bail!("Can't find '{public_key_path:?}' as public_key_path");
        }

        Ok(EnclaveParams {
            manifest_path,
            public_key_path,
        })
    }
}
