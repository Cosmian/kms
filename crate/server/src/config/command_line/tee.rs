use std::path::{Path, PathBuf};

use clap::Args;
use tee_attestation::is_running_inside_tee;

use super::WorkspaceConfig;
use crate::{config::params::TeeParams, kms_bail, result::KResult};

#[derive(Debug, Args)]
pub struct TeeConfig {
    /// The directory where the public key or other required files are located
    /// This path should not be encrypted by the enclave and should be directly readable from it
    ///
    /// A relative path is taken relative to the `root_data_path` (see `WorkspaceConfig` struct)
    #[clap(long, env("KMS_TEE_DIR_PATH"), default_value("./tee"))]
    pub tee_dir_path: PathBuf,

    /// The filename of the public key for SGX
    #[clap(long, env("KMS_SGX_PUBLIC_SIGNER_KEY_FILENAME"))]
    pub sgx_public_signer_key_filename: Option<PathBuf>,
}

impl Default for TeeConfig {
    fn default() -> Self {
        Self {
            tee_dir_path: PathBuf::from("./tee"),
            sgx_public_signer_key_filename: None,
        }
    }
}

impl TeeConfig {
    pub fn init(&self, workspace: &WorkspaceConfig) -> KResult<TeeParams> {
        if !is_running_inside_tee() {
            let default = Self::default();
            // these paths are never used nor created
            return Ok(TeeParams {
                sgx_public_signer_key: default.sgx_public_signer_key_filename,
            })
        }

        if let Some(sgx_public_signer_key_filename) = &self.sgx_public_signer_key_filename {
            // finalize the enclave dir path
            let enclave_dir_path = workspace.finalize_directory(&self.tee_dir_path)?;

            let sgx_public_signer_key = enclave_dir_path.join(sgx_public_signer_key_filename);
            if !Path::new(&sgx_public_signer_key).exists() {
                kms_bail!("Can't find '{sgx_public_signer_key:?}' as sgx_public_signer_key");
            }

            return Ok(TeeParams {
                sgx_public_signer_key: Some(sgx_public_signer_key),
            })
        }

        Ok(TeeParams {
            sgx_public_signer_key: None,
        })
    }
}
