use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Args;
use dirs;

use crate::{kms_error, result::KResult};

#[derive(Debug, Args)]
pub struct WorkspaceConfig {
    /// The root folder where the KMS will store its data
    /// A relative path is taken relative to the user HOME directory
    #[clap(long, env = "KMS_ROOT_DATA_PATH", default_value = "./cosmian-kms")]
    pub root_data_path: PathBuf,

    /// The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution)
    #[clap(long, env = "KMS_TMP_PATH", default_value = "/tmp")]
    pub tmp_path: PathBuf,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            root_data_path: std::env::temp_dir(),
            tmp_path: std::env::temp_dir(),
        }
    }
}

impl WorkspaceConfig {
    pub fn init(&self) -> KResult<Self> {
        let root_data_path = Self::finalize_directory_path(
            &self.root_data_path,
            &dirs::home_dir().ok_or_else(|| {
                kms_error!("Unable to get the user home to set the KMS data path")
            })?,
        )?;
        let tmp_path = Self::finalize_directory_path(&self.tmp_path, &root_data_path)?;
        Ok(Self {
            root_data_path,
            tmp_path,
        })
    }

    /// Transform a relative path to `root_data_path` to an absolute path and ensure that the directory exists.
    /// An absolute path is left unchanged.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to be transformed.
    /// * `relative_root` - The root directory that will be used to make `path` absolute if it's relative.
    ///
    /// # Returns
    ///
    /// Returns the canonicalized path.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory can't be created or if an error occurs while calling `std::fs::canonicalize`
    pub fn finalize_directory(&self, path: &PathBuf) -> KResult<PathBuf> {
        Self::finalize_directory_path(path, &self.root_data_path)
    }

    /// Transform a relative path to `root_data_path` to an absolute path and ensure that the directory exists.
    /// An absolute path is left unchanged.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to be transformed.
    /// * `relative_root` - The root directory that will be used to make `path` absolute if it's relative.
    ///
    /// # Returns
    ///
    /// Returns the canonicalized path.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory can't be created or if an error occurs while calling `std::fs::canonicalize`
    pub fn finalize_directory_path(path: &PathBuf, relative_root: &Path) -> KResult<PathBuf> {
        let path = if path.is_relative() {
            relative_root.join(path)
        } else {
            path.clone()
        };
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
        fs::canonicalize(path).map_err(|e| kms_error!(e))
    }

    /// Transform a relative path to `root_data_path` to an absolute path.
    /// An absolute path is left unchanged.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to be transformed.
    ///
    /// # Returns
    ///
    /// Returns the canonicalized path.
    ///
    /// # Errors
    ///
    /// Returns if an error occurs while calling `std::fs::canonicalize`
    pub fn finalize_file_path(&self, path: &PathBuf) -> KResult<PathBuf> {
        let path = if path.is_relative() {
            self.root_data_path.join(path)
        } else {
            path.clone()
        };
        fs::canonicalize(path).map_err(|e| kms_error!(e))
    }
}
