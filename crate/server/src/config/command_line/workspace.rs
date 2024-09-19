use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Args;
use serde::{Deserialize, Serialize};

use crate::{kms_error, result::KResult};

const DEFAULT_ROOT_DATA_PATH: &str = "./cosmian-kms";
const DEFAULT_TMP_PATH: &str = "/tmp";

#[derive(Debug, Args, Deserialize, Serialize)]
#[serde(default)]
pub struct WorkspaceConfig {
    /// The root folder where the KMS will store its data
    /// A relative path is taken relative to the user HOME directory
    #[clap(long, env = "KMS_ROOT_DATA_PATH", default_value = DEFAULT_ROOT_DATA_PATH)]
    pub root_data_path: PathBuf,

    /// The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution)
    #[clap(long, env = "KMS_TMP_PATH", default_value = DEFAULT_TMP_PATH)]
    pub tmp_path: PathBuf,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            root_data_path: PathBuf::from(DEFAULT_ROOT_DATA_PATH),
            tmp_path: PathBuf::from(DEFAULT_TMP_PATH),
        }
    }
}

impl WorkspaceConfig {
    pub(crate) fn init(&self) -> KResult<Self> {
        let root_data_path = Self::finalize_directory_path(&self.root_data_path, None)?;
        let tmp_path = Self::finalize_directory_path(&self.tmp_path, Some(&root_data_path))?;
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
    pub(crate) fn finalize_directory(&self, path: &PathBuf) -> KResult<PathBuf> {
        Self::finalize_directory_path(path, Some(&self.root_data_path))
    }

    /// Transform a relative path to `root_data_path` to an absolute path and ensure that the directory exists.
    /// An absolute path is left unchanged.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to be transformed.
    /// * `relative_root` - The root directory that will be used to make `path` absolute if it's relative. Or current directory is None.
    ///
    /// # Returns
    ///
    /// Returns the canonicalized path.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory can't be created or if an error occurs while calling `std::fs::canonicalize`
    pub(crate) fn finalize_directory_path(
        path: &PathBuf,
        relative_root: Option<&Path>,
    ) -> KResult<PathBuf> {
        let path = if path.is_relative() {
            relative_root.map_or_else(|| path.clone(), |relative_root| relative_root.join(path))
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
    #[allow(dead_code)]
    pub(crate) fn finalize_file_path(&self, path: &PathBuf) -> KResult<PathBuf> {
        let path = if path.is_relative() {
            self.root_data_path.join(path)
        } else {
            path.clone()
        };
        fs::canonicalize(path).map_err(|e| kms_error!(e))
    }
}
