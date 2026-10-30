use std::{
    fs,
    path::{Path, PathBuf},
};

use clap::Args;
use clap_config_fallback::ConfigArgs;
use serde::{Deserialize, Serialize};

use crate::{
    kms_error,
    result::{KResult, KResultHelper},
};

const DEFAULT_ROOT_DATA_PATH: &str = "./cosmian-kms";
const DEFAULT_TMP_PATH: &str = "/tmp";

#[derive(Debug, Args, ConfigArgs, Deserialize, Serialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceConfig {
    /// The root folder where the KMS will store its data
    /// A relative path is taken relative to the user's HOME directory
    #[clap(long, env = "KMS_ROOT_DATA_PATH", default_value = DEFAULT_ROOT_DATA_PATH)]
    pub root_data_path: PathBuf,

    /// The folder to store temporary data (non-persistent data readable by no one but the current instance during the current execution)
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
            fs::create_dir_all(&path)
                .context(&format!("finalize_directory_path: {}", path.display()))?;
        }

        fs::canonicalize(path).map_err(|e| kms_error!(e))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;

    use super::WorkspaceConfig;

    /// A relative path is resolved against the given root, created when missing,
    /// and returned canonicalized.
    #[test]
    fn finalize_directory_path_resolves_relative_to_root_and_creates() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();

        let resolved =
            WorkspaceConfig::finalize_directory_path(&PathBuf::from("a/b"), Some(&root)).unwrap();

        assert_eq!(resolved, root.join("a").join("b"));
        assert!(resolved.is_dir(), "directory must have been created");
    }

    /// An absolute path ignores the relative root and is only created/canonicalized.
    #[test]
    fn finalize_directory_path_keeps_absolute_path() {
        let tmp = TempDir::new().unwrap();
        let other_root = TempDir::new().unwrap();
        let absolute = tmp.path().join("abs");

        let resolved =
            WorkspaceConfig::finalize_directory_path(&absolute, Some(other_root.path())).unwrap();

        assert_eq!(resolved, absolute.canonicalize().unwrap());
        assert!(
            !other_root.path().join("abs").exists(),
            "an absolute path must not be re-rooted"
        );
    }

    /// `finalize_directory` resolves against the workspace `root_data_path`.
    #[test]
    fn finalize_directory_uses_root_data_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let workspace = WorkspaceConfig {
            root_data_path: root.clone(),
            tmp_path: root.join("tmp"),
        };

        let resolved = workspace
            .finalize_directory(&PathBuf::from("sqlite"))
            .unwrap();

        assert_eq!(resolved, root.join("sqlite"));
        assert!(resolved.is_dir());
    }

    /// `init` creates the root data path and resolves a relative `tmp_path` under it,
    /// while an absolute `tmp_path` is kept as is.
    #[test]
    fn init_creates_root_and_resolves_tmp_path() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("kms-data");
        let abs_tmp = tmp.path().join("abs-tmp");

        let relative_tmp = WorkspaceConfig {
            root_data_path: root.clone(),
            tmp_path: PathBuf::from("scratch"),
        }
        .init()
        .unwrap();
        let canonical_root = root.canonicalize().unwrap();
        assert_eq!(relative_tmp.root_data_path, canonical_root);
        assert_eq!(relative_tmp.tmp_path, canonical_root.join("scratch"));
        assert!(relative_tmp.tmp_path.is_dir());

        let absolute_tmp = WorkspaceConfig {
            root_data_path: root,
            tmp_path: abs_tmp.clone(),
        }
        .init()
        .unwrap();
        assert_eq!(absolute_tmp.tmp_path, abs_tmp.canonicalize().unwrap());
    }
}
