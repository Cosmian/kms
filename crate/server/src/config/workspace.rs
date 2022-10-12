use std::{
    env,
    path::{Path, PathBuf},
};

use clap::Args;

#[derive(Debug, Args)]
pub struct WorkspaceConfig {
    /// The folder to store public data (plain text and readable by anyone)
    #[clap(long, env = "KMS_PUBLIC_PATH", parse(from_os_str))]
    pub public_path: PathBuf,

    /// The folder to store data to share between KMS instance (encrypted and readable by any KMS)
    #[clap(long, env = "KMS_SHARED_PATH", parse(from_os_str))]
    pub shared_path: PathBuf,

    /// The folder to store private data (encrypted and readable by none but the current instance)
    #[clap(long, env = "KMS_PRIVATE_PATH", parse(from_os_str))]
    pub private_path: PathBuf,

    /// The folder to store temporary data (non-persistent data readable by no-one but the current instance during the current execution)
    #[clap(long, env = "KMS_TMP_PATH", parse(from_os_str), default_value = "/tmp")]
    pub tmp_path: PathBuf,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        WorkspaceConfig {
            public_path: std::env::temp_dir(),
            shared_path: std::env::temp_dir(),
            private_path: std::env::temp_dir(),
            tmp_path: std::env::temp_dir(),
        }
    }
}

impl WorkspaceConfig {
    pub fn init(&self) -> eyre::Result<WorkspaceConfig> {
        let path = env::current_dir()?;

        let workspace = WorkspaceConfig {
            public_path: normalize_path(&path, &self.public_path),
            shared_path: normalize_path(&path, &self.shared_path),
            private_path: normalize_path(&path, &self.private_path),
            tmp_path: normalize_path(&path, &self.tmp_path),
        };

        if !Path::new(&workspace.public_path).exists() {
            eyre::bail!("Can't find '{:?}' as public_path", workspace.public_path);
        }

        if !Path::new(&workspace.shared_path).exists() {
            eyre::bail!("Can't find '{:?}' as shared_path", workspace.shared_path);
        }

        if !Path::new(&workspace.private_path).exists() {
            eyre::bail!("Can't find '{:?}' as private_path", workspace.private_path);
        }

        if !Path::new(&workspace.tmp_path).exists() {
            eyre::bail!("Can't find '{:?}' as tmp_path", workspace.tmp_path);
        }

        Ok(workspace)
    }
}

fn normalize_path(current_path: &Path, target: &Path) -> PathBuf {
    if target.is_absolute() {
        target.to_owned()
    } else {
        current_path.join(&target)
    }
}
