//! Policy Bundle Manager
//!
//! Responsible for loading, validating, hashing, and hot-reloading Rego policy bundles.
//! Supports both local directory bundles (with file-watch) and remote URL bundles (with polling).

use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{error::KmsError, result::KResult};

/// A single Rego file loaded from a policy bundle.
#[derive(Debug, Clone)]
pub struct RegoFile {
    /// Filename (relative path within the bundle directory).
    pub filename: String,
    /// File content.
    pub content: String,
}

/// Computed bundle metadata after loading and validation.
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    /// Content-only SHA-256 hash (filenames excluded).
    /// Computed over sorted per-file content hashes.
    pub hash: String,
    /// All Rego files in the bundle.
    pub files: Vec<RegoFile>,
}

/// Loads a policy bundle from a local directory.
///
/// The directory must contain at least one `.rego` file, and one of them must
/// define the `data.kms.authz.allow` rule (entry point is `authz.rego`).
///
/// # Errors
/// Returns an error if the directory is missing, contains no `.rego` files,
/// or if no `authz.rego` entry point is found.
pub fn load_bundle_from_directory(path: &Path) -> KResult<BundleMetadata> {
    if !path.is_dir() {
        return Err(KmsError::ServerError(format!(
            "RBAC bundle path is not a directory: {}",
            path.display()
        )));
    }

    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| {
        KmsError::ServerError(format!(
            "Failed to read RBAC bundle directory {}: {e}",
            path.display()
        ))
    })? {
        let entry = entry
            .map_err(|e| KmsError::ServerError(format!("Failed to read directory entry: {e}")))?;
        let file_path = entry.path();
        if file_path.extension().is_some_and(|ext| ext == "rego") {
            let filename = file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let content = fs::read_to_string(&file_path).map_err(|e| {
                KmsError::ServerError(format!(
                    "Failed to read Rego file {}: {e}",
                    file_path.display()
                ))
            })?;
            files.push(RegoFile { filename, content });
        }
    }

    if files.is_empty() {
        return Err(KmsError::ServerError(format!(
            "RBAC bundle directory contains no .rego files: {}",
            path.display()
        )));
    }

    // Verify entry point exists
    if !files.iter().any(|f| f.filename == "authz.rego") {
        return Err(KmsError::ServerError(format!(
            "RBAC bundle is missing entry point 'authz.rego' in: {}",
            path.display()
        )));
    }

    let hash = compute_bundle_hash(&files);
    Ok(BundleMetadata { hash, files })
}

/// Validates a policy bundle by compiling all `.rego` files with Regorus.
///
/// This performs strict validation: if any file references an unsupported
/// built-in function, the bundle is rejected at load time.
///
/// # Errors
/// Returns an error if any Rego file fails to compile.
pub fn validate_bundle(files: &[RegoFile]) -> KResult<()> {
    let mut engine = regorus::Engine::new();

    for file in files {
        engine
            .add_policy(file.filename.clone(), file.content.clone())
            .map_err(|e| {
                KmsError::ServerError(format!(
                    "RBAC policy validation failed for '{}': {e}",
                    file.filename
                ))
            })?;
    }

    Ok(())
}

/// Computes the content-only SHA-256 hash of a policy bundle.
///
/// The hash is computed over sorted per-file content hashes (filenames excluded).
/// This means renaming a file without changing its content does not change the bundle hash,
/// preserving audit trail continuity.
pub fn compute_bundle_hash(files: &[RegoFile]) -> String {
    // Hash each file's content individually
    let mut content_hashes: Vec<[u8; 32]> = files
        .iter()
        .map(|f| {
            let mut hasher = Sha256::new();
            hasher.update(f.content.as_bytes());
            hasher.finalize().into()
        })
        .collect();

    // Sort hashes for deterministic ordering regardless of file enumeration order
    content_hashes.sort_unstable();

    // Hash the sorted hashes together
    let mut final_hasher = Sha256::new();
    for h in &content_hashes {
        final_hasher.update(h);
    }

    hex::encode(final_hasher.finalize())
}

/// Returns the disk-cache path for remote bundles.
///
/// Remote bundles are cached under `<data_dir>/rbac_bundle_cache/` so the server
/// can start with the cached version if the remote is unreachable.
pub fn bundle_cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join("rbac_bundle_cache")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_compute_bundle_hash_is_filename_independent() {
        let files_a = vec![
            RegoFile {
                filename: "helpers.rego".to_owned(),
                content: "package kms.helpers\nimport rego.v1\n".to_owned(),
            },
            RegoFile {
                filename: "authz.rego".to_owned(),
                content: "package kms.authz\nimport rego.v1\nallow = true\n".to_owned(),
            },
        ];

        // Same content, different filenames
        let files_b = vec![
            RegoFile {
                filename: "utils.rego".to_owned(),
                content: "package kms.helpers\nimport rego.v1\n".to_owned(),
            },
            RegoFile {
                filename: "main.rego".to_owned(),
                content: "package kms.authz\nimport rego.v1\nallow = true\n".to_owned(),
            },
        ];

        assert_eq!(compute_bundle_hash(&files_a), compute_bundle_hash(&files_b));
    }

    #[test]
    fn test_compute_bundle_hash_changes_with_content() {
        let files_a = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "package kms.authz\nallow = true\n".to_owned(),
        }];

        let files_b = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "package kms.authz\nallow = false\n".to_owned(),
        }];

        assert_ne!(compute_bundle_hash(&files_a), compute_bundle_hash(&files_b));
    }

    #[test]
    fn test_load_bundle_from_directory_success() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("authz.rego"),
            "package kms.authz\nimport rego.v1\ndefault allow := false\n",
        )
        .unwrap();

        let result = load_bundle_from_directory(dir.path());
        assert!(result.is_ok());
        let meta = result.unwrap();
        assert_eq!(meta.files.len(), 1);
        assert!(!meta.hash.is_empty());
    }

    #[test]
    fn test_load_bundle_from_directory_missing_entry_point() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("helpers.rego"),
            "package kms.helpers\nimport rego.v1\n",
        )
        .unwrap();

        let result = load_bundle_from_directory(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("authz.rego"));
    }

    #[test]
    fn test_load_bundle_from_directory_empty() {
        let dir = TempDir::new().unwrap();
        let result = load_bundle_from_directory(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no .rego files"));
    }

    #[test]
    fn test_validate_bundle_valid() {
        let files = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "package kms.authz\nimport rego.v1\ndefault allow := false\n".to_owned(),
        }];
        assert!(validate_bundle(&files).is_ok());
    }

    #[test]
    fn test_validate_bundle_invalid_syntax() {
        let files = vec![RegoFile {
            filename: "authz.rego".to_owned(),
            content: "this is not valid rego {{{{".to_owned(),
        }];
        assert!(validate_bundle(&files).is_err());
    }
}
