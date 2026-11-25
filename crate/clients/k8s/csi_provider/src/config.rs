use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// Top-level structure of the CSI provider YAML configuration file.
///
/// Example:
/// ```yaml
/// cosmian_kms:
///   server_url: https://kms.example.com:9998
///   api_key: ""
///   tls_cert: /etc/cosmian-kms-csi/client.crt
///   tls_key: /etc/cosmian-kms-csi/client.key
///   ca_cert: /etc/cosmian-kms-csi/ca.crt
///   socket_path: /var/run/cosmian-kms-provider.sock
///   allowed_uids_by_namespace:
///     team-a: ["550e8400-e29b-41d4-a716-446655440000"]
/// ```
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct CsiProviderConfig {
    pub cosmian_kms: KmsCsiSettings,
}

impl CsiProviderConfig {
    /// Load configuration from a YAML file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or the YAML is malformed.
    pub fn from_file(path: &str) -> Result<Self, crate::error::CsiProviderError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::error::CsiProviderError::Config(format!("cannot read {path}: {e}"))
        })?;
        serde_saphyr::from_str(&content).map_err(|e| {
            crate::error::CsiProviderError::Config(format!("invalid YAML in {path}: {e}"))
        })
    }
}

/// Connection settings for the CSI provider.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct KmsCsiSettings {
    /// Full URL of the Cosmian KMS server (e.g. `https://kms.example.com:9998`).
    pub server_url: String,

    /// Optional API key sent as the `Authorization: Bearer <api_key>` header.
    #[serde(default)]
    pub api_key: Option<String>,

    /// Path to PEM-encoded client TLS certificate (mutual TLS).
    #[serde(default)]
    pub tls_cert: Option<String>,

    /// Path to PEM-encoded client TLS private key (mutual TLS).
    #[serde(default)]
    pub tls_key: Option<String>,

    /// Path to PEM-encoded CA certificate used to verify the KMS server TLS
    /// certificate.
    #[serde(default)]
    pub ca_cert: Option<String>,

    /// Filesystem path of the Unix domain socket the provider listens on.
    #[serde(default = "default_socket_path")]
    pub socket_path: String,

    /// Required allowlist: pod namespace → set of KMS UIDs a pod of that namespace may
    /// mount. A namespace or UID that is not listed is refused; an empty map refuses every
    /// mount.
    #[serde(default)]
    pub allowed_uids_by_namespace: BTreeMap<String, BTreeSet<String>>,
}

fn default_socket_path() -> String {
    "/var/run/cosmian-kms-provider.sock".to_owned()
}
