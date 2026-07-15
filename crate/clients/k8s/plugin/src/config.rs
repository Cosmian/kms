use serde::Deserialize;

/// Top-level structure of the plugin YAML configuration file.
///
/// Example:
/// ```yaml
/// cosmian_kms:
///   server_url: https://kms.example.com:9998
///   api_key: ""
///   tls_cert: /etc/cosmian-kms-plugin/client.crt
///   tls_key: /etc/cosmian-kms-plugin/client.key
///   ca_cert: /etc/cosmian-kms-plugin/ca.crt
///   wrapping_key_uid: "550e8400-e29b-41d4-a716-446655440000"
///   socket_path: /var/run/cosmian-kms-plugin/kms.sock
/// ```
#[derive(Deserialize, Debug, Clone)]
pub struct PluginConfig {
    pub cosmian_kms: KmsPluginSettings,
}

/// Connection and operation settings for the plugin.
#[derive(Deserialize, Debug, Clone)]
pub struct KmsPluginSettings {
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

    /// Path to PEM-encoded CA certificate used to verify the KMS server certificate.
    #[serde(default)]
    pub ca_cert: Option<String>,

    /// UID of the KMS wrapping key (KEK) to use for Encrypt/Decrypt operations.
    /// This corresponds to the `key_id` returned to `kube-apiserver`.
    pub wrapping_key_uid: String,

    /// Filesystem path of the Unix domain socket the plugin listens on.
    #[serde(default = "default_socket_path")]
    pub socket_path: String,
}

fn default_socket_path() -> String {
    "/var/run/cosmian-kms-plugin/kms.sock".to_owned()
}

impl PluginConfig {
    /// Load and deserialize a `PluginConfig` from a YAML file at `path`.
    pub fn from_file(path: &str) -> Result<Self, crate::error::PluginError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PluginError::Config(format!("cannot read {path}: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| crate::error::PluginError::Config(format!("invalid YAML in {path}: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let yaml = r"
cosmian_kms:
  server_url: https://kms.example.com:9998
  api_key: secret
  tls_cert: /etc/client.crt
  tls_key: /etc/client.key
  ca_cert: /etc/ca.crt
  wrapping_key_uid: 550e8400-e29b-41d4-a716-446655440000
  socket_path: /var/run/cosmian-kms-plugin.sock
";
        let cfg: PluginConfig = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(cfg.cosmian_kms.server_url, "https://kms.example.com:9998");
        assert_eq!(cfg.cosmian_kms.api_key.as_deref(), Some("secret"));
        assert_eq!(
            cfg.cosmian_kms.wrapping_key_uid,
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            cfg.cosmian_kms.socket_path,
            "/var/run/cosmian-kms-plugin.sock"
        );
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r"
cosmian_kms:
  server_url: http://localhost:9998
  wrapping_key_uid: my-key
  socket_path: /tmp/kms.sock
";
        let cfg: PluginConfig = serde_yaml::from_str(yaml).expect("should parse minimal config");
        assert!(cfg.cosmian_kms.api_key.is_none());
        assert!(cfg.cosmian_kms.tls_cert.is_none());
        assert!(cfg.cosmian_kms.ca_cert.is_none());
    }
}
