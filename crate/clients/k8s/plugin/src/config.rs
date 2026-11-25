use serde::Deserialize;

/// Top-level structure of the plugin YAML configuration file.
///
/// Example:
/// ```yaml
/// cosmian_kms:
///   server_url: https://kms.example.com:9998
///   api_key: ""
///   tls_cert: /etc/kubernetes-kms-plugin/client.crt
///   tls_key: /etc/kubernetes-kms-plugin/client.key
///   ca_cert: /etc/kubernetes-kms-plugin/ca.crt
///   wrapping_key_uid: "550e8400-e29b-41d4-a716-446655440000"
///   socket_path: /var/run/kubernetes-kms-plugin/kms.sock
///   allowed_peer_uids: [65532]
/// ```
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    pub cosmian_kms: KmsPluginSettings,
}

/// Connection and operation settings for the plugin.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
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

    /// Required: UIDs (kernel `SO_PEERCRED`) allowed to connect to the socket, i.e. the
    /// kube-apiserver UID. Any other peer is disconnected.
    #[serde(default)]
    pub allowed_peer_uids: Vec<u32>,
}

fn default_socket_path() -> String {
    "/var/run/kubernetes-kms-plugin/kms.sock".to_owned()
}

impl PluginConfig {
    /// Load and deserialize a `PluginConfig` from a YAML file at `path`.
    pub fn from_file(path: &str) -> Result<Self, crate::error::PluginError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| crate::error::PluginError::Config(format!("cannot read {path}: {e}")))?;
        let config: Self = serde_saphyr::from_str(&content).map_err(|e| {
            crate::error::PluginError::Config(format!("invalid YAML in {path}: {e}"))
        })?;
        if config.cosmian_kms.allowed_peer_uids.is_empty() {
            return Err(crate::error::PluginError::Config(
                "allowed_peer_uids must list the kube-apiserver UID".to_owned(),
            ));
        }
        Ok(config)
    }
}

#[cfg(test)]
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
  socket_path: /var/run/kubernetes-kms-plugin.sock
  allowed_peer_uids: [65532, 0]
";
        let cfg: PluginConfig = serde_saphyr::from_str(yaml).expect("should parse");
        assert_eq!(cfg.cosmian_kms.server_url, "https://kms.example.com:9998");
        assert_eq!(cfg.cosmian_kms.api_key.as_deref(), Some("secret"));
        assert_eq!(
            cfg.cosmian_kms.wrapping_key_uid,
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(
            cfg.cosmian_kms.socket_path,
            "/var/run/kubernetes-kms-plugin.sock"
        );
        assert_eq!(cfg.cosmian_kms.allowed_peer_uids, vec![65532, 0]);
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r"
cosmian_kms:
  server_url: http://localhost:9998
  wrapping_key_uid: my-key
  socket_path: /tmp/kms.sock
";
        let cfg: PluginConfig = serde_saphyr::from_str(yaml).expect("should parse minimal config");
        assert!(cfg.cosmian_kms.api_key.is_none());
        assert!(cfg.cosmian_kms.tls_cert.is_none());
        assert!(cfg.cosmian_kms.ca_cert.is_none());
    }

    #[test]
    fn from_file_requires_allowed_peer_uids() {
        let base = "cosmian_kms:\n  server_url: http://localhost:9998\n  wrapping_key_uid: k\n";
        for (name, extra, ok) in [
            ("missing", "", false),
            ("empty", "  allowed_peer_uids: []\n", false),
            ("listed", "  allowed_peer_uids: [65532]\n", true),
        ] {
            let path = std::env::temp_dir()
                .join(format!("kms_plugin_cfg_{name}_{}.yaml", std::process::id()));
            std::fs::write(&path, format!("{base}{extra}")).expect("write temp config");
            let result = PluginConfig::from_file(path.to_str().expect("utf-8 path"));
            std::fs::remove_file(&path).ok();
            match (ok, result) {
                (true, Ok(_)) => {}
                (false, Err(e)) => assert_eq!(
                    e.to_string(),
                    "Configuration error: allowed_peer_uids must list the kube-apiserver UID",
                    "{name}"
                ),
                (ok, r) => panic!("{name}: expected ok={ok}, got {r:?}"),
            }
        }
    }
}
