//! Characterization tests for the operator YAML configuration and `WebhookConfig` defaults.

use cosmian_kms_client::KmsClientConfig;

use super::{OperatorConfig, WebhookConfig};

const MINIMAL: &str = r"
kms:
  server_url: https://kms.example.com
webhook:
  injector_image: ghcr.io/cosmian/injector:1
";

const FULL: &str = r"
kms:
  server_url: https://kms.example.com
  api_token: tok
  api_token_secret_ref:
    name: kms-token
    key: token
  tls_client_cert: /c.pem
  tls_client_key: /k.pem
webhook:
  port: 9443
  tls_cert: /w.crt
  tls_key: /w.key
  injector_image: img
default_refresh_interval: 15m
";

fn write_temp(name: &str, content: &str) -> String {
    let path = std::env::temp_dir().join(format!(
        "kms_operator_characterization_{name}_{}.yaml",
        std::process::id()
    ));
    std::fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_owned()
}

#[test]
fn characterization_operator_config_from_file_defaults() {
    let path = write_temp("minimal", MINIMAL);
    let config = OperatorConfig::from_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(config.kms.server_url, "https://kms.example.com");
    assert!(config.kms.api_token.is_none());
    assert!(config.kms.api_token_secret_ref.is_none());
    assert_eq!(config.webhook.port, 8443);
    assert_eq!(config.webhook.tls_cert, "");
    assert_eq!(config.webhook.tls_key, "");
    assert_eq!(config.webhook.injector_image, "ghcr.io/cosmian/injector:1");
    assert_eq!(config.default_refresh_interval, "1h");
}

#[test]
fn characterization_operator_config_from_file_full() {
    let path = write_temp("full", FULL);
    let config = OperatorConfig::from_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(config.kms.api_token.as_deref(), Some("tok"));
    let secret_ref = config.kms.api_token_secret_ref.as_ref().unwrap();
    assert_eq!(secret_ref.name, "kms-token");
    assert_eq!(secret_ref.key, "token");
    assert_eq!(config.kms.tls_client_cert.as_deref(), Some("/c.pem"));
    assert_eq!(config.kms.tls_client_key.as_deref(), Some("/k.pem"));
    assert!(config.kms.tls_ca_cert.is_none());
    assert_eq!(config.webhook.port, 9443);
    assert_eq!(config.webhook.tls_cert, "/w.crt");
    assert_eq!(config.webhook.tls_key, "/w.key");
    assert_eq!(config.default_refresh_interval, "15m");
}

#[test]
fn characterization_operator_config_from_file_errors() {
    let missing = std::env::temp_dir().join("kms_operator_characterization_missing.yaml");
    std::fs::remove_file(&missing).ok();
    let missing = missing.to_str().unwrap().to_owned();
    let err = OperatorConfig::from_file(&missing).unwrap_err();
    assert!(
        err.to_string().starts_with(&format!(
            "Configuration error: cannot read config file {missing}: "
        )),
        "{err}"
    );

    let path = write_temp(
        "unknown",
        "kms:\n  server_url: u\n  bogus: 1\nwebhook:\n  injector_image: i\n",
    );
    let err = OperatorConfig::from_file(&path).unwrap_err();
    std::fs::remove_file(&path).unwrap();
    assert!(
        err.to_string()
            .starts_with("Configuration error: invalid config YAML: "),
        "{err}"
    );
    assert!(err.to_string().contains("bogus"), "{err}");
}

#[test]
fn characterization_webhook_config_serialization_field_names() {
    let config = WebhookConfig {
        port: 1,
        tls_cert: "c".to_owned(),
        tls_key: "k".to_owned(),
        injector_image: "i".to_owned(),
    };
    assert_eq!(
        serde_json::to_string(&config).unwrap(),
        r#"{"port":1,"tls_cert":"c","tls_key":"k","injector_image":"i"}"#
    );
}

#[test]
fn characterization_kms_client_config_maps_kms_section() {
    let path = write_temp("kmsconf", FULL);
    let config = OperatorConfig::from_file(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let client = config.kms_client_config().unwrap();
    assert_eq!(client.http_config.server_url, "https://kms.example.com");
    assert_eq!(client.http_config.access_token.as_deref(), Some("tok"));
    assert_eq!(
        client.http_config.tls_client_pem_cert_path.as_deref(),
        Some("/c.pem")
    );
    assert_eq!(
        client.http_config.tls_client_pem_key_path.as_deref(),
        Some("/k.pem")
    );
    assert!(client.http_config.verified_cert.is_none());
    assert_eq!(client.vendor_id, KmsClientConfig::default().vendor_id);
}

#[test]
fn characterization_kms_client_config_reads_ca_cert_inline() {
    let ca = write_temp("ca", "PEM-CONTENT");
    let yaml =
        format!("kms:\n  server_url: u\n  tls_ca_cert: {ca}\nwebhook:\n  injector_image: i\n");
    let path = write_temp("kmsca", &yaml);
    let config = OperatorConfig::from_file(&path).unwrap();
    let client = config.kms_client_config().unwrap();
    assert_eq!(
        client.http_config.verified_cert.as_deref(),
        Some("PEM-CONTENT")
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(&ca).unwrap();
    let err = config.kms_client_config().unwrap_err();
    assert!(
        err.to_string()
            .starts_with("Configuration error: cannot read CA cert file: "),
        "{err}"
    );
}
